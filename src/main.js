import { Client, Databases, Users, Account } from "appwrite";
import { createHash, randomBytes, createCipheriv, createHmac } from "crypto";

// =========================================================================
// 1. CONSTANTS
// =========================================================================
const APPWRITE_DATABASE_ID = "keepflip";
const OAUTH_STATES_TABLE_ID = "ebay_oauth_states";
const CONNECTIONS_TABLE_ID = "ebay_connections";

const CONNECT_PATH = "/connect";
const STATUS_PATH = "/status";
const CALLBACK_PATH = "/oauth/ebay/callback";
const DECLINED_PATH = "/oauth/ebay/declined";
const APP_RETURN_URL = "keepflip://ebay/connected";
const STATE_TTL_MS = 10 * 60 * 1000;
const MAX_CODE_LENGTH = 1024;
const MAX_STATE_LENGTH = 160;

// =========================================================================
// 2. ERROR HANDLERS & HELPERS
// =========================================================================
export class RequestError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.name = "RequestError";
    this.statusCode = statusCode;
  }
}

function cleanText(value, maximumLength = 2_000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maximumLength);
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const expected = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== expected) continue;
    return cleanText(Array.isArray(value) ? value[0] : value, 8_000);
  }
  return "";
}

function getRequestPath(req) {
  const providedPath = cleanText(req?.path, 500);
  if (providedPath) {
    try {
      return new URL(providedPath, "https://keepflip.invalid").pathname;
    } catch {
      return "/";
    }
  }
  const requestUrl = cleanText(req?.url, 8_000);
  if (requestUrl) {
    try {
      return new URL(requestUrl, "https://keepflip.invalid").pathname;
    } catch {
      return "/";
    }
  }
  return "/";
}

function queryValue(req, key) {
  const parsedQuery = req?.query;
  if (parsedQuery && typeof parsedQuery === "object") {
    const value = parsedQuery[key];
    const first = Array.isArray(value) ? value[0] : value;
    const cleaned = cleanText(first, 8_000);
    if (cleaned) return cleaned;
  }
  if (typeof parsedQuery === "string") {
    const value = cleanText(new URLSearchParams(parsedQuery).get(key), 8_000);
    if (value) return value;
  }
  const queryString = cleanText(req?.queryString, 8_000);
  if (queryString) {
    return cleanText(new URLSearchParams(queryString).get(key), 8_000);
  }
  const requestUrl = cleanText(req?.url, 8_000);
  if (requestUrl) {
    try {
      const value = cleanText(
        new URL(requestUrl, "https://keepflip.invalid").searchParams.get(key),
        8_000
      );
      if (value) return value;
    } catch {}
  }
  return "";
}

function requireEnvironment(name) {
  const value = cleanText(process.env[name], 8_000);
  if (!value) {
    throw new RequestError(
      `KeepFlip's eBay connection is missing the ${name} Function variable.`,
      500
    );
  }
  return value;
}

function oauthEnvironment(requestedValue) {
  const value = cleanText(requestedValue, 32).toLowerCase();
  if (value === "sandbox" || value === "production") return value;
  throw new RequestError(
    "KeepFlip must request either the sandbox or production eBay environment.",
    400
  );
}

function requestBody(req) {
  const body = req?.bodyJson ?? req?.body;
  if (body && typeof body === "object") return body;
  if (typeof body === "string") {
    try {
      const parsed = JSON.parse(body);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

function requestedScopeText(value) {
  const supplied = cleanText(value, 4_000);
  const scopes = supplied.split(/\s+/).filter(Boolean);
  if (
    scopes.length === 0 ||
    scopes.some(
      (scope) =>
        !/^https:\/\/api\.ebay\.com\/oauth\/(?:api_scope(?:\/[A-Za-z0-9._-]+)*|scope\/[A-Za-z0-9._-]+)$/.test(scope)
    )
  ) {
    throw new RequestError("KeepFlip supplied an invalid eBay OAuth scope list.", 400);
  }
  return [...new Set(scopes)].join(" ");
}

function ebayTokenEndpoint(environment) {
  return environment === "production"
    ? "https://ebay.com"
    : "https://ebay.com";
}

function ebayIdentityEndpoint(environment) {
  return environment === "production"
    ? "https://ebay.com"
    : "https://ebay.com";
}

function credentialsFor(environment) {
  const prefix = environment === "production" ? "EBAY_PRODUCTION" : "EBAY_SANDBOX";
  return {
    clientId: requireEnvironment(`${prefix}_CLIENT_ID`),
    clientSecret: requireEnvironment(`${prefix}_CLIENT_SECRET`),
  };
}

function ruNameFor(environment) {
  return requireEnvironment(
    environment === "production" ? "EBAY_PRODUCTION_RUNAME" : "EBAY_SANDBOX_RUNAME"
  );
}

function oauthStateRowId(state) {
  const digest = createHash("sha256").update(state).digest("base64url");
  return `s_${digest.slice(0, 34)}`;
}

function connectionRowId(ownerId, environment) {
  const digest = createHash("sha256")
    .update(`${ownerId}|ebay|${environment}`)
    .digest("base64url");
  return `c_${digest.slice(0, 34)}`;
}

function isOpaqueState(value) {
  return value.length >= 32 && value.length <= MAX_STATE_LENGTH && /^[A-Za-z0-9_-]+$/.test(value);
}

function isValidAuthorizationCode(value) {
  return value.length > 0 && value.length <= MAX_CODE_LENGTH;
}

function dateAfterSeconds(now, rawSeconds, maximumSeconds) {
  const seconds = Number(rawSeconds);
  if (!Number.isFinite(seconds) || seconds < 60 || seconds > maximumSeconds) {
    throw new RequestError("eBay returned an invalid token expiration. Please connect again.", 502);
  }
  return new Date(now.getTime() + Math.round(seconds * 1_000)).toISOString();
}

function decodeBase64Key(name, keyBase64) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(keyBase64)) {
    throw new RequestError(`${name} must be a Base64-encoded 32-byte key.`, 500);
  }
  const key = Buffer.from(keyBase64, "base64");
  if (key.length !== 32) {
    throw new RequestError(`${name} must decode to exactly 32 bytes.`, 500);
  }
  return key;
}

function encryptTokenPayload({ keyBase64, ownerId, environment, tokenPayload }) {
  const key = decodeBase64Key("EBAY_TOKEN_ENCRYPTION_KEY", keyBase64);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`${ownerId}|ebay|${environment}|v1`, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(tokenPayload), "utf8"),
    cipher.final(),
  ]);
  return [
    "v1",
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

function hashEbayUserId(userId) {
  const key = decodeBase64Key("EBAY_USER_ID_HMAC_KEY", requireEnvironment("EBAY_USER_ID_HMAC_KEY"));
  return createHmac("sha256", key).update(`keepflip|ebay-user-id|v1|${userId}`, "utf8").digest("hex");
}

function appwriteRuntime(req) {
  const endpoint = requireEnvironment("APPWRITE_FUNCTION_API_ENDPOINT").replace(/\/+$/, "");
  const projectId = requireEnvironment("APPWRITE_FUNCTION_PROJECT_ID");
  const apiKey = getHeader(req?.headers, "x-appwrite-key");
  if (!apiKey) {
    throw new RequestError("KeepFlip could not access its secure eBay connection storage.", 500);
  }
  return { apiKey, endpoint, projectId };
}

// =========================================================================
// 3. MAIN ROUTING CONTROLLER
// =========================================================================
export default async function (context) {
  const req = context.req;
  const res = context.res;

  try {
    const targetPath = getRequestPath(req);
    const { apiKey, endpoint, projectId } = appwriteRuntime(req);
    
    const systemClient = new Client()
      .setEndpoint(endpoint)
      .setProject(projectId)
      .setKey(apiKey);

    const databases = new Databases(systemClient);
    const users = new Users(systemClient);

    // ---------------------------------------------------------------------
    // PATHWAY A: /connect (Called by App to kick off tracking)
    // ---------------------------------------------------------------------
    if (targetPath === CONNECT_PATH) {
      const body = requestBody(req);
      const environment = oauthEnvironment(body.environment);
      const scopeText = requestedScopeText(body.scopeText);
      
      const userJwt = cleanText(body.jwt, 2048);
      if (!userJwt) throw new RequestError("Unauthorized client execution framework.", 401);

      const userClient = new Client().setEndpoint(endpoint).setProject(projectId).setJWT(userJwt);
      const accountService = new Account(userClient);
      const activeUser = await accountService.get();
      const ownerId = activeUser.$id;

      const state = randomBytes(48).toString("base64url");
      const stateDocumentId = oauthStateRowId(state);

      await databases.createDocument(
        APPWRITE_DATABASE_ID,
        OAUTH_STATES_TABLE_ID,
        stateDocumentId,
        {
          ownerId,
          environment,
          scopeText,
          createdAt: new Date().toISOString(),
        }
      );

      return res.json({ state, environment });
    }

    // ---------------------------------------------------------------------
    // PATHWAY B: /status (Called by App to check mapping status)
    // ---------------------------------------------------------------------
    if (targetPath === STATUS_PATH) {
      const body = requestBody(req);
      const environment = oauthEnvironment(body.environment);
      const userJwt = cleanText(body.jwt, 2048);
      if (!userJwt) throw new RequestError("Missing security credentials context.", 401);
  
      const userClient = new Client().setEndpoint(endpoint).setProject(projectId).setJWT(userJwt);
      const accountService = new Account(userClient);
      const activeUser = await accountService.get();
  
      const connectionDocId = connectionRowId(activeUser.$id, environment);
  
      try {
        await databases.getDocument(APPWRITE_DATABASE_ID, CONNECTIONS_TABLE_ID, connectionDocId);
        return res.json({ connected: true });
      } catch (dbError) {
        if (dbError.code === 404) {
          return res.json({ connected: false });
        }
        throw dbError;
      }
    }
  
    // ---------------------------------------------------------------------
    // PATHWAY C: /oauth/ebay/callback (Redirected from eBay)
    // ---------------------------------------------------------------------
    if (targetPath === CALLBACK_PATH) {
      const code = queryValue(req, "code");
      const state = queryValue(req, "state");
  
      if (!isValidAuthorizationCode(code) || !isOpaqueState(state)) {
        throw new RequestError("Malformed callback signatures returned from eBay.", 400);
      }
  
      const stateDocumentId = oauthStateRowId(state);
      let stateRecord;
      try {
        stateRecord = await databases.getDocument(APPWRITE_DATABASE_ID, OAUTH_STATES_TABLE_ID, stateDocumentId);
        await databases.deleteDocument(APPWRITE_DATABASE_ID, OAUTH_STATES_TABLE_ID, stateDocumentId);
      } catch {
        throw new RequestError("Expired or invalid session authorization state sequence.", 403);
      }
  
      const recordAge = Date.now() - Date.parse(stateRecord.createdAt);
      if (recordAge > STATE_TTL_MS) {
        throw new RequestError("The authentication request session has expired.", 403);
      }
  
      const activeEnv = stateRecord.environment;
      const ownerId = stateRecord.ownerId;
      const { clientId, clientSecret } = credentialsFor(activeEnv);
      const ruName = ruNameFor(activeEnv);
  
      const basicAuthHeader = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
      const tokenEndpoint = ebayTokenEndpoint(activeEnv);
  
      const tokenResponse = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": `Basic ${basicAuthHeader}`,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          redirect_uri: ruName,
        }),
      });
  
      const tokenPayload = await tokenResponse.json();
      if (!tokenResponse.ok) {
        throw new RequestError(`eBay authorization exchange rejected: ${tokenPayload.error_description || 'Unknown Error'}`, 502);
      }
  
      const identityEndpoint = ebayIdentityEndpoint(activeEnv);
      const identityResponse = await fetch(identityEndpoint, {
        headers: { "Authorization": `Bearer ${tokenPayload.access_token}` },
      });
  
      const identityPayload = await identityResponse.json();
      if (!identityResponse.ok) {
        throw new RequestError("Could not retrieve clean identity metrics from the eBay portal.", 502);
      }
  
      const rawEbayUserId = identityPayload.userId;
      const hashedEbayId = hashEbayUserId(rawEbayUserId);
  
      const encryptionKey = requireEnvironment("EBAY_TOKEN_ENCRYPTION_KEY");
      const secureTokenBlob = encryptTokenPayload({
        keyBase64: encryptionKey,
        ownerId,
        environment: activeEnv,
        tokenPayload: {
          access_token: tokenPayload.access_token,
          refresh_token: tokenPayload.refresh_token,
          expires_at: dateAfterSeconds(new Date(), tokenPayload.expires_in, 7200),
          refresh_token_expires_at: dateAfterSeconds(new Date(), tokenPayload.refresh_token_expires_in, 60 * 60 * 24 * 500),
        },
      });
  
      const connectionDocId = connectionRowId(ownerId, activeEnv);
      const connectionData = {
        ownerId,
        hashedEbayId,
        encryptedTokens: secureTokenBlob,
        ebayUsername: cleanText(identityPayload.username || identityPayload.displayName, 200),
        updatedAt: new Date().toISOString(),
      };
  
      try {
        await databases.updateDocument(APPWRITE_DATABASE_ID, CONNECTIONS_TABLE_ID, connectionDocId, connectionData);
      } catch (updateError) {
        if (updateError.code === 404) {
          await databases.createDocument(APPWRITE_DATABASE_ID, CONNECTIONS_TABLE_ID, connectionDocId, connectionData);
        } else {
          throw updateError;
        }
      }
  
      const tokenObj = await users.createToken(ownerId);
      const finalRedirectUrl = `${APP_RETURN_URL}?userId=${ownerId}&secret=${tokenObj.secret}&state=${state}`;
      return res.redirect(finalRedirectUrl);
    }
  
    // ---------------------------------------------------------------------
    // PATHWAY D: /oauth/ebay/declined (User cancelled)
    // ---------------------------------------------------------------------
    if (targetPath === DECLINED_PATH) {
      return res.redirect("keepflip://ebay/declined");
    }
  
    throw new RequestError("Resource endpoint not found.", 404);
  
  } catch (error) {
    const statusCode = error instanceof RequestError ? error.statusCode : 500;
    context.error(`[KeepFlip OAuth Error]: ${error.message}`);
    
    return res.json(
      {
        success: false,
        message: error.message || "An unexpected infrastructure error occurred.",
      },
      statusCode
    );
  }
}