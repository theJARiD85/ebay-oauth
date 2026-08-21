import {
  createCipheriv,
  createHash,
  createHmac,
  randomBytes,
} from "node:crypto";

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
    const value = cleanText(
      new URLSearchParams(parsedQuery).get(key),
      8_000,
    );
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
        8_000,
      );
      if (value) return value;
    } catch {
      // Try the explicit request path below.
    }
  }

  const requestPath = cleanText(req?.path, 8_000);
  if (requestPath) {
    try {
      return cleanText(
        new URL(requestPath, "https://keepflip.invalid").searchParams.get(key),
        8_000,
      );
    } catch {
      return "";
    }
  }

  return "";
}

function requireEnvironment(name) {
  const value = cleanText(process.env[name], 8_000);
  if (!value) {
    throw new RequestError(
      `KeepFlip's eBay connection is missing the ${name} Function variable.`,
      500,
    );
  }
  return value;
}

function oauthEnvironment(requestedValue) {
  const value = cleanText(requestedValue, 32).toLowerCase();
  if (value === "sandbox" || value === "production") return value;

  throw new RequestError(
    "KeepFlip must request either the sandbox or production eBay environment.",
    400,
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
        !/^https:\/\/api\.ebay\.com\/oauth\/(?:api_scope(?:\/[A-Za-z0-9._-]+)*|scope\/[A-Za-z0-9._-]+)$/.test(scope),
    )
  ) {
    throw new RequestError(
      "KeepFlip supplied an invalid eBay OAuth scope list.",
      400,
    );
  }

  return [...new Set(scopes)].join(" ");
}

function ebayTokenEndpoint(environment) {
  return environment === "production"
    ? "https://api.ebay.com/identity/v1/oauth2/token"
    : "https://api.sandbox.ebay.com/identity/v1/oauth2/token";
}

function ebayIdentityEndpoint(environment) {
  return environment === "production"
    ? "https://api.ebay.com/commerce/identity/v1/user/"
    : "https://api.sandbox.ebay.com/commerce/identity/v1/user/";
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
    environment === "production"
      ? "EBAY_PRODUCTION_RUNAME"
      : "EBAY_SANDBOX_RUNAME",
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
  return (
    value.length >= 32 &&
    value.length <= MAX_STATE_LENGTH &&
    /^[A-Za-z0-9_-]+$/.test(value)
  );
}

function isValidAuthorizationCode(value) {
  return value.length > 0 && value.length <= MAX_CODE_LENGTH;
}

function isFutureIsoDate(value, now) {
  const parsed = Date.parse(cleanText(value, 80));
  return Number.isFinite(parsed) && parsed > now.getTime();
}

function dateAfterSeconds(now, rawSeconds, maximumSeconds) {
  const seconds = Number(rawSeconds);
  if (!Number.isFinite(seconds) || seconds < 60 || seconds > maximumSeconds) {
    throw new RequestError(
      "eBay returned an invalid token expiration. Please connect again.",
      502,
    );
  }
  return new Date(now.getTime() + Math.round(seconds * 1_000)).toISOString();
}

function decodeBase64Key(name, keyBase64) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(keyBase64)) {
    throw new RequestError(
      `${name} must be a Base64-encoded 32-byte key.`,
      500,
    );
  }

  const key = Buffer.from(keyBase64, "base64");
  if (key.length !== 32) {
    throw new RequestError(
      `${name} must decode to exactly 32 bytes.`,
      500,
    );
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
  const key = decodeBase64Key(
    "EBAY_USER_ID_HMAC_KEY",
    requireEnvironment("EBAY_USER_ID_HMAC_KEY"),
  );

  return createHmac("sha256", key)
    .update(`keepflip|ebay-user-id|v1|${userId}`, "utf8")
    .digest("hex");
}

function appwriteRuntime(req) {
  const endpoint = requireEnvironment("APPWRITE_FUNCTION_API_ENDPOINT").replace(
    /\/+$/,
    "",
  );
  const projectId = requireEnvironment("APPWRITE_FUNCTION_PROJECT_ID");
  const apiKey = getHeader(req?.headers, "x-appwrite-key");

  if (!apiKey) {
    throw new RequestError(
      "KeepFlip could not access its secure eBay connection storage.",
      500,
    );
  }

  return { apiKey, endpoint, projectId };
}

async function appwriteRequest({
  apiKey,
  body,
  endpoint,
  fetchImpl,
  method = "GET",
  path,
  projectId,
  userJwt,
}) {
  let response;
  try {
    response = await fetchImpl(`${endpoint}${path}`, {
      method,
      headers: {
        "X-Appwrite-Project": projectId,
        ...(apiKey ? { "X-Appwrite-Key": apiKey } : {}),
        ...(userJwt ? { "X-Appwrite-JWT": userJwt } : {}),
        ...(body ? { "Content-Type": "application/json" } : {}),
        Accept: "application/json",
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch {
    throw new RequestError(
      "KeepFlip could not reach its secure eBay connection storage.",
      503,
    );
  }

  const rawBody = await response.text();
  let payload = {};
  if (rawBody) {
    try {
      payload = JSON.parse(rawBody);
    } catch {
      throw new RequestError(
        "KeepFlip's secure eBay connection storage returned an unreadable response.",
        503,
      );
    }
  }

  return { ok: response.ok, payload, status: response.status };
}

async function requireAppwriteSuccess(request) {
  const result = await appwriteRequest(request);
  if (!result.ok) {
    throw new RequestError(
      "KeepFlip could not update the secure eBay connection.",
      result.status === 401 || result.status === 403 ? 403 : 503,
    );
  }
  return result.payload;
}

async function authenticateCaller({ fetchImpl, req, runtime }) {
  const callerUserId = getHeader(req?.headers, "x-appwrite-user-id");
  const userJwt = getHeader(req?.headers, "x-appwrite-user-jwt");

  if (!callerUserId || !userJwt) {
    throw new RequestError("Sign in to KeepFlip before connecting eBay.", 401);
  }

  const account = await appwriteRequest({
    endpoint: runtime.endpoint,
    fetchImpl,
    path: "/account",
    projectId: runtime.projectId,
    userJwt,
  });

  if (!account.ok) {
    throw new RequestError(
      "Sign in to KeepFlip before connecting eBay.",
      account.status === 401 ? 401 : 503,
    );
  }

  const user = account.payload;
  if (user?.$id !== callerUserId || user?.status !== true) {
    throw new RequestError("A registered KeepFlip account is required.", 403);
  }

  return { ownerId: callerUserId };
}

function appReturnUrl(status) {
  const url = new URL(APP_RETURN_URL);
  url.searchParams.set("status", status);
  return url.toString();
}

function browserPage(res, { message, statusCode, title }) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title></head><body><main><h1>${title}</h1><p>${message}</p><p>You can return to KeepFlip and try again if needed.</p></main></body></html>`;
  return res.text(html, statusCode, {
    "cache-control": "no-store",
    "content-type": "text/html; charset=utf-8",
  });
}

function jsonError(res, caughtError) {
  const message =
    caughtError instanceof Error
      ? caughtError.message
      : "KeepFlip could not complete the eBay connection.";
  const statusCode =
    caughtError instanceof RequestError ? caughtError.statusCode : 500;
  return res.json({ ok: false, error: message }, statusCode);
}

async function updateState({ data, fetchImpl, runtime, stateRowId }) {
  return requireAppwriteSuccess({
    apiKey: runtime.apiKey,
    body: { data },
    endpoint: runtime.endpoint,
    fetchImpl,
    method: "PATCH",
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(OAUTH_STATES_TABLE_ID)}/rows/${encodeURIComponent(
      stateRowId,
    )}`,
    projectId: runtime.projectId,
  });
}

async function claimState({ fetchImpl, now, runtime, stateRowId }) {
  const queryFor = (column, value) =>
    JSON.stringify({ method: "equal", column, values: [value] });
  const payload = await requireAppwriteSuccess({
    apiKey: runtime.apiKey,
    body: {
      data: { claimedAt: now.toISOString(), status: "processing" },
      queries: [
        queryFor("$id", stateRowId),
        queryFor("status", "pending"),
      ],
    },
    endpoint: runtime.endpoint,
    fetchImpl,
    method: "PATCH",
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(OAUTH_STATES_TABLE_ID)}/rows`,
    projectId: runtime.projectId,
  });

  return Number(payload?.total) === 1;
}

async function exchangeAuthorizationCode({
  clientId,
  clientSecret,
  code,
  environment,
  fetchImpl,
  ruName,
}) {
  let response;
  try {
    response = await fetchImpl(ebayTokenEndpoint(environment), {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(
          `${clientId}:${clientSecret}`,
        ).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        code,
        grant_type: "authorization_code",
        redirect_uri: ruName,
      }).toString(),
    });
  } catch {
    throw new RequestError(
      "eBay could not complete the connection. Please try again.",
      503,
    );
  }

  const rawBody = await response.text();
  if (!response.ok) {
    throw new RequestError(
      "eBay could not complete the connection. Please try again.",
      502,
    );
  }

  try {
    return JSON.parse(rawBody);
  } catch {
    throw new RequestError(
      "eBay returned an unreadable connection response. Please try again.",
      502,
    );
  }
}

async function fetchEbayUserId({ accessToken, environment, fetchImpl }) {
  let response;
  try {
    response = await fetchImpl(ebayIdentityEndpoint(environment), {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      method: "GET",
    });
  } catch {
    throw new RequestError(
      "eBay could not verify the connected account. Please try again.",
      503,
    );
  }

  const rawBody = await response.text();
  if (!response.ok) {
    throw new RequestError(
      "eBay could not verify the connected account. Please try again.",
      502,
    );
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    throw new RequestError(
      "eBay returned an unreadable account response. Please try again.",
      502,
    );
  }

  const userId = cleanText(payload?.userId, 500);
  if (!userId) {
    throw new RequestError(
      "eBay could not verify the connected account. Please try again.",
      502,
    );
  }

  return userId;
}

async function handleConnect({ fetchImpl, now, req, res }) {
  const runtime = appwriteRuntime(req);
  const { ownerId } = await authenticateCaller({ fetchImpl, req, runtime });
  const body = requestBody(req);
  const environment = oauthEnvironment(body.environment);
  const scopeText = requestedScopeText(body.scopeText);
  decodeBase64Key(
    "EBAY_TOKEN_ENCRYPTION_KEY",
    requireEnvironment("EBAY_TOKEN_ENCRYPTION_KEY"),
  );
  decodeBase64Key(
    "EBAY_USER_ID_HMAC_KEY",
    requireEnvironment("EBAY_USER_ID_HMAC_KEY"),
  );
  const state = randomBytes(32).toString("base64url");
  const stateRowId = oauthStateRowId(state);
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + STATE_TTL_MS).toISOString();

  await requireAppwriteSuccess({
    apiKey: runtime.apiKey,
    body: {
      data: {
        createdAt,
        environment,
        expiresAt,
        ownerId,
        scopeText,
        status: "pending",
      },
      permissions: [],
      rowId: stateRowId,
    },
    endpoint: runtime.endpoint,
    fetchImpl,
    method: "POST",
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(OAUTH_STATES_TABLE_ID)}/rows`,
    projectId: runtime.projectId,
  });

  return res.json({
    expiresAt,
    environment,
    ok: true,
    state,
  });
}

async function handleStatus({ fetchImpl, req, res }) {
  const runtime = appwriteRuntime(req);
  const { ownerId } = await authenticateCaller({ fetchImpl, req, runtime });
  const environment = oauthEnvironment(requestBody(req).environment);
  const rowId = connectionRowId(ownerId, environment);
  const result = await appwriteRequest({
    apiKey: runtime.apiKey,
    endpoint: runtime.endpoint,
    fetchImpl,
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(CONNECTIONS_TABLE_ID)}/rows/${encodeURIComponent(
      rowId,
    )}`,
    projectId: runtime.projectId,
  });

  if (result.status === 404) {
    return res.json({
      connected: false,
      marketplace: "ebay",
      ok: true,
      status: "not_connected",
    });
  }

  if (!result.ok || result.payload?.ownerId !== ownerId) {
    throw new RequestError(
      "KeepFlip could not read the eBay connection status.",
      503,
    );
  }

  return res.json({
    connected: result.payload?.status === "active",
    marketplace: "ebay",
    ok: true,
    status: result.payload?.status === "active" ? "connected" : "not_connected",
  });
}

async function handleCallback({ fetchImpl, now, req, res }) {
  const runtime = appwriteRuntime(req);
  const state = queryValue(req, "state");

  if (!isOpaqueState(state)) {
    return browserPage(res, {
      message: "This eBay connection link is invalid or has already expired.",
      statusCode: 400,
      title: "eBay connection unavailable",
    });
  }

  const stateRowId = oauthStateRowId(state);
  const stateResult = await appwriteRequest({
    apiKey: runtime.apiKey,
    endpoint: runtime.endpoint,
    fetchImpl,
    path: `/tablesdb/${encodeURIComponent(
      APPWRITE_DATABASE_ID,
    )}/tables/${encodeURIComponent(OAUTH_STATES_TABLE_ID)}/rows/${encodeURIComponent(
      stateRowId,
    )}`,
    projectId: runtime.projectId,
  });

  const stateRow = stateResult.ok ? stateResult.payload : null;
  const environment =
    stateRow?.environment === "production" || stateRow?.environment === "sandbox"
      ? stateRow.environment
      : null;
  if (
    !stateRow ||
    !environment ||
    stateRow.status !== "pending" ||
    !isFutureIsoDate(stateRow.expiresAt, now)
  ) {
    return browserPage(res, {
      message: "This eBay connection link is invalid, expired, or already used.",
      statusCode: 400,
      title: "eBay connection unavailable",
    });
  }

  const claimed = await claimState({ fetchImpl, now, runtime, stateRowId });
  if (!claimed) {
    return browserPage(res, {
      message: "This eBay connection link has already been used. Return to KeepFlip to check its status.",
      statusCode: 409,
      title: "eBay connection already handled",
    });
  }

  const code = queryValue(req, "code");
  const declined =
    getRequestPath(req) === DECLINED_PATH || Boolean(queryValue(req, "error"));
  if (declined || !isValidAuthorizationCode(code)) {
    await updateState({
      data: {
        completedAt: now.toISOString(),
        failureCode: "declined",
        status: "declined",
      },
      fetchImpl,
      runtime,
      stateRowId,
    });
    return res.redirect(appReturnUrl("cancelled"), 302);
  }

  try {
    const { clientId, clientSecret } = credentialsFor(environment);
    const ruName = ruNameFor(environment);
    const tokenResponse = await exchangeAuthorizationCode({
      clientId,
      clientSecret,
      code,
      environment,
      fetchImpl,
      ruName,
    });
    const accessToken = cleanText(tokenResponse?.access_token, 8_000);
    const refreshToken = cleanText(tokenResponse?.refresh_token, 8_000);

    if (!accessToken || !refreshToken) {
      throw new RequestError(
        "eBay did not provide a usable connection token. Please try again.",
        502,
      );
    }

    const ebayUserId = await fetchEbayUserId({
      accessToken,
      environment,
      fetchImpl,
    });
    const ebayUserIdHmac = hashEbayUserId(ebayUserId);

    const ownerId = cleanText(stateRow.ownerId, 36);
    if (!ownerId) {
      throw new RequestError(
        "KeepFlip could not verify the account that started this eBay connection.",
        503,
      );
    }

    const grantedScopes =
      cleanText(tokenResponse?.scope, 4_000) ||
      cleanText(stateRow.scopeText, 4_000);
    const tokenCiphertext = encryptTokenPayload({
      environment,
      keyBase64: requireEnvironment("EBAY_TOKEN_ENCRYPTION_KEY"),
      ownerId,
      tokenPayload: {
        accessToken,
        issuedAt: now.toISOString(),
        refreshToken,
        scopeText: grantedScopes,
        tokenType: cleanText(tokenResponse?.token_type, 80) || "Bearer",
      },
    });

    await requireAppwriteSuccess({
      apiKey: runtime.apiKey,
      body: {
        data: {
          accessTokenExpiresAt: dateAfterSeconds(
            now,
            tokenResponse?.expires_in,
            24 * 60 * 60,
          ),
          createdAt: now.toISOString(),
          ebayUserIdHmac,
          environment,
          ownerId,
          refreshTokenExpiresAt: dateAfterSeconds(
            now,
            tokenResponse?.refresh_token_expires_in,
            2 * 365 * 24 * 60 * 60,
          ),
          revokedAt: null,
          scopeText: grantedScopes,
          status: "active",
          tokenCiphertext,
          updatedAt: now.toISOString(),
        },
        permissions: [],
      },
      endpoint: runtime.endpoint,
      fetchImpl,
      method: "PUT",
      path: `/tablesdb/${encodeURIComponent(
        APPWRITE_DATABASE_ID,
      )}/tables/${encodeURIComponent(CONNECTIONS_TABLE_ID)}/rows/${encodeURIComponent(
        connectionRowId(ownerId, environment),
      )}`,
      projectId: runtime.projectId,
    });

    await updateState({
      data: {
        completedAt: now.toISOString(),
        failureCode: null,
        status: "completed",
      },
      fetchImpl,
      runtime,
      stateRowId,
    });
  } catch (caughtError) {
    try {
      await updateState({
        data: {
          completedAt: now.toISOString(),
          failureCode: "connection_failed",
          status: "failed",
        },
        fetchImpl,
        runtime,
        stateRowId,
      });
    } catch {
      // Preserve the original safe error. The state has already been claimed.
    }

    throw caughtError;
  }

  return res.redirect(appReturnUrl("connected"), 302);
}

export function createHandler({ fetchImpl = fetch, now = () => new Date() } = {}) {
  return async ({ req, res, log = () => {}, error = () => {} }) => {
    const method = cleanText(req?.method, 16).toUpperCase();
    const path = getRequestPath(req);

    try {
      if (path === CONNECT_PATH) {
        if (method !== "POST") {
          throw new RequestError("Use POST to start an eBay connection.", 405);
        }
        return await handleConnect({ fetchImpl, now: now(), req, res });
      }

      if (path === STATUS_PATH) {
        if (method !== "POST") {
          throw new RequestError("Use POST to check the eBay connection.", 405);
        }
        return await handleStatus({ fetchImpl, req, res });
      }

      if (path === CALLBACK_PATH || path === DECLINED_PATH) {
        if (method !== "GET") {
          return browserPage(res, {
            message: "This eBay connection endpoint only accepts the redirect from eBay.",
            statusCode: 405,
            title: "Method not allowed",
          });
        }
        return await handleCallback({ fetchImpl, now: now(), req, res });
      }

      return browserPage(res, {
        message: "This endpoint is used only to connect an eBay account to KeepFlip.",
        statusCode: 404,
        title: "KeepFlip eBay connection",
      });
    } catch (caughtError) {
      const message =
        caughtError instanceof Error
          ? caughtError.message
          : "KeepFlip could not complete the eBay connection.";
      // Do not log request URLs, OAuth codes, states, tokens, or provider bodies.
      error(`[eBay OAuth] ${message}`);
      log("eBay OAuth request ended without exposing credentials.");

      if (path === CALLBACK_PATH || path === DECLINED_PATH) {
        return browserPage(res, {
          message:
            caughtError instanceof RequestError
              ? caughtError.message
              : "KeepFlip could not complete the eBay connection. Return to the app and try again.",
          statusCode:
            caughtError instanceof RequestError ? caughtError.statusCode : 500,
          title: "eBay connection unavailable",
        });
      }

      return jsonError(res, caughtError);
    }
  };
}

export {
  connectionRowId,
  encryptTokenPayload,
  hashEbayUserId,
  oauthStateRowId,
};

export default createHandler();
