import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import {
  connectionRowId,
  createHandler,
  oauthStateRowId,
} from "../src/main.js";

const NOW = new Date("2026-08-17T12:00:00.000Z");
const OWNER_ID = "user_keepflip_123";

function jsonResponse(status, body = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function responseSink() {
  let response;
  return {
    res: {
      json(body, statusCode = 200) {
        response = { body, kind: "json", statusCode };
        return response;
      },
      redirect(url, statusCode = 302) {
        response = { kind: "redirect", statusCode, url };
        return response;
      },
      text(body, statusCode = 200, headers = {}) {
        response = { body, headers, kind: "text", statusCode };
        return response;
      },
    },
    response: () => response,
  };
}

function configureEnvironment() {
  process.env.APPWRITE_FUNCTION_API_ENDPOINT = "https://appwrite.example/v1";
  process.env.APPWRITE_FUNCTION_PROJECT_ID = "keepflip";
  process.env.EBAY_OAUTH_ENVIRONMENT = "sandbox";
  process.env.EBAY_CLIENT_ID = "client-id";
  process.env.EBAY_CLIENT_SECRET = "client-secret";
  process.env.EBAY_SANDBOX_RUNAME = "KeepFlip-TheJa-SBX-123";
  process.env.EBAY_PRODUCTION_RUNAME = "KeepFlip-TheJa-PRD-123";
  process.env.EBAY_TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
  process.env.EBAY_OAUTH_SCOPES = "https://api.ebay.com/oauth/api_scope";
}

function authenticatedHeaders() {
  return {
    "x-appwrite-key": "dynamic-function-key",
    "x-appwrite-user-id": OWNER_ID,
    "x-appwrite-user-jwt": "user-jwt",
  };
}

test("creates a private state row and returns an eBay consent URL", async () => {
  configureEnvironment();
  const calls = [];
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      calls.push({ options, url: String(url) });
      if (String(url).endsWith("/account")) {
        return jsonResponse(200, { $id: OWNER_ID, status: true });
      }
      if (String(url).endsWith("/tablesdb/keepflip/tables/ebay_oauth_states/rows")) {
        return jsonResponse(201, { $id: "state-row" });
      }
      throw new Error(`Unexpected request: ${url}`);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      headers: authenticatedHeaders(),
      method: "POST",
      path: "/connect",
    },
    res: sink.res,
  });

  const result = sink.response();
  assert.equal(result.kind, "json");
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.ok, true);

  const authorizeUrl = new URL(result.body.authorizationUrl);
  assert.equal(authorizeUrl.origin, "https://auth.sandbox.ebay.com");
  assert.equal(authorizeUrl.pathname, "/oauth2/authorize");
  assert.equal(authorizeUrl.searchParams.get("client_id"), "client-id");
  assert.equal(
    authorizeUrl.searchParams.get("redirect_uri"),
    "KeepFlip-TheJa-SBX-123",
  );

  const state = authorizeUrl.searchParams.get("state");
  assert.match(state, /^[A-Za-z0-9_-]{32,160}$/);

  const stateWrite = calls.find((call) =>
    call.url.endsWith("/tablesdb/keepflip/tables/ebay_oauth_states/rows"),
  );
  const payload = JSON.parse(stateWrite.options.body);
  assert.equal(payload.rowId, oauthStateRowId(state));
  assert.equal(payload.data.ownerId, OWNER_ID);
  assert.equal(payload.data.status, "pending");
  assert.equal(JSON.stringify(payload.data).includes(state), false);
});

test("claims a state, encrypts token data, and returns no eBay secret to the app", async () => {
  configureEnvironment();
  const state = randomBytes(32).toString("base64url");
  const stateRowId = oauthStateRowId(state);
  const calls = [];
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      const request = { options, url: String(url) };
      calls.push(request);

      if (request.url.endsWith(`/rows/${stateRowId}`) && options.method === "GET") {
        return jsonResponse(200, {
          environment: "sandbox",
          expiresAt: "2026-08-17T12:10:00.000Z",
          ownerId: OWNER_ID,
          scopeText: "https://api.ebay.com/oauth/api_scope",
          status: "pending",
        });
      }
      if (
        request.url.endsWith("/tablesdb/keepflip/tables/ebay_oauth_states/rows") &&
        options.method === "PATCH"
      ) {
        return jsonResponse(200, { rows: [{ $id: stateRowId }], total: 1 });
      }
      if (request.url === "https://api.sandbox.ebay.com/identity/v1/oauth2/token") {
        return jsonResponse(200, {
          access_token: "access-token-that-must-not-leak",
          expires_in: 7_200,
          refresh_token: "refresh-token-that-must-not-leak",
          refresh_token_expires_in: 15_552_000,
          scope: "https://api.ebay.com/oauth/api_scope",
          token_type: "User Access Token",
        });
      }
      if (
        request.url.endsWith(
          `/rows/${connectionRowId(OWNER_ID, "sandbox")}`,
        ) && options.method === "PUT"
      ) {
        return jsonResponse(200, { $id: "connection-row" });
      }
      if (request.url.endsWith(`/rows/${stateRowId}`) && options.method === "PATCH") {
        return jsonResponse(200, { $id: stateRowId });
      }
      throw new Error(`Unexpected request: ${request.url}`);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      headers: { "x-appwrite-key": "dynamic-function-key" },
      method: "GET",
      path: "/oauth/ebay/callback",
      query: { code: "one-time-authorization-code", state },
    },
    res: sink.res,
  });

  const result = sink.response();
  assert.deepEqual(result, {
    kind: "redirect",
    statusCode: 302,
    url: "keepflip://ebay/connected?status=connected",
  });

  const connectionWrite = calls.find(
    (call) =>
      call.url.endsWith(`/rows/${connectionRowId(OWNER_ID, "sandbox")}`) &&
      call.options.method === "PUT",
  );
  const payload = JSON.parse(connectionWrite.options.body);
  assert.match(payload.data.tokenCiphertext, /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal(payload.data.tokenCiphertext.includes("access-token"), false);
  assert.equal(payload.data.tokenCiphertext.includes("refresh-token"), false);
  assert.equal(JSON.stringify(result).includes("authorization-code"), false);
  assert.equal(JSON.stringify(result).includes("access-token"), false);
  assert.equal(JSON.stringify(result).includes("refresh-token"), false);
});

test("rejects an expired OAuth state before it contacts eBay", async () => {
  configureEnvironment();
  const state = randomBytes(32).toString("base64url");
  let ebayCalled = false;
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      if (String(url).includes("api.sandbox.ebay.com")) ebayCalled = true;
      if (options.method === "GET") {
        return jsonResponse(200, {
          environment: "sandbox",
          expiresAt: "2026-08-17T11:59:00.000Z",
          ownerId: OWNER_ID,
          status: "pending",
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      headers: { "x-appwrite-key": "dynamic-function-key" },
      method: "GET",
      path: "/oauth/ebay/callback",
      query: { code: "one-time-authorization-code", state },
    },
    res: sink.res,
  });

  assert.equal(sink.response().kind, "text");
  assert.equal(sink.response().statusCode, 400);
  assert.equal(ebayCalled, false);
});

test("does not expose encrypted token material through authenticated status", async () => {
  configureEnvironment();
  const handler = createHandler({
    fetchImpl: async (url, options = {}) => {
      if (String(url).endsWith("/account")) {
        return jsonResponse(200, { $id: OWNER_ID, status: true });
      }
      if (String(url).endsWith(`/rows/${connectionRowId(OWNER_ID, "sandbox")}`)) {
        return jsonResponse(200, {
          ownerId: OWNER_ID,
          status: "active",
          tokenCiphertext: "v1.not.returned.to.client",
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    },
    now: () => NOW,
  });
  const sink = responseSink();

  await handler({
    req: {
      headers: authenticatedHeaders(),
      method: "POST",
      path: "/status",
    },
    res: sink.res,
  });

  assert.deepEqual(sink.response().body, {
    connected: true,
    marketplace: "ebay",
    ok: true,
    status: "connected",
  });
});
