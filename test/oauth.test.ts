import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-oauth-ws-"));
const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-oauth-state-"));
const testToken = "test-oauth-token-0123456789abcdef";

process.env.NODE_ENV = "test";
process.env.CODE_BRIDGE_WORKSPACE = workspace;
process.env.CODE_BRIDGE_TOKEN = testToken;
process.env.CODE_BRIDGE_AUDIT_LOG = path.join(workspace, "audit.jsonl");
process.env.CODE_BRIDGE_STATE_DIR = stateDir;
process.env.CODE_BRIDGE_EDITOR_PORT = "3339";
process.env.CODE_BRIDGE_ALLOWED_HOSTS = "tunnel.example.com";
process.env.CODE_BRIDGE_AUTO_APPROVE_WRITES = "false";

await fs.writeFile(path.join(workspace, "sample.txt"), "OAuth test content\n", "utf8");
await fs.writeFile(path.join(workspace, "package.json"), JSON.stringify({
  scripts: { test: "node -e \"console.log('OK')\"" }
}), "utf8");

const { app } = await import("../src/server.js");
const { verifyPkce, clearOAuthStores, closeOAuthStore, insertTestAuthCode, insertTestRefreshToken, registerClient } = await import("../src/oauth.js");
const { decide } = await import("../src/approvals.js");

let server: http.Server;
let baseUrl: string;

test.before(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  closeOAuthStore();
  await fs.rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  await fs.rm(stateDir, { recursive: true, force: true }).catch(() => undefined);
});

test.beforeEach(() => {
  clearOAuthStores();
});

test("verifyPkce correctly validates S256 and plain challenges", () => {
  const verifier = "test-verifier-random-string-abcdef1234567890";
  const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");

  assert.equal(verifyPkce(verifier, challenge, "S256"), true);
  assert.equal(verifyPkce("wrong-verifier", challenge, "S256"), false);
  assert.equal(verifyPkce(verifier, "wrong-challenge", "S256"), false);

  assert.equal(verifyPkce("plain-secret", "plain-secret", "plain"), true);
  assert.equal(verifyPkce("plain-secret", "wrong-secret", "plain"), false);
  assert.equal(verifyPkce(verifier, challenge, "unknown"), false);
});

test("Protected Resource Metadata endpoints conform to RFC 9728", async () => {
  for (const endpoint of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      headers: { Host: "127.0.0.1" },
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.resource, `${baseUrl}/mcp`);
    assert.deepEqual(data.authorization_servers, [baseUrl]);
    assert.deepEqual(data.scopes_supported, ["mcp:all"]);
    assert.deepEqual(data.bearer_methods_supported, ["header"]);
  }
});

test("Authorization Server Metadata endpoints conform to RFC 8414", async () => {
  for (const endpoint of ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]) {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      headers: { Host: "127.0.0.1" },
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.issuer, baseUrl);
    assert.equal(data.authorization_endpoint, `${baseUrl}/oauth/authorize`);
    assert.equal(data.token_endpoint, `${baseUrl}/oauth/token`);
    assert.equal(data.registration_endpoint, `${baseUrl}/oauth/register`);
    assert.equal(data.revocation_endpoint, `${baseUrl}/oauth/revoke`);
    assert.deepEqual(data.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(data.response_types_supported, ["code"]);
    assert.deepEqual(data.grant_types_supported, ["authorization_code", "refresh_token"]);
  }
});

test("Unauthenticated requests return 401 with WWW-Authenticate pointing to resource_metadata", async () => {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })
  });
  assert.equal(res.status, 401);
  const wwwAuth = res.headers.get("www-authenticate");
  assert.ok(wwwAuth, "WWW-Authenticate header must be present");
  assert.match(wwwAuth, /Bearer realm="Code Bridge"/);
  assert.match(wwwAuth, /resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource"/);
  const body = await res.json();
  assert.ok(body.resource_metadata);
});

test("GET /oauth/authorize renders HTML consent UI for user verification", async () => {
  const verifier = "pkce-verifier-test-12345678901234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";

  const res = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=claude-web&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=state-123`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  const html = await res.text();
  assert.match(html, /Authorize AI Client/);
  assert.match(html, /claude-web/);
  assert.match(html, /CODE_BRIDGE_TOKEN/);
});

test("POST /oauth/authorize rejects wrong token with 401 HTML error", async () => {
  const verifier = "pkce-verifier-test-12345678901234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";

  const res = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "state-abc",
      token: "wrong-token"
    }).toString()
  });
  assert.equal(res.status, 401);
  const html = await res.text();
  assert.match(html, /Invalid CODE_BRIDGE_TOKEN/);
});

test("Complete OAuth 2.1 PKCE Flow: Authorize -> Token Exchange -> Tool Call", async () => {
  const verifier = "my-secure-pkce-verifier-9876543210987654321";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";
  const state = "random-client-state-456";

  // Step 1: Submit authorization form with correct token
  const authRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      token: testToken
    }).toString()
  });

  assert.equal(authRes.status, 302);
  const location = authRes.headers.get("location");
  assert.ok(location);
  const redirectUrl = new URL(location);
  assert.equal(redirectUrl.origin + redirectUrl.pathname, redirectUri);
  assert.equal(redirectUrl.searchParams.get("state"), state);
  const code = redirectUrl.searchParams.get("code");
  assert.ok(code);
  assert.ok(code.startsWith("cb_code_"));

  // Step 2: Failed Token Exchange with mismatched verifier
  const failExchangeRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: "wrong-verifier"
    }).toString()
  });
  assert.equal(failExchangeRes.status, 400);
  const failData = await failExchangeRes.json();
  assert.equal(failData.error, "invalid_grant");

  // Step 3: Because code is single-use, re-authorizing to get a fresh code
  const reauthRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      token: testToken
    }).toString()
  });
  const freshCode = new URL(reauthRes.headers.get("location")!).searchParams.get("code")!;

  // Step 4: Successful Token Exchange with valid verifier
  const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: redirectUri,
      code_verifier: verifier
    }).toString()
  });

  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();
  assert.ok(tokenData.access_token);
  assert.ok(tokenData.access_token.startsWith("cb_at_"));
  assert.equal(tokenData.token_type, "Bearer");
  assert.ok(tokenData.expires_in > 0);
  assert.ok(tokenData.refresh_token);
  assert.ok(tokenData.refresh_token.startsWith("cb_rt_"));

  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;

  // Step 5: Code replay must be rejected
  const replayRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: redirectUri,
      code_verifier: verifier
    }).toString()
  });
  assert.equal(replayRes.status, 400);

  // Step 6: Use issued OAuth access_token to query /health
  const healthRes = await fetch(`${baseUrl}/health`, {
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`
    }
  });
  assert.equal(healthRes.status, 200);
  const healthData = await healthRes.json();
  assert.equal(healthData.ok, true);

  // Step 7: Use issued OAuth access_token on /mcp initialize
  const initRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "claude-web", version: "1.0" }
      }
    })
  });
  assert.equal(initRes.status, 200);
  const initData = await initRes.json();
  assert.equal(initData.result.serverInfo.name, "Code Bridge");

  // Step 8: Use OAuth access_token on /mcp tools/list
  const toolsRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {}
    })
  });
  assert.equal(toolsRes.status, 200);
  const toolsData = await toolsRes.json();
  const toolNames = toolsData.result.tools.map((t: { name: string }) => t.name);
  assert.ok(toolNames.includes("list_files"));
  assert.ok(toolNames.includes("read_file"));
  assert.ok(toolNames.includes("write_file"));

  // Step 9: Call read-only tool list_files via OAuth
  const listRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "list_files", arguments: {} }
    })
  });
  assert.equal(listRes.status, 200);
  const listData = await listRes.json();
  assert.equal(listData.result.isError, undefined);
  const parsedFiles = JSON.parse(listData.result.content[0].text) as string[];
  assert.ok(parsedFiles.includes("sample.txt"));

  // Step 10: Call write_file via OAuth (verify approval enforcement is preserved!)
  const writeRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "approved.txt", content: "safe write" } }
    })
  });
  assert.equal(writeRes.status, 200);
  const writeData = await writeRes.json();
  const approvalMatch = writeData.result.content[0].text.match(/approval_id:\s*(req_[A-Za-z0-9_-]+)/i);
  assert.ok(approvalMatch, "Approval ID must be issued for mutation");
  const approvalId = approvalMatch[1];

  // Approve operation and verify redemption
  await decide(stateDir, approvalId, "approved");
  const redeemedRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "approved.txt", content: "safe write", approval_id: approvalId } }
    })
  });
  assert.equal(redeemedRes.status, 200);
  const redeemedData = await redeemedRes.json();
  assert.equal(redeemedData.result.isError, undefined);

  // Step 11: Refresh Token Exchange
  const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken
    }).toString()
  });
  assert.equal(refreshRes.status, 200);
  const newTokens = await refreshRes.json();
  assert.ok(newTokens.access_token);
  assert.notEqual(newTokens.access_token, accessToken);

  // Step 12: Old access token is invalidated, new access token works
  const oldTokenRes = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${accessToken}` }
  });
  assert.equal(oldTokenRes.status, 401);

  const newTokenRes = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${newTokens.access_token}` }
  });
  assert.equal(newTokenRes.status, 200);

  // Step 13: Token Revocation
  const revokeRes = await fetch(`${baseUrl}/oauth/revoke`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({ token: newTokens.access_token }).toString()
  });
  assert.equal(revokeRes.status, 200);

  const afterRevokeRes = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${newTokens.access_token}` }
  });
  assert.equal(afterRevokeRes.status, 401);

  // Step 14: Existing static token still works seamlessly!
  const staticRes = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${testToken}` }
  });
  assert.equal(staticRes.status, 200);
});

test("Dynamic Client Registration (RFC 7591) at /oauth/register and /register", async () => {
  for (const endpoint of ["/oauth/register", "/register"]) {
    const regRes = await fetch(`${baseUrl}${endpoint}`, {
      method: "POST",
      headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Test Gemini Dynamic Client",
        redirect_uris: ["https://vertexaisearch.cloud.google.com/oauth-redirect", "https://custom.example.com/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post"
      })
    });
    assert.equal(regRes.status, 201);
    const regData = await regRes.json();
    assert.ok(regData.client_id.startsWith("cb_client_"));
    assert.ok(regData.client_secret.startsWith("cb_sec_"));
    assert.equal(regData.client_name, "Test Gemini Dynamic Client");
    assert.deepEqual(regData.redirect_uris, ["https://vertexaisearch.cloud.google.com/oauth-redirect", "https://custom.example.com/callback"]);
    assert.equal(regData.client_secret_expires_at, 0);
  }
});

test("Dynamic Client Registration rejects empty or malformed redirect_uris", async () => {
  const emptyRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: [] })
  });
  assert.equal(emptyRes.status, 400);
  const emptyData = await emptyRes.json();
  assert.equal(emptyData.error, "invalid_redirect_uri");

  const invalidRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["not-a-valid-url"] })
  });
  assert.equal(invalidRes.status, 400);
  const invalidData = await invalidRes.json();
  assert.equal(invalidData.error, "invalid_redirect_uri");
});

test("Authorization endpoint validates redirect_uri and accepts Gemini redirect URI", async () => {
  const verifier = "pkce-gemini-verifier-01234567890123456789";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  // 1. Gemini redirect URI is accepted
  const geminiRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=gemini-client&redirect_uri=${encodeURIComponent("https://vertexaisearch.cloud.google.com/oauth-redirect")}&code_challenge=${challenge}&code_challenge_method=S256&state=gemini-state`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(geminiRes.status, 200);
  const html = await geminiRes.text();
  assert.match(html, /https:\/\/vertexaisearch\.cloud\.google\.com\/oauth-redirect/);

  // 2. Unauthorized redirect URI is rejected
  const badRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=gemini-client&redirect_uri=${encodeURIComponent("https://evil-site.example.com/callback")}&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(badRes.status, 400);
  const badText = await badRes.text();
  assert.match(badText, /Invalid or unauthorized redirect_uri/);

  // 3. POST /oauth/authorize also rejects unauthorized redirect_uri
  const postBadRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "gemini-client",
      redirect_uri: "https://evil-site.example.com/callback",
      code_challenge: challenge,
      token: testToken
    }).toString()
  });
  assert.equal(postBadRes.status, 400);
});

test("Client secret authentication in /oauth/token supports client_secret_post and client_secret_basic", async () => {
  // Step 1: Register dynamic client
  const regRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Secret Validation Client",
      redirect_uris: ["https://vertexaisearch.cloud.google.com/oauth-redirect"]
    })
  });
  const regData = await regRes.json();
  const clientId = regData.client_id;
  const clientSecret = regData.client_secret;
  const redirectUri = "https://vertexaisearch.cloud.google.com/oauth-redirect";

  const verifier = "verifier-secret-test-12345678901234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  // Step 2: Obtain authorization code
  const authRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken
    }).toString()
  });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

  // Step 3: Attempt token exchange with wrong client_secret in body -> 401 invalid_client
  const failPostRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: clientId,
      client_secret: "wrong-secret"
    }).toString()
  });
  assert.equal(failPostRes.status, 401);
  const failData = await failPostRes.json();
  assert.equal(failData.error, "invalid_client");

  // Code is single-use, so get fresh code for next test
  const authRes2 = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken
    }).toString()
  });
  const code2 = new URL(authRes2.headers.get("location")!).searchParams.get("code")!;

  // Step 4: Successful token exchange with client_secret_post
  const successPostRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code2,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: clientId,
      client_secret: clientSecret
    }).toString()
  });
  assert.equal(successPostRes.status, 200);
  const tokenData = await successPostRes.json();
  assert.ok(tokenData.access_token);

  // Step 5: Test client_secret_basic authentication (HTTP Basic Auth)
  const authRes3 = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken
    }).toString()
  });
  const code3 = new URL(authRes3.headers.get("location")!).searchParams.get("code")!;

  const basicCredentials = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  const successBasicRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basicCredentials}`
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code3,
      redirect_uri: redirectUri,
      code_verifier: verifier
    }).toString()
  });
  assert.equal(successBasicRes.status, 200);
  const basicData = await successBasicRes.json();
  assert.ok(basicData.access_token);
});

test("Token exchange rejects client_id mismatch with authorization code", async () => {
  const verifier = "verifier-mismatch-test-123456789012345";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://vertexaisearch.cloud.google.com/oauth-redirect";

  const authRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "authorized-client-id",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken
    }).toString()
  });
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

  const exchangeRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: "different-client-id"
    }).toString()
  });
  assert.equal(exchangeRes.status, 400);
  const data = await exchangeRes.json();
  assert.equal(data.error, "invalid_grant");
  assert.match(data.error_description, /Client ID does not match/);
});

test("Token exchange rejects expired authorization codes", async () => {
  const verifier = "verifier-expired-test-123456789012345";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://vertexaisearch.cloud.google.com/oauth-redirect";
  const expiredCode = "cb_code_already_expired_code_12345";

  insertTestAuthCode({
    code: expiredCode,
    clientId: "test-client",
    redirectUri,
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
    scope: "mcp:all",
    expiresAt: Date.now() - 1000 // Already expired in the past!
  });

  const exchangeRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: expiredCode,
      redirect_uri: redirectUri,
      code_verifier: verifier
    }).toString()
  });
  assert.equal(exchangeRes.status, 400);
  const data = await exchangeRes.json();
  assert.equal(data.error, "invalid_grant");
  assert.match(data.error_description, /Authorization code has expired/);
});

test("GET /oauth/authorize with token query parameter does NOT bypass consent or redirect", async () => {
  const verifier = "pkce-query-token-test-1234567890123456";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";

  // Attempting to pass the token in query parameter to bypass consent
  const res = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=claude-web&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&token=${testToken}`,
    { headers: { Host: "127.0.0.1" }, redirect: "manual" }
  );

  // Must NOT redirect (status must be 200, not 302)
  assert.equal(res.status, 200, "Query token must not trigger auto-redirect");
  assert.equal(res.headers.get("location"), null, "No redirect Location header should be present");
  const html = await res.text();
  assert.match(html, /Authorize AI Client/, "Must render the interactive HTML consent page");
  assert.match(html, /form method="post"/i);
});

test("GET and POST /oauth/authorize reject plain code_challenge_method (enforcing S256)", async () => {
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";

  // 1. GET with code_challenge_method=plain is rejected
  const getRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=claude-web&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=plain-secret&code_challenge_method=plain`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(getRes.status, 400);
  assert.match(await getRes.text(), /Only S256 is supported/);

  // 2. POST with code_challenge_method=plain is rejected
  const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: redirectUri,
      code_challenge: "plain-secret",
      code_challenge_method: "plain",
      token: testToken
    }).toString()
  });
  assert.equal(postRes.status, 400);
  assert.match(await postRes.text(), /Only S256 is supported/);
});

test("OAuth refresh-token preserves client identity, scope, and resource even when original access token is expired or deleted", async () => {
  const refreshToken = "cb_rt_independent_refresh_token_test_12345";
  const originalScope = "mcp:all custom:read";
  const originalResource = `${baseUrl}/mcp`;
  const originalClientId = "test-refresh-client";

  // Public client with custom scope and resource
  registerClient({
    clientId: originalClientId,
    clientName: "Refresh Scope Test Client",
    redirectUris: ["https://vertexaisearch.cloud.google.com/oauth-redirect"],
    tokenEndpointAuthMethod: "none",
    createdAt: Date.now()
  });

  // Insert refresh token whose original access token does NOT exist in accessTokens map (expired/deleted)
  insertTestRefreshToken({
    token: refreshToken,
    clientId: originalClientId,
    scope: originalScope,
    resource: originalResource,
    createdAt: Date.now() - 60000,
    expiresAt: Date.now() + 86400000
  });

  // Call /oauth/token with grant_type=refresh_token
  const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken
    }).toString()
  });

  assert.equal(refreshRes.status, 200);
  const data = await refreshRes.json();
  assert.ok(data.access_token);
  assert.ok(data.refresh_token);
  assert.equal(data.scope, originalScope, "Original scope must be preserved upon refresh");

  // Verify the new access token works against the original resource
  const healthRes = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${data.access_token}` }
  });
  assert.equal(healthRes.status, 200);

  // Single-use verification: reusing the old refresh token must be rejected
  const reuseRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken
    }).toString()
  });
  assert.equal(reuseRes.status, 400);
  const reuseData = await reuseRes.json();
  assert.equal(reuseData.error, "invalid_grant");
});

test("OAuth refresh-token: confidential clients require client_secret, reject missing or wrong secret", async () => {
  const confidentialClientId = "gemini-confidential-refresh";
  const confidentialSecret = "confidential-refresh-secret-12345678";
  const refreshToken = "cb_rt_confidential_refresh_99999";

  registerClient({
    clientId: confidentialClientId,
    clientSecret: confidentialSecret,
    clientName: "Confidential Gemini Client",
    redirectUris: ["https://vertexaisearch.cloud.google.com/oauth-redirect"],
    tokenEndpointAuthMethod: "client_secret_post",
    createdAt: Date.now()
  });

  insertTestRefreshToken({
    token: refreshToken,
    clientId: confidentialClientId,
    scope: "mcp:all",
    createdAt: Date.now(),
    expiresAt: Date.now() + 86400000
  });

  // 1. Missing secret -> 401 invalid_client
  const missingSecretRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: confidentialClientId
    }).toString()
  });
  assert.equal(missingSecretRes.status, 401);
  const missingData = await missingSecretRes.json();
  assert.equal(missingData.error, "invalid_client");

  // 2. Wrong secret -> 401 invalid_client
  const wrongSecretRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: confidentialClientId,
      client_secret: "wrong-secret-value"
    }).toString()
  });
  assert.equal(wrongSecretRes.status, 401);
  const wrongData = await wrongSecretRes.json();
  assert.equal(wrongData.error, "invalid_client");

  // 3. Correct secret via POST body -> 200 OK
  const validSecretRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: confidentialClientId,
      client_secret: confidentialSecret
    }).toString()
  });
  assert.equal(validSecretRes.status, 200);
  const validData = await validSecretRes.json();
  assert.ok(validData.access_token);
  assert.ok(validData.refresh_token);
});

test("OAuth refresh-token: expired refresh tokens are rejected with invalid_grant", async () => {
  const expiredRefreshToken = "cb_rt_already_expired_rt_12345";

  insertTestRefreshToken({
    token: expiredRefreshToken,
    clientId: "claude-web",
    scope: "mcp:all",
    createdAt: Date.now() - 100000,
    expiresAt: Date.now() - 1000 // Expired in the past!
  });

  const res = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: expiredRefreshToken
    }).toString()
  });
  assert.equal(res.status, 400);
  const data = await res.json();
  assert.equal(data.error, "invalid_grant");
  assert.match(data.error_description, /Refresh token has expired/);
});

test("POST /oauth/authorize enforces rate limit after repeated failed token submissions", async () => {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  // Send 10 wrong attempts
  for (let i = 0; i < 10; i++) {
    const res = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "claude-web",
        redirect_uri: "https://claude.ai/api/mcp/auth_callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        token: `wrong-token-attempt-${i}`,
      }).toString(),
    });
    assert.equal(res.status, 401);
  }

  // 11th attempt must be rejected with 429 Too Many Requests
  const rateLimitedRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: "wrong-token-11",
    }).toString(),
  });
  assert.equal(rateLimitedRes.status, 429);
  const html = await rateLimitedRes.text();
  assert.match(html, /Too many failed authorization attempts/);

  // Clean up
  clearOAuthStores();
});

