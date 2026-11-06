import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-providers-ws-"));
const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-providers-state-"));
const testToken = "test-provider-token-0123456789abcdef";

process.env.NODE_ENV = "test";
process.env.CODE_BRIDGE_WORKSPACE = workspace;
process.env.CODE_BRIDGE_TOKEN = testToken;
process.env.CODE_BRIDGE_AUDIT_LOG = path.join(workspace, "audit.jsonl");
process.env.CODE_BRIDGE_STATE_DIR = stateDir;
process.env.CODE_BRIDGE_EDITOR_PORT = "3340";
process.env.CODE_BRIDGE_ALLOWED_HOSTS = "tunnel.example.com";
process.env.CODE_BRIDGE_AUTO_APPROVE_WRITES = "false";

await fs.writeFile(path.join(workspace, "provider-sample.txt"), "Three-provider compatibility test content\n", "utf8");
await fs.writeFile(path.join(workspace, "package.json"), JSON.stringify({
  scripts: { test: "node -e \"console.log('OK')\"" }
}), "utf8");

const { app } = await import("../src/server.js");
const {
  verifyPkce,
  clearOAuthStores,
  closeOAuthStore,
  isChatGptRedirectUri,
  isChatGptClientId,
  isValidResource,
  isMatchingResource
} = await import("../src/oauth.js");
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

// ============================================================================
// 1. CHATGPT CUSTOM MCP COMPATIBILITY SUITE (All 10 Verification Steps)
// ============================================================================

test("ChatGPT: Unit helpers correctly identify ChatGPT redirect URIs and client IDs", () => {
  // Stable connector redirect URI
  assert.equal(isChatGptRedirectUri("https://chatgpt.com/connector_platform_oauth_redirect"), true);
  assert.equal(isChatGptRedirectUri("https://chat.openai.com/connector_platform_oauth_redirect"), true);
  // Per-connector dynamic redirect URI
  assert.equal(isChatGptRedirectUri("https://chatgpt.com/connector/oauth/c_conn_12345_abc"), true);
  // Legacy Custom Actions callback
  assert.equal(isChatGptRedirectUri("https://chatgpt.com/api/aip/v1/oauth/callback"), true);

  // Invalid redirect URIs
  assert.equal(isChatGptRedirectUri("https://evil.com/connector_platform_oauth_redirect"), false);
  assert.equal(isChatGptRedirectUri("https://chatgpt.com.evil.com/connector_platform_oauth_redirect"), false);
  assert.equal(isChatGptRedirectUri("http://chatgpt.com/connector_platform_oauth_redirect"), false);
  assert.equal(isChatGptRedirectUri("https://claude.ai/api/mcp/auth_callback"), false);

  // Client ID identification
  assert.equal(isChatGptClientId("chatgpt"), true);
  assert.equal(isChatGptClientId("chatgpt-mcp"), true);
  assert.equal(isChatGptClientId("chatgpt-connector"), true);
  assert.equal(isChatGptClientId("https://chatgpt.com/connector_platform_client.json"), true);
  assert.equal(isChatGptClientId("https://platform.openai.com/apps/client.json"), true);
  assert.equal(isChatGptClientId("claude-web"), false);
  assert.equal(isChatGptClientId("gemini-client"), false);
  assert.equal(isChatGptClientId("https://evil.com/client.json"), false);
});

test("ChatGPT: Step 1 & 2 - Authorization initiation, redirect URI validation & RFC 9207 iss callback", async () => {
  const verifier = "chatgpt-secure-pkce-verifier-12345678901234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const state = "chatgpt-client-state-abc";
  const validRedirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
  const dynamicRedirectUri = "https://chatgpt.com/connector/oauth/c_test_98765";
  const invalidRedirectUri = "https://malicious-site.example.com/callback";

  // 1. GET /oauth/authorize with valid stable redirect URI renders HTML consent UI
  const getRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=chatgpt&redirect_uri=${encodeURIComponent(validRedirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}&resource=${encodeURIComponent(`${baseUrl}/mcp`)}`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(getRes.status, 200);
  const html = await getRes.text();
  assert.match(html, /Authorize AI Client/);
  assert.match(html, /chatgpt/);

  // 2. GET /oauth/authorize with dynamic per-connector redirect URI succeeds
  const getDynamicRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=chatgpt&redirect_uri=${encodeURIComponent(dynamicRedirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(getDynamicRes.status, 200);

  // 3. Rejection of invalid redirect URI on GET
  const getBadRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=chatgpt&redirect_uri=${encodeURIComponent(invalidRedirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(getBadRes.status, 400);

  // 4. POST /oauth/authorize rejects invalid redirect URI
  const postBadRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "chatgpt",
      redirect_uri: invalidRedirectUri,
      code_challenge: challenge,
      token: testToken
    }).toString()
  });
  assert.equal(postBadRes.status, 400);

  // 5. Successful POST /oauth/authorize returns 302 with code, state, and RFC 9207 iss parameter
  const postAuthRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "chatgpt",
      redirect_uri: validRedirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      token: testToken,
      resource: `${baseUrl}/mcp`
    }).toString()
  });
  assert.equal(postAuthRes.status, 302);
  const location = postAuthRes.headers.get("location")!;
  assert.ok(location);
  const redirectUrl = new URL(location);
  assert.equal(redirectUrl.origin + redirectUrl.pathname, validRedirectUri);
  assert.equal(redirectUrl.searchParams.get("state"), state);
  assert.equal(redirectUrl.searchParams.get("iss"), baseUrl);
  assert.ok(redirectUrl.searchParams.get("code"));
});

test("ChatGPT: Complete flow - Steps 3 to 10 (Token Exchange, PKCE S256, Refresh, MCP, Read, Approval Mutation)", async () => {
  const verifier = "chatgpt-complete-flow-verifier-abcdef1234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
  const state = "chatgpt-state-999";
  const resource = `${baseUrl}/mcp`;

  // Step 1: Obtain Authorization Code via POST /oauth/authorize
  const authRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "https://chatgpt.com/connector_platform_client.json",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      token: testToken,
      resource
    }).toString()
  });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  assert.ok(code.startsWith("cb_code_"));

  // Step 4: PKCE validation - invalid verifier rejected
  const failPkceRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: "wrong-verifier",
      client_id: "https://chatgpt.com/connector_platform_client.json"
    }).toString()
  });
  assert.equal(failPkceRes.status, 400);
  const failPkceData = await failPkceRes.json();
  assert.equal(failPkceData.error, "invalid_grant");

  // Single-use check: code was invalidated on attempt; re-authorize to get fresh code
  const reauthRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "https://chatgpt.com/connector_platform_client.json",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      token: testToken,
      resource
    }).toString()
  });
  const freshCode = new URL(reauthRes.headers.get("location")!).searchParams.get("code")!;

  // Step 3: Authorization Code Exchange (Public client without client_secret)
  const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: "https://chatgpt.com/connector_platform_client.json",
      resource
    }).toString()
  });
  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();
  assert.ok(tokenData.access_token.startsWith("cb_at_"));
  assert.ok(tokenData.refresh_token.startsWith("cb_rt_"));
  assert.equal(tokenData.token_type, "Bearer");
  assert.ok(tokenData.expires_in > 0);

  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;

  // Single-use: Replay must be rejected
  const replayRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: redirectUri,
      code_verifier: verifier
    }).toString()
  });
  assert.equal(replayRes.status, 400);

  // Step 6: MCP initialization & protocol negotiation with ChatGPT OAuth token
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
        clientInfo: { name: "chatgpt-custom-mcp", version: "1.0" }
      }
    })
  });
  assert.equal(initRes.status, 200);
  const initData = await initRes.json();
  assert.equal(initData.result.serverInfo.name, "Code Bridge");

  // Step 7: tools/list discovery
  const toolsRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })
  });
  assert.equal(toolsRes.status, 200);
  const toolsData = await toolsRes.json();
  const toolNames = toolsData.result.tools.map((t: { name: string }) => t.name);
  assert.ok(toolNames.includes("read_file"));
  assert.ok(toolNames.includes("list_files"));
  assert.ok(toolNames.includes("write_file"));

  // Step 8: Read-only tool call (read_file)
  const readRes = await fetch(`${baseUrl}/mcp`, {
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
      params: { name: "read_file", arguments: { relative_path: "provider-sample.txt" } }
    })
  });
  assert.equal(readRes.status, 200);
  const readData = await readRes.json();
  assert.equal(readData.result.isError, undefined);
  assert.match(readData.result.content[0].text, /Three-provider compatibility test content/);

  // Step 9: Rejection of missing and invalid credentials
  const unauthRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} })
  });
  assert.equal(unauthRes.status, 401);

  const fakeRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: { Host: "127.0.0.1", Authorization: "Bearer cb_at_fake_token_12345", "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/list", params: {} })
  });
  assert.equal(fakeRes.status, 401);

  // Step 10: Rejection of unauthorized mutations & human approval preservation
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
      id: 6,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "chatgpt-file.txt", content: "safe write" } }
    })
  });
  assert.equal(writeRes.status, 200);
  const writeData = await writeRes.json();
  const approvalMatch = writeData.result.content[0].text.match(/approval_id:\s*(req_[A-Za-z0-9_-]+)/i);
  assert.ok(approvalMatch, "Must return pending approval record ID");
  const approvalId = approvalMatch[1];

  // Self-approval failure: re-invoking with pending ID fails
  const selfApproveRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "chatgpt-file.txt", content: "safe write", approval_id: approvalId } }
    })
  });
  assert.equal(selfApproveRes.status, 200);
  const selfApproveData = await selfApproveRes.json();
  assert.equal(selfApproveData.result.isError, true);

  // Operator approves out-of-band via CLI engine
  await decide(stateDir, approvalId, "approved");
  const executeRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "chatgpt-file.txt", content: "safe write", approval_id: approvalId } }
    })
  });
  assert.equal(executeRes.status, 200);
  const executeData = await executeRes.json();
  assert.equal(executeData.result.isError, undefined);

  // Replay of consumed approval is rejected
  const replayMutationRes = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Host: "127.0.0.1",
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream"
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "chatgpt-file.txt", content: "safe write", approval_id: approvalId } }
    })
  });
  assert.equal(replayMutationRes.status, 200);
  const replayMutationData = await replayMutationRes.json();
  assert.equal(replayMutationData.result.isError, true);

  // Step 5: Token Refresh
  const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }).toString()
  });
  assert.equal(refreshRes.status, 200);
  const newTokens = await refreshRes.json();
  assert.ok(newTokens.access_token);
  assert.notEqual(newTokens.access_token, accessToken);

  // Old access token invalidated; new token works
  const oldTokenCheck = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${accessToken}` }
  });
  assert.equal(oldTokenCheck.status, 401);

  const newTokenCheck = await fetch(`${baseUrl}/health`, {
    headers: { Host: "127.0.0.1", Authorization: `Bearer ${newTokens.access_token}` }
  });
  assert.equal(newTokenCheck.status, 200);
});

// ============================================================================
// 2. RESOURCE INDICATOR & AUDIENCE VALIDATION (RFC 8707)
// ============================================================================

test("Resource Indicators (RFC 8707): Validates target resource and enforces audience check", async () => {
  const verifier = "resource-test-verifier-012345678901234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";

  // 1. Authorization with invalid foreign resource rejected
  const badResourceAuthRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=chatgpt&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent("https://evil-server.example.com/mcp")}`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(badResourceAuthRes.status, 400);

  // 2. Authorization with valid resource succeeds
  const goodResourceAuthRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "chatgpt",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken,
      resource: `${baseUrl}/mcp`
    }).toString()
  });
  assert.equal(goodResourceAuthRes.status, 302);
  const code = new URL(goodResourceAuthRes.headers.get("location")!).searchParams.get("code")!;

  // 3. Token exchange with mismatched target resource rejected with invalid_target
  const badTargetRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      resource: "https://different-host.example.com/mcp"
    }).toString()
  });
  assert.equal(badTargetRes.status, 400);
  const badTargetData = await badTargetRes.json();
  assert.equal(badTargetData.error, "invalid_target");
});

// ============================================================================
// 3. GEMINI VERIFICATION SUITE (Preserved & Verified)
// ============================================================================

test("Gemini: Dynamic Client Registration, PKCE S256, confidential client auth, tool discovery & mutation", async () => {
  // Step 1: Dynamic Client Registration
  const regRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Gemini Gems Connector",
      redirect_uris: ["https://vertexaisearch.cloud.google.com/oauth-redirect"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post"
    })
  });
  assert.equal(regRes.status, 201);
  const regData = await regRes.json();
  const clientId = regData.client_id;
  const clientSecret = regData.client_secret;
  assert.ok(clientId);
  assert.ok(clientSecret);

  // Step 2: Authorization initiation
  const verifier = "gemini-pkce-verifier-98765432101234567890";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://vertexaisearch.cloud.google.com/oauth-redirect";

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

  // Step 3 & 4: Token exchange with client credentials and PKCE S256
  const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: clientId,
      client_secret: clientSecret
    }).toString()
  });
  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();
  const accessToken = tokenData.access_token;
  const refreshToken = tokenData.refresh_token;

  // Step 6 & 7 & 8: MCP initialization, tool listing, read_file
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
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "gemini", version: "1.0" } }
    })
  });
  assert.equal(initRes.status, 200);

  const readRes = await fetch(`${baseUrl}/mcp`, {
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
      method: "tools/call",
      params: { name: "read_file", arguments: { relative_path: "provider-sample.txt" } }
    })
  });
  assert.equal(readRes.status, 200);

  // Gemini CRUD mutation: write_file requires approval
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
      id: 3,
      method: "tools/call",
      params: { name: "write_file", arguments: { relative_path: "gemini-file.txt", content: "gemini write" } }
    })
  });
  assert.equal(writeRes.status, 200);
  const writeData = await writeRes.json();
  const approvalMatch = writeData.result.content[0].text.match(/approval_id:\s*(req_[A-Za-z0-9_-]+)/i);
  assert.ok(approvalMatch, "Gemini mutation must return pending approval record ID");
  const approvalId = approvalMatch[1];

  // Self-approval failure: re-invoking with pending ID fails
  const selfApproveRes = await fetch(`${baseUrl}/mcp`, {
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
      params: { name: "write_file", arguments: { relative_path: "gemini-file.txt", content: "gemini write", approval_id: approvalId } }
    })
  });
  assert.equal(selfApproveRes.status, 200);
  const selfApproveData = await selfApproveRes.json();
  assert.equal(selfApproveData.result.isError, true);

  // Operator approves out-of-band via CLI engine
  await decide(stateDir, approvalId, "approved");
  const execRes = await fetch(`${baseUrl}/mcp`, {
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
      params: { name: "write_file", arguments: { relative_path: "gemini-file.txt", content: "gemini write", approval_id: approvalId } }
    })
  });
  assert.equal(execRes.status, 200);
  const execData = await execRes.json();
  assert.equal(execData.result.isError, undefined);

  // Step 5: Refresh token with confidential client authentication
  const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret
    }).toString()
  });
  assert.equal(refreshRes.status, 200);
});

// ============================================================================
// 4. CLAUDE WEB VERIFICATION SUITE (Preserved & Verified)
// ============================================================================

test("Claude: Public client flow with claude-web, PKCE S256, tool listing & reading", async () => {
  const verifier = "claude-web-verifier-abcdef987654321012345";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";

  // Authorization
  const authRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken
    }).toString()
  });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

  // Token exchange (no client secret)
  const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: "claude-web"
    }).toString()
  });
  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();
  const accessToken = tokenData.access_token;

  // Call list_files
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
      id: 1,
      method: "tools/call",
      params: { name: "list_files", arguments: {} }
    })
  });
  assert.equal(listRes.status, 200);
  const listData = await listRes.json();
  assert.equal(listData.result.isError, undefined);
  const files = JSON.parse(listData.result.content[0].text);
  assert.ok(files.includes("provider-sample.txt"));

  // Claude CRUD mutation: delete_file requires approval
  const deleteRes = await fetch(`${baseUrl}/mcp`, {
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
      method: "tools/call",
      params: { name: "delete_file", arguments: { relative_path: "gemini-file.txt" } }
    })
  });
  assert.equal(deleteRes.status, 200);
  const deleteData = await deleteRes.json();
  const deleteApprovalMatch = deleteData.result.content[0].text.match(/approval_id:\s*(req_[A-Za-z0-9_-]+)/i);
  assert.ok(deleteApprovalMatch, "Claude delete mutation must return pending approval record ID");
  const deleteApprovalId = deleteApprovalMatch[1];

  // Operator approves out-of-band via CLI engine
  await decide(stateDir, deleteApprovalId, "approved");
  const execDeleteRes = await fetch(`${baseUrl}/mcp`, {
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
      params: { name: "delete_file", arguments: { relative_path: "gemini-file.txt", approval_id: deleteApprovalId } }
    })
  });
  assert.equal(execDeleteRes.status, 200);
  const execDeleteData = await execDeleteRes.json();
  assert.equal(execDeleteData.result.isError, undefined);
});

test("Claude: Automatic Dynamic Client Registration (RFC 7591), PKCE S256, tool call & secret omission", async () => {
  // Step 1: Claude Web initiates Dynamic Client Registration
  const regRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Claude",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"]
    })
  });
  assert.equal(regRes.status, 201);
  const regData = await regRes.json();

  // Validate RFC 7591 Section 3.2.1 compliance for public clients
  assert.ok(regData.client_id.startsWith("cb_client_"));
  assert.equal(regData.token_endpoint_auth_method, "none");
  assert.equal(regData.client_secret, undefined, "Public client MUST NOT have client_secret");
  assert.equal(regData.client_secret_expires_at, undefined, "Public client MUST NOT have client_secret_expires_at per RFC 7591");
  assert.deepEqual(regData.redirect_uris, ["https://claude.ai/api/mcp/auth_callback"]);

  const clientId = regData.client_id;
  const verifier = "claude-dcr-verifier-1234567890abcdefghijklmnop";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const redirectUri = "https://claude.ai/api/mcp/auth_callback";
  const state = "claude-dcr-state-999";

  // Step 2: Authorization
  const authRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      token: testToken
    }).toString()
  });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
  assert.ok(code.startsWith("cb_code_"));

  // Step 3: Token Exchange (Public client without client secret)
  const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: clientId
    }).toString()
  });
  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();
  assert.ok(tokenData.access_token.startsWith("cb_at_"));
  assert.ok(tokenData.refresh_token.startsWith("cb_rt_"));
  assert.equal(tokenData.token_type, "Bearer");

  const accessToken = tokenData.access_token;

  // Step 4: Streamable HTTP MCP initialize
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
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "Claude", version: "1.0" } }
    })
  });
  assert.equal(initRes.status, 200);

  // Step 5: Read-only tool call (read_file)
  const readRes = await fetch(`${baseUrl}/mcp`, {
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
      method: "tools/call",
      params: { name: "read_file", arguments: { relative_path: "provider-sample.txt" } }
    })
  });
  assert.equal(readRes.status, 200);
  const readData = await readRes.json();
  assert.equal(readData.result.isError, undefined);
  assert.match(readData.result.content[0].text, /Three-provider compatibility test content/);
});

// ============================================================================
// 5. CROSS-PROVIDER ISOLATION SUITE
// ============================================================================

test("Cross-Provider Isolation: Provider redirect URIs, client IDs and tokens cannot cross boundaries", async () => {
  const verifier = "cross-provider-verifier-123456789012345";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  // 1. claude-web client cannot use ChatGPT redirect URI
  const claudeToChatGptRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=claude-web&redirect_uri=${encodeURIComponent("https://chatgpt.com/connector_platform_oauth_redirect")}&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(claudeToChatGptRes.status, 400);

  // 2. claude-web client cannot use Gemini redirect URI
  const claudeToGeminiRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=claude-web&redirect_uri=${encodeURIComponent("https://vertexaisearch.cloud.google.com/oauth-redirect")}&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(claudeToGeminiRes.status, 400);

  // 3. chatgpt client cannot use Claude redirect URI
  const chatgptToClaudeRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=chatgpt&redirect_uri=${encodeURIComponent("https://claude.ai/api/mcp/auth_callback")}&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(chatgptToClaudeRes.status, 400);

  // 4. chatgpt client cannot use Gemini redirect URI
  const chatgptToGeminiRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=chatgpt&redirect_uri=${encodeURIComponent("https://vertexaisearch.cloud.google.com/oauth-redirect")}&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: { Host: "127.0.0.1" } }
  );
  assert.equal(chatgptToGeminiRes.status, 400);

  // 5. Auth code issued for Claude cannot be redeemed by ChatGPT
  const claudeAuthRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "claude-web",
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      code_challenge: challenge,
      code_challenge_method: "S256",
      token: testToken
    }).toString()
  });
  const claudeCode = new URL(claudeAuthRes.headers.get("location")!).searchParams.get("code")!;

  const crossExchangeRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { Host: "127.0.0.1", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: claudeCode,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      code_verifier: verifier,
      client_id: "chatgpt" // Mismatched client ID!
    }).toString()
  });
  assert.equal(crossExchangeRes.status, 400);
  const crossData = await crossExchangeRes.json();
  assert.equal(crossData.error, "invalid_grant");
});
