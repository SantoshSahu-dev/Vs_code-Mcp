import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import http from "node:http";

const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-rest-ws-"));
const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-rest-state-"));
const testToken = "test-rest-token-0123456789abcdef";

process.env.NODE_ENV = "test";
process.env.CODE_BRIDGE_WORKSPACE = workspace;
process.env.CODE_BRIDGE_TOKEN = testToken;
process.env.CODE_BRIDGE_AUDIT_LOG = path.join(workspace, "audit.jsonl");
process.env.CODE_BRIDGE_STATE_DIR = stateDir;
process.env.CODE_BRIDGE_EDITOR_PORT = "3339";
process.env.CODE_BRIDGE_ALLOWED_HOSTS = "tunnel.chatgpt.test";

await fs.writeFile(path.join(workspace, "hello.txt"), "hello world\n", "utf8");
await fs.writeFile(path.join(workspace, "package.json"), JSON.stringify({
  scripts: {
    test: "node -e \"console.log('REST_TEST_OK')\"",
    build: "node -e \"console.log('REST_BUILD_OK')\"",
    lint: "node -e \"console.log('REST_LINT_OK')\"",
    typecheck: "node -e \"console.log('REST_TYPECHECK_OK')\""
  }
}), "utf8");
await fs.writeFile(path.join(workspace, ".env"), "SECRET=classified\n", "utf8");

const { decide } = await import("../src/approvals.js");
const { app } = await import("../src/server.js");

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
  await fs.rm(workspace, { recursive: true, force: true }).catch(() => undefined);
  await fs.rm(stateDir, { recursive: true, force: true }).catch(() => undefined);
});

async function api(
  endpoint: string,
  options: { method?: string; body?: unknown; headers?: Record<string, string> } = {}
) {
  const url = `${baseUrl}${endpoint}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${testToken}`,
    Host: "127.0.0.1",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(options.headers ?? {}),
  };
  const res = await fetch(url, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}

test("REST /api/health returns system status", async () => {
  const { status, data } = await api("/api/health");
  assert.equal(status, 200);
  assert.equal(data.ok, true);
  assert.equal(data.writesAutoApproved, false);
});

test("REST unauthenticated requests are rejected with 401", async () => {
  const res = await fetch(`${baseUrl}/api/health`, {
    headers: { Host: "127.0.0.1" },
  });
  assert.equal(res.status, 401);
});

test("REST requests with disallowed Host header are rejected with 403", async () => {
  const addr = server.address() as { port: number };
  const statusCode = await new Promise<number>((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: addr.port,
        path: "/api/health",
        method: "GET",
        headers: {
          Host: "attacker.invalid",
          Authorization: `Bearer ${testToken}`,
        },
      },
      (res) => {
        resolve(res.statusCode ?? 0);
      }
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(statusCode, 403);
});

test("REST requests with allowed tunnel Host header succeed", async () => {
  const { status, data } = await api("/api/health", {
    headers: { Host: "tunnel.chatgpt.test" },
  });
  assert.equal(status, 200);
  assert.equal(data.ok, true);
});

test("REST /api/files/list returns workspace files and omits secret files", async () => {
  const { status, data } = await api("/api/files/list", {
    method: "POST",
    body: { relative_path: "." },
  });
  assert.equal(status, 200);
  assert.ok(Array.isArray(data.files));
  assert.ok(data.files.includes("hello.txt"));
  assert.ok(!data.files.includes(".env"));
});

test("REST /api/files/read reads permitted file and rejects secret file", async () => {
  const readOk = await api("/api/files/read", {
    method: "POST",
    body: { relative_path: "hello.txt" },
  });
  assert.equal(readOk.status, 200);
  assert.equal(readOk.data.content, "hello world\n");

  const readSecret = await api("/api/files/read", {
    method: "POST",
    body: { relative_path: ".env" },
  });
  assert.equal(readSecret.status, 403);

  const readTraversal = await api("/api/files/read", {
    method: "POST",
    body: { relative_path: "../../outside.txt" },
  });
  assert.equal(readTraversal.status, 403);
});

test("REST /api/files/search searches workspace content", async () => {
  const { status, data } = await api("/api/files/search", {
    method: "POST",
    body: { query: "world" },
  });
  assert.equal(status, 200);
  assert.ok(Array.isArray(data.matches));
  assert.ok(data.matches.some((m: string) => m.includes("hello.txt:1: hello world")));
});

test("REST /api/files/write requires approval, executes upon approval, rejects replay", async () => {
  // Step 1: Initial call without approval_id -> pending_approval
  const pending = await api("/api/files/write", {
    method: "POST",
    body: { relative_path: "created-by-rest.txt", content: "first content" },
  });
  assert.equal(pending.status, 200);
  assert.equal(pending.data.success, false);
  assert.equal(pending.data.status, "pending_approval");
  assert.match(pending.data.approval_id, /^req_[A-Za-z0-9_-]{24}$/);

  const approvalId = pending.data.approval_id;

  // File should not exist yet
  await assert.rejects(fs.stat(path.join(workspace, "created-by-rest.txt")));

  // Step 2: Human approves the request via CLI logic
  await decide(stateDir, approvalId, "approved");

  // Step 3: Client repeats call with approval_id
  const approved = await api("/api/files/write", {
    method: "POST",
    body: { relative_path: "created-by-rest.txt", content: "first content", approval_id: approvalId },
  });
  assert.equal(approved.status, 200);
  assert.equal(approved.data.success, true);
  assert.equal(approved.data.status, "success");

  // File now exists
  const fileContent = await fs.readFile(path.join(workspace, "created-by-rest.txt"), "utf8");
  assert.equal(fileContent, "first content");

  // Step 4: Replay attack with same approval_id must fail
  const replay = await api("/api/files/write", {
    method: "POST",
    body: { relative_path: "created-by-rest.txt", content: "first content", approval_id: approvalId },
  });
  assert.equal(replay.status, 403);
});

test("REST /api/files/delete requires approval, executes upon approval", async () => {
  const target = "disposable-delete.txt";
  await fs.writeFile(path.join(workspace, target), "to be deleted", "utf8");

  // Step 1: Call without approval_id -> pending_approval
  const pending = await api("/api/files/delete", {
    method: "POST",
    body: { relative_path: target },
  });
  assert.equal(pending.status, 200);
  assert.equal(pending.data.success, false);
  assert.equal(pending.data.status, "pending_approval");
  assert.match(pending.data.approval_id, /^req_[A-Za-z0-9_-]{24}$/);

  // File still exists
  assert.ok(await fs.stat(path.join(workspace, target)));

  // Step 2: Human approves
  await decide(stateDir, pending.data.approval_id, "approved");

  // Step 3: Re-call with approval_id
  const approved = await api("/api/files/delete", {
    method: "POST",
    body: { relative_path: target, approval_id: pending.data.approval_id },
  });
  assert.equal(approved.status, 200);
  assert.equal(approved.data.success, true);

  // File no longer exists
  await assert.rejects(fs.stat(path.join(workspace, target)));
});

test("REST /api/commands/run requires approval, validates allowlist, executes upon approval", async () => {
  // Disallowed command is rejected immediately
  const disallowed = await api("/api/commands/run", {
    method: "POST",
    body: { command: "rm -rf /" },
  });
  assert.equal(disallowed.status, 400);

  // Allowed command without approval_id -> pending_approval
  const pending = await api("/api/commands/run", {
    method: "POST",
    body: { command: "npm test" },
  });
  assert.equal(pending.status, 200);
  assert.equal(pending.data.success, false);
  assert.equal(pending.data.status, "pending_approval");

  // Approve
  await decide(stateDir, pending.data.approval_id, "approved");

  // Execute
  const executed = await api("/api/commands/run", {
    method: "POST",
    body: { command: "npm test", approval_id: pending.data.approval_id },
  });
  assert.equal(executed.status, 200);
  assert.equal(executed.data.success, true);
  assert.ok(executed.data.stdout.includes("REST_TEST_OK"));
  assert.equal(executed.data.code, 0);
});

test("REST requests with subdomain suffix of allowed host succeed", async () => {
  const { status, data } = await api("/api/health", {
    headers: { Host: "sub.tunnel.chatgpt.test" },
  });
  assert.equal(status, 200);
  assert.equal(data.ok, true);
});

test("REST mutating endpoints are blocked when blockRemoteMutations is active", async () => {
  const { config } = await import("../src/config.js");
  (config as any).blockRemoteMutations = true;
  try {
    const writeRes = await api("/api/files/write", {
      method: "POST",
      body: { relative_path: "blocked.txt", content: "data" },
    });
    assert.equal(writeRes.status, 403);
    assert.equal(writeRes.data.status, "blocked_by_safe_mode");

    const deleteRes = await api("/api/files/delete", {
      method: "POST",
      body: { relative_path: "blocked.txt" },
    });
    assert.equal(deleteRes.status, 403);
    assert.equal(deleteRes.data.status, "blocked_by_safe_mode");

    const cmdRes = await api("/api/commands/run", {
      method: "POST",
      body: { command: "npm test" },
    });
    assert.equal(cmdRes.status, 403);
    assert.equal(cmdRes.data.status, "blocked_by_safe_mode");
  } finally {
    (config as any).blockRemoteMutations = false;
  }
});

test("REST CORS: allowed AI origins receive CORS headers", async () => {
  const res = await fetch(`${baseUrl}/health`, {
    headers: {
      Authorization: `Bearer ${testToken}`,
      Host: "127.0.0.1",
      Origin: "https://chatgpt.com",
    },
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://chatgpt.com");
  assert.match(res.headers.get("access-control-allow-headers") ?? "", /authorization/i);
});

test("REST CORS: OPTIONS preflight succeeds with 204 and CORS headers", async () => {
  const res = await fetch(`${baseUrl}/health`, {
    method: "OPTIONS",
    headers: {
      Host: "127.0.0.1",
      Origin: "https://chatgpt.com",
      "Access-Control-Request-Method": "GET",
    },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://chatgpt.com");
  assert.match(res.headers.get("access-control-allow-methods") ?? "", /GET/);
});

test("REST CORS: allowed tunnel host permits web AI origins", async () => {
  const res = await fetch(`${baseUrl}/health`, {
    headers: {
      Authorization: `Bearer ${testToken}`,
      Host: "tunnel.chatgpt.test",
      Origin: "https://claude.ai",
    },
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://claude.ai");
});

test("REST /health and /api/health include remoteMutationsBlocked", async () => {
  const rootHealth = await api("/health");
  assert.equal(rootHealth.status, 200);
  assert.equal(rootHealth.data.ok, true);
  assert.equal(typeof rootHealth.data.remoteMutationsBlocked, "boolean");

  const apiHealth = await api("/api/health");
  assert.equal(apiHealth.status, 200);
  assert.equal(apiHealth.data.ok, true);
  assert.equal(typeof apiHealth.data.remoteMutationsBlocked, "boolean");
});

test("REST /openapi.json serves valid OpenAPI 3.0.3 specification", async () => {
  const res = await fetch(`${baseUrl}/openapi.json`, {
    headers: { Host: "127.0.0.1" },
  });
  assert.equal(res.status, 200);
  const spec = await res.json();
  assert.equal(spec.openapi, "3.0.3");
  assert.equal(spec.info.title, "Code Bridge Local Workspace API");
  assert.ok(spec.paths["/health"]);
  assert.ok(spec.paths["/api/files/read"]);
});

test("REST /.well-known/oauth-protected-resource returns 200 with RFC 9728 metadata without authentication error", async () => {
  const res = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`, {
    headers: { Host: "127.0.0.1" },
  });
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.resource, `${baseUrl}/mcp`);
  assert.deepEqual(data.authorization_servers, [baseUrl]);
  assert.deepEqual(data.scopes_supported, ["mcp:all"]);
});

test("REST /api router handles duplicate /api prefix smoothly", async () => {
  const { status, data } = await api("/api/api/health");
  assert.equal(status, 200);
  assert.equal(data.ok, true);
});


