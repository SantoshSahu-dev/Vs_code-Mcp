import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";

const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-mcp-e2e-"));
const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-mcp-state-"));
process.env.NODE_ENV = "test";
process.env.CODE_BRIDGE_WORKSPACE = workspace;
process.env.CODE_BRIDGE_TOKEN = "isolated-e2e-token-0123456789abcdef";
process.env.CODE_BRIDGE_AUDIT_LOG = path.join(workspace, "audit.jsonl");
process.env.CODE_BRIDGE_STATE_DIR = stateDir;
process.env.CODE_BRIDGE_EDITOR_PORT = "3339";
process.env.CODE_BRIDGE_ALLOWED_HOSTS = "tunnel.example.com";
await fs.writeFile(path.join(workspace, "known.txt"), "needle: original\n", "utf8");
await fs.writeFile(path.join(workspace, "package.json"), JSON.stringify({
  scripts: {
    test: "node -e \"console.log('TOKEN=' + (process.env.CODE_BRIDGE_TOKEN || 'REDACTED'))\"",
    build: "node -e \"console.log('BUILD_OK')\"",
    lint: "node -e \"console.log('LINT_OK')\"",
    typecheck: "node -e \"console.log('TYPECHECK_OK')\""
  }
}), "utf8");
// Secret-bearing files that should be blocked by policy for reads, writes, search, and listing.
await fs.writeFile(path.join(workspace, ".env"), "SECRET_KEY=super-secret\n", "utf8");
await fs.writeFile(path.join(workspace, "credentials"), "aws_secret_access_key=hunter2\n", "utf8");
await fs.mkdir(path.join(workspace, "node_modules", "pkg"), { recursive: true });
await fs.writeFile(path.join(workspace, "node_modules", "pkg", "index.js"), "module.exports = 'dep';", "utf8");
await fs.mkdir(path.join(workspace, "dist"), { recursive: true });
await fs.writeFile(path.join(workspace, "dist", "bundle.js"), "console.log('bundled');", "utf8");

const { decide, listRecords } = await import("../src/approvals.js");
const { config } = await import("../src/config.js");
const { authenticateRequest, createMcpServer, loopbackRequestGuard } = await import("../src/server.js");

async function rpc(method: string, params: Record<string, unknown>, id = 1): Promise<Record<string, any>> {
  const server = createMcpServer();
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  await server.connect(transport);
  const response = await transport.handleRequest(new Request("http://127.0.0.1/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  }));
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^application\/json/);
  const result = await response.json() as Record<string, any>;
  await transport.close();
  return result;
}

async function notification(method: string, params: Record<string, unknown>): Promise<number> {
  const server = createMcpServer();
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  await server.connect(transport);
  const response = await transport.handleRequest(new Request("http://127.0.0.1/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params }),
  }));
  await transport.close();
  return response.status;
}

function approval(response: Record<string, any>): string {
  const message = response.result?.content?.[0]?.text ?? "";
  const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec(message);
  assert.ok(match, `expected approval response, received: ${message}`);
  return match[1];
}

test.after(async () => {
  const { closeOAuthStore } = await import("../src/oauth.js");
  closeOAuthStore();
  await fs.rm(workspace, { recursive: true, force: true });
  await fs.rm(stateDir, { recursive: true, force: true });
});

test("isolated MCP workflow authenticates, reads, searches, approves writes, and runs allowlisted commands", async () => {
  const initialized = await rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
  assert.equal(initialized.result.serverInfo.name, "Code Bridge");
  assert.ok([200, 202].includes(await notification("notifications/initialized", {})));
  const listed = await rpc("tools/list", {});
  assert.ok(listed.result.tools.some((tool: { name: string }) => tool.name === "write_file"));
  assert.ok(listed.result.tools.some((tool: { name: string }) => tool.name === "delete_file"));

  const read = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "known.txt" } });
  assert.match(read.result.content[0].text, /needle: original/);
  const search = await rpc("tools/call", { name: "search_code", arguments: { query: "needle" } });
  assert.match(search.result.content[0].text, /known\.txt:1/);

  // 1. Write without approval fails
  const rejected = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "created.txt", content: "first" } });
  assert.equal(rejected.result.isError, true);
  assert.equal(await fs.stat(path.join(workspace, "created.txt")).then(() => true, () => false), false);
  const createApproval = approval(rejected);

  // 2. Self-approval attempt without human action MUST FAIL
  const selfApproveAttempt = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "created.txt", content: "first", approval_id: createApproval } });
  assert.equal(selfApproveAttempt.result.isError, true, "AI self-approval must be rejected");

  // 3. Human approves via decide()
  await decide(stateDir, createApproval, "approved");

  // 4. Redeeming approved request succeeds
  const created = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "created.txt", content: "first", approval_id: createApproval } });
  assert.equal(created.result.isError, undefined, created.result.content?.[0]?.text);
  assert.equal(await fs.readFile(path.join(workspace, "created.txt"), "utf8"), "first");

  // 5. Replay / reuse attempt of consumed approval must fail
  const reuseAttempt = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "created.txt", content: "first", approval_id: createApproval } });
  assert.equal(reuseAttempt.result.isError, true, "Reusing consumed approval must fail");

  // 6. Update file with human approval
  const updateRejected = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "created.txt", content: "second" } });
  const updateApproval = approval(updateRejected);
  await decide(stateDir, updateApproval, "approved");
  await rpc("tools/call", { name: "write_file", arguments: { relative_path: "created.txt", content: "second", approval_id: updateApproval } });
  assert.equal(await fs.readFile(path.join(workspace, "created.txt"), "utf8"), "second");

  // 6b. Delete file with human approval (complete CRUD lifecycle)
  const prepDelete = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "to-delete.txt", content: "temp content" } });
  const prepApproval = approval(prepDelete);
  await decide(stateDir, prepApproval, "approved");
  await rpc("tools/call", { name: "write_file", arguments: { relative_path: "to-delete.txt", content: "temp content", approval_id: prepApproval } });
  assert.equal(await fs.readFile(path.join(workspace, "to-delete.txt"), "utf8"), "temp content");

  // Delete without approval fails
  const deleteRejected = await rpc("tools/call", { name: "delete_file", arguments: { relative_path: "to-delete.txt" } });
  assert.equal(deleteRejected.result.isError, true, "Delete without approval must fail");
  const deleteApproval = approval(deleteRejected);

  // Self-approval attempt without human action MUST FAIL
  const deleteSelfAttempt = await rpc("tools/call", { name: "delete_file", arguments: { relative_path: "to-delete.txt", approval_id: deleteApproval } });
  assert.equal(deleteSelfAttempt.result.isError, true, "AI self-approval on delete must fail");

  // Human approves delete via decide()
  await decide(stateDir, deleteApproval, "approved");

  // Redeeming approved delete succeeds
  const deleteResult = await rpc("tools/call", { name: "delete_file", arguments: { relative_path: "to-delete.txt", approval_id: deleteApproval } });
  assert.equal(deleteResult.result.isError, undefined, deleteResult.result.content?.[0]?.text);
  assert.equal(await fs.stat(path.join(workspace, "to-delete.txt")).then(() => true, () => false), false, "File must be removed from disk");

  // Replay of consumed delete approval must fail
  const deleteReuse = await rpc("tools/call", { name: "delete_file", arguments: { relative_path: "to-delete.txt", approval_id: deleteApproval } });
  assert.equal(deleteReuse.result.isError, true, "Reusing consumed delete approval must fail");

  // Delete of non-existent file fails
  const deleteMissing = await rpc("tools/call", { name: "delete_file", arguments: { relative_path: "does-not-exist.txt" } });
  assert.equal(deleteMissing.result.isError, true, "Deleting non-existent file must fail");

  // Delete of protected file fails policy check
  const deleteProtected = await rpc("tools/call", { name: "delete_file", arguments: { relative_path: ".env" } });
  assert.equal(deleteProtected.result.isError, true, "Deleting .env must fail policy check");

  const traversal = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "../outside.txt" } });
  assert.equal(traversal.result.isError, true);
  const blockedCommand = await rpc("tools/call", { name: "run_project_command", arguments: { command: "cmd /c echo unsafe" } });
  assert.equal(blockedCommand.result.isError, true);

  // 7. Command execution requires human approval
  const commandRejected = await rpc("tools/call", { name: "run_project_command", arguments: { command: "npm test" } });
  const commandApproval = approval(commandRejected);

  // Command self-approval attempt must fail
  const commandSelfAttempt = await rpc("tools/call", { name: "run_project_command", arguments: { command: "npm test", approval_id: commandApproval } });
  assert.equal(commandSelfAttempt.result.isError, true, "Command self-approval must fail");

  // Human approves command
  await decide(stateDir, commandApproval, "approved");
  const command = await rpc("tools/call", { name: "run_project_command", arguments: { command: "npm test", approval_id: commandApproval } });
  assert.match(command.result.content[0].text, /"code": 0/);
  assert.match(command.result.content[0].text, /TOKEN=REDACTED/, "child command must not inherit CODE_BRIDGE_TOKEN");
  assert.doesNotMatch(command.result.content[0].text, /isolated-e2e-token-0123456789abcdef/, "bridge token must never appear in command output");

  // Command approval reuse must fail
  const commandReuse = await rpc("tools/call", { name: "run_project_command", arguments: { command: "npm test", approval_id: commandApproval } });
  assert.equal(commandReuse.result.isError, true, "Reusing command approval must fail");

  // Verify all other allowlisted commands (npm run build, npm run lint, npm run typecheck)
  for (const cmd of ["npm run build", "npm run lint", "npm run typecheck"] as const) {
    const unapproved = await rpc("tools/call", { name: "run_project_command", arguments: { command: cmd } });
    assert.equal(unapproved.result.isError, true, `${cmd} must require approval`);
    const apprvId = approval(unapproved);
    await decide(stateDir, apprvId, "approved");
    const executed = await rpc("tools/call", { name: "run_project_command", arguments: { command: cmd, approval_id: apprvId } });
    assert.match(executed.result.content[0].text, /"code": 0/, `${cmd} should execute successfully`);
  }
});

test("MCP rejects invalid tool arguments and protected file targets", async () => {
  const invalid = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "known.txt", max_chars: 0 } });
  assert.equal(invalid.result.isError, true);
  const secretWrite = await rpc("tools/call", { name: "write_file", arguments: { relative_path: ".env", content: "NO" } });
  assert.equal(secretWrite.result.isError, true);
});

test("Policy blocks read_file, search_code, and list_files for secret files", async () => {
  // read_file must reject .env and credentials directly
  const readEnv = await rpc("tools/call", { name: "read_file", arguments: { relative_path: ".env" } });
  assert.equal(readEnv.result.isError, true, ".env must not be readable via read_file");
  assert.match(readEnv.result.content[0].text, /policy/, "error must mention policy");

  const readCred = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "credentials" } });
  assert.equal(readCred.result.isError, true, "credentials must not be readable via read_file");

  // search_code must not return matches from secret files
  const searchEnv = await rpc("tools/call", { name: "search_code", arguments: { query: "super-secret" } });
  assert.equal(searchEnv.result.isError, undefined, "search_code itself should not error");
  assert.doesNotMatch(
    searchEnv.result.content[0].text ?? "",
    /\.env/,
    "search_code must not return matches from .env"
  );

  const searchCred = await rpc("tools/call", { name: "search_code", arguments: { query: "hunter2" } });
  assert.doesNotMatch(
    searchCred.result.content[0].text ?? "",
    /credentials/,
    "search_code must not return matches from credentials file"
  );

  // list_files must not include secret filenames
  const listed = await rpc("tools/call", { name: "list_files", arguments: { relative_path: ".", max_depth: 1 } });
  const listing = listed.result.content[0].text ?? "";
  assert.doesNotMatch(listing, /\.env/, "list_files must not include .env");
  assert.doesNotMatch(listing, /credentials/, "list_files must not include credentials");
  assert.match(listing, /known\.txt/, "list_files must still include normal files");
});

test("Policy blocks reading and listing generated directories (node_modules, dist) unless explicitly permitted", async () => {
  // 1. By default, read_file on node_modules or dist must fail
  const readDep = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "node_modules/pkg/index.js" } });
  assert.equal(readDep.result.isError, true, "read_file on node_modules must error by default");
  assert.match(readDep.result.content[0].text, /generated or dependency directory/);

  const readDist = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "dist/bundle.js" } });
  assert.equal(readDist.result.isError, true, "read_file on dist must error by default");
  assert.match(readDist.result.content[0].text, /generated or dependency directory/);

  // 2. By default, list_files on node_modules or dist must fail
  const listDep = await rpc("tools/call", { name: "list_files", arguments: { relative_path: "node_modules" } });
  assert.equal(listDep.result.isError, true, "list_files on node_modules must error by default");
  assert.match(listDep.result.content[0].text, /generated or dependency directory/);

  const listDist = await rpc("tools/call", { name: "list_files", arguments: { relative_path: "dist" } });
  assert.equal(listDist.result.isError, true, "list_files on dist must error by default");
  assert.match(listDist.result.content[0].text, /generated or dependency directory/);

  // 3. When CODE_BRIDGE_ALLOW_READ_GENERATED is explicitly enabled, read_file succeeds
  process.env.CODE_BRIDGE_ALLOW_READ_GENERATED = "true";
  try {
    const readAllowed = await rpc("tools/call", { name: "read_file", arguments: { relative_path: "node_modules/pkg/index.js" } });
    assert.equal(readAllowed.result.isError, undefined, "read_file should succeed when explicitly permitted");
    assert.match(readAllowed.result.content[0].text, /module\.exports/);

    // 4. Writing to generated directories remains unconditionally blocked
    const writeBlocked = await rpc("tools/call", { name: "write_file", arguments: { relative_path: "node_modules/pkg/index.js", content: "hacked" } });
    assert.equal(writeBlocked.result.isError, true, "write_file to node_modules must remain blocked even when reading is permitted");
    assert.match(writeBlocked.result.content[0].text, /generated or dependency directory/);
  } finally {
    delete process.env.CODE_BRIDGE_ALLOW_READ_GENERATED;
  }
});

test("HTTP request guards reject missing credentials, wrong credentials, foreign Hosts, and cross-origin requests", () => {
  function invoke(guard: Function, request: Record<string, any>): { status?: number; body?: unknown; next: boolean } {
    const result: { status?: number; body?: unknown; next: boolean } = { next: false };
    const response = { status: (status: number) => ({ json: (body: unknown) => { result.status = status; result.body = body; } }) };
    guard(request, response, () => { result.next = true; });
    return result;
  }
  // Missing header -> 401
  assert.equal(invoke(authenticateRequest, { header: () => undefined, method: "POST", path: "/mcp" }).status, 401);
  // Wrong header -> 401
  assert.equal(invoke(authenticateRequest, { header: () => "wrong", method: "POST", path: "/mcp" }).status, 401);
  // Valid x-code-bridge-token -> pass
  assert.equal(invoke(authenticateRequest, { header: (h: string) => h.toLowerCase() === "x-code-bridge-token" ? "isolated-e2e-token-0123456789abcdef" : undefined, method: "POST", path: "/mcp" }).next, true);
  // Valid Authorization: Bearer token -> pass
  assert.equal(invoke(authenticateRequest, { header: (h: string) => h.toLowerCase() === "authorization" ? "Bearer isolated-e2e-token-0123456789abcdef" : undefined, method: "POST", path: "/mcp" }).next, true);
  // Invalid Authorization: Bearer token -> 401
  assert.equal(invoke(authenticateRequest, { header: (h: string) => h.toLowerCase() === "authorization" ? "Bearer wrong-bearer-token" : undefined, method: "POST", path: "/mcp" }).status, 401);

  // Foreign unallowed host -> 403
  assert.equal(invoke(loopbackRequestGuard, { hostname: "example.test", headers: {} }).status, 403);
  // Cross-origin request -> 403
  assert.equal(invoke(loopbackRequestGuard, { hostname: "127.0.0.1", headers: { origin: "https://example.test" } }).status, 403);
  // Loopback hosts -> pass
  assert.equal(invoke(loopbackRequestGuard, { hostname: "localhost", headers: {} }).next, true);
  assert.equal(invoke(loopbackRequestGuard, { hostname: "127.0.0.1", headers: {} }).next, true);
  assert.equal(invoke(loopbackRequestGuard, { hostname: "[::1]", headers: {} }).next, true);
  // Configured allowed tunnel host -> pass
  assert.equal(invoke(loopbackRequestGuard, { hostname: "tunnel.example.com", headers: {} }).next, true);
});

test("editor_context and editor_diagnostics redact secret files", async () => {
  const http = await import("node:http");
  const mockServer = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    if (req.url === "/context") {
      res.end(JSON.stringify({ workspaceOpen: true, activeFile: ".env", selection: "SUPER_SECRET=xyz" }));
    } else if (req.url === "/diagnostics") {
      res.end(JSON.stringify([
        { file: ".env", diagnostics: [{ message: "syntax error in secret" }] },
        { file: "src/index.ts", diagnostics: [{ message: "unused var" }] },
      ]));
    } else {
      res.end(JSON.stringify({}));
    }
  });

  await new Promise<void>((resolve) => mockServer.listen(3339, "127.0.0.1", () => resolve()));

  try {
    const ctx = await rpc("tools/call", { name: "editor_context", arguments: {} });
    const ctxText = ctx.result.content[0].text;
    assert.doesNotMatch(ctxText, /SUPER_SECRET/, "editor_context must never leak secret file selection");
    assert.match(ctxText, /"selection":\s*""/, "selection in protected file must be empty");

    const diag = await rpc("tools/call", { name: "editor_diagnostics", arguments: {} });
    const diagText = diag.result.content[0].text;
    assert.doesNotMatch(diagText, /\.env/, "editor_diagnostics must exclude protected files");
    assert.match(diagText, /src\/index\.ts/, "editor_diagnostics must keep non-secret files");
  } finally {
    await new Promise<void>((resolve) => mockServer.close(() => resolve()));
  }
});

test("MCP mutating tools are blocked when blockRemoteMutations is active without creating approval records", async () => {
  (config as any).blockRemoteMutations = true;
  try {
    const recordsBefore = (await listRecords(stateDir)).length;

    // 1. write_file is blocked immediately
    const writeRes = await rpc("tools/call", {
      name: "write_file",
      arguments: { relative_path: "should-not-exist.txt", content: "forbidden" },
    });
    assert.equal(writeRes.result.isError, true);
    assert.match(writeRes.result.content[0].text, /safely disabled/);
    assert.equal(await fs.stat(path.join(workspace, "should-not-exist.txt")).then(() => true, () => false), false);

    // 2. delete_file is blocked immediately
    const deleteRes = await rpc("tools/call", {
      name: "delete_file",
      arguments: { relative_path: "known.txt" },
    });
    assert.equal(deleteRes.result.isError, true);
    assert.match(deleteRes.result.content[0].text, /safely disabled/);
    assert.equal(await fs.stat(path.join(workspace, "known.txt")).then(() => true, () => false), true);

    // 3. run_project_command is blocked immediately
    const cmdRes = await rpc("tools/call", {
      name: "run_project_command",
      arguments: { command: "npm test" },
    });
    assert.equal(cmdRes.result.isError, true);
    assert.match(cmdRes.result.content[0].text, /safely disabled/);

    // 4. Verify no pending approval records were created in stateDir
    const recordsAfter = (await listRecords(stateDir)).length;
    assert.equal(recordsAfter, recordsBefore, "No approval records must be generated when safe mode blocks mutations");

    // 5. Read-only tools must continue functioning normally
    const readRes = await rpc("tools/call", {
      name: "read_file",
      arguments: { relative_path: "known.txt" },
    });
    assert.equal(readRes.result.isError, undefined);
    assert.match(readRes.result.content[0].text, /needle: original/);

    const listRes = await rpc("tools/call", {
      name: "list_files",
      arguments: { relative_path: "." },
    });
    assert.equal(listRes.result.isError, undefined);
  } finally {
    (config as any).blockRemoteMutations = false;
  }
});

test("MCP Streamable HTTP rejects invalid MCP messages and unknown tools", async () => {
  const unknownToolRes = await rpc("tools/call", {
    name: "non_existent_tool_12345",
    arguments: {},
  });
  assert.equal(unknownToolRes.result.isError, true);
  assert.match(unknownToolRes.result.content[0].text, /Tool non_existent_tool_12345 not found/);
});

test("Express error handler rejects oversized payloads and malformed JSON with expected status codes", async () => {
  const { app } = await import("../src/server.js");
  const request = (await import("node:http")).request;
  
  // Test error handler logic directly with mock req/res/next
  let capturedStatus = 0;
  let capturedBody: any = null;
  const mockRes: any = {
    status(code: number) {
      capturedStatus = code;
      return this;
    },
    json(body: any) {
      capturedBody = body;
      return this;
    }
  };
  
  // 1. Entity too large error
  const tooLargeError = new Error("entity too large");
  (tooLargeError as any).type = "entity.too.large";
  const errorHandler = (app as any)._router?.stack?.slice(-2)?.[0]?.handle;
  if (typeof errorHandler === "function") {
    errorHandler(tooLargeError, {} as any, mockRes, (() => {}) as any);
    assert.equal(capturedStatus, 413);
    assert.equal(capturedBody?.error, "Request body is too large");

    // 2. Malformed JSON error
    const badJsonError = new SyntaxError("Unexpected token in JSON");
    errorHandler(badJsonError, {} as any, mockRes, (() => {}) as any);
    assert.equal(capturedStatus, 400);
    assert.equal(capturedBody?.error, "Invalid JSON request body");
  }
});


