import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import test from "node:test";

const testDir = await fs.mkdtemp(path.join(os.tmpdir(), "cb-ws-sync-test-"));
const workspaceA = path.join(testDir, "project-alpha");
const workspaceB = path.join(testDir, "project-beta");
const workspaceOutside = path.join(testDir, "outside-folder");

await fs.mkdir(workspaceA, { recursive: true });
await fs.mkdir(workspaceB, { recursive: true });
await fs.mkdir(workspaceOutside, { recursive: true });

await fs.writeFile(path.join(workspaceA, "alpha.txt"), "Content in project Alpha", "utf8");
await fs.writeFile(path.join(workspaceB, "beta.txt"), "Content in project Beta", "utf8");
await fs.writeFile(path.join(workspaceOutside, "secret.txt"), "Secret outside workspace", "utf8");

process.env.CODE_BRIDGE_WORKSPACE = workspaceA;
process.env.CODE_BRIDGE_TOKEN = "test-token-workspace-sync-0123456789";
process.env.CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS = "false";
process.env.CODE_BRIDGE_STATE_DIR = path.join(testDir, ".code-bridge");

test.after(async () => {
  await fs.rm(testDir, { recursive: true, force: true });
});

const { workspaceManager } = await import("../src/workspace-manager.js");
const { listFiles, readFile, searchCode, writeFile, deleteFile, getEditorContext } = await import("../src/operations.js");
const { decide } = await import("../src/approvals.js");
const { safePath } = await import("../src/safety.js");
const { config } = await import("../src/config.js");

test("1. Fallback workspace initially accessible from .env configuration", async () => {
  workspaceManager.resetToFallback();
  assert.equal(workspaceManager.getSource(), "fallback");
  assert.equal(workspaceManager.getWorkspace().toLowerCase(), workspaceA.toLowerCase());

  const list = await listFiles(".");
  assert.ok(list.includes("alpha.txt"), "alpha.txt should be in file list");

  const read = await readFile("alpha.txt");
  assert.match(read.content, /Content in project Alpha/);

  // workspaceB and outside files are not authorized and cannot be accessed via path escape
  assert.throws(() => safePath("../project-beta/beta.txt"), /Path escapes the approved workspace/);
  assert.throws(() => safePath("../outside-folder/secret.txt"), /Path escapes the approved workspace/);
  await assert.rejects(async () => {
    await readFile("../outside-folder/secret.txt");
  }, /Path escapes the approved workspace/);
});

test("2. Opening a different workspace dynamically synchronizes without server restart", async () => {
  // Simulate VS Code extension synchronizing a newly opened workspace folder B
  workspaceManager.setAuthorizedWorkspaces([workspaceB]);
  assert.equal(workspaceManager.getSource(), "vscode");
  assert.equal(workspaceManager.getWorkspace().toLowerCase(), workspaceB.toLowerCase());
  assert.equal(config.workspace.toLowerCase(), workspaceB.toLowerCase());

  // Workspace B is now accessible
  const list = await listFiles(".");
  assert.ok(list.includes("beta.txt"), "beta.txt should be in file list");
  const read = await readFile("beta.txt");
  assert.match(read.content, /Content in project Beta/);

  // Workspace A is no longer authorized - accessing it via path escape throws
  assert.throws(() => safePath("../project-alpha/alpha.txt"), /Path escapes the approved workspace/);
  await assert.rejects(async () => {
    await readFile("../project-alpha/alpha.txt");
  }, /Path escapes the approved workspace/);

  // Looking for alpha.txt in workspaceB directly fails with ENOENT
  await assert.rejects(async () => {
    await readFile("alpha.txt");
  }, (err: any) => err.code === "ENOENT");
});

test("3. Multi-root workspace authorizes multiple folders simultaneously", async () => {
  // Authorize both workspaceA and workspaceB simultaneously
  workspaceManager.setAuthorizedWorkspaces([workspaceA, workspaceB], workspaceA);
  const folders = workspaceManager.getWorkspaceFolders();
  assert.equal(folders.length, 2);

  // Multi-root top-level listing shows files prefixed by their folder name
  const allFiles = await listFiles(".");
  assert.ok(allFiles.some(f => f.includes("alpha.txt")), "multi-root should list files from workspace A");
  assert.ok(allFiles.some(f => f.includes("beta.txt")), "multi-root should list files from workspace B");

  // Read files from active root (workspaceA)
  const readA = await readFile("alpha.txt");
  assert.match(readA.content, /Content in project Alpha/);

  // Read files from second root (workspaceB) via prefix
  const readB = await readFile("project-beta/beta.txt");
  assert.match(readB.content, /Content in project Beta/);

  // Files outside both roots are strictly blocked
  assert.throws(() => safePath("../outside-folder/secret.txt"), /Invalid workspace path|escapes/);
  await assert.rejects(async () => {
    await readFile("../outside-folder/secret.txt");
  }, /Invalid workspace path|escapes/);
});

test("4. Multi-root search traverses all authorized workspace roots", async () => {
  workspaceManager.setAuthorizedWorkspaces([workspaceA, workspaceB], workspaceA);
  const results = await searchCode("Content in project");
  assert.equal(results.length, 2, "searchCode should find matches in both workspace roots");
  assert.ok(results.some(r => r.includes("project-alpha") && r.includes("Alpha")));
  assert.ok(results.some(r => r.includes("project-beta") && r.includes("Beta")));
});

test("5. Removing a folder in multi-root immediately revokes access to it", async () => {
  // Remove workspaceB, leaving only workspaceA
  workspaceManager.setAuthorizedWorkspaces([workspaceA], workspaceA);
  assert.equal(workspaceManager.getWorkspaceFolders().length, 1);

  // workspaceA remains accessible
  const readA = await readFile("alpha.txt");
  assert.match(readA.content, /Content in project Alpha/);

  // workspaceB access is immediately revoked: attempting to reach workspaceB via path escape throws
  assert.throws(() => safePath("../project-beta/beta.txt"), /Path escapes the approved workspace/);
  await assert.rejects(async () => {
    await readFile("../project-beta/beta.txt");
  }, /Path escapes the approved workspace/);

  // Attempting to read project-beta/beta.txt no longer resolves to workspaceB (it resolves inside workspaceA and fails with ENOENT)
  await assert.rejects(async () => {
    await readFile("project-beta/beta.txt");
  }, (err: any) => err.code === "ENOENT");
});

test("6. Stale or closed workspace fails closed and does not expose old folders", async () => {
  // Simulate user closing all folders in VS Code
  workspaceManager.setAuthorizedWorkspaces([]);
  assert.equal(workspaceManager.hasActiveWorkspace(), false);

  // Operations must fail closed with a clear error
  await assert.rejects(async () => {
    await listFiles(".");
  }, /No authorized workspace folder is open/);

  await assert.rejects(async () => {
    await readFile("alpha.txt");
  }, /No authorized workspace folder is open/);
});

test("7. Approval created in one workspace cannot be redeemed in another (workspace binding)", async () => {
  // Start in workspaceA
  workspaceManager.setAuthorizedWorkspaces([workspaceA], workspaceA);

  let approvalId = "";
  try {
    await writeFile("created-in-a.txt", "Initial file data");
  } catch (err) {
    const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec((err as Error).message);
    approvalId = match![1];
  }
  assert.ok(approvalId, "Should generate pending approval ID");

  // Operator approves the operation
  await decide(process.env.CODE_BRIDGE_STATE_DIR!, approvalId, "approved");

  // User switches workspace to workspaceB before redeeming
  workspaceManager.setAuthorizedWorkspaces([workspaceB], workspaceB);

  // Attempt to redeem the approval in workspaceB MUST FAIL
  await assert.rejects(async () => {
    await writeFile("created-in-a.txt", "Initial file data", approvalId);
  }, /approval_id is bound to a different workspace/);

  // Switch back to workspaceA -> redemption succeeds
  workspaceManager.setAuthorizedWorkspaces([workspaceA], workspaceA);
  const writeResult = await writeFile("created-in-a.txt", "Initial file data", approvalId);
  assert.match(writeResult.message, /Wrote created-in-a\.txt/);

  // Replay attempt fails
  await assert.rejects(async () => {
    await writeFile("created-in-a.txt", "Initial file data", approvalId);
  }, /already used/);
});

test("8. editor_context auto-recovers and syncs when VS Code is open on a different workspace than .env", async () => {
  // Start server on fallback workspaceA (simulating .env pointing to workspaceA)
  workspaceManager.resetToFallback();
  assert.equal(workspaceManager.getWorkspace().toLowerCase(), workspaceA.toLowerCase());

  // Spin up a mock VS Code extension server on an ephemeral port
  // The mock extension has workspaceB open
  const mockPort = 3388;
  process.env.CODE_BRIDGE_EDITOR_PORT = String(mockPort);

  const mockExtension = http.createServer((req, res) => {
    if (req.url === "/workspaces") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        folders: [workspaceB],
        activeFolder: workspaceB,
        workspaceOpen: true,
      }));
      return;
    }
    const wsHeader = req.headers["x-code-bridge-workspace"] as string;
    // If incoming workspace header does not match workspaceB, return 403 (mismatch)
    if (!wsHeader || wsHeader.toLowerCase() !== workspaceB.toLowerCase()) {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "The active VS Code workspace does not match Code Bridge." }));
      return;
    }
    if (req.url === "/context") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        workspaceOpen: true,
        activeFile: "beta.txt",
        selection: "selected in beta",
      }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => mockExtension.listen(mockPort, "127.0.0.1", resolve));

  try {
    // When editor_context is requested, editorClient encounters 403 for workspaceA,
    // queries /workspaces, discovers and synchronizes workspaceManager to workspaceB, and succeeds!
    const ctx = await getEditorContext();
    assert.equal(ctx.workspaceOpen, true);
    assert.equal(ctx.activeFile, "beta.txt");
    assert.equal(ctx.selection, "selected in beta");

    // workspaceManager is now synchronized with workspaceB!
    assert.equal(workspaceManager.getSource(), "vscode");
    assert.equal(workspaceManager.getWorkspace().toLowerCase(), workspaceB.toLowerCase());

    // File operations now immediately work on workspaceB
    const files = await listFiles(".");
    assert.ok(files.includes("beta.txt"));
  } finally {
    await new Promise((resolve) => mockExtension.close(resolve));
    delete process.env.CODE_BRIDGE_EDITOR_PORT;
    workspaceManager.resetToFallback();
  }
});

