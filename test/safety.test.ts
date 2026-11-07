import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const rawWorkspace = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-test-"));
const workspace = await fs.realpath(rawWorkspace);
process.env.CODE_BRIDGE_WORKSPACE = workspace;
process.env.CODE_BRIDGE_TOKEN = "test-token-not-a-real-secret-0123456789";
process.env.CODE_BRIDGE_AUDIT_LOG = path.join(workspace, "audit.jsonl");

const { assertNoSymlink, assertWritableFilePath, constantTimeTokenMatch, safePath } = await import("../src/safety.js");
const { audit } = await import("../src/audit.js");

test("rejects path escapes and accepts a workspace-relative path", () => {
  assert.throws(() => safePath("../outside.txt"));
  assert.throws(() => safePath(path.resolve(workspace, "outside.txt")));
  assert.equal(safePath("inside.txt"), path.join(workspace, "inside.txt"));
});

test("safePath respects case-insensitive boundary checks on Windows", () => {
  if (process.platform === "win32") {
    const altBase = workspace.replace(/^[A-Za-z]:/, m => m === m.toUpperCase() ? m.toLowerCase() : m.toUpperCase());
    assert.doesNotThrow(() => safePath("inside.txt", altBase));
  }
});

test("rejects symlink paths", async (t) => {
  const outside = path.join(os.tmpdir(), "code-bridge-outside.txt");
  await fs.writeFile(outside, "outside");
  const link = path.join(workspace, "link.txt");
  try {
    await fs.symlink(outside, link);
  } catch {
    t.skip("Symlink creation is unavailable on this Windows configuration.");
    return;
  }
  await assert.rejects(assertNoSymlink("link.txt"), /Symlinks are not allowed/);
});

test("rejects NTFS junction paths on Windows", async (t) => {
  if (process.platform !== "win32") {
    t.skip("Junction test is only applicable on Windows.");
    return;
  }
  const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-outside-junc-"));
  await fs.writeFile(path.join(outsideDir, "secret.txt"), "outside-data");
  const junction = path.join(workspace, "junction_target");
  const cp = await import("node:child_process");
  try {
    cp.execSync(`cmd /c mklink /J "${junction}" "${outsideDir}"`, { stdio: "pipe" });
  } catch {
    t.skip("NTFS junction creation failed or not supported.");
    return;
  }
  try {
    await assert.rejects(
      async () => { await assertNoSymlink("junction_target/secret.txt"); },
      /Symlinks are not allowed/
    );
  } finally {
    try {
      cp.execSync(`cmd /c rmdir "${junction}"`, { stdio: "pipe" });
      await fs.rm(outsideDir, { recursive: true, force: true });
    } catch {}
  }
});

test("assertWritableFilePath rejects credential and secret file patterns", () => {
  assert.throws(() => assertWritableFilePath(".env"), /credential or secret/);
  assert.throws(() => assertWritableFilePath(".env.local"), /credential or secret/);
  assert.throws(() => assertWritableFilePath(".npmrc"), /credential or secret/);
  assert.throws(() => assertWritableFilePath("credentials"), /credential or secret/);
  assert.throws(() => assertWritableFilePath("id_rsa"), /credential or secret/);
  assert.throws(() => assertWritableFilePath("server.key"), /credential or secret/);
  assert.throws(() => assertWritableFilePath("cert.pem"), /credential or secret/);
  assert.equal(assertWritableFilePath("src/index.ts"), path.join(workspace, "src/index.ts"));
});

test("token comparison accepts only the configured token", () => {
  assert.equal(constantTimeTokenMatch("test-token-not-a-real-secret-0123456789"), true);
  assert.equal(constantTimeTokenMatch("wrong-token"), false);
  assert.equal(constantTimeTokenMatch(undefined), false);
});

test("audit records metadata without the configured token or file content", async () => {
  const token = "test-token-not-a-real-secret-0123456789";
  const fileContent = "this content must never enter the audit log";
  await audit("write_file", { path: "example.ts", characters: fileContent.length });
  const log = await fs.readFile(path.join(workspace, "audit.jsonl"), "utf8");
  assert.match(log, /"event":"write_file"/);
  assert.doesNotMatch(log, new RegExp(token));
  assert.doesNotMatch(log, new RegExp(fileContent));
});

test("child-process environment isolation: strips host secrets and enforces allowlist", async () => {
  const { runProjectCommand } = await import("../src/operations.js");
  const { decide, defaultStateDir } = await import("../src/approvals.js");

  // Create a reliable helper script in workspace to dump child process environment
  await fs.writeFile(path.join(workspace, "dump-env.mjs"), `
import fs from "node:fs";
fs.writeFileSync("child-env.json", JSON.stringify(process.env));
`, "utf8");

  await fs.writeFile(path.join(workspace, "package.json"), JSON.stringify({
    scripts: {
      test: "node dump-env.mjs"
    }
  }), "utf8");

  // Set synthetic secrets in host process
  process.env.SYNTHETIC_HOST_SECRET = "super-secret-host-key-12345";
  process.env.AWS_SECRET_ACCESS_KEY = "synthetic-aws-key-67890";
  process.env.GITHUB_TOKEN = "synthetic-ghp-token-abcdef";

  try {
    // 1. Calling without approval triggers pending approval
    let approvalId: string | undefined;
    try {
      await runProjectCommand("npm test");
    } catch (err) {
      const match = (err as Error).message.match(/req_[A-Za-z0-9_-]{24}/);
      assert.ok(match, "Expected pending approval error with req_ ID");
      approvalId = match[0];
    }
    assert.ok(approvalId);

    // 2. Operator approves
    await decide(defaultStateDir(), approvalId, "approved");

    // 3. Re-run with approvalId
    const res = await runProjectCommand("npm test", approvalId);
    assert.equal(res.code, 0, `Command failed: ${res.stderr}`);

    // Read the dumped environment from file
    const dumpRaw = await fs.readFile(path.join(workspace, "child-env.json"), "utf8");
    const childEnv = JSON.parse(dumpRaw) as Record<string, string>;

    // 4. Assert host secrets are NOT present in child process
    assert.equal(childEnv.SYNTHETIC_HOST_SECRET, undefined, "SYNTHETIC_HOST_SECRET must not leak to child process");
    assert.equal(childEnv.AWS_SECRET_ACCESS_KEY, undefined, "AWS_SECRET_ACCESS_KEY must not leak to child process");
    assert.equal(childEnv.GITHUB_TOKEN, undefined, "GITHUB_TOKEN must not leak to child process");
    assert.equal(childEnv.CODE_BRIDGE_TOKEN, undefined, "CODE_BRIDGE_TOKEN must not leak to child process");

    // 5. Assert essential execution variables ARE present
    const hasPath = Boolean(childEnv.PATH || childEnv.Path);
    assert.ok(hasPath, "PATH must be preserved for child process execution");
  } finally {
    delete process.env.SYNTHETIC_HOST_SECRET;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    delete process.env.GITHUB_TOKEN;
  }
});
