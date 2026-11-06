import assert from "node:assert/strict";
import cp from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mcpbFile = path.join(root, "code-bridge.mcpb");

assert.ok(fs.existsSync(mcpbFile), "code-bridge.mcpb does not exist. Run 'npm run package:mcpb' first.");

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "code-bridge-mcpb-test-"));
const testWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), "code-bridge-mcpb-ws-"));

try {
  // Extract bundle to isolated directory
  cp.execSync(`tar -xf "${mcpbFile}" -C "${tempDir}"`);
  const serverScript = path.join(tempDir, "server", "index.js");
  assert.ok(fs.existsSync(serverScript), "server/index.js was not found in extracted package.");

  // Test 1: Verify missing env fails gracefully without dotenv ERR_MODULE_NOT_FOUND
  const unconfigured = cp.spawnSync(process.execPath, [serverScript], {
    encoding: "utf8",
    env: { ...process.env, CODE_BRIDGE_WORKSPACE: "", CODE_BRIDGE_TOKEN: "" },
  });
  assert.equal(unconfigured.status, 1, "Unconfigured server should exit with code 1.");
  assert.doesNotMatch(
    unconfigured.stderr,
    /ERR_MODULE_NOT_FOUND/,
    "Packaged server must not throw ERR_MODULE_NOT_FOUND for dotenv."
  );
  assert.match(
    unconfigured.stderr,
    /Missing CODE_BRIDGE_WORKSPACE/,
    "Unconfigured server must cleanly report missing CODE_BRIDGE_WORKSPACE."
  );

  // Test 2: Full MCP stdio handshake with isolated test environment
  fs.writeFileSync(path.join(testWorkspace, "hello.txt"), "packaged-bridge-ok\n", "utf8");

  const testEnv = {
    ...process.env,
    CODE_BRIDGE_WORKSPACE: testWorkspace,
    CODE_BRIDGE_TOKEN: "01234567890123456789012345678901",
    CODE_BRIDGE_AUTO_APPROVE_WRITES: "false",
    CODE_BRIDGE_AUDIT_LOG: path.join(testWorkspace, "audit.jsonl"),
  };

  const child = cp.spawn(process.execPath, [serverScript], {
    env: testEnv,
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });

  const messages = [
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test-mcpb", version: "1.0" } } }),
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
    JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_files", arguments: { relative_path: ".", max_depth: 1 } } }),
    JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "read_file", arguments: { relative_path: "hello.txt" } } }),
  ].join("\n") + "\n";

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.stdin.write(messages);

    const checkInterval = setInterval(() => {
      const lines = stdout.trim().split("\n").filter(Boolean);
      if (lines.length >= 4) {
        clearInterval(checkInterval);
        child.stdin.end();
        resolve();
      }
    }, 100);

    setTimeout(() => {
      clearInterval(checkInterval);
      child.stdin.end();
      reject(new Error(`Timed out waiting for MCP responses. Received stderr: ${stderr}\nstdout: ${stdout}`));
    }, 8000);
  });

  const parsedResponses = stdout
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));

  const initResponse = parsedResponses.find((r) => r.id === 1);
  assert.ok(initResponse?.result?.serverInfo?.name === "Code Bridge", "initialize did not return Code Bridge");

  const listResponse = parsedResponses.find((r) => r.id === 2);
  const toolNames = listResponse?.result?.tools?.map((t) => t.name) ?? [];
  assert.ok(toolNames.includes("read_file"), "tools/list did not include read_file");
  assert.ok(toolNames.includes("write_file"), "tools/list did not include write_file");
  assert.ok(toolNames.includes("list_files"), "tools/list did not include list_files");

  const listCallResponse = parsedResponses.find((r) => r.id === 3);
  assert.match(listCallResponse?.result?.content?.[0]?.text ?? "", /hello\.txt/);

  const readCallResponse = parsedResponses.find((r) => r.id === 4);
  assert.match(readCallResponse?.result?.content?.[0]?.text ?? "", /packaged-bridge-ok/);

  console.log("PASS: Packaged MCPB server verified over stdio (initialize, tools/list, read_file).");
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
  fs.rmSync(testWorkspace, { recursive: true, force: true });
}
