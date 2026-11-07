import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const projectDirectory = fileURLToPath(new URL("../", import.meta.url));
const testDirectory = join(projectDirectory, "test");
const testFiles = [];

function discoverTests(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      discoverTests(entryPath);
    } else if (entry.isFile() && entry.name.endsWith(".test.ts")) {
      testFiles.push(entryPath);
    }
  }
}

discoverTests(testDirectory);
testFiles.sort();

if (testFiles.length === 0) {
  throw new Error(`No test files found under ${testDirectory}`);
}

const result = spawnSync(
  process.execPath,
  [require.resolve("tsx/cli"), "--test", "--test-concurrency=1", ...testFiles],
  {
    stdio: "inherit",
    env: {
      ...process.env,
      NODE_ENV: process.env.NODE_ENV || "test",
    },
  },
);

if (result.error) {
  throw result.error;
}

process.exitCode = result.status ?? 1;
