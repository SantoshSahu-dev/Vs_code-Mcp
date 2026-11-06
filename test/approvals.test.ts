import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  APPROVAL_TTL_MS,
  decide,
  hashPayload,
  listRecords,
  requireApproval,
  type ApprovalSummary,
} from "../src/approvals.js";

const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-approvals-test-"));
test.after(async () => {
  await fs.rm(stateDir, { recursive: true, force: true });
});

const sampleSummary: ApprovalSummary = {
  title: "Test Operation",
  details: { file: "test.txt" },
  warnings: ["Test warning"],
  preview: "test preview content",
};

test("requireApproval creates pending request and throws on unapproved invocation", async () => {
  const payload = { file: "test.txt", content: "hello" };
  let caughtError: Error | undefined;

  try {
    await requireApproval(stateDir, "write_file", payload, sampleSummary);
  } catch (err) {
    caughtError = err as Error;
  }

  assert.ok(caughtError, "should have thrown an approval error");
  assert.match(caughtError.message, /Approval required/);
  const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec(caughtError.message);
  assert.ok(match, "error should contain request id matching ID_PATTERN");
  const reqId = match[1];

  // Verify record was created on disk in stateDir/approvals
  const records = await listRecords(stateDir);
  const record = records.find((r) => r.id === reqId);
  assert.ok(record, "record should exist on disk");
  assert.equal(record.status, "pending");
  assert.equal(record.action, "write_file");
  assert.equal(record.payloadHash, hashPayload(payload));

  // Verify AI self-approval attempt: passing the pending ID immediately without human action MUST FAIL
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "write_file", payload, sampleSummary, reqId);
    },
    /Approval required\. Tell the user exactly what you intend to change/,
    "AI client passing pending request ID must be rejected without human approval"
  );
});

test("decide() approves request, allowing single-use redemption", async () => {
  const payload = { command: "npm test" };
  const summary: ApprovalSummary = {
    title: "Run command",
    details: { command: "npm test" },
    warnings: [],
    preview: "npm test",
  };

  // Step 1: Create pending request
  let reqId = "";
  try {
    await requireApproval(stateDir, "run_project_command", payload, summary);
  } catch (err) {
    const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec((err as Error).message);
    reqId = match![1];
  }

  // Step 2: Human approves the request
  await decide(stateDir, reqId, "approved");

  // Step 3: Tool redemption succeeds
  await assert.doesNotReject(async () => {
    await requireApproval(stateDir, "run_project_command", payload, summary, reqId);
  });

  // Step 4: Replay / reuse attempt MUST FAIL
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "run_project_command", payload, summary, reqId);
    },
    /That approval_id does not match this exact operation, or it expired or was already used/,
    "Reused approval must be rejected"
  );
});

test("decide() denial blocks operation and informs caller", async () => {
  const payload = { command: "npm run lint" };
  const summary: ApprovalSummary = {
    title: "Run lint",
    details: { command: "npm run lint" },
    warnings: [],
    preview: "npm run lint",
  };

  let reqId = "";
  try {
    await requireApproval(stateDir, "run_project_command", payload, summary);
  } catch (err) {
    const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec((err as Error).message);
    reqId = match![1];
  }

  // Human denies request
  await decide(stateDir, reqId, "denied");

  // Caller receives denial
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "run_project_command", payload, summary, reqId);
    },
    /The user denied this exact request\. Do not retry it unless the user gives new instructions\./,
    "Denied approval must reject"
  );
});

test("rejects mismatched payload, mismatched action, and invalid IDs", async () => {
  const payload = { file: "doc.md", content: "safe" };
  let reqId = "";
  try {
    await requireApproval(stateDir, "write_file", payload, sampleSummary);
  } catch (err) {
    const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec((err as Error).message);
    reqId = match![1];
  }

  await decide(stateDir, reqId, "approved");

  // Mismatched payload (tampered content)
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "write_file", { ...payload, content: "malicious" }, sampleSummary, reqId);
    },
    /That approval_id does not match this exact operation/,
    "Tampered payload must be rejected"
  );

  // Mismatched action
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "run_project_command", payload, sampleSummary, reqId);
    },
    /That approval_id does not match this exact operation/,
    "Mismatched action must be rejected"
  );

  // Invalid format IDs
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "write_file", payload, sampleSummary, "invalid-format-id");
    },
    /approval_id has an invalid format\./
  );

  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "write_file", payload, sampleSummary, "../escape_path_id_12345678");
    },
    /approval_id has an invalid format\./
  );
});

test("rejects expired approval requests", async () => {
  const payload = { file: "expire.txt", content: "data" };
  let reqId = "";
  try {
    await requireApproval(stateDir, "write_file", payload, sampleSummary);
  } catch (err) {
    const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec((err as Error).message);
    reqId = match![1];
  }

  // Force expiration by modifying file on disk
  const file = path.join(stateDir, "approvals", `${reqId}.json`);
  const record = JSON.parse(await fs.readFile(file, "utf8"));
  record.status = "approved";
  record.expiresAt = Date.now() - 1000;
  await fs.writeFile(file, JSON.stringify(record));

  // Expired approval must be rejected
  await assert.rejects(
    async () => {
      await requireApproval(stateDir, "write_file", payload, sampleSummary, reqId);
    },
    /That approval_id does not match this exact operation, or it expired or was already used/,
    "Expired approval must be rejected"
  );
});

test("concurrent race condition: exactly one redemption succeeds and all other parallel calls fail", async () => {
  const payload = { file: "race.txt", content: "race-data" };
  let reqId = "";
  try {
    await requireApproval(stateDir, "write_file", payload, sampleSummary);
  } catch (err) {
    const match = /approval_id: (req_[A-Za-z0-9_-]{24})/.exec((err as Error).message);
    reqId = match![1];
  }

  await decide(stateDir, reqId, "approved");

  // Fire 10 parallel redemption attempts simultaneously
  const attempts = await Promise.allSettled(
    Array.from({ length: 10 }, () =>
      requireApproval(stateDir, "write_file", payload, sampleSummary, reqId)
    )
  );

  const fulfilled = attempts.filter((a) => a.status === "fulfilled");
  const rejected = attempts.filter((a) => a.status === "rejected");

  assert.equal(fulfilled.length, 1, "Exactly one parallel redemption must succeed");
  assert.equal(rejected.length, 9, "All 9 other parallel attempts must be rejected");
  for (const r of rejected) {
    if (r.status === "rejected") {
      assert.match(
        (r.reason as Error).message,
        /already used|does not match/,
        "Parallel losers must fail with used/expired rejection"
      );
    }
  }
});
