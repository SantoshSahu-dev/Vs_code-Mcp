import readline from "node:readline/promises";
import { decide, defaultStateDir, listRecords, type ApprovalRecord } from "./approvals.js";

// Human-only approval console. It needs an interactive terminal, so it cannot be driven through MCP tools.
if (!process.stdin.isTTY || !process.stdout.isTTY) {
  console.error("Code Bridge approvals need an interactive terminal. Run `npm run approve` yourself.");
  process.exit(2);
}

const stateDir = defaultStateDir();
const pending = (await listRecords(stateDir))
  .filter(record => record.status === "pending" && record.expiresAt > Date.now())
  .sort((left, right) => left.createdAt - right.createdAt);

if (pending.length === 0) {
  console.log("No pending Code Bridge approval requests.");
  process.exit(0);
}

function show(record: ApprovalRecord): void {
  const minutes = Math.max(0, Math.round((record.expiresAt - Date.now()) / 60_000));
  console.log("\n" + "=".repeat(72));
  console.log(`${record.summary.title}   [${record.id}, expires in ~${minutes} min]`);
  for (const [key, value] of Object.entries(record.summary.details)) console.log(`  ${key}: ${value}`);
  for (const warning of record.summary.warnings) console.log(`  WARNING: ${warning}`);
  console.log("-".repeat(72));
  console.log(record.summary.preview.split("\n").map(line => `  ${line}`).join("\n"));
  console.log("=".repeat(72));
}

const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
let approved = 0;
let denied = 0;
for (const record of pending) {
  show(record);
  const answer = (await prompt.question("Approve this exact request? [y] approve / [n] deny / [Enter] skip: ")).trim().toLowerCase();
  try {
    if (answer === "y" || answer === "yes") { await decide(stateDir, record.id, "approved"); approved++; console.log("Approved."); }
    else if (answer === "n" || answer === "no") { await decide(stateDir, record.id, "denied"); denied++; console.log("Denied."); }
    else console.log("Skipped.");
  } catch (error) {
    console.log(error instanceof Error ? error.message : "Could not record the decision.");
  }
}
prompt.close();
console.log(`\nDone: ${approved} approved, ${denied} denied. Tell the AI to retry with the approval_id.`);
