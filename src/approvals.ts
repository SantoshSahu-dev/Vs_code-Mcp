import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/**
 * Human approvals live in a state folder OUTSIDE the workspace, so the bridge's own file tools cannot read or
 * write them. The AI receives only a request id, which is useless until a person approves it with `npm run approve`.
 * Approvals are single-use (an atomic rename consumes them), expire, and are bound to the exact operation.
 */
export type ApprovalStatus = "pending" | "approved" | "denied";

export interface ApprovalSummary {
  title: string;
  details: Record<string, string | number | boolean | null>;
  warnings: string[];
  preview: string;
}

export interface ApprovalRecord {
  id: string;
  action: string;
  payloadHash: string;
  summary: ApprovalSummary;
  status: ApprovalStatus;
  createdAt: number;
  expiresAt: number;
  decidedAt?: number;
  workspace?: string;
}

export const APPROVAL_TTL_MS = 10 * 60_000;
const RETENTION_MS = 24 * 60 * 60_000;
const ID_PATTERN = /^req_[A-Za-z0-9_-]{24}$/;

export function defaultStateDir(): string {
  return path.resolve(process.env.CODE_BRIDGE_STATE_DIR || path.join(os.homedir(), ".code-bridge"));
}

const approvalsDir = (stateDir: string) => path.join(stateDir, "approvals");
const fileFor = (stateDir: string, id: string) => path.join(approvalsDir(stateDir), `${id}.json`);

export function hashPayload(payload: unknown): string {
  function canonicalize(val: unknown): unknown {
    if (val === null || typeof val !== "object") return val;
    if (Array.isArray(val)) return val.map(canonicalize);
    const sortedObj: Record<string, unknown> = {};
    for (const key of Object.keys(val as Record<string, unknown>).sort()) {
      sortedObj[key] = canonicalize((val as Record<string, unknown>)[key]);
    }
    return sortedObj;
  }
  return crypto.createHash("sha256").update(JSON.stringify(canonicalize(payload))).digest("hex");
}

async function readRecord(file: string): Promise<ApprovalRecord | undefined> {
  try { return JSON.parse(await fs.readFile(file, "utf8")) as ApprovalRecord; } catch { return undefined; }
}

export async function listRecords(stateDir: string): Promise<ApprovalRecord[]> {
  let names: string[];
  try { names = await fs.readdir(approvalsDir(stateDir)); } catch { return []; }
  const records = await Promise.all(names.filter(name => name.endsWith(".json")).map(name => readRecord(path.join(approvalsDir(stateDir), name))));
  return records.filter((record): record is ApprovalRecord => Boolean(record && ID_PATTERN.test(record.id)));
}

async function prune(stateDir: string): Promise<void> {
  let names: string[];
  try { names = await fs.readdir(approvalsDir(stateDir)); } catch { return; }
  for (const name of names) {
    const file = path.join(approvalsDir(stateDir), name);
    try {
      if (Date.now() - (await fs.stat(file)).mtimeMs > RETENTION_MS) await fs.rm(file, { force: true });
    } catch { /* Another process may have removed it already. */ }
  }
}

function outstandingMessage(record: ApprovalRecord): string {
  if (record.status === "approved") return `This exact request is already approved. Repeat the identical call with approval_id: ${record.id}`;
  if (record.status === "denied") return "The user denied this exact request. Do not retry it unless the user gives new instructions.";
  return `Approval required. Tell the user exactly what you intend to change, then ask them to review and approve request ${record.id} by running "npm run approve" in the Code Bridge folder. Once they confirm, repeat the identical call with approval_id: ${record.id}`;
}

async function createRequest(stateDir: string, action: string, payloadHash: string, summary: ApprovalSummary, workspace?: string): Promise<ApprovalRecord> {
  await fs.mkdir(approvalsDir(stateDir), { recursive: true });
  await prune(stateDir);
  const now = Date.now();
  const existing = (await listRecords(stateDir)).find(record =>
    record.action === action &&
    record.payloadHash === payloadHash &&
    record.expiresAt > now &&
    (!workspace || !record.workspace || record.workspace === workspace)
  );
  if (existing) return existing;
  const record: ApprovalRecord = {
    id: `req_${crypto.randomBytes(18).toString("base64url")}`,
    action,
    payloadHash,
    summary,
    status: "pending",
    createdAt: now,
    expiresAt: now + APPROVAL_TTL_MS,
    workspace,
  };
  await fs.writeFile(fileFor(stateDir, record.id), JSON.stringify(record, null, 2), { encoding: "utf8", flag: "wx", mode: 0o600 });
  return record;
}

/** Returns normally only when a person approved this exact operation; the approval is consumed. Otherwise throws. */
export async function requireApproval(stateDir: string, action: string, payload: unknown, summary: ApprovalSummary, approvalId?: string, workspaceIdentity?: string): Promise<void> {
  const payloadHash = hashPayload(payload);
  if (approvalId !== undefined) {
    if (!ID_PATTERN.test(approvalId)) throw new Error("approval_id has an invalid format.");
    const file = fileFor(stateDir, approvalId);
    const record = await readRecord(file);
    if (record && record.action === action && record.payloadHash === payloadHash && record.expiresAt > Date.now()) {
      if (record.workspace && workspaceIdentity && record.workspace !== workspaceIdentity) {
        throw new Error("That approval_id is bound to a different workspace. The workspace has changed; request a new approval.");
      }
      if (record.status !== "approved") throw new Error(outstandingMessage(record));
      const usedFile = file.replace(/\.json$/, ".used");
      try {
        await fs.writeFile(usedFile, JSON.stringify({ ...record, status: "used", usedAt: Date.now() }), { flag: "wx", mode: 0o600 });
      } catch {
        throw new Error("This approval was already used. Request a new one.");
      }
      await fs.rm(file, { force: true });
      return;
    }
  }
  const record = await createRequest(stateDir, action, payloadHash, summary, workspaceIdentity);
  const prefix = approvalId ? "That approval_id does not match this exact operation, or it expired or was already used. " : "";
  throw new Error(prefix + outstandingMessage(record));
}

/** Used by the approval CLI (a human at a terminal). */
export async function decide(stateDir: string, id: string, status: "approved" | "denied"): Promise<void> {
  if (!ID_PATTERN.test(id)) throw new Error("Invalid request id.");
  const file = fileFor(stateDir, id);
  const record = await readRecord(file);
  if (!record || record.status !== "pending" || record.expiresAt <= Date.now()) throw new Error("Request not found, expired, or already decided.");
  await fs.writeFile(file, JSON.stringify({ ...record, status, decidedAt: Date.now() }, null, 2), { encoding: "utf8", mode: 0o600 });
}
