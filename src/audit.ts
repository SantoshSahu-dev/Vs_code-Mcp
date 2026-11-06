import fs from "node:fs/promises";
import path from "node:path";
import { config } from "./config.js";

/** Records operation metadata only. Never pass tokens, file contents, or request bodies here. */
export async function audit(event: string, details: Record<string, unknown> = {}): Promise<void> {
  const entry = JSON.stringify({ at: new Date().toISOString(), event, ...details }) + "\n";
  try {
    await fs.mkdir(path.dirname(config.auditLog), { recursive: true });
    await fs.appendFile(config.auditLog, entry, { encoding: "utf8", mode: 0o600 });
  } catch {
    // Auditing must not leak operational details or make a safe request unsafe.
  }
}
