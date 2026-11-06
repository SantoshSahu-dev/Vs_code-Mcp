import fs from "node:fs";
import path from "node:path";
import { defaultStateDir } from "./approvals.js";
import { assertAutoApproveDisabled, parseAllowedHosts, validateToken } from "./config-rules.js";

// Desktop extensions supply these values directly. The normal local server can
// still use .env, but only when the required environment has not been provided.
if (!process.env.CODE_BRIDGE_WORKSPACE || !process.env.CODE_BRIDGE_TOKEN) {
  await import("dotenv/config");
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}. Copy .env.example to .env and configure it.`);
  return value;
}

function port(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error(`${name} must be a valid TCP port.`);
  return value;
}

import { workspaceManager } from "./workspace-manager.js";

const configuredWorkspace = required("CODE_BRIDGE_WORKSPACE").trim().replace(/>+$/, "");
if (!configuredWorkspace) throw new Error("CODE_BRIDGE_WORKSPACE cannot be empty.");
const workspace = path.resolve(configuredWorkspace);
if (!fs.existsSync(workspace) || !fs.statSync(workspace).isDirectory()) throw new Error("CODE_BRIDGE_WORKSPACE must name an existing directory.");

const canonicalFallback = fs.realpathSync(workspace);
workspaceManager.initFallback(canonicalFallback);

export const config = {
  get workspace(): string {
    return workspaceManager.getWorkspace();
  },
  fallbackWorkspace: canonicalFallback,
  token: (() => {
    const token = required("CODE_BRIDGE_TOKEN");
    validateToken(token);
    return token;
  })(),
  port: port("PORT", 3333),
  allowedHosts: parseAllowedHosts(process.env.CODE_BRIDGE_ALLOWED_HOSTS),
  autoApproveWrites: (() => {
    assertAutoApproveDisabled(process.env.CODE_BRIDGE_AUTO_APPROVE_WRITES);
    return false as const;
  })(),
  blockRemoteMutations: process.env.CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS === "true" || process.env.CODE_BRIDGE_READ_ONLY === "true",
  allowReadGenerated: process.env.CODE_BRIDGE_ALLOW_READ_GENERATED === "true",
  get editorPort(): number {
    return port("CODE_BRIDGE_EDITOR_PORT", 3334);
  },
  auditLog: path.resolve(process.env.CODE_BRIDGE_AUDIT_LOG ?? "logs/audit.jsonl"),
  get stateDir(): string {
    return defaultStateDir();
  },
  get oauthDbPath(): string {
    return process.env.CODE_BRIDGE_OAUTH_DB || path.join(defaultStateDir(), "oauth.db");
  },
  oauthClientId: process.env.OAUTH_CLIENT_ID?.trim() || undefined,
  oauthClientSecret: process.env.OAUTH_CLIENT_SECRET?.trim() || undefined,
  oauthAllowedRedirectUris: (process.env.OAUTH_ALLOWED_REDIRECT_URIS ?? "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean),
};
