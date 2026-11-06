/**
 * Single source of truth for which workspace files the AI may see or change.
 * Pure functions on workspace-relative paths; no filesystem access.
 */
export type Access = "read" | "write";

export interface PolicyResult {
  allowed: boolean;
  /** True for files that can change what approved commands execute (allowed, but flagged in approvals). */
  sensitive: boolean;
  reason?: string;
}

const SECRET_DIRECTORIES = new Set([".git", ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".code-bridge"]);
const GENERATED_DIRECTORIES = new Set(["node_modules", "dist"]);
const SECRET_NAMES = new Set([
  ".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".htpasswd",
  "credentials", "credentials.json", "secrets.json", "secrets.yml", "secrets.yaml",
]);
const SECRET_SUFFIXES = [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx"];
const ENV_TEMPLATE = /^\.env\.(example|sample|template|dist)$/;
const PACKAGE_FILES = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]);
const DENY_REASON_SECRET = "credential or secret file";

/** Lower-cases each segment and drops trailing dots/spaces, which Windows ignores (".env " is ".env"). */
function segmentsOf(relativePath: string): string[] {
  return relativePath.split(/[\\/]+/).map(segment => segment.toLowerCase().replace(/[. ]+$/, "")).filter(Boolean);
}

function isSecretName(name: string): boolean {
  if (ENV_TEMPLATE.test(name)) return false;
  if (name.startsWith(".env") || name.endsWith(".env")) return true;
  if (SECRET_NAMES.has(name)) return true;
  if (SECRET_SUFFIXES.some(suffix => name.endsWith(suffix))) return true;
  return /^id_(rsa|dsa|ecdsa|ed25519)/.test(name) && !name.endsWith(".pub");
}

function executionSensitiveReason(segments: string[], name: string): string | undefined {
  if (PACKAGE_FILES.has(name)) return "package manifest or lockfile";
  if (segments.includes(".husky")) return "git hook script";
  if (segments[0] === ".github" && segments[1] === "workflows") return "CI workflow";
  if (segments.includes(".vscode") && ["tasks.json", "settings.json", "launch.json"].includes(name)) return "editor task or settings file";
  if (name === "makefile" || /\.(ps1|bat|cmd|sh)$/.test(name)) return "shell or build script";
  if (/\.config\.(js|cjs|mjs|ts)$/.test(name) || /^\.(babelrc|eslintrc)/.test(name)) return "build or tool configuration";
  return undefined;
}

export interface ClassifyOptions {
  allowGenerated?: boolean;
}

export function classify(relativePath: string, access: Access, options?: ClassifyOptions): PolicyResult {
  const segments = segmentsOf(relativePath);
  const name = segments[segments.length - 1] ?? "";
  if (segments.some(segment => SECRET_DIRECTORIES.has(segment))) return { allowed: false, sensitive: false, reason: "protected directory" };
  if (isSecretName(name)) return { allowed: false, sensitive: false, reason: DENY_REASON_SECRET };
  const isGenerated = segments.some(segment => GENERATED_DIRECTORIES.has(segment));
  if (isGenerated) {
    if (access === "write") return { allowed: false, sensitive: false, reason: "generated or dependency directory" };
    const allowGenerated = options?.allowGenerated ?? (process.env.CODE_BRIDGE_ALLOW_READ_GENERATED === "true");
    if (!allowGenerated) return { allowed: false, sensitive: false, reason: "generated or dependency directory" };
  }
  if (access === "write") {
    const reason = executionSensitiveReason(segments, name);
    if (reason) return { allowed: true, sensitive: true, reason };
  }
  return { allowed: true, sensitive: false };
}

export const isReadable = (relativePath: string, options?: ClassifyOptions): boolean => classify(relativePath, "read", options).allowed;

export function assertReadable(relativePath: string, options?: ClassifyOptions): void {
  const result = classify(relativePath, "read", options);
  if (!result.allowed) throw new Error(`Access blocked by Code Bridge policy (${result.reason}).`);
}

export function assertWritable(relativePath: string): PolicyResult {
  const result = classify(relativePath, "write");
  if (!result.allowed) throw new Error(`Change blocked by Code Bridge policy (${result.reason}).`);
  return result;
}

/** Directories skipped by list_files and search_code. They remain subject to the read/write rules above. */
export function isHiddenDirectory(name: string): boolean {
  const normalized = name.toLowerCase().replace(/[. ]+$/, "");
  const allowGenerated = process.env.CODE_BRIDGE_ALLOW_READ_GENERATED === "true";
  if (SECRET_DIRECTORIES.has(normalized)) return true;
  if (!allowGenerated && (normalized === "node_modules" || normalized === "dist")) return true;
  return false;
}
