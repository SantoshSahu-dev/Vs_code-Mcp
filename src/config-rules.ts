/** Pure configuration rules, kept separate from config.ts so they can be unit-tested without environment side effects. */

const PLACEHOLDER_TOKEN = /replace|change[-_ ]?me|placeholder|example|your[-_ ]?(secret|token)|random-char/i;

/** Rejects short, placeholder-looking, or low-variety tokens. Returns the token when acceptable. */
export function validateToken(token: string): string {
  if (token.length < 32) throw new Error("CODE_BRIDGE_TOKEN must be at least 32 characters.");
  if (PLACEHOLDER_TOKEN.test(token) || new Set(token).size < 10) {
    throw new Error("CODE_BRIDGE_TOKEN looks like a placeholder or is too predictable. Generate a long random value.");
  }
  return token;
}

/** Automatic approval was removed: every write, delete and command needs a human decision. */
export function assertAutoApproveDisabled(value: string | undefined): void {
  const normalized = value?.trim().toLowerCase();
  if (normalized && !["false", "0", "no"].includes(normalized)) {
    throw new Error("CODE_BRIDGE_AUTO_APPROVE_WRITES is no longer supported. Code Bridge always requires human approval (run `npm run approve`). Remove the setting.");
  }
}

/** Parses extra Host header names (for a named tunnel). Loopback names are always allowed by the caller. */
export function parseAllowedHosts(value: string | undefined): string[] {
  const hosts = (value ?? "").split(",").map(host => host.trim().toLowerCase()).filter(Boolean);
  for (const host of hosts) {
    if (!/^[a-z0-9.-]+$/.test(host)) throw new Error("CODE_BRIDGE_ALLOWED_HOSTS must be a comma-separated list of host names (no scheme, port, or path).");
  }
  return hosts;
}
