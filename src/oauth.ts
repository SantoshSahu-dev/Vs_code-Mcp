import crypto from "node:crypto";
import path from "node:path";
import express from "express";
import { audit } from "./audit.js";
import { config } from "./config.js";
import { constantTimeTokenMatch } from "./safety.js";
import {
  OAuthStore,
  type OAuthClient,
  type AccessTokenEntry,
  type RefreshTokenEntry,
} from "./oauth-store.js";

export { OAuthStore, type OAuthClient, type AccessTokenEntry, type RefreshTokenEntry };

export interface AuthorizationCodeEntry {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256" | "plain";
  scope: string;
  resource?: string;
  expiresAt: number;
}

// Short-lived, single-use authorization codes remain in-memory (5 min TTL)
const authorizationCodes = new Map<string, AuthorizationCodeEntry>();

// In-memory rate limiting for OAuth authorize attempts (prevents token brute-forcing)
const failedAuthAttempts = new Map<string, { count: number; firstAttempt: number }>();
const MAX_FAILED_ATTEMPTS = 10;
const LOCKOUT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

export function checkRateLimit(ip: string): boolean {
  const record = failedAuthAttempts.get(ip);
  if (!record) return true;
  if (Date.now() - record.firstAttempt > LOCKOUT_WINDOW_MS) {
    failedAuthAttempts.delete(ip);
    return true;
  }
  return record.count < MAX_FAILED_ATTEMPTS;
}

export function recordFailedAttempt(ip: string): void {
  const now = Date.now();
  const record = failedAuthAttempts.get(ip);
  if (!record || now - record.firstAttempt > LOCKOUT_WINDOW_MS) {
    failedAuthAttempts.set(ip, { count: 1, firstAttempt: now });
  } else {
    record.count++;
  }
}

export function clearRateLimit(ip: string): void {
  failedAuthAttempts.delete(ip);
}

let oauthStoreInstance: OAuthStore | undefined;

export function getOAuthStore(): OAuthStore {
  if (!oauthStoreInstance) {
    oauthStoreInstance = new OAuthStore({
      dbPath: config.oauthDbPath,
      secret: process.env.CODE_BRIDGE_OAUTH_KEY || config.token,
    });
  }
  return oauthStoreInstance;
}

export function setOAuthStore(store: OAuthStore | undefined): void {
  oauthStoreInstance = store;
}

export function closeOAuthStore(): void {
  if (oauthStoreInstance) {
    oauthStoreInstance.close();
    oauthStoreInstance = undefined;
  }
}

const AUTH_CODE_LIFETIME_MS = 5 * 60 * 1000; // 5 minutes
const ACCESS_TOKEN_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const ACCESS_TOKEN_LIFETIME_SECONDS = Math.floor(ACCESS_TOKEN_LIFETIME_MS / 1000);
const REFRESH_TOKEN_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

export function clearOAuthStores(): void {
  authorizationCodes.clear();
  failedAuthAttempts.clear();
  getOAuthStore().clear();
}

export function insertTestAuthCode(entry: AuthorizationCodeEntry): void {
  authorizationCodes.set(entry.code, entry);
}

export function insertTestRefreshToken(entry: RefreshTokenEntry): void {
  getOAuthStore().insertRefreshToken(entry);
}

export function getRefreshTokenEntry(token: string): RefreshTokenEntry | undefined {
  return getOAuthStore().getRefreshToken(token);
}

export function registerClient(client: OAuthClient): void {
  getOAuthStore().registerClient(client);
}

export function getClient(clientId: string): OAuthClient | undefined {
  if (!clientId) return undefined;
  const stored = getOAuthStore().getClient(clientId);
  if (stored) {
    return stored;
  }
  const envClientId = config.oauthClientId || process.env.OAUTH_CLIENT_ID;
  if (envClientId && envClientId === clientId) {
    const envSecret = config.oauthClientSecret || process.env.OAUTH_CLIENT_SECRET;
    const envRedirects = config.oauthAllowedRedirectUris && config.oauthAllowedRedirectUris.length > 0
      ? config.oauthAllowedRedirectUris
      : (process.env.OAUTH_ALLOWED_REDIRECT_URIS || "")
          .split(",")
          .map(s => s.trim())
          .filter(Boolean);
    return {
      clientId: envClientId,
      clientSecret: envSecret,
      clientName: "Configured Client",
      redirectUris: envRedirects,
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: envSecret ? "client_secret_post" : "none",
      createdAt: 0,
    };
  }

  // Claude Web provider client definition
  if (clientId === "claude-web") {
    return {
      clientId: "claude-web",
      clientName: "Claude Web",
      redirectUris: ["https://claude.ai/api/mcp/auth_callback"],
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      createdAt: 0,
    };
  }

  // ChatGPT provider client definition (supports named IDs and HTTPS CIMD URLs)
  if (isChatGptClientId(clientId)) {
    return {
      clientId,
      clientName: "ChatGPT Custom MCP",
      redirectUris: [
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chat.openai.com/connector_platform_oauth_redirect",
        "https://chatgpt.com/api/aip/v1/oauth/callback",
        "https://chat.openai.com/api/aip/v1/oauth/callback"
      ],
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "none",
      createdAt: 0,
    };
  }

  return undefined;
}

export function timingSafeEqualString(a: string | undefined, b: string | undefined): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

const KNOWN_ALLOWED_REDIRECT_URIS = new Set([
  "https://vertexaisearch.cloud.google.com/oauth-redirect",
  "https://claude.ai/api/mcp/auth_callback",
  "https://chatgpt.com/api/aip/v1/oauth/callback",
  "https://chat.openai.com/aip/v1/oauth/callback",
  "https://chat.openai.com/api/aip/v1/oauth/callback",
  "https://chatgpt.com/connector_platform_oauth_redirect",
  "https://chat.openai.com/connector_platform_oauth_redirect"
]);

export function isChatGptRedirectUri(redirectUri: string): boolean {
  if (!redirectUri || typeof redirectUri !== "string") return false;
  try {
    const parsed = new URL(redirectUri);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    if (host !== "chatgpt.com" && host !== "chat.openai.com") return false;
    if (parsed.pathname === "/connector_platform_oauth_redirect") return true;
    if (/^\/connector\/oauth\/[a-zA-Z0-9_-]+$/.test(parsed.pathname)) return true;
    if (parsed.pathname === "/api/aip/v1/oauth/callback") return true;
    return false;
  } catch {
    return false;
  }
}

export function isChatGptClientId(clientId: string): boolean {
  if (!clientId || typeof clientId !== "string") return false;
  const lower = clientId.toLowerCase();
  if (
    lower === "chatgpt" ||
    lower === "chatgpt-mcp" ||
    lower === "chatgpt-connector" ||
    lower === "chatgpt-custom-mcp" ||
    lower === "openai"
  ) {
    return true;
  }
  try {
    const parsed = new URL(clientId);
    if (parsed.protocol === "https:") {
      const host = parsed.hostname.toLowerCase();
      return host === "chatgpt.com" || host === "chat.openai.com" || host === "platform.openai.com";
    }
  } catch {
    // Not an HTTPS URL
  }
  return false;
}

export function isValidResource(requestedResource: string | undefined, baseUrl: string): boolean {
  if (!requestedResource) return true;
  try {
    const requested = new URL(requestedResource, baseUrl);
    const serverBase = new URL(baseUrl);
    if (requested.origin !== serverBase.origin) {
      return false;
    }
    const normPath = requested.pathname.replace(/\/+$/, "") || "/";
    return normPath === "/mcp" || normPath === "/" || normPath === "/api";
  } catch {
    return false;
  }
}

export function isMatchingResource(tokenResource: string | undefined, expectedResource: string | undefined): boolean {
  if (!tokenResource || !expectedResource) return true;
  if (tokenResource === expectedResource) return true;
  try {
    const tokenUrl = new URL(tokenResource);
    const expectedUrl = new URL(expectedResource);
    if (tokenUrl.origin !== expectedUrl.origin) return false;
    const tokenPath = tokenUrl.pathname.replace(/\/+$/, "") || "/";
    const expectedPath = expectedUrl.pathname.replace(/\/+$/, "") || "/";
    return tokenPath === expectedPath || tokenPath === "/" || expectedPath === "/mcp" || tokenPath === "/mcp";
  } catch {
    return false;
  }
}

export function isAllowedRedirectUri(redirectUri: string, client?: OAuthClient): boolean {
  if (!redirectUri || typeof redirectUri !== "string") return false;
  try {
    const parsed = new URL(redirectUri);
    if (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]")
    ) {
      return true;
    }
  } catch {
    return false;
  }

  if (client?.redirectUris && client.redirectUris.length > 0) {
    if (client.redirectUris.includes(redirectUri)) return true;
    if (isChatGptClientId(client.clientId) && isChatGptRedirectUri(redirectUri)) return true;
    return false;
  }

  if (KNOWN_ALLOWED_REDIRECT_URIS.has(redirectUri)) return true;
  if (isChatGptRedirectUri(redirectUri)) return true;

  const envRedirects = config.oauthAllowedRedirectUris && config.oauthAllowedRedirectUris.length > 0
    ? config.oauthAllowedRedirectUris
    : (process.env.OAUTH_ALLOWED_REDIRECT_URIS || "")
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);
  if (envRedirects.includes(redirectUri)) return true;

  if (process.env.NODE_ENV === "test" && process.env.OAUTH_ALLOW_ANY_REDIRECT_URI === "true") return true;

  return false;
}

export function isValidOAuthToken(token: string, expectedResource?: string): boolean {
  if (!token || typeof token !== "string") return false;
  const entry = getOAuthStore().getAccessToken(token);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    getOAuthStore().revokeOAuthToken(token);
    return false;
  }
  if (expectedResource && entry.resource) {
    if (!isMatchingResource(entry.resource, expectedResource)) {
      return false;
    }
  }
  return true;
}

export function revokeOAuthToken(token: string): boolean {
  return getOAuthStore().revokeOAuthToken(token);
}

export function verifyPkce(codeVerifier: string, codeChallenge: string, method: string): boolean {
  if (!codeVerifier || !codeChallenge) return false;
  if (method === "plain") {
    if (codeVerifier.length !== codeChallenge.length) return false;
    return crypto.timingSafeEqual(Buffer.from(codeVerifier), Buffer.from(codeChallenge));
  }
  if (method === "S256") {
    const computed = crypto.createHash("sha256").update(codeVerifier, "utf8").digest("base64url");
    if (computed.length !== codeChallenge.length) return false;
    return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(codeChallenge));
  }
  return false;
}

export function getBaseUrl(req: express.Request): string {
  const host = req?.headers?.host || (typeof req?.header === "function" ? req.header("host") : undefined) || `127.0.0.1:${config.port}`;
  const proto = req?.secure || req?.headers?.["x-forwarded-proto"] === "https" ? "https" : "http";
  return `${proto}://${host}`;
}

export function getProtectedResourceMetadata(baseUrl: string) {
  return {
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    scopes_supported: ["mcp:all"],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}/`
  };
}

export function getAuthorizationServerMetadata(baseUrl: string) {
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    scopes_supported: ["mcp:all"],
    authorization_response_iss_parameter_supported: true,
    service_documentation: `${baseUrl}/`
  };
}

export function renderAuthorizeHtml(options: {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource?: string;
  error?: string;
  workspaceName: string;
}): string {
  const escapeHtml = (str: string) =>
    str.replace(/[&<>'"]/g, tag => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[tag] || tag));

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize Code Bridge MCP</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --danger: #ef4444;
      --success: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 100%;
      max-width: 480px;
      padding: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.5rem;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-radius: 4px;
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
      margin-bottom: 1rem;
    }
    h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; }
    p.subtitle { color: var(--text-muted); font-size: 0.875rem; margin-bottom: 1.5rem; line-height: 1.4; }
    .details {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
      font-size: 0.875rem;
    }
    .details-row { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
    .details-row:last-child { margin-bottom: 0; }
    .details-label { color: var(--text-muted); }
    .details-val { font-family: monospace; font-weight: 600; word-break: break-all; text-align: right; margin-left: 0.5rem; }
    .error-banner {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid var(--danger);
      color: #fca5a5;
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.875rem;
      margin-bottom: 1.5rem;
    }
    .form-group { margin-bottom: 1.5rem; }
    label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.5rem; color: var(--text); }
    input[type="password"], input[type="text"] {
      width: 100%;
      padding: 0.75rem;
      background: #0f172a;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: #fff;
      font-family: monospace;
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="password"]:focus, input[type="text"]:focus {
      border-color: var(--accent);
    }
    .actions { display: flex; gap: 1rem; }
    button.btn-primary {
      flex: 1;
      background: var(--accent);
      color: #0f172a;
      border: none;
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-weight: 600;
      font-size: 0.95rem;
      cursor: pointer;
      transition: background 0.2s;
    }
    button.btn-primary:hover { background: var(--accent-hover); }
    .footer-note {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-align: center;
      margin-top: 1.5rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Model Context Protocol</span>
    <h1>Authorize AI Client</h1>
    <p class="subtitle">A remote client is requesting secure Model Context Protocol tool access to your local workspace.</p>

    ${options.error ? `<div class="error-banner">${escapeHtml(options.error)}</div>` : ""}

    <div class="details">
      <div class="details-row">
        <span class="details-label">Workspace</span>
        <span class="details-val">${escapeHtml(options.workspaceName)}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Client</span>
        <span class="details-val">${escapeHtml(options.clientId || "AI Client")}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Redirect URI</span>
        <span class="details-val">${escapeHtml(options.redirectUri)}</span>
      </div>
      <div class="details-row">
        <span class="details-label">Requested Scope</span>
        <span class="details-val">${escapeHtml(options.scope || "mcp:all")}</span>
      </div>
    </div>

    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(options.clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(options.redirectUri)}">
      <input type="hidden" name="scope" value="${escapeHtml(options.scope)}">
      <input type="hidden" name="state" value="${escapeHtml(options.state)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(options.codeChallenge)}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(options.codeChallengeMethod)}">
      <input type="hidden" name="resource" value="${escapeHtml(options.resource || "")}">

      <div class="form-group">
        <label for="token">Enter CODE_BRIDGE_TOKEN</label>
        <input type="password" id="token" name="token" placeholder="Paste token from local .env" required autofocus>
      </div>

      <div class="actions">
        <button type="submit" class="btn-primary">Authorize &amp; Connect</button>
      </div>
    </form>

    <p class="footer-note">All mutating file writes, deletions, and commands will still require human approval via <code>npm run approve</code>.</p>
  </div>
</body>
</html>`;
}

export function handleClientRegistration(req: express.Request, res: express.Response): void {
  const body = req.body || {};
  const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.map(String) : [];

  if (redirectUris.length === 0) {
    res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "redirect_uris must be a non-empty array of valid URIs"
    });
    return;
  }

  for (const uri of redirectUris) {
    try {
      new URL(uri);
    } catch {
      res.status(400).json({
        error: "invalid_redirect_uri",
        error_description: `Invalid URI format: ${uri}`
      });
      return;
    }
  }

  const clientId = "cb_client_" + crypto.randomBytes(16).toString("hex");
  const clientName = typeof body.client_name === "string" && body.client_name ? body.client_name : "Dynamic MCP Client";
  const isClaude = clientName.toLowerCase().includes("claude") || redirectUris.some((u: string) => u.includes("claude.ai"));
  const tokenEndpointAuthMethod = (isClaude || body.token_endpoint_auth_method === "none")
    ? "none"
    : body.token_endpoint_auth_method === "client_secret_basic"
      ? "client_secret_basic"
      : "client_secret_post";
  const clientSecret = tokenEndpointAuthMethod === "none"
    ? undefined
    : "cb_sec_" + crypto.randomBytes(32).toString("base64url");
  const grantTypes = Array.isArray(body.grant_types) && body.grant_types.length > 0
    ? body.grant_types.map(String)
    : ["authorization_code", "refresh_token"];
  const responseTypes = Array.isArray(body.response_types) && body.response_types.length > 0
    ? body.response_types.map(String)
    : ["code"];

  const client: OAuthClient = {
    clientId,
    clientSecret,
    clientName,
    redirectUris,
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod,
    createdAt: Date.now()
  };

  getOAuthStore().registerClient(client);
  void audit("oauth_client_registered", { clientId, clientName, redirectUris });

  const responsePayload: Record<string, unknown> = {
    client_id: clientId,
    client_id_issued_at: Math.floor(client.createdAt / 1000),
    client_name: clientName,
    redirect_uris: redirectUris,
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: tokenEndpointAuthMethod
  };
  if (clientSecret) {
    responsePayload.client_secret = clientSecret;
    responsePayload.client_secret_expires_at = 0;
  }

  res.status(201).json(responsePayload);
}

export const oauthRouter = express.Router();

// Dynamic Client Registration (RFC 7591)
oauthRouter.post("/register", handleClientRegistration);

// GET /oauth/authorize
oauthRouter.get("/authorize", (req, res) => {
  const clientId = String(req.query.client_id || "");
  const redirectUri = String(req.query.redirect_uri || "");
  const responseType = String(req.query.response_type || "");
  const scope = String(req.query.scope || "mcp:all");
  const state = String(req.query.state || "");
  const codeChallenge = String(req.query.code_challenge || "");
  const codeChallengeMethod = String(req.query.code_challenge_method || "S256");
  const resource = req.query.resource ? String(req.query.resource) : undefined;
  const baseUrl = getBaseUrl(req);

  if (responseType !== "code") {
    res.status(400).send("Invalid response_type. Only 'code' is supported.");
    return;
  }
  if (!clientId) {
    res.status(400).send("Missing client_id parameter.");
    return;
  }
  if (!redirectUri) {
    res.status(400).send("Missing redirect_uri parameter.");
    return;
  }
  const client = getClient(clientId);
  if (!isAllowedRedirectUri(redirectUri, client)) {
    res.status(400).send("Invalid or unauthorized redirect_uri.");
    return;
  }
  if (!codeChallenge) {
    res.status(400).send("Missing code_challenge. OAuth 2.1 PKCE is required.");
    return;
  }
  if (codeChallengeMethod !== "S256") {
    res.status(400).send("Invalid code_challenge_method. Only S256 is supported.");
    return;
  }
  if (resource && !isValidResource(resource, baseUrl)) {
    res.status(400).send("Invalid resource parameter. Resource does not match this server.");
    return;
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(renderAuthorizeHtml({
    clientId,
    redirectUri,
    scope,
    state,
    codeChallenge,
    codeChallengeMethod,
    resource,
    workspaceName: path.basename(config.workspace)
  }));
});

// POST /oauth/authorize
oauthRouter.post("/authorize", (req, res) => {
  const clientId = String(req.body.client_id || "");
  const redirectUri = String(req.body.redirect_uri || "");
  const scope = String(req.body.scope || "mcp:all");
  const state = String(req.body.state || "");
  const codeChallenge = String(req.body.code_challenge || "");
  const codeChallengeMethod = String(req.body.code_challenge_method || "S256");
  const resource = req.body.resource ? String(req.body.resource) : undefined;
  const enteredToken = String(req.body.token || "");
  const baseUrl = getBaseUrl(req);

  if (!clientId) {
    res.status(400).send("Missing client_id parameter.");
    return;
  }
  if (!redirectUri || !codeChallenge) {
    res.status(400).send("Missing redirect_uri or code_challenge parameter.");
    return;
  }
  if (codeChallengeMethod !== "S256") {
    res.status(400).send("Invalid code_challenge_method. Only S256 is supported.");
    return;
  }
  const client = getClient(clientId);
  if (!isAllowedRedirectUri(redirectUri, client)) {
    res.status(400).send("Invalid or unauthorized redirect_uri.");
    return;
  }
  if (resource && !isValidResource(resource, baseUrl)) {
    res.status(400).send("Invalid resource parameter. Resource does not match this server.");
    return;
  }

  const clientIp = req.ip || req.socket.remoteAddress || "unknown";
  if (!checkRateLimit(clientIp)) {
    res.status(429).setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(renderAuthorizeHtml({
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge,
      codeChallengeMethod,
      resource,
      workspaceName: path.basename(config.workspace),
      error: "Too many failed authorization attempts. Please wait 5 minutes before trying again."
    }));
    return;
  }

  if (!constantTimeTokenMatch(enteredToken)) {
    recordFailedAttempt(clientIp);
    void audit("oauth_authorization_failed", { clientId, redirectUri, ip: clientIp });
    res.status(401).setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(renderAuthorizeHtml({
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge,
      codeChallengeMethod,
      resource,
      workspaceName: path.basename(config.workspace),
      error: "Invalid CODE_BRIDGE_TOKEN. Please check the token in your local .env file."
    }));
    return;
  }

  clearRateLimit(clientIp);

  const code = "cb_code_" + crypto.randomBytes(32).toString("base64url");
  authorizationCodes.set(code, {
    code,
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod: "S256",
    scope,
    resource,
    expiresAt: Date.now() + AUTH_CODE_LIFETIME_MS
  });

  void audit("oauth_authorized", { clientId, redirectUri, method: "form_submission" });

  try {
    const targetUrl = new URL(redirectUri);
    targetUrl.searchParams.set("code", code);
    if (state) targetUrl.searchParams.set("state", state);
    targetUrl.searchParams.set("iss", baseUrl);
    res.redirect(302, targetUrl.toString());
  } catch {
    res.status(400).send("Invalid redirect_uri format.");
  }
});

// POST /oauth/token
oauthRouter.post("/token", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // Extract client credentials from Basic Auth header or body
  let authClientId: string | undefined;
  let authClientSecret: string | undefined;

  const authHeader = req.header("authorization");
  if (authHeader && authHeader.toLowerCase().startsWith("basic ")) {
    try {
      const credentials = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf8");
      const colonIdx = credentials.indexOf(":");
      if (colonIdx !== -1) {
        authClientId = decodeURIComponent(credentials.slice(0, colonIdx));
        authClientSecret = decodeURIComponent(credentials.slice(colonIdx + 1));
      }
    } catch {
      // Malformed basic auth
    }
  }

  if (!authClientId && req.body.client_id) {
    authClientId = String(req.body.client_id);
  }
  if (!authClientSecret && req.body.client_secret) {
    authClientSecret = String(req.body.client_secret);
  }

  if (authClientId) {
    const client = getClient(authClientId);
    if (client) {
      if (client.clientSecret && client.tokenEndpointAuthMethod !== "none") {
        if (!authClientSecret || !timingSafeEqualString(authClientSecret, client.clientSecret)) {
          void audit("oauth_client_auth_failed", { clientId: authClientId });
          res.status(401).json({ error: "invalid_client", error_description: "Client authentication failed" });
          return;
        }
      }
    } else if (authClientSecret) {
      void audit("oauth_unknown_client", { clientId: authClientId });
      res.status(401).json({ error: "invalid_client", error_description: "Unknown client" });
      return;
    }
  }

  const grantType = req.body.grant_type;
  const baseUrl = getBaseUrl(req);

  if (grantType === "authorization_code") {
    const code = String(req.body.code || "");
    const codeVerifier = String(req.body.code_verifier || "");
    const redirectUri = String(req.body.redirect_uri || "");
    const requestedResource = req.body.resource ? String(req.body.resource) : undefined;

    if (!code || !codeVerifier) {
      res.status(400).json({ error: "invalid_request", error_description: "Missing code or code_verifier" });
      return;
    }

    const authCode = authorizationCodes.get(code);
    if (!authCode) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid authorization code" });
      return;
    }

    // Single use: delete code immediately
    authorizationCodes.delete(code);

    if (Date.now() > authCode.expiresAt) {
      res.status(400).json({ error: "invalid_grant", error_description: "Authorization code has expired" });
      return;
    }

    const effectiveClientId = authClientId || authCode.clientId;
    if (authClientId && authCode.clientId && authClientId !== authCode.clientId) {
      res.status(400).json({ error: "invalid_grant", error_description: "Client ID does not match authorization code" });
      return;
    }

    const registeredClient = effectiveClientId ? getClient(effectiveClientId) : undefined;
    if (registeredClient && registeredClient.clientSecret && registeredClient.tokenEndpointAuthMethod !== "none") {
      if (!authClientSecret || !timingSafeEqualString(authClientSecret, registeredClient.clientSecret)) {
        void audit("oauth_client_auth_failed", { clientId: effectiveClientId });
        res.status(401).json({ error: "invalid_client", error_description: "Client authentication failed" });
        return;
      }
    }

    if (authCode.redirectUri && redirectUri && authCode.redirectUri !== redirectUri) {
      res.status(400).json({ error: "invalid_grant", error_description: "Redirect URI mismatch" });
      return;
    }

    if (requestedResource && !isValidResource(requestedResource, baseUrl)) {
      res.status(400).json({ error: "invalid_target", error_description: "Requested resource is invalid for this server" });
      return;
    }

    if (authCode.resource && requestedResource && !isMatchingResource(authCode.resource, requestedResource)) {
      res.status(400).json({ error: "invalid_target", error_description: "Requested resource does not match authorization code target" });
      return;
    }

    const isValidPkce = verifyPkce(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod);
    if (!isValidPkce) {
      void audit("oauth_pkce_failed", { clientId: authCode.clientId });
      res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }

    const accessToken = "cb_at_" + crypto.randomBytes(32).toString("base64url");
    const refreshToken = "cb_rt_" + crypto.randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + ACCESS_TOKEN_LIFETIME_MS;
    const effectiveResource = requestedResource || authCode.resource;
    const effectiveClient = effectiveClientId || "client";
    const effectiveScope = authCode.scope || "mcp:all";

    getOAuthStore().saveTokens(
      {
        token: accessToken,
        refreshToken,
        clientId: effectiveClient,
        scope: effectiveScope,
        resource: effectiveResource,
        createdAt: Date.now(),
        expiresAt
      },
      {
        token: refreshToken,
        accessToken,
        clientId: effectiveClient,
        scope: effectiveScope,
        resource: effectiveResource,
        createdAt: Date.now(),
        expiresAt: Date.now() + REFRESH_TOKEN_LIFETIME_MS
      }
    );

    void audit("oauth_token_issued", { clientId: effectiveClient });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
      refresh_token: refreshToken,
      scope: effectiveScope
    });
    return;
  }

  if (grantType === "refresh_token") {
    const refreshToken = String(req.body.refresh_token || "");
    const requestedResource = req.body.resource ? String(req.body.resource) : undefined;

    const refreshEntry = getOAuthStore().getRefreshToken(refreshToken);
    if (!refreshToken || !refreshEntry) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid refresh token" });
      return;
    }

    if (Date.now() > refreshEntry.expiresAt) {
      getOAuthStore().revokeOAuthToken(refreshToken);
      res.status(400).json({ error: "invalid_grant", error_description: "Refresh token has expired" });
      return;
    }

    // Client verification: if a client_id was supplied, it must match the token's original client
    if (authClientId && authClientId !== refreshEntry.clientId) {
      res.status(400).json({ error: "invalid_grant", error_description: "Client ID does not match refresh token" });
      return;
    }

    // Check client authentication for confidential clients
    const registeredClient = getClient(refreshEntry.clientId);
    if (registeredClient && registeredClient.clientSecret && registeredClient.tokenEndpointAuthMethod !== "none") {
      if (!authClientSecret || !timingSafeEqualString(authClientSecret, registeredClient.clientSecret)) {
        void audit("oauth_client_auth_failed", { clientId: refreshEntry.clientId });
        res.status(401).json({ error: "invalid_client", error_description: "Client authentication failed" });
        return;
      }
    }

    if (requestedResource && !isValidResource(requestedResource, baseUrl)) {
      res.status(400).json({ error: "invalid_target", error_description: "Requested resource is invalid on refresh" });
      return;
    }

    if (refreshEntry.resource && requestedResource && !isMatchingResource(refreshEntry.resource, requestedResource)) {
      res.status(400).json({ error: "invalid_target", error_description: "Requested resource does not match original token target" });
      return;
    }

    const effectiveResource = requestedResource || refreshEntry.resource;
    const newAccessToken = "cb_at_" + crypto.randomBytes(32).toString("base64url");
    const newRefreshToken = "cb_rt_" + crypto.randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + ACCESS_TOKEN_LIFETIME_MS;

    const rotated = getOAuthStore().rotateRefreshToken(
      refreshToken,
      {
        token: newAccessToken,
        refreshToken: newRefreshToken,
        clientId: refreshEntry.clientId,
        scope: refreshEntry.scope,
        resource: effectiveResource,
        createdAt: Date.now(),
        expiresAt
      },
      {
        token: newRefreshToken,
        accessToken: newAccessToken,
        clientId: refreshEntry.clientId,
        scope: refreshEntry.scope,
        resource: effectiveResource,
        createdAt: Date.now(),
        expiresAt: Date.now() + REFRESH_TOKEN_LIFETIME_MS
      }
    );

    if (!rotated) {
      res.status(400).json({ error: "invalid_grant", error_description: "Refresh token already used or expired" });
      return;
    }

    void audit("oauth_token_refreshed", { clientId: refreshEntry.clientId });

    res.json({
      access_token: newAccessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
      refresh_token: newRefreshToken,
      scope: refreshEntry.scope
    });
    return;
  }

  res.status(400).json({ error: "unsupported_grant_type", error_description: "Supported grant types: authorization_code, refresh_token" });
});

// POST /oauth/revoke
oauthRouter.post("/revoke", (req, res) => {
  const token = String(req.body.token || "");
  if (token) {
    revokeOAuthToken(token);
    void audit("oauth_token_revoked", { token_prefix: token.slice(0, 8) });
  }
  res.json({ ok: true });
});
