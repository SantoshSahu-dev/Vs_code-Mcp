import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const envPath = path.join(rootDir, ".env");

// Generate high-entropy OAuth client credentials for local testing
const clientId = "cb_client_" + crypto.randomBytes(16).toString("hex");
const clientSecret = "cb_sec_" + crypto.randomBytes(32).toString("base64url");
const defaultRedirectUris = "https://vertexaisearch.cloud.google.com/oauth-redirect,https://claude.ai/api/mcp/auth_callback";

let envContent = "";
if (fs.existsSync(envPath)) {
  envContent = fs.readFileSync(envPath, "utf8");
} else {
  const examplePath = path.join(rootDir, ".env.example");
  if (fs.existsSync(examplePath)) {
    envContent = fs.readFileSync(examplePath, "utf8");
  }
}

// Update or append OAUTH_CLIENT_ID
if (/^OAUTH_CLIENT_ID=.*$/m.test(envContent)) {
  envContent = envContent.replace(/^OAUTH_CLIENT_ID=.*$/m, `OAUTH_CLIENT_ID=${clientId}`);
} else {
  envContent += (envContent.endsWith("\n") || envContent === "" ? "" : "\n") + `OAUTH_CLIENT_ID=${clientId}\n`;
}

// Update or append OAUTH_CLIENT_SECRET
if (/^OAUTH_CLIENT_SECRET=.*$/m.test(envContent)) {
  envContent = envContent.replace(/^OAUTH_CLIENT_SECRET=.*$/m, `OAUTH_CLIENT_SECRET=${clientSecret}`);
} else {
  envContent += (envContent.endsWith("\n") ? "" : "\n") + `OAUTH_CLIENT_SECRET=${clientSecret}\n`;
}

// Ensure OAUTH_ALLOWED_REDIRECT_URIS is present
if (!/^OAUTH_ALLOWED_REDIRECT_URIS=.*$/m.test(envContent)) {
  envContent += (envContent.endsWith("\n") ? "" : "\n") + `OAUTH_ALLOWED_REDIRECT_URIS=${defaultRedirectUris}\n`;
}

fs.writeFileSync(envPath, envContent, "utf8");

console.log("==================================================================");
console.log("  Code Bridge: OAuth Client Credentials Generated Successfully   ");
console.log("==================================================================");
console.log("");
console.log("Client ID:");
console.log(`  ${clientId}`);
console.log("");
console.log("Client Secret:");
console.log(`  ${clientSecret}`);
console.log("");
console.log("Persisted to local .env (never committed to git):");
console.log("  OAUTH_CLIENT_ID");
console.log("  OAUTH_CLIENT_SECRET");
console.log("  OAUTH_ALLOWED_REDIRECT_URIS");
console.log("");
console.log("------------------------------------------------------------------");
console.log("  Gemini Custom Apps (gemini.google.com) Configuration Guide     ");
console.log("------------------------------------------------------------------");
console.log("1. Ensure your Code Bridge server is running and tunneled (e.g. Cloudflare).");
console.log("2. In Gemini Custom Apps / Gems settings, enter:");
console.log("   - Server URL:        https://<your-tunnel-domain>/mcp");
console.log("   - Authorization URL: https://<your-tunnel-domain>/oauth/authorize");
console.log("   - Token URL:         https://<your-tunnel-domain>/oauth/token");
console.log(`   - Client ID:         ${clientId}`);
console.log(`   - Client Secret:     ${clientSecret}`);
console.log("   - Scopes:            mcp:all");
console.log("3. Google's callback URL is automatically whitelisted:");
console.log("   - Redirect URI:      https://vertexaisearch.cloud.google.com/oauth-redirect");
console.log("==================================================================");
