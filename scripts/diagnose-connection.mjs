#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

// Load .env manually if dotenv not loaded
function loadEnv() {
  const envPath = path.join(rootDir, ".env");
  if (!fs.existsSync(envPath)) return {};
  const content = fs.readFileSync(envPath, "utf8");
  const env = {};
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx !== -1) {
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      env[key] = val;
    }
  }
  return env;
}

const env = loadEnv();
const port = Number(process.env.PORT || env.PORT || 3333);
const token = process.env.CODE_BRIDGE_TOKEN || env.CODE_BRIDGE_TOKEN || "";
const allowedHosts = (process.env.CODE_BRIDGE_ALLOWED_HOSTS || env.CODE_BRIDGE_ALLOWED_HOSTS || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const stateDir = process.env.CODE_BRIDGE_STATE_DIR || path.join(os.homedir(), ".code-bridge");

console.log("\n========================================================");
console.log("   Code Bridge MCP — Connectivity & OAuth Diagnostics   ");
console.log("========================================================\n");

export async function runDiagnostics(options = {}) {
  const results = {
    localServer: { ok: false, message: "" },
    tunnelProcess: { ok: false, pid: null, message: "" },
    tunnelPublic: { ok: false, url: null, message: "" },
    hostnameAlignment: { ok: false, message: "" },
    oauthState: { ok: false, stats: null, message: "" },
    recoveryActions: [],
  };

  const fetchFn = options.fetchFn || globalThis.fetch;

  // 1. Check Local Server Health
  try {
    const res = await fetchFn(`http://127.0.0.1:${port}/health`, {
      headers: { "x-code-bridge-token": token },
      signal: AbortSignal.timeout(3000),
    });
    if (res.status === 200) {
      const data = await res.json();
      results.localServer.ok = true;
      results.localServer.message = `HTTP 200 OK (Workspace: '${data.workspace}', RemoteMutationsBlocked: ${data.remoteMutationsBlocked})`;
    } else if (res.status === 401) {
      results.localServer.ok = false;
      results.localServer.message = `HTTP 401 Unauthorized (CODE_BRIDGE_TOKEN in request does not match running server)`;
      results.recoveryActions.push("Local server returned HTTP 401. Verify that CODE_BRIDGE_TOKEN in .env matches the token the server started with, then restart server.");
    } else {
      results.localServer.ok = false;
      results.localServer.message = `Unexpected HTTP ${res.status}`;
      results.recoveryActions.push(`Local server returned HTTP ${res.status}. Check server logs.`);
    }
  } catch (err) {
    results.localServer.ok = false;
    results.localServer.message = `Unreachable at http://127.0.0.1:${port} (${err.message || err})`;
    results.recoveryActions.push("Local server is not running. Start it with: npm start");
  }

  // 2. Check Quick Tunnel Process & Hostname
  const logFile = path.join(rootDir, "logs", "quick-tunnel.log");
  let capturedUrl = null;
  if (fs.existsSync(logFile)) {
    try {
      const logContent = fs.readFileSync(logFile, "utf8");
      const matches = logContent.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/g);
      if (matches && matches.length > 0) {
        capturedUrl = matches[matches.length - 1];
      }
    } catch {}
  }

  let cfRunning = false;
  let cfPids = [];
  try {
    if (process.platform === "win32") {
      const output = execSync("tasklist /FI \"IMAGENAME eq cloudflared.exe\" /FO CSV /NH", { encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] });
      if (output.includes("cloudflared.exe")) {
        cfRunning = true;
        for (const line of output.split(/\r?\n/)) {
          const parts = line.split(",");
          if (parts.length > 1) {
            const pid = parts[1].replace(/"/g, "").trim();
            if (pid) cfPids.push(pid);
          }
        }
      }
    } else {
      const output = execSync("pgrep -l cloudflared || true", { encoding: "utf8" });
      if (output.trim()) {
        cfRunning = true;
        cfPids = output.trim().split(/\s+/);
      }
    }
  } catch {}

  results.tunnelProcess.ok = cfRunning;
  results.tunnelProcess.pid = cfPids.join(", ") || null;
  if (cfRunning) {
    results.tunnelProcess.message = `Active (PID: ${cfPids.join(", ")})`;
  } else {
    results.tunnelProcess.message = "No cloudflared process detected";
    results.recoveryActions.push("Cloudflare Quick Tunnel is not active. Start it with: powershell -File .\\start-quick-tunnel.ps1");
  }

  // 3. Public Tunnel Reachability
  if (capturedUrl) {
    results.tunnelPublic.url = capturedUrl;
    try {
      const res = await fetchFn(`${capturedUrl}/openapi.json`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.status === 200) {
        results.tunnelPublic.ok = true;
        results.tunnelPublic.message = `Reachable at ${capturedUrl} (HTTP 200 OpenAPI discovered)`;
      } else {
        results.tunnelPublic.ok = false;
        results.tunnelPublic.message = `Responded with HTTP ${res.status}`;
        results.recoveryActions.push(`Tunnel endpoint returned HTTP ${res.status}. Restart Quick Tunnel.`);
      }
    } catch (err) {
      results.tunnelPublic.ok = false;
      results.tunnelPublic.message = `Connection failed to ${capturedUrl} (${err.message || err})`;
      results.recoveryActions.push(`Tunnel URL is unreachable (${capturedUrl}). Cloudflare Quick Tunnel has likely renewed; run .\\start-quick-tunnel.ps1 to get the new active URL.`);
    }
  } else {
    results.tunnelPublic.ok = false;
    results.tunnelPublic.message = "No active tunnel URL recorded in logs/quick-tunnel.log";
    results.recoveryActions.push("No recorded Quick Tunnel URL found. Start tunnel with: powershell -File .\\start-quick-tunnel.ps1");
  }

  // 4. Hostname Alignment
  const hasTryCloudflare = allowedHosts.includes("trycloudflare.com");
  if (hasTryCloudflare) {
    results.hostnameAlignment.ok = true;
    results.hostnameAlignment.message = "trycloudflare.com is included in CODE_BRIDGE_ALLOWED_HOSTS";
  } else {
    results.hostnameAlignment.ok = false;
    results.hostnameAlignment.message = "trycloudflare.com is MISSING from CODE_BRIDGE_ALLOWED_HOSTS";
    results.recoveryActions.push("Add 'trycloudflare.com' to CODE_BRIDGE_ALLOWED_HOSTS in .env so remote requests are accepted.");
  }

  // 5. OAuth Persistence State Health
  const dbPath = process.env.CODE_BRIDGE_OAUTH_DB || path.join(stateDir, "oauth.db");
  try {
    let OAuthStore;
    const distPath = path.join(rootDir, "dist", "oauth-store.js");
    if (fs.existsSync(distPath)) {
      ({ OAuthStore } = await import("../dist/oauth-store.js"));
    } else {
      try {
        ({ OAuthStore } = await import("../src/oauth-store.js"));
      } catch {
        ({ OAuthStore } = await import("../src/oauth-store.ts"));
      }
    }
    const store = new OAuthStore({
      dbPath,
      secret: process.env.CODE_BRIDGE_OAUTH_KEY || token,
    });
    const pruned = store.pruneExpiredTokens();
    const stats = store.getStats();
    results.oauthState.ok = true;
    results.oauthState.stats = stats;
    results.oauthState.message = `SQLite Store operational (${stats.clientCount} dynamic client(s), ${stats.activeAccessCount} active access token(s), ${stats.activeRefreshCount} active refresh token(s); pruned ${pruned.expiredAccess + pruned.expiredRefresh} expired)`;
    store.close();
  } catch (err) {
    results.oauthState.ok = false;
    results.oauthState.message = `OAuth storage error: ${err.message || err}`;
    results.recoveryActions.push(`OAuth storage failed to open or decrypt. If CODE_BRIDGE_TOKEN changed, restore original token or re-authenticate clients via /oauth/authorize.`);
  }

  return results;
}

// CLI Output Formatter
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const results = await runDiagnostics();

  console.log(`[1] Local Server Health:        ${results.localServer.ok ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`    ${results.localServer.message}`);

  console.log(`\n[2] Tunnel Process:             ${results.tunnelProcess.ok ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`    ${results.tunnelProcess.message}`);

  console.log(`\n[3] Public Tunnel Endpoint:     ${results.tunnelPublic.ok ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`    ${results.tunnelPublic.message}`);

  console.log(`\n[4] Hostname Alignment:         ${results.hostnameAlignment.ok ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`    ${results.hostnameAlignment.message}`);

  console.log(`\n[5] OAuth State (Encrypted DB): ${results.oauthState.ok ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`    ${results.oauthState.message}`);

  console.log("\n--------------------------------------------------------");
  if (results.tunnelPublic.url) {
    console.log("Current Active Endpoints for AI Clients:");
    console.log(`  • MCP Server Endpoint:  ${results.tunnelPublic.url}/mcp`);
    console.log(`  • OpenAPI Specification: ${results.tunnelPublic.url}/openapi.json`);
    console.log(`  • OAuth Authorize UI:   ${results.tunnelPublic.url}/oauth/authorize`);
  }

  if (results.recoveryActions.length > 0) {
    console.log("\nRequired Operator Actions / Recovery Steps:");
    for (let i = 0; i < results.recoveryActions.length; i++) {
      console.log(`  ${i + 1}. ${results.recoveryActions[i]}`);
    }
  } else {
    console.log("\nAll diagnostic checks passed. Code Bridge is healthy and reachable.");
  }
  console.log("========================================================\n");
}
