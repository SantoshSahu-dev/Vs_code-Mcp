import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runDiagnostics } from "../scripts/diagnose-connection.mjs";

test("Connection Diagnostics - independent checks and actionable recovery", async (t) => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-diag-test-"));
  const tempDb = path.join(tempDir, "oauth.db");
  const origEnv = { ...process.env };

  t.after(async () => {
    process.env = origEnv;
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
  });

  await t.test("diagnostics handles server down gracefully with actionable advice", async () => {
    process.env.PORT = "3399";
    process.env.CODE_BRIDGE_TOKEN = "dummy-token";
    process.env.CODE_BRIDGE_OAUTH_DB = tempDb;

    // Mock fetchFn that simulates connection refused
    const mockFetch = async () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:3399");
    };

    const results = await runDiagnostics({ fetchFn: mockFetch });

    assert.equal(results.localServer.ok, false);
    assert.match(results.localServer.message, /Unreachable/);
    assert.ok(results.recoveryActions.some((a) => a.includes("npm start")));
  });

  await t.test("diagnostics validates healthy server and operational OAuth store", async () => {
    process.env.PORT = "3398";
    process.env.CODE_BRIDGE_TOKEN = "valid-diag-test-token";
    process.env.CODE_BRIDGE_ALLOWED_HOSTS = "trycloudflare.com,localhost";
    process.env.CODE_BRIDGE_OAUTH_DB = tempDb;

    // Mock fetchFn that responds with 200 for both health and public tunnel
    const mockFetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("/health")) {
        return new Response(JSON.stringify({
          status: "ok",
          workspace: "test-workspace",
          remoteMutationsBlocked: true,
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      if (urlStr.includes("/openapi.json")) {
        return new Response(JSON.stringify({ openapi: "3.1.0" }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response("Not found", { status: 404 });
    };

    const results = await runDiagnostics({ fetchFn: mockFetch });

    assert.equal(results.localServer.ok, true);
    assert.equal(results.hostnameAlignment.ok, true);
    assert.equal(results.oauthState.ok, true);
    assert.ok(results.oauthState.stats);
    assert.equal(results.oauthState.stats.clientCount, 0);

    // Verify no secret leak in messages
    const serialized = JSON.stringify(results);
    assert.equal(serialized.includes("valid-diag-test-token"), false, "Diagnostics must never log token secret");
  });

  await t.test("diagnostics supports programmatic options overriding process.env", async () => {
    const mockFetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes("/health")) {
        return new Response(JSON.stringify({
          status: "ok",
          workspace: "custom-workspace",
          remoteMutationsBlocked: false,
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response("Not found", { status: 404 });
    };

    const results = await runDiagnostics({
      port: 3397,
      token: "explicit-token-0123456789abcdef",
      allowedHosts: "trycloudflare.com",
      dbPath: tempDb,
      fetchFn: mockFetch,
    });

    assert.equal(results.localServer.ok, true);
    assert.equal(results.hostnameAlignment.ok, true);
    assert.equal(results.oauthState.ok, true);
  });
});
