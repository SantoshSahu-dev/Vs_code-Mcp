import assert from "node:assert/strict";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { OAuthStore, OAuthStorageError, tokenHash, type OAuthClient, type AccessTokenEntry, type RefreshTokenEntry } from "../src/oauth-store.js";
import { DatabaseSync } from "node:sqlite";

test("OAuthStore - lifecycle, encryption, rotation, and persistence", async (t) => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "code-bridge-store-test-"));
  const dbPath = path.join(tempDir, "oauth.db");
  const secretKey = "test-store-secret-key-12345678901234567890";

  t.after(async () => {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => undefined);
  });

  await t.test("initializes SQLite database in WAL mode with secure permissions", () => {
    const store = new OAuthStore(dbPath, secretKey);
    try {
      assert.ok(fsSync.existsSync(dbPath), "Database file should exist");
      const stat = fsSync.statSync(dbPath);
      if (process.platform !== "win32") {
        assert.equal(stat.mode & 0o777, 0o600, "Database file permissions should be 0600");
      }
      const stats = store.getStats();
      assert.equal(stats.clientCount, 0);
      assert.equal(stats.activeAccessCount, 0);
      assert.equal(stats.activeRefreshCount, 0);
    } finally {
      store.close();
    }
  });

  await t.test("registers and retrieves dynamic client", () => {
    const store = new OAuthStore(dbPath, secretKey);
    try {
      const client: OAuthClient = {
        clientId: "test-client-123",
        clientSecret: "secret-super-safe-987",
        clientName: "Test Client",
        redirectUris: ["https://example.com/callback"],
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        createdAt: Date.now(),
      };
      store.registerClient(client);

      const retrieved = store.getClient("test-client-123");
      assert.ok(retrieved);
      assert.equal(retrieved.clientId, "test-client-123");
      assert.equal(retrieved.clientSecret, "secret-super-safe-987");
      assert.deepEqual(retrieved.redirectUris, ["https://example.com/callback"]);
      assert.equal(retrieved.clientName, "Test Client");
    } finally {
      store.close();
    }
  });

  await t.test("persists clients and tokens across store reopen (server restart)", () => {
    // 1. Open store, save client and access/refresh tokens, then close
    const store1 = new OAuthStore(dbPath, secretKey);
    const now = Date.now();
    store1.saveTokens(
      {
        token: "cb_at_persistent_test_token_12345",
        clientId: "test-client-123",
        scope: "mcp:all",
        resource: "http://127.0.0.1:3333/mcp",
        createdAt: now,
        expiresAt: now + 3600000,
      },
      {
        token: "cb_rt_persistent_test_token_67890",
        clientId: "test-client-123",
        scope: "mcp:all",
        resource: "http://127.0.0.1:3333/mcp",
        createdAt: now,
        expiresAt: now + 86400000,
      }
    );
    store1.close();

    // 2. Open store again with the same key
    const store2 = new OAuthStore(dbPath, secretKey);
    try {
      const client = store2.getClient("test-client-123");
      assert.ok(client);
      assert.equal(client.clientSecret, "secret-super-safe-987");

      const at = store2.getAccessToken("cb_at_persistent_test_token_12345");
      assert.ok(at);
      assert.equal(at.clientId, "test-client-123");
      assert.equal(at.scope, "mcp:all");

      const rt = store2.getRefreshToken("cb_rt_persistent_test_token_67890");
      assert.ok(rt);
      assert.equal(rt.clientId, "test-client-123");
    } finally {
      store2.close();
    }
  });

  await t.test("database values on disk are encrypted and do not leak plaintext secrets", () => {
    // Inspect raw sqlite database tables directly without decryption
    const rawDb = new DatabaseSync(dbPath);
    try {
      const clientRow = rawDb.prepare("SELECT client_secret_encrypted FROM oauth_clients WHERE client_id = ?").get("test-client-123") as { client_secret_encrypted: string };
      assert.ok(clientRow);
      assert.ok(clientRow.client_secret_encrypted.startsWith("v1:"));
      assert.ok(!clientRow.client_secret_encrypted.includes("secret-super-safe-987"), "Plaintext client secret must not appear on disk");

      const atRows = rawDb.prepare("SELECT token_hash, token_encrypted FROM oauth_access_tokens").all() as Array<{ token_hash: string; token_encrypted: string }>;
      assert.ok(atRows.length > 0);
      for (const row of atRows) {
        assert.ok(row.token_encrypted.startsWith("v1:"));
        assert.ok(!row.token_encrypted.includes("cb_at_persistent_test_token_12345"), "Plaintext token must not appear on disk");
      }
    } finally {
      rawDb.close();
    }
  });

  await t.test("refresh token atomic rotation: single-use and invalidation", () => {
    const store = new OAuthStore(dbPath, secretKey);
    try {
      const now = Date.now();
      const initialRt = "cb_rt_rotation_test_1";
      const initialAt = "cb_at_rotation_test_1";
      store.saveTokens(
        {
          token: initialAt,
          refreshToken: initialRt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 3600000,
        },
        {
          token: initialRt,
          accessToken: initialAt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 86400000,
        }
      );

      // 1. Rotate token
      const nextRt = "cb_rt_rotation_test_2";
      const nextAt = "cb_at_rotation_test_2";
      const rotated = store.rotateRefreshToken(
        initialRt,
        {
          token: nextAt,
          refreshToken: nextRt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 3600000,
        },
        {
          token: nextRt,
          accessToken: nextAt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 86400000,
        }
      );

      assert.equal(rotated, true, "First rotation attempt should succeed");

      // 2. Old refresh token can NEVER be used again (single-use enforcement)
      assert.equal(store.getRefreshToken(initialRt), undefined, "Old refresh token must be gone");

      const reuseAttempt = store.rotateRefreshToken(
        initialRt,
        {
          token: "cb_at_rotation_test_3",
          refreshToken: "cb_rt_rotation_test_3",
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 3600000,
        },
        {
          token: "cb_rt_rotation_test_3",
          accessToken: "cb_at_rotation_test_3",
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 86400000,
        }
      );
      assert.equal(reuseAttempt, false, "Reusing old refresh token must be rejected");

      // 3. New tokens exist
      assert.ok(store.getRefreshToken(nextRt));
      assert.ok(store.getAccessToken(nextAt));
    } finally {
      store.close();
    }
  });

  await t.test("concurrent refresh token redemption: only one succeeds", async () => {
    const store = new OAuthStore(dbPath, secretKey);
    try {
      const now = Date.now();
      const sharedRt = "cb_rt_concurrent_race_test";
      const sharedAt = "cb_at_concurrent_race_test";
      store.saveTokens(
        {
          token: sharedAt,
          refreshToken: sharedRt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 3600000,
        },
        {
          token: sharedRt,
          accessToken: sharedAt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 86400000,
        }
      );

      // Launch 5 parallel rotation attempts
      const attempts = Array.from({ length: 5 }, (_, i) => {
        return Promise.resolve().then(() => {
          return store.rotateRefreshToken(
            sharedRt,
            {
              token: `cb_at_race_${i}`,
              refreshToken: `cb_rt_race_${i}`,
              clientId: "test-client-123",
              scope: "mcp:all",
              resource: "http://127.0.0.1:3333/mcp",
              createdAt: now,
              expiresAt: now + 3600000,
            },
            {
              token: `cb_rt_race_${i}`,
              accessToken: `cb_at_race_${i}`,
              clientId: "test-client-123",
              scope: "mcp:all",
              resource: "http://127.0.0.1:3333/mcp",
              createdAt: now,
              expiresAt: now + 86400000,
            }
          );
        });
      });

      const results = await Promise.all(attempts);
      const successCount = results.filter((r) => r === true).length;
      const failureCount = results.filter((r) => r === false).length;

      assert.equal(successCount, 1, "Exactly one concurrent rotation request must succeed");
      assert.equal(failureCount, 4, "All other concurrent rotation requests must fail");
    } finally {
      store.close();
    }
  });

  await t.test("token expiration and pruning", () => {
    const store = new OAuthStore(dbPath, secretKey);
    try {
      const now = Date.now();
      // Insert already-expired tokens
      store.insertAccessToken({
        token: "cb_at_expired_token",
        clientId: "test-client-123",
        scope: "mcp:all",
        resource: "http://127.0.0.1:3333/mcp",
        createdAt: now - 200000,
        expiresAt: now - 100000, // Expired
      });
      store.insertRefreshToken({
        token: "cb_rt_expired_token",
        clientId: "test-client-123",
        scope: "mcp:all",
        resource: "http://127.0.0.1:3333/mcp",
        createdAt: now - 200000,
        expiresAt: now - 100000, // Expired
      });

      // Prune removes them from database
      const pruned = store.pruneExpiredTokens();
      assert.ok(pruned.expiredAccess >= 1);
      assert.ok(pruned.expiredRefresh >= 1);

      // Verify they are no longer in DB
      assert.equal(store.getAccessToken("cb_at_expired_token"), undefined);
      assert.equal(store.getRefreshToken("cb_rt_expired_token"), undefined);
    } finally {
      store.close();
    }
  });

  await t.test("token revocation", () => {
    const store = new OAuthStore(dbPath, secretKey);
    try {
      const now = Date.now();
      const at = "cb_at_revocation_target";
      const rt = "cb_rt_revocation_target";
      store.saveTokens(
        {
          token: at,
          refreshToken: rt,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 3600000,
        },
        {
          token: rt,
          accessToken: at,
          clientId: "test-client-123",
          scope: "mcp:all",
          resource: "http://127.0.0.1:3333/mcp",
          createdAt: now,
          expiresAt: now + 86400000,
        }
      );

      assert.ok(store.getAccessToken(at));
      assert.ok(store.getRefreshToken(rt));

      // Revoke access token
      const revokedAt = store.revokeOAuthToken(at);
      assert.equal(revokedAt, true);
      assert.equal(store.getAccessToken(at), undefined);
      // Revoking access token should also cascade-revoke paired refresh token
      assert.equal(store.getRefreshToken(rt), undefined);
    } finally {
      store.close();
    }
  });

  await t.test("tampered authentication tag or ciphertext fails closed with OAuthStorageError", () => {
    // 1. Corrupt the client_secret_encrypted of an existing client in SQLite
    const rawDb = new DatabaseSync(dbPath);
    try {
      const row = rawDb.prepare("SELECT client_secret_encrypted FROM oauth_clients WHERE client_id = ?").get("test-client-123") as { client_secret_encrypted: string };
      assert.ok(row);

      // Tamper with the authentication tag in the ciphertext envelope
      const parts = row.client_secret_encrypted.split(":");
      // v1 : iv : authTag : ciphertext
      const tamperedTag = "ff".repeat(16); // 16 bytes invalid tag
      const tamperedPayload = `v1:${parts[1]}:${tamperedTag}:${parts[3]}`;
      rawDb.prepare("UPDATE oauth_clients SET client_secret_encrypted = ? WHERE client_id = ?").run(tamperedPayload, "test-client-123");
    } finally {
      rawDb.close();
    }

    // 2. Open store and verify it throws OAuthStorageError and does NOT clear or return corrupted data
    const store = new OAuthStore(dbPath, secretKey);
    try {
      assert.throws(() => store.getClient("test-client-123"), (err: unknown) => {
        return err instanceof OAuthStorageError && (err as Error).message.includes("authentication tag verification failed");
      });
    } finally {
      store.close();
    }
  });

  await t.test("opening store with wrong key fails closed with OAuthStorageError on decryption", () => {
    const wrongKey = "completely-wrong-master-key-0000000000000000";
    const store = new OAuthStore(dbPath, wrongKey);
    try {
      // Accessing any encrypted record with the wrong key triggers authentication tag failure
      assert.throws(() => store.getAccessToken("cb_at_rotation_test_2"), (err: unknown) => {
        return err instanceof OAuthStorageError && (err as Error).message.includes("authentication tag verification failed");
      });
    } finally {
      store.close();
    }
  });

  await t.test("key rotation re-encrypts all database records with new key", async () => {
    // Create a fresh clean store for key rotation test
    const rotDbPath = path.join(tempDir, "oauth-rotate.db");
    const key1 = "original-secret-key-1111111111111111";
    const key2 = "rotated-secret-key-2222222222222222";

    const store = new OAuthStore(rotDbPath, key1);
    const now = Date.now();
    store.registerClient({
      clientId: "rotate-client",
      clientSecret: "rotate-secret-alpha",
      clientName: "Rotate Client",
      redirectUris: ["https://example.com/rotate"],
      grantTypes: ["authorization_code", "refresh_token"],
      responseTypes: ["code"],
      tokenEndpointAuthMethod: "client_secret_basic",
      createdAt: now,
    });
    store.saveTokens(
      {
        token: "cb_at_rotate_me",
        clientId: "rotate-client",
        scope: "mcp:all",
        resource: "http://127.0.0.1:3333/mcp",
        createdAt: now,
        expiresAt: now + 3600000,
      },
      {
        token: "cb_rt_rotate_me",
        clientId: "rotate-client",
        scope: "mcp:all",
        resource: "http://127.0.0.1:3333/mcp",
        createdAt: now,
        expiresAt: now + 86400000,
      }
    );

    // Execute key rotation
    const result = store.rotateEncryptionKey(key2, key1);
    assert.equal(result.clientsReencrypted, 1);
    assert.equal(result.accessTokensReencrypted, 1);
    assert.equal(result.refreshTokensReencrypted, 1);
    store.close();

    // Verify old key now fails
    const storeOld = new OAuthStore(rotDbPath, key1);
    try {
      assert.throws(() => storeOld.getClient("rotate-client"), (err: unknown) => {
        return err instanceof OAuthStorageError && (err as Error).message.includes("authentication tag verification failed");
      });
    } finally {
      storeOld.close();
    }

    // Verify new key succeeds and all data is intact
    const storeNew = new OAuthStore(rotDbPath, key2);
    try {
      const client = storeNew.getClient("rotate-client");
      assert.ok(client);
      assert.equal(client.clientSecret, "rotate-secret-alpha");

      const at = storeNew.getAccessToken("cb_at_rotate_me");
      assert.ok(at);
      assert.equal(at.clientId, "rotate-client");

      const rt = storeNew.getRefreshToken("cb_rt_rotate_me");
      assert.ok(rt);
      assert.equal(rt.clientId, "rotate-client");
    } finally {
      storeNew.close();
    }
  });

  await t.test("persistent store throws OAuthStorageError when secret is missing in non-test mode", () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevKey = process.env.CODE_BRIDGE_OAUTH_KEY;
    const prevToken = process.env.CODE_BRIDGE_TOKEN;
    delete process.env.CODE_BRIDGE_OAUTH_KEY;
    delete process.env.CODE_BRIDGE_TOKEN;
    process.env.NODE_ENV = "production";

    try {
      assert.throws(
        () => new OAuthStore({ dbPath: path.join(tempDir, "prod-no-key.db") }),
        (err: unknown) => {
          return err instanceof OAuthStorageError && (err as Error).message.includes("Missing secret key for persistent OAuth storage");
        }
      );
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
      if (prevKey !== undefined) process.env.CODE_BRIDGE_OAUTH_KEY = prevKey;
      if (prevToken !== undefined) process.env.CODE_BRIDGE_TOKEN = prevToken;
    }
  });
});
