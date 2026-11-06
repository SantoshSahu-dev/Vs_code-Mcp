import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export class OAuthStorageError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "OAuthStorageError";
  }
}

export interface OAuthClient {
  clientId: string;
  clientSecret?: string;
  clientName?: string;
  redirectUris: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic" | "none";
  createdAt: number;
}

export interface AccessTokenEntry {
  token: string;
  refreshToken?: string;
  clientId: string;
  scope: string;
  resource?: string;
  createdAt: number;
  expiresAt: number;
}

export interface RefreshTokenEntry {
  token: string;
  accessToken?: string;
  clientId: string;
  scope: string;
  resource?: string;
  createdAt: number;
  expiresAt: number;
}

export interface OAuthStoreOptions {
  dbPath?: string;
  secret?: string;
}

export function tokenHash(token: string): string {
  if (!token || typeof token !== "string") {
    throw new OAuthStorageError("Invalid token provided for hashing");
  }
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}

export class OAuthStore {
  private db: DatabaseSync;
  private encryptionKey: Buffer;
  private keySalt: string;
  private keyVersion = "v1";

  constructor(optionsOrDbPath?: OAuthStoreOptions | string, maybeSecret?: string) {
    const options: OAuthStoreOptions = typeof optionsOrDbPath === "string"
      ? { dbPath: optionsOrDbPath, secret: maybeSecret }
      : (optionsOrDbPath || {});
    const dbPath = options.dbPath || (process.env.CODE_BRIDGE_OAUTH_DB ? process.env.CODE_BRIDGE_OAUTH_DB : ":memory:");
    let rawSecret = options.secret || process.env.CODE_BRIDGE_OAUTH_KEY || process.env.CODE_BRIDGE_TOKEN;
    if (!rawSecret) {
      if (dbPath !== ":memory:" && process.env.NODE_ENV !== "test") {
        throw new OAuthStorageError("Missing secret key for persistent OAuth storage. Set CODE_BRIDGE_OAUTH_KEY or CODE_BRIDGE_TOKEN.");
      }
      rawSecret = "default-fallback-in-memory-test-secret-key-0123456789";
    }

    if (dbPath !== ":memory:") {
      const dir = path.dirname(path.resolve(dbPath));
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
    }

    try {
      this.db = new DatabaseSync(dbPath);
    } catch (err) {
      throw new OAuthStorageError(`Failed to open SQLite OAuth database at ${dbPath}: ${(err as Error).message}`, err);
    }

    if (dbPath !== ":memory:" && fs.existsSync(dbPath)) {
      try {
        fs.chmodSync(dbPath, 0o600);
      } catch {
        // Windows NTFS file permissions inherit from user profile directory.
      }
    }

    this.initPragmas();
    this.initTables();
    this.keySalt = this.initKeySalt();
    this.encryptionKey = this.deriveKey(rawSecret, this.keySalt);
  }

  private initPragmas(): void {
    try {
      this.db.exec("PRAGMA journal_mode = WAL;");
      this.db.exec("PRAGMA synchronous = NORMAL;");
      this.db.exec("PRAGMA foreign_keys = ON;");
    } catch (err) {
      throw new OAuthStorageError("Failed to configure SQLite pragmas", err);
    }
  }

  private initTables(): void {
    const schema = `
      CREATE TABLE IF NOT EXISTS oauth_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret_encrypted TEXT,
        client_name TEXT NOT NULL,
        redirect_uris_json TEXT NOT NULL,
        grant_types_json TEXT NOT NULL,
        response_types_json TEXT NOT NULL,
        token_endpoint_auth_method TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        token_hash TEXT PRIMARY KEY,
        token_encrypted TEXT NOT NULL,
        refresh_token_hash TEXT,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        token_encrypted TEXT NOT NULL,
        access_token_hash TEXT,
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        resource TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_access_expires ON oauth_access_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_refresh_expires ON oauth_refresh_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_access_client ON oauth_access_tokens(client_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_client ON oauth_refresh_tokens(client_id);
    `;
    try {
      this.db.exec(schema);
    } catch (err) {
      throw new OAuthStorageError("Failed to initialize SQLite tables", err);
    }
  }

  private initKeySalt(): string {
    const getStmt = this.db.prepare("SELECT value FROM oauth_metadata WHERE key = 'key_salt'");
    const row = getStmt.get() as { value?: string } | undefined;
    if (row?.value) {
      return row.value;
    }
    const newSalt = crypto.randomBytes(16).toString("hex");
    const insertStmt = this.db.prepare("INSERT INTO oauth_metadata (key, value) VALUES ('key_salt', ?)");
    insertStmt.run(newSalt);
    return newSalt;
  }

  private deriveKey(secret: string, salt: string): Buffer {
    return Buffer.from(crypto.hkdfSync("sha256", secret, salt, "code-bridge-oauth-storage-v1", 32));
  }

  private encrypt(plaintext: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.encryptionKey, iv);
    let ciphertext = cipher.update(plaintext, "utf8", "hex");
    ciphertext += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");
    return `${this.keyVersion}:${iv.toString("hex")}:${tag}:${ciphertext}`;
  }

  private decryptWithKey(encrypted: string, key: Buffer): string {
    const parts = encrypted.split(":");
    if (parts.length !== 4 || parts[0] !== "v1") {
      throw new OAuthStorageError("Invalid encrypted payload format or unsupported version");
    }
    const iv = Buffer.from(parts[1], "hex");
    const tag = Buffer.from(parts[2], "hex");
    const ciphertext = parts[3];

    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      let plaintext = decipher.update(ciphertext, "hex", "utf8");
      plaintext += decipher.final("utf8");
      return plaintext;
    } catch (err) {
      throw new OAuthStorageError("Decryption failed: authentication tag verification failed or key mismatch", err);
    }
  }

  private decrypt(encrypted: string): string {
    return this.decryptWithKey(encrypted, this.encryptionKey);
  }

  public registerClient(client: OAuthClient): void {
    const encryptedSecret = client.clientSecret ? this.encrypt(client.clientSecret) : null;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO oauth_clients (
        client_id, client_secret_encrypted, client_name, redirect_uris_json,
        grant_types_json, response_types_json, token_endpoint_auth_method, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      client.clientId,
      encryptedSecret,
      client.clientName || "Dynamic Client",
      JSON.stringify(client.redirectUris || []),
      JSON.stringify(client.grantTypes || ["authorization_code", "refresh_token"]),
      JSON.stringify(client.responseTypes || ["code"]),
      client.tokenEndpointAuthMethod || "none",
      client.createdAt || Date.now()
    );
  }

  public getClient(clientId: string): OAuthClient | undefined {
    if (!clientId) return undefined;
    const stmt = this.db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?");
    const row = stmt.get(clientId) as {
      client_id: string;
      client_secret_encrypted: string | null;
      client_name: string;
      redirect_uris_json: string;
      grant_types_json: string;
      response_types_json: string;
      token_endpoint_auth_method: string;
      created_at: number;
    } | undefined;

    if (!row) return undefined;

    let clientSecret: string | undefined;
    if (row.client_secret_encrypted) {
      clientSecret = this.decrypt(row.client_secret_encrypted);
    }

    return {
      clientId: row.client_id,
      clientSecret,
      clientName: row.client_name,
      redirectUris: JSON.parse(row.redirect_uris_json),
      grantTypes: JSON.parse(row.grant_types_json),
      responseTypes: JSON.parse(row.response_types_json),
      tokenEndpointAuthMethod: row.token_endpoint_auth_method as any,
      createdAt: row.created_at,
    };
  }

  public saveTokens(access: AccessTokenEntry, refresh: RefreshTokenEntry): void {
    const accessHash = tokenHash(access.token);
    const refreshHash = tokenHash(refresh.token);

    const encAccess = this.encrypt(access.token);
    const encRefresh = this.encrypt(refresh.token);

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const insertAccess = this.db.prepare(`
        INSERT OR REPLACE INTO oauth_access_tokens (
          token_hash, token_encrypted, refresh_token_hash, client_id, scope, resource, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      insertAccess.run(
        accessHash,
        encAccess,
        refreshHash,
        access.clientId,
        access.scope,
        access.resource || null,
        access.createdAt,
        access.expiresAt
      );

      const insertRefresh = this.db.prepare(`
        INSERT OR REPLACE INTO oauth_refresh_tokens (
          token_hash, token_encrypted, access_token_hash, client_id, scope, resource, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      insertRefresh.run(
        refreshHash,
        encRefresh,
        accessHash,
        refresh.clientId,
        refresh.scope,
        refresh.resource || null,
        refresh.createdAt,
        refresh.expiresAt
      );

      this.db.exec("COMMIT;");
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw new OAuthStorageError("Failed to save tokens transactionally", err);
    }
  }

  public insertAccessToken(access: AccessTokenEntry): void {
    const accessHash = tokenHash(access.token);
    const encAccess = this.encrypt(access.token);
    const refreshHash = access.refreshToken ? tokenHash(access.refreshToken) : null;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO oauth_access_tokens (
        token_hash, token_encrypted, refresh_token_hash, client_id, scope, resource, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      accessHash,
      encAccess,
      refreshHash,
      access.clientId,
      access.scope,
      access.resource || null,
      access.createdAt,
      access.expiresAt
    );
  }

  public insertRefreshToken(refresh: RefreshTokenEntry): void {
    const refreshHash = tokenHash(refresh.token);
    const encRefresh = this.encrypt(refresh.token);
    const accessHash = refresh.accessToken ? tokenHash(refresh.accessToken) : null;
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO oauth_refresh_tokens (
        token_hash, token_encrypted, access_token_hash, client_id, scope, resource, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      refreshHash,
      encRefresh,
      accessHash,
      refresh.clientId,
      refresh.scope,
      refresh.resource || null,
      refresh.createdAt,
      refresh.expiresAt
    );
  }

  public getAccessToken(token: string): AccessTokenEntry | undefined {
    if (!token) return undefined;
    const hash = tokenHash(token);
    const stmt = this.db.prepare("SELECT * FROM oauth_access_tokens WHERE token_hash = ?");
    const row = stmt.get(hash) as {
      token_hash: string;
      token_encrypted: string;
      refresh_token_hash: string | null;
      client_id: string;
      scope: string;
      resource: string | null;
      created_at: number;
      expires_at: number;
    } | undefined;

    if (!row) return undefined;
    const decryptedToken = this.decrypt(row.token_encrypted);

    return {
      token: decryptedToken,
      refreshToken: row.refresh_token_hash || undefined,
      clientId: row.client_id,
      scope: row.scope,
      resource: row.resource || undefined,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    };
  }

  public getRefreshToken(token: string): RefreshTokenEntry | undefined {
    if (!token) return undefined;
    const hash = tokenHash(token);
    const stmt = this.db.prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?");
    const row = stmt.get(hash) as {
      token_hash: string;
      token_encrypted: string;
      access_token_hash: string | null;
      client_id: string;
      scope: string;
      resource: string | null;
      created_at: number;
      expires_at: number;
    } | undefined;

    if (!row) return undefined;
    const decryptedToken = this.decrypt(row.token_encrypted);

    return {
      token: decryptedToken,
      accessToken: row.access_token_hash || undefined,
      clientId: row.client_id,
      scope: row.scope,
      resource: row.resource || undefined,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    };
  }

  public rotateRefreshToken(
    oldRefreshToken: string,
    newAccess: AccessTokenEntry,
    newRefresh: RefreshTokenEntry
  ): boolean {
    if (!oldRefreshToken) return false;
    const oldRefreshHash = tokenHash(oldRefreshToken);

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const getOld = this.db.prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?");
      const oldRow = getOld.get(oldRefreshHash) as {
        token_hash: string;
        access_token_hash: string | null;
        expires_at: number;
      } | undefined;

      if (!oldRow) {
        this.db.exec("ROLLBACK;");
        return false;
      }

      if (Date.now() > oldRow.expires_at) {
        this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?").run(oldRefreshHash);
        if (oldRow.access_token_hash) {
          this.db.prepare("DELETE FROM oauth_access_tokens WHERE token_hash = ?").run(oldRow.access_token_hash);
        }
        this.db.exec("COMMIT;");
        return false;
      }

      // Delete consumed old refresh token and old access token
      this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?").run(oldRefreshHash);
      if (oldRow.access_token_hash) {
        this.db.prepare("DELETE FROM oauth_access_tokens WHERE token_hash = ?").run(oldRow.access_token_hash);
      }

      // Insert new token pair
      const newAccessHash = tokenHash(newAccess.token);
      const newRefreshHash = tokenHash(newRefresh.token);
      const encAccess = this.encrypt(newAccess.token);
      const encRefresh = this.encrypt(newRefresh.token);

      this.db.prepare(`
        INSERT INTO oauth_access_tokens (
          token_hash, token_encrypted, refresh_token_hash, client_id, scope, resource, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        newAccessHash,
        encAccess,
        newRefreshHash,
        newAccess.clientId,
        newAccess.scope,
        newAccess.resource || null,
        newAccess.createdAt,
        newAccess.expiresAt
      );

      this.db.prepare(`
        INSERT INTO oauth_refresh_tokens (
          token_hash, token_encrypted, access_token_hash, client_id, scope, resource, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        newRefreshHash,
        encRefresh,
        newAccessHash,
        newRefresh.clientId,
        newRefresh.scope,
        newRefresh.resource || null,
        newRefresh.createdAt,
        newRefresh.expiresAt
      );

      this.db.exec("COMMIT;");
      return true;
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw new OAuthStorageError("Failed to rotate refresh token transactionally", err);
    }
  }

  public revokeOAuthToken(token: string): boolean {
    if (!token) return false;
    const hash = tokenHash(token);
    let revoked = false;

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const accessRow = this.db.prepare("SELECT * FROM oauth_access_tokens WHERE token_hash = ?").get(hash) as {
        refresh_token_hash: string | null;
      } | undefined;

      if (accessRow) {
        this.db.prepare("DELETE FROM oauth_access_tokens WHERE token_hash = ?").run(hash);
        if (accessRow.refresh_token_hash) {
          this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?").run(accessRow.refresh_token_hash);
        }
        revoked = true;
      }

      const refreshRow = this.db.prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?").get(hash) as {
        access_token_hash: string | null;
      } | undefined;

      if (refreshRow) {
        this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?").run(hash);
        if (refreshRow.access_token_hash) {
          this.db.prepare("DELETE FROM oauth_access_tokens WHERE token_hash = ?").run(refreshRow.access_token_hash);
        }
        revoked = true;
      }

      this.db.exec("COMMIT;");
      return revoked;
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw new OAuthStorageError("Failed to revoke token transactionally", err);
    }
  }

  public pruneExpiredTokens(): { expiredAccess: number; expiredRefresh: number } {
    const now = Date.now();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const resAccess = this.db.prepare("DELETE FROM oauth_access_tokens WHERE expires_at < ?").run(now);
      const resRefresh = this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE expires_at < ?").run(now);
      this.db.exec("COMMIT;");
      return {
        expiredAccess: Number(resAccess.changes),
        expiredRefresh: Number(resRefresh.changes),
      };
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw new OAuthStorageError("Failed to prune expired tokens", err);
    }
  }

  public rotateEncryptionKey(newSecret: string, oldSecret?: string): { clientsReencrypted: number; accessTokensReencrypted: number; refreshTokensReencrypted: number } {
    const activeOldKey = oldSecret ? this.deriveKey(oldSecret, this.keySalt) : this.encryptionKey;
    const newKey = this.deriveKey(newSecret, this.keySalt);

    this.db.exec("BEGIN IMMEDIATE;");
    try {
      // 1. Re-encrypt clients
      const clients = this.db.prepare("SELECT client_id, client_secret_encrypted FROM oauth_clients WHERE client_secret_encrypted IS NOT NULL").all() as Array<{
        client_id: string;
        client_secret_encrypted: string;
      }>;
      const updateClient = this.db.prepare("UPDATE oauth_clients SET client_secret_encrypted = ? WHERE client_id = ?");
      for (const client of clients) {
        const decrypted = this.decryptWithKey(client.client_secret_encrypted, activeOldKey);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", newKey, iv);
        let enc = cipher.update(decrypted, "utf8", "hex");
        enc += cipher.final("hex");
        const tag = cipher.getAuthTag().toString("hex");
        const reEncrypted = `${this.keyVersion}:${iv.toString("hex")}:${tag}:${enc}`;
        updateClient.run(reEncrypted, client.client_id);
      }

      // 2. Re-encrypt access tokens
      const accessTokens = this.db.prepare("SELECT token_hash, token_encrypted FROM oauth_access_tokens").all() as Array<{
        token_hash: string;
        token_encrypted: string;
      }>;
      const updateAccess = this.db.prepare("UPDATE oauth_access_tokens SET token_encrypted = ? WHERE token_hash = ?");
      for (const at of accessTokens) {
        const decrypted = this.decryptWithKey(at.token_encrypted, activeOldKey);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", newKey, iv);
        let enc = cipher.update(decrypted, "utf8", "hex");
        enc += cipher.final("hex");
        const tag = cipher.getAuthTag().toString("hex");
        const reEncrypted = `${this.keyVersion}:${iv.toString("hex")}:${tag}:${enc}`;
        updateAccess.run(reEncrypted, at.token_hash);
      }

      // 3. Re-encrypt refresh tokens
      const refreshTokens = this.db.prepare("SELECT token_hash, token_encrypted FROM oauth_refresh_tokens").all() as Array<{
        token_hash: string;
        token_encrypted: string;
      }>;
      const updateRefresh = this.db.prepare("UPDATE oauth_refresh_tokens SET token_encrypted = ? WHERE token_hash = ?");
      for (const rt of refreshTokens) {
        const decrypted = this.decryptWithKey(rt.token_encrypted, activeOldKey);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", newKey, iv);
        let enc = cipher.update(decrypted, "utf8", "hex");
        enc += cipher.final("hex");
        const tag = cipher.getAuthTag().toString("hex");
        const reEncrypted = `${this.keyVersion}:${iv.toString("hex")}:${tag}:${enc}`;
        updateRefresh.run(reEncrypted, rt.token_hash);
      }

      this.db.exec("COMMIT;");
      this.encryptionKey = newKey;
      return {
        clientsReencrypted: clients.length,
        accessTokensReencrypted: accessTokens.length,
        refreshTokensReencrypted: refreshTokens.length,
      };
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw new OAuthStorageError("Failed to rotate encryption key", err);
    }
  }

  public getStats(): { clientCount: number; activeAccessCount: number; activeRefreshCount: number } {
    const clients = (this.db.prepare("SELECT count(*) as c FROM oauth_clients").get() as { c: number }).c;
    const access = (this.db.prepare("SELECT count(*) as c FROM oauth_access_tokens WHERE expires_at > ?").get(Date.now()) as { c: number }).c;
    const refresh = (this.db.prepare("SELECT count(*) as c FROM oauth_refresh_tokens WHERE expires_at > ?").get(Date.now()) as { c: number }).c;
    return {
      clientCount: Number(clients),
      activeAccessCount: Number(access),
      activeRefreshCount: Number(refresh),
    };
  }

  public clear(): void {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db.exec("DELETE FROM oauth_access_tokens;");
      this.db.exec("DELETE FROM oauth_refresh_tokens;");
      this.db.exec("DELETE FROM oauth_clients;");
      this.db.exec("COMMIT;");
    } catch (err) {
      this.db.exec("ROLLBACK;");
      throw new OAuthStorageError("Failed to clear database", err);
    }
  }

  public close(): void {
    try {
      this.db.close();
    } catch {
      // Ignored if already closed
    }
  }
}
