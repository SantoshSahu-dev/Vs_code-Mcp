import * as http from "node:http";
import * as crypto from "node:crypto";
import * as path from "node:path";
import * as vscode from "vscode";

const MAX_BODY_BYTES = 1_000_000;

const SECRET_DIRECTORIES = new Set([".git", ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".code-bridge"]);
const GENERATED_DIRECTORIES = new Set(["node_modules", "dist"]);
const SECRET_NAMES = new Set([
  ".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".htpasswd",
  "credentials", "credentials.json", "secrets.json", "secrets.yml", "secrets.yaml",
]);
const SECRET_SUFFIXES = [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx"];
const ENV_TEMPLATE = /^\.env\.(example|sample|template|dist)$/;

function isProtectedPath(relativePath: string): boolean {
  const segments = relativePath.split(/[\\/]+/).map(s => s.toLowerCase().replace(/[. ]+$/, "")).filter(Boolean);
  const name = segments[segments.length - 1] ?? "";
  if (segments.some(s => SECRET_DIRECTORIES.has(s))) return true;
  if (process.env.CODE_BRIDGE_ALLOW_READ_GENERATED !== "true" && segments.some(s => GENERATED_DIRECTORIES.has(s))) return true;
  if (ENV_TEMPLATE.test(name)) return false;
  if (name.startsWith(".env") || name.endsWith(".env")) return true;
  if (SECRET_NAMES.has(name)) return true;
  if (SECRET_SUFFIXES.some(s => name.endsWith(s))) return true;
  return /^id_(rsa|dsa|ecdsa|ed25519)/.test(name) && !name.endsWith(".pub");
}

function send(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

function getAuthorizedFolders(): string[] {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return [];
  return folders.map(f => path.resolve(f.uri.fsPath));
}

function getActiveFolder(): string | null {
  const activeDoc = vscode.window.activeTextEditor?.document.uri;
  if (activeDoc) {
    const folder = vscode.workspace.getWorkspaceFolder(activeDoc);
    if (folder) return path.resolve(folder.uri.fsPath);
  }
  const folders = getAuthorizedFolders();
  return folders.length > 0 ? folders[0] : null;
}

function workspaceRoot(): string {
  const active = getActiveFolder();
  if (!active) throw new Error("Open a project folder in VS Code first.");
  return active;
}

function relative(uri: vscode.Uri): string {
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  const root = folder ? path.resolve(folder.uri.fsPath) : workspaceRoot();
  const value = path.relative(root, uri.fsPath);
  if (!value || value.startsWith("..") || path.isAbsolute(value)) throw new Error("File is outside the workspace.");
  const folders = getAuthorizedFolders();
  if (folders.length > 1 && folder) {
    return path.join(path.basename(root), value).replace(/\\/g, "/");
  }
  return value.replace(/\\/g, "/");
}

function safeUri(relativePath: string): vscode.Uri {
  if (!relativePath || relativePath.includes("\0") || relativePath.includes(":") || path.isAbsolute(relativePath)) {
    throw new Error("Invalid workspace path.");
  }
  if (isProtectedPath(relativePath)) {
    throw new Error("Writing to credential or secret configuration files is not allowed.");
  }
  const folders = getAuthorizedFolders();
  if (folders.length === 0) throw new Error("Open a project folder in VS Code first.");

  if (folders.length > 1) {
    const segments = relativePath.split(/[\\/]+/).filter(Boolean);
    if (segments.length > 0) {
      const prefix = segments[0].toLowerCase();
      for (const folder of folders) {
        if (path.basename(folder).toLowerCase() === prefix) {
          const remainder = segments.slice(1).join(path.sep);
          const target = remainder ? path.resolve(folder, remainder) : folder;
          if (target.startsWith(folder + path.sep) || target === folder) {
            return vscode.Uri.file(target);
          }
        }
      }
    }
  }

  const root = workspaceRoot();
  const target = path.resolve(root, relativePath);
  if (!target.startsWith(root + path.sep)) throw new Error("File is outside the workspace.");
  return vscode.Uri.file(target);
}

function validPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function tokenMatches(value: string | string[] | undefined, expected: string | undefined): boolean {
  if (!expected || typeof value !== "string") return false;
  const left = Buffer.from(value);
  const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function requestedWorkspaceMatches(value: string | string[] | undefined): boolean {
  if (typeof value !== "string") return false;
  const folders = getAuthorizedFolders();
  if (folders.length === 0) return false;
  try {
    const requested = path.resolve(value);
    return folders.some(folder => {
      if (process.platform === "win32") {
        return requested.toLowerCase() === folder.toLowerCase();
      }
      return requested === folder;
    });
  } catch {
    return false;
  }
}

function syncWithServer(serverPort: number, token?: string, retryCount: number = 0): void {
  const secret = token || process.env.CODE_BRIDGE_TOKEN || vscode.workspace.getConfiguration("codeBridge").get<string>("token");
  if (!secret) return;
  const folders = getAuthorizedFolders();
  const activeFolder = getActiveFolder();
  const payload = JSON.stringify({ folders, activeFolder });
  try {
    const req = http.request({
      hostname: "127.0.0.1",
      port: serverPort,
      path: "/api/workspace/sync",
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-code-bridge-token": secret,
        "content-length": Buffer.byteLength(payload),
      },
      timeout: 3000,
    });
    req.on("error", () => {
      // If server is not listening yet, retry once after a short delay
      if (retryCount < 2) {
        setTimeout(() => syncWithServer(serverPort, token, retryCount + 1), 2500);
      }
    });
    req.on("response", (res) => {
      res.resume();
    });
    req.write(payload);
    req.end();
  } catch {
    /* Ignore synchronous dispatch errors */
  }
}

export function activate(context: vscode.ExtensionContext) {
  const settings = vscode.workspace.getConfiguration("codeBridge");
  const port = settings.get<number>("port") ?? Number(process.env.CODE_BRIDGE_EDITOR_PORT ?? 3334);
  const serverPort = settings.get<number>("serverPort") ?? Number(process.env.PORT ?? 3333);
  if (!validPort(port)) {
    vscode.window.showErrorMessage("Code Bridge: configured extension port is invalid.");
    return;
  }
  const token = process.env.CODE_BRIDGE_TOKEN || settings.get<string>("token");

  // Synchronize workspace immediately and on changes
  syncWithServer(serverPort, token);
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => syncWithServer(serverPort, token)));
  context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(() => syncWithServer(serverPort, token)));

  const bridge = http.createServer(async (req, res) => {
    if (!tokenMatches(req.headers["x-code-bridge-token"], token)) {
      return send(res, 401, { error: "Missing or invalid credentials" });
    }
    if (req.headers.origin) {
      return send(res, 403, { error: "Cross-origin requests are not allowed" });
    }
    try {
      if (req.method === "GET" && req.url === "/workspaces") {
        return send(res, 200, {
          folders: getAuthorizedFolders(),
          activeFolder: getActiveFolder(),
          workspaceOpen: Boolean(vscode.workspace.workspaceFolders?.length),
        });
      }
      if (!requestedWorkspaceMatches(req.headers["x-code-bridge-workspace"])) {
        return send(res, 403, { error: "The active VS Code workspace does not match Code Bridge." });
      }
      if (req.method === "GET" && req.url === "/context") {
        const editor = vscode.window.activeTextEditor;
        let activeFile: string | null = null;
        let selection = "";
        if (editor) {
          try {
            const rel = relative(editor.document.uri);
            if (isProtectedPath(rel)) {
              activeFile = "[protected]";
              selection = "";
            } else {
              activeFile = rel;
              selection = editor.document.getText(editor.selection);
            }
          } catch {
            activeFile = null;
            selection = "";
          }
        }
        return send(res, 200, {
          workspaceOpen: Boolean(vscode.workspace.workspaceFolders?.length),
          activeFile,
          selection,
          folders: getAuthorizedFolders(),
          activeFolder: getActiveFolder(),
        });
      }
      if (req.method === "GET" && req.url === "/diagnostics") {
        const diagnostics = vscode.languages.getDiagnostics().flatMap(([uri, entries]) => {
          try {
            const file = relative(uri);
            if (isProtectedPath(file)) return [];
            return [{
              file,
              diagnostics: entries.map(d => ({
                message: d.message,
                severity: vscode.DiagnosticSeverity[d.severity],
                line: d.range.start.line + 1,
                column: d.range.start.character + 1,
              })),
            }];
          } catch {
            return [];
          }
        });
        return send(res, 200, diagnostics);
      }
      if (req.method === "POST" && req.url === "/apply-edit") {
        if (req.headers["content-type"]?.split(";")[0] !== "application/json") {
          return send(res, 415, { error: "Content-Type must be application/json" });
        }
        let raw = "";
        let bytes = 0;
        for await (const piece of req) {
          bytes += Buffer.byteLength(piece);
          if (bytes > MAX_BODY_BYTES) return send(res, 413, { error: "Request body is too large" });
          raw += piece;
        }
        const { relativePath, content } = JSON.parse(raw) as { relativePath?: unknown; content?: unknown };
        if (typeof relativePath !== "string" || typeof content !== "string") {
          throw new Error("relativePath and content must be strings.");
        }
        const uri = safeUri(relativePath);
        const edit = new vscode.WorkspaceEdit();
        edit.replace(uri, new vscode.Range(0, 0, Number.MAX_SAFE_INTEGER, 0), content);
        if (!await vscode.workspace.applyEdit(edit)) throw new Error("VS Code rejected edit.");
        await vscode.workspace.save(uri);
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: "Unknown endpoint" });
    } catch (error) {
      return send(res, 400, { error: error instanceof Error ? error.message : "Invalid request" });
    }
  });

  bridge.on("error", error => vscode.window.showErrorMessage(`Code Bridge extension failed to listen on 127.0.0.1:${port}: ${error.message}`));
  bridge.listen(port, "127.0.0.1");
  context.subscriptions.push({ dispose: () => bridge.close() });
  context.subscriptions.push(vscode.commands.registerCommand("codeBridge.showStatus", () => vscode.window.showInformationMessage(`Code Bridge extension listening on 127.0.0.1:${port}`)));
}

export function deactivate() {}
