import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { requireApproval, type ApprovalSummary } from "./approvals.js";
import { audit } from "./audit.js";
import { config } from "./config.js";
import { editorClient } from "./editor-client.js";
import { assertReadable, assertWritable, isHiddenDirectory, isReadable } from "./policy.js";
import { assertNoSymlink, assertRegularFileOrMissing, assertWritableFilePath } from "./safety.js";
import { workspaceManager } from "./workspace-manager.js";

async function atomicWrite(target: string, content: string): Promise<void> {
  const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
    try { await fs.rename(temporary, target); }
    catch (error) {
      if (!["EPERM", "EXDEV", "EACCES"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
      await fs.copyFile(temporary, target);
    }
  } finally { await fs.rm(temporary, { force: true }).catch(() => undefined); }
}

export async function getEditorContext(): Promise<{ workspaceOpen?: boolean; activeFile?: string | null; selection?: string }> {
  const raw = (await editorClient.context()) as { workspaceOpen?: boolean; activeFile?: string | null; selection?: string };
  if (raw?.activeFile && (raw.activeFile === "[protected]" || !isReadable(raw.activeFile))) {
    return { workspaceOpen: raw.workspaceOpen, activeFile: raw.activeFile, selection: "" };
  }
  return raw ?? { workspaceOpen: false, activeFile: null, selection: "" };
}

export async function getEditorDiagnostics(): Promise<Array<{ file: string; diagnostics: unknown[] }>> {
  const raw = (await editorClient.diagnostics()) as Array<{ file: string; diagnostics: unknown[] }>;
  const filtered = Array.isArray(raw) ? raw.filter((entry) => isReadable(entry.file)) : [];
  return filtered;
}

async function walkFolder(directory: string, baseFolder: string, maxDepth: number, prefix: string = ""): Promise<string[]> {
  async function walk(dir: string, depth: number): Promise<string[]> {
    if (depth > maxDepth) return [];
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return [];
    }
    const children = await Promise.all(
      entries
        .filter(entry => !entry.isSymbolicLink() && !isHiddenDirectory(entry.name))
        .map(async entry => {
          const child = path.join(dir, entry.name);
          const relInside = path.relative(baseFolder, child);
          const displayRel = prefix ? path.join(prefix, relInside).replace(/\\/g, "/") : relInside.replace(/\\/g, "/");
          if (entry.isDirectory()) return walk(child, depth + 1);
          return isReadable(relInside) ? [displayRel] : [];
        })
    );
    return children.flat();
  }
  return walk(directory, 0);
}

export async function listFiles(relativePath: string = ".", maxDepth: number = 2): Promise<string[]> {
  const folders = workspaceManager.getWorkspaceFolders();
  if (folders.length === 0) {
    throw new Error("No authorized workspace folder is open.");
  }

  if (folders.length > 1 && (relativePath === "." || relativePath === "")) {
    const allResults: string[] = [];
    for (const folder of folders) {
      const folderName = path.basename(folder);
      const entries = await walkFolder(folder, folder, maxDepth, folderName);
      allResults.push(...entries);
    }
    return allResults.sort();
  }

  assertReadable(relativePath);
  const rootTarget = await assertNoSymlink(relativePath);
  const containingFolder = workspaceManager.findContainingFolder(rootTarget) || workspaceManager.getWorkspace();
  const folderPrefix = (folders.length > 1 && relativePath.toLowerCase().startsWith(path.basename(containingFolder).toLowerCase()))
    ? path.basename(containingFolder)
    : "";
  return (await walkFolder(rootTarget, containingFolder, maxDepth, folderPrefix)).sort();
}

export async function readFile(relativePath: string, maxChars: number = 30000): Promise<{ content: string; characters: number }> {
  assertReadable(relativePath);
  const target = await assertNoSymlink(relativePath);
  if (!(await fs.stat(target)).isFile()) throw new Error("Target must be a regular file.");
  const content = (await fs.readFile(target, "utf8")).slice(0, maxChars);
  await audit("read_file", { path: relativePath, characters: content.length });
  return { content, characters: content.length };
}

export async function searchCode(query: string, maxResults: number = 30): Promise<string[]> {
  if (!query || typeof query !== "string") throw new Error("Search query must be a non-empty string.");
  const folders = workspaceManager.getWorkspaceFolders();
  if (folders.length === 0) throw new Error("No authorized workspace folder is open.");
  const results: string[] = [];

  for (const folder of folders) {
    if (results.length >= maxResults) break;
    const isMultiRoot = folders.length > 1;
    const folderName = path.basename(folder);

    async function visit(directory: string): Promise<void> {
      if (results.length >= maxResults) return;
      let entries;
      try {
        entries = await fs.readdir(directory, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (isHiddenDirectory(entry.name) || entry.isSymbolicLink()) continue;
        const target = path.join(directory, entry.name);
        const rel = path.relative(folder, target);
        const displayRel = isMultiRoot ? `${folderName}/${rel}`.replace(/\\/g, "/") : rel.replace(/\\/g, "/");
        if (entry.isDirectory()) { await visit(target); continue; }
        if (!isReadable(rel)) continue;
        if (results.length < maxResults) {
          try {
            (await fs.readFile(target, "utf8")).split(/\r?\n/).forEach((line, i) => {
              if (line.includes(query) && results.length < maxResults) results.push(`${displayRel}:${i + 1}: ${line.trim()}`);
            });
          } catch { /* Skip binary and unreadable files. */ }
        }
      }
    }
    await visit(folder);
  }
  return results;
}

export const ALLOWED_ENV_KEYS = new Set([
  // Path & Execution
  "PATH",
  "PATHEXT",
  "COMSPEC",
  "SYSTEMROOT",
  "WINDIR",
  "SYSTEMDRIVE",
  // User & Profiles
  "USERPROFILE",
  "HOME",
  "HOMEPATH",
  "HOMEDRIVE",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "COMMONPROGRAMFILES",
  "COMMONPROGRAMFILES(X86)",
  "ALLUSERSPROFILE",
  // System / Hardware
  "OS",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
  "PROCESSOR_ARCHITEW6432",
  "PROCESSOR_IDENTIFIER",
  "PROCESSOR_LEVEL",
  "PROCESSOR_REVISION",
  // Temp dirs
  "TEMP",
  "TMP",
  "TMPDIR",
  // Locale & Terminal
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TERM",
  // Node / Build
  "NODE_ENV",
  "NODE_PATH",
  "CI",
  "NPM_CONFIG_CACHE",
  "NPM_CONFIG_PREFIX",
]);

export async function writeFile(relativePath: string, content: string, approvalId?: string): Promise<{ message: string; path: string }> {
  if (config.blockRemoteMutations) {
    throw new Error("Mutating operations are safely disabled (CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS=true). Only read operations are permitted.");
  }
  const policyResult = assertWritable(relativePath);
  assertWritableFilePath(relativePath);
  const warnings: string[] = [];
  if (policyResult.sensitive) {
    warnings.push(`Modifies sensitive project file: ${policyResult.reason}`);
  }
  const previewCap = 4000;
  let preview = content;
  if (content.length > previewCap) {
    preview = content.slice(0, previewCap) + `\n... [truncated: ${content.length - previewCap} more characters]`;
    warnings.push(`Preview truncated (${content.length} characters total). Verify full content before approving.`);
  }
  const target = await assertRegularFileOrMissing(relativePath);
  const containingFolder = workspaceManager.findContainingFolder(target) || workspaceManager.getWorkspace();
  const workspaceIdentity = workspaceManager.getWorkspaceIdentity(containingFolder);
  const summary: ApprovalSummary = {
    title: `Write file: ${relativePath}`,
    details: {
      "Target path": relativePath,
      "Workspace": containingFolder,
      "Size": `${content.length} characters (${content.split(/\r?\n/).length} lines)`,
    },
    warnings,
    preview,
  };
  await requireApproval(config.stateDir, "write_file", { relative_path: relativePath, content }, summary, approvalId, workspaceIdentity);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await atomicWrite(target, content);
  await audit("write_file", { path: relativePath, characters: content.length, workspace: containingFolder });
  try { await editorClient.applyEdit(relativePath, content); } catch { /* Optional extension */ }
  return { message: `Wrote ${relativePath}.`, path: relativePath };
}

export async function deleteFile(relativePath: string, approvalId?: string): Promise<{ message: string; path: string }> {
  if (config.blockRemoteMutations) {
    throw new Error("Mutating operations are safely disabled (CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS=true). Only read operations are permitted.");
  }
  const policyResult = assertWritable(relativePath);
  assertWritableFilePath(relativePath);
  const target = await assertNoSymlink(relativePath);
  const containingFolder = workspaceManager.findContainingFolder(target) || workspaceManager.getWorkspace();
  const workspaceIdentity = workspaceManager.getWorkspaceIdentity(containingFolder);
  let stat;
  try {
    stat = await fs.lstat(target);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`File does not exist: ${relativePath}`);
    }
    throw err;
  }
  if (!stat.isFile()) throw new Error("Target to delete must be a regular file.");

  const warnings: string[] = [
    "DESTRUCTIVE ACTION: Permanently deletes this file from the workspace.",
  ];
  if (policyResult.sensitive) {
    warnings.push(`Deletes sensitive project file: ${policyResult.reason}`);
  }
  const summary: ApprovalSummary = {
    title: `Delete file: ${relativePath}`,
    details: {
      "Target path": relativePath,
      "Workspace": containingFolder,
      "File size": `${stat.size} bytes`,
    },
    warnings,
    preview: `Delete file ${relativePath} (${stat.size} bytes)`,
  };
  await requireApproval(config.stateDir, "delete_file", { relative_path: relativePath }, summary, approvalId, workspaceIdentity);
  await fs.unlink(target);
  await audit("delete_file", { path: relativePath, size: stat.size, workspace: containingFolder });
  try { await editorClient.applyEdit(relativePath, ""); } catch { /* Optional extension */ }
  return { message: `Deleted ${relativePath}.`, path: relativePath };
}

export const ALLOWED_COMMANDS = ["npm test", "npm run build", "npm run lint", "npm run typecheck"] as const;
export type AllowedCommand = typeof ALLOWED_COMMANDS[number];

export async function runProjectCommand(
  command: AllowedCommand,
  approvalId?: string
): Promise<{ stdout: string; stderr: string; code: number; timedOut: boolean; outputTruncated: boolean }> {
  if (config.blockRemoteMutations) {
    throw new Error("Command execution is safely disabled (CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS=true). Only read operations are permitted.");
  }
  if (!ALLOWED_COMMANDS.includes(command)) {
    throw new Error(`Command not allowed: ${command}. Allowed commands: ${ALLOWED_COMMANDS.join(", ")}`);
  }
  const activeWorkspace = workspaceManager.getWorkspace();
  const workspaceIdentity = workspaceManager.getWorkspaceIdentity(activeWorkspace);
  const summary: ApprovalSummary = {
    title: `Run command: ${command}`,
    details: {
      "Command": command,
      "Working directory": activeWorkspace,
    },
    warnings: ["Executes child process command in the project environment."],
    preview: command,
  };
  await requireApproval(config.stateDir, "run_project_command", { command }, summary, approvalId, workspaceIdentity);
  await audit("run_project_command", { command, workspace: activeWorkspace });
  const { execFile } = await import("node:child_process");
  const npmArguments = command.split(" ").slice(1);
  const executable = process.platform === "win32" ? process.env.ComSpec ?? "cmd.exe" : "npm";
  const arguments_ = process.platform === "win32" ? ["/d", "/s", "/c", "npm.cmd", ...npmArguments] : npmArguments;
  const childEnv: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && ALLOWED_ENV_KEYS.has(key.toUpperCase()) && !key.toUpperCase().startsWith("CODE_BRIDGE_")) {
      childEnv[key] = value;
    }
  }
  return new Promise((resolve) =>
    execFile(
      executable,
      arguments_,
      { cwd: activeWorkspace, env: childEnv, timeout: 120_000, maxBuffer: 1_000_000, windowsHide: true },
      (error, stdout, stderr) =>
        resolve({
          stdout: String(stdout).slice(0, 500_000),
          stderr: String(stderr).slice(0, 500_000),
          code: error ? Number((error as { code?: number }).code ?? 1) : 0,
          timedOut: Boolean((error as { killed?: boolean; signal?: string } | null)?.killed || (error as { signal?: string } | null)?.signal === "SIGTERM"),
          outputTruncated: (error as { code?: string } | null)?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
        })
    )
  );
}
