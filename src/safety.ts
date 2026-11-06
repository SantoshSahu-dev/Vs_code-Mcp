import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { config } from "./config.js";
import { workspaceManager } from "./workspace-manager.js";


function isWithinBase(candidate: string, base: string): boolean {
  const root = base.endsWith(path.sep) ? base : base + path.sep;
  if (process.platform === "win32") {
    const cLower = candidate.toLowerCase();
    const rLower = root.toLowerCase();
    const bLower = base.toLowerCase();
    return cLower === bLower || cLower.startsWith(rLower);
  }
  return candidate === base || candidate.startsWith(root);
}

export function safePath(relativePath: string, explicitBase?: string): string {
  if (!relativePath || relativePath.includes("\0") || relativePath.includes(":") || relativePath.startsWith("\\\\")) {
    throw new Error("Invalid workspace path.");
  }
  if (path.isAbsolute(relativePath)) {
    throw new Error("Use a path relative to the approved workspace.");
  }

  if (explicitBase) {
    const resolved = path.resolve(explicitBase, relativePath);
    if (!isWithinBase(resolved, explicitBase)) {
      throw new Error("Path escapes the approved workspace.");
    }
    return resolved;
  }

  const folders = workspaceManager.getWorkspaceFolders();
  if (folders.length === 0) {
    throw new Error("No authorized workspace folder is open.");
  }

  if (folders.length > 1) {
    const segments = relativePath.split(/[\\/]+/).filter(Boolean);
    if (segments.length > 0) {
      const targetFolderPrefix = segments[0].toLowerCase();
      for (const folder of folders) {
        if (path.basename(folder).toLowerCase() === targetFolderPrefix) {
          const remainder = segments.slice(1).join(path.sep);
          const resolved = remainder ? path.resolve(folder, remainder) : folder;
          if (isWithinBase(resolved, folder)) {
            return resolved;
          }
        }
      }
    }
  }

  const activeWorkspace = workspaceManager.getWorkspace();
  const primaryResolved = path.resolve(activeWorkspace, relativePath);
  if (isWithinBase(primaryResolved, activeWorkspace)) {
    return primaryResolved;
  }

  throw new Error("Path escapes the approved workspace.");
}

/** Secret-bearing configuration is intentionally not mutable through an AI bridge. */
export function assertWritableFilePath(relativePath: string): string {
  const target = safePath(relativePath);
  const name = path.basename(target).toLowerCase();
  if (name === ".env" || name.startsWith(".env.") || [".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"].includes(name) || name.endsWith(".pem") || name.endsWith(".key")) {
    throw new Error("Writing credential or secret configuration files is not allowed.");
  }
  return target;
}

/** Reject symlinks in every existing path component so filesystem calls cannot escape the workspace. */
export async function assertNoSymlink(relativePath: string): Promise<string> {
  const target = safePath(relativePath);
  const baseWorkspace = workspaceManager.findContainingFolder(target) || workspaceManager.getWorkspace();
  const rel = path.relative(baseWorkspace, target);
  let current = baseWorkspace;
  for (const component of rel ? rel.split(path.sep) : []) {
    current = path.join(current, component);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) throw new Error("Symlinks are not allowed in Code Bridge paths.");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") break;
      throw error;
    }
  }
  return target;
}

export async function assertRegularFileOrMissing(relativePath: string): Promise<string> {
  const target = await assertNoSymlink(relativePath);
  try {
    const stat = await fs.lstat(target);
    if (!stat.isFile()) throw new Error("Target must be a regular file.");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return target;
}


export function constantTimeTokenMatch(value: string | undefined): boolean {
  if (!value) return false;
  const left = Buffer.from(value);
  const right = Buffer.from(config.token);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
