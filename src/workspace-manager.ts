import fs from "node:fs";
import path from "node:path";

export interface WorkspaceState {
  folders: string[];
  activeFolder: string | null;
  source: "vscode" | "fallback";
  synchronizedAt: number;
}

class WorkspaceManager {
  private fallbackFolder: string = "";
  private authorizedFolders: string[] = [];
  private activeFolder: string | null = null;
  private source: "vscode" | "fallback" = "fallback";
  private synchronizedAt: number = 0;

  /** Initialize with the fallback workspace configured via .env / environment variable. */
  public initFallback(fallbackPath: string): void {
    const resolved = path.resolve(fallbackPath);
    try {
      this.fallbackFolder = fs.realpathSync(resolved);
    } catch {
      this.fallbackFolder = resolved;
    }
    if (this.source === "fallback") {
      this.authorizedFolders = [this.fallbackFolder];
      this.activeFolder = this.fallbackFolder;
    }
  }

  /**
   * Update authorized workspaces received from VS Code extension synchronization.
   * If folders is empty, VS Code has closed all workspace folders.
   */
  public setAuthorizedWorkspaces(folders: string[], activeFolder?: string | null): void {
    const validFolders: string[] = [];
    for (const folder of folders) {
      if (!folder || typeof folder !== "string") continue;
      const resolved = path.resolve(folder);
      try {
        if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
          validFolders.push(fs.realpathSync(resolved));
        }
      } catch {
        // Skip unresolvable directory
      }
    }

    this.authorizedFolders = validFolders;
    if (activeFolder) {
      const resolvedActive = path.resolve(activeFolder);
      const canonicalActive = validFolders.find(
        (f) => f.toLowerCase() === resolvedActive.toLowerCase()
      ) || (validFolders.length > 0 ? validFolders[0] : null);
      this.activeFolder = canonicalActive;
    } else {
      this.activeFolder = validFolders.length > 0 ? validFolders[0] : null;
    }

    this.source = "vscode";
    this.synchronizedAt = Date.now();
  }

  /** Reset to the static fallback workspace from .env (used for tests and disconnects). */
  public resetToFallback(): void {
    this.authorizedFolders = this.fallbackFolder ? [this.fallbackFolder] : [];
    this.activeFolder = this.fallbackFolder || null;
    this.source = "fallback";
    this.synchronizedAt = 0;
  }

  /** Get the primary active workspace folder. Fails closed if no workspace is authorized. */
  public getWorkspace(): string {
    if (this.activeFolder) {
      return this.activeFolder;
    }
    if (this.source === "fallback" && this.fallbackFolder) {
      return this.fallbackFolder;
    }
    throw new Error("No authorized workspace folder is currently open in VS Code. Please open a project folder in VS Code.");
  }

  /** Get all currently authorized workspace folders. */
  public getWorkspaceFolders(): string[] {
    if (this.authorizedFolders.length > 0) {
      return [...this.authorizedFolders];
    }
    if (this.source === "fallback" && this.fallbackFolder) {
      return [this.fallbackFolder];
    }
    return [];
  }

  /** Check if any workspace folder is currently open and authorized. */
  public hasActiveWorkspace(): boolean {
    return Boolean(this.activeFolder || (this.source === "fallback" && this.fallbackFolder));
  }

  /** Get current synchronization source ("vscode" or "fallback"). */
  public getSource(): "vscode" | "fallback" {
    return this.source;
  }

  /** Get current synchronization timestamp. */
  public getSynchronizedAt(): number {
    return this.synchronizedAt;
  }

  /**
   * Find which authorized workspace folder contains the given absolute path.
   * Returns undefined if the path is outside all authorized workspace folders.
   */
  public findContainingFolder(targetPath: string): string | undefined {
    const resolved = path.resolve(targetPath);
    const folders = this.getWorkspaceFolders();
    for (const folder of folders) {
      const root = folder.endsWith(path.sep) ? folder : folder + path.sep;
      if (resolved === folder || resolved.startsWith(root)) {
        return folder;
      }
      if (process.platform === "win32") {
        if (
          resolved.toLowerCase() === folder.toLowerCase() ||
          resolved.toLowerCase().startsWith(root.toLowerCase())
        ) {
          return folder;
        }
      }
    }
    return undefined;
  }

  /**
   * Returns a canonical identity string for the workspace (or a specific folder within it)
   * used to cryptographically bind approval records to exact workspace instances.
   */
  public getWorkspaceIdentity(folder?: string): string {
    const target = folder || this.getWorkspace();
    return process.platform === "win32" ? target.toLowerCase() : target;
  }
}

export const workspaceManager = new WorkspaceManager();
