import { config } from "./config.js";
import { workspaceManager } from "./workspace-manager.js";

async function editor(path: string, init?: RequestInit): Promise<unknown> {
  let response: Response;
  const sendRequest = async (ws: string) => {
    return fetch(`http://127.0.0.1:${config.editorPort}${path}`, {
      ...init,
      headers: { "content-type": "application/json", "x-code-bridge-token": config.token, "x-code-bridge-workspace": ws, ...(init?.headers ?? {}) },
      signal: AbortSignal.timeout(4_000),
    });
  };
  try {
    const currentWs = workspaceManager.hasActiveWorkspace() ? workspaceManager.getWorkspace() : config.fallbackWorkspace;
    response = await sendRequest(currentWs);
    if (response.status === 403) {
      if (process.platform === "win32" && /^[A-Za-z]:/.test(currentWs)) {
        const altWorkspace = currentWs.replace(/^[A-Za-z]:/, m => m === m.toUpperCase() ? m.toLowerCase() : m.toUpperCase());
        const retryResponse = await sendRequest(altWorkspace);
        if (retryResponse.ok) {
          response = retryResponse;
        }
      }
      if (!response.ok && path !== "/workspaces") {
        try {
          const wsRes = await fetch(`http://127.0.0.1:${config.editorPort}/workspaces`, {
            headers: { "x-code-bridge-token": config.token },
            signal: AbortSignal.timeout(2_000),
          });
          if (wsRes.ok) {
            const data = (await wsRes.json()) as { folders?: string[]; activeFolder?: string | null };
            if (Array.isArray(data?.folders) && data.folders.length > 0) {
              workspaceManager.setAuthorizedWorkspaces(data.folders, data.activeFolder);
              const newWs = workspaceManager.getWorkspace();
              const refreshedResponse = await sendRequest(newWs);
              if (refreshedResponse.ok) {
                response = refreshedResponse;
              }
            }
          }
        } catch {
          // Extension might not support /workspaces or be unreachable
        }
      }
    }
  } catch {
    throw new Error(`VS Code extension is not running or unreachable on 127.0.0.1:${config.editorPort}`);
  }
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`VS Code extension rejected request (HTTP ${response.status}): ${errorText}`);
  }
  return response.json();
}

export const editorClient = {
  context: () => editor("/context"),
  diagnostics: () => editor("/diagnostics"),
  applyEdit: (relativePath: string, content: string) => editor("/apply-edit", { method: "POST", body: JSON.stringify({ relativePath, content }) }),
  getWorkspaces: async (): Promise<{ folders: string[]; activeFolder: string | null } | undefined> => {
    try {
      const res = await fetch(`http://127.0.0.1:${config.editorPort}/workspaces`, {
        headers: { "x-code-bridge-token": config.token },
        signal: AbortSignal.timeout(2_000),
      });
      if (res.ok) {
        const data = (await res.json()) as { folders?: string[]; activeFolder?: string | null };
        if (Array.isArray(data?.folders) && data.folders.length > 0) {
          workspaceManager.setAuthorizedWorkspaces(data.folders, data.activeFolder ?? undefined);
          return { folders: data.folders, activeFolder: data.activeFolder ?? null };
        }
      }
    } catch {
      // Extension may not be reachable or not support /workspaces
    }
    return undefined;
  },
};
