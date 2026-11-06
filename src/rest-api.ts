import path from "node:path";
import express from "express";
import { config } from "./config.js";
import {
  deleteFile,
  getEditorContext,
  getEditorDiagnostics,
  listFiles,
  readFile,
  runProjectCommand,
  searchCode,
  writeFile,
  ALLOWED_COMMANDS,
  type AllowedCommand,
} from "./operations.js";

export const restApi = express.Router();
restApi.use("/api", restApi);

function extractApprovalId(message: string): string | undefined {
  const match = message.match(/req_[A-Za-z0-9_-]{24}/);
  return match ? match[0] : undefined;
}

function handleOperationError(err: unknown, res: express.Response): void {
  const message = err instanceof Error ? err.message : String(err);
  const approvalId = extractApprovalId(message);

  if (
    message.includes("does not match this exact operation") ||
    message.includes("expired") ||
    message.includes("already used") ||
    message.includes("invalid format") ||
    message.includes("denied")
  ) {
    res.status(403).json({ error: message, success: false, status: "approval_rejected" });
    return;
  }

  if (
    message.includes("cannot escape") ||
    message.includes("escapes") ||
    message.includes("Access denied") ||
    message.includes("outside workspace") ||
    message.includes("symlink") ||
    message.includes("junction") ||
    message.includes("protected") ||
    message.includes("blocked by Code Bridge policy")
  ) {
    res.status(403).json({ error: message, success: false });
    return;
  }

  if (
    message.includes("safely disabled") ||
    message.includes("CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS")
  ) {
    res.status(403).json({ error: message, success: false, status: "blocked_by_safe_mode" });
    return;
  }

  if (message.includes("Approval required")) {
    res.status(200).json({
      success: false,
      status: "pending_approval",
      approval_id: approvalId,
      message,
      instructions: "Tell the user to approve this request by running 'npm run approve' in the Code Bridge terminal, then repeat this call with approval_id.",
    });
    return;
  }

  if (message.includes("not found") || message.includes("does not exist")) {
    res.status(404).json({ error: message, success: false });
    return;
  }

  res.status(400).json({ error: message, success: false });
}

import { workspaceManager } from "./workspace-manager.js";

// Health check
restApi.get("/health", (_req, res) => {
  let wsName = "unknown";
  try {
    wsName = path.basename(config.workspace);
  } catch {
    wsName = "[none]";
  }
  res.json({
    ok: true,
    workspace: wsName,
    writesAutoApproved: config.autoApproveWrites,
    remoteMutationsBlocked: config.blockRemoteMutations,
  });
});

// Workspace synchronization from VS Code extension
restApi.post("/workspace/sync", (req, res) => {
  const body = req.body || {};
  const folders = Array.isArray(body.folders) ? body.folders.map(String) : [];
  const activeFolder = typeof body.activeFolder === "string" ? body.activeFolder : undefined;

  workspaceManager.setAuthorizedWorkspaces(folders, activeFolder);
  res.json({
    ok: true,
    activeWorkspace: workspaceManager.hasActiveWorkspace() ? workspaceManager.getWorkspace() : null,
    folders: workspaceManager.getWorkspaceFolders(),
    source: workspaceManager.getSource(),
  });
});

// Get current workspace status
restApi.get("/workspace", (_req, res) => {
  res.json({
    ok: true,
    activeWorkspace: workspaceManager.hasActiveWorkspace() ? workspaceManager.getWorkspace() : null,
    folders: workspaceManager.getWorkspaceFolders(),
    source: workspaceManager.getSource(),
    synchronizedAt: workspaceManager.getSynchronizedAt(),
  });
});

// Editor context
restApi.get("/editor/context", async (_req, res) => {
  try {
    const data = await getEditorContext();
    res.json(data);
  } catch (err) {
    handleOperationError(err, res);
  }
});

// Editor diagnostics
restApi.get("/editor/diagnostics", async (_req, res) => {
  try {
    const data = await getEditorDiagnostics();
    res.json({ diagnostics: data });
  } catch (err) {
    handleOperationError(err, res);
  }
});

// List files
restApi.post("/files/list", async (req, res) => {
  try {
    const relativePath = typeof req.body?.relative_path === "string" ? req.body.relative_path : ".";
    const maxDepth = typeof req.body?.max_depth === "number" ? Math.max(0, Math.min(5, req.body.max_depth)) : 2;
    const files = await listFiles(relativePath, maxDepth);
    res.json({ files });
  } catch (err) {
    handleOperationError(err, res);
  }
});

// Read file
restApi.post("/files/read", async (req, res) => {
  try {
    const relativePath = req.body?.relative_path;
    if (typeof relativePath !== "string" || !relativePath.trim()) {
      res.status(400).json({ error: "Missing required string 'relative_path'." });
      return;
    }
    const maxChars = typeof req.body?.max_chars === "number" ? Math.max(1, Math.min(100000, req.body.max_chars)) : 30000;
    const result = await readFile(relativePath, maxChars);
    res.json(result);
  } catch (err) {
    handleOperationError(err, res);
  }
});

// Search code
restApi.post("/files/search", async (req, res) => {
  try {
    const query = req.body?.query;
    if (typeof query !== "string" || !query.trim()) {
      res.status(400).json({ error: "Missing required string 'query'." });
      return;
    }
    const maxResults = typeof req.body?.max_results === "number" ? Math.max(1, Math.min(100, req.body.max_results)) : 30;
    const matches = await searchCode(query, maxResults);
    res.json({ matches });
  } catch (err) {
    handleOperationError(err, res);
  }
});

// Write file (create or update) - Approval Gated
restApi.post("/files/write", async (req, res) => {
  try {
    if (config.blockRemoteMutations) {
      res.status(403).json({
        error: "Mutating operations are safely disabled (CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS=true). Only read operations are permitted during Quick Tunnel testing.",
        success: false,
        status: "blocked_by_safe_mode",
      });
      return;
    }

    const relativePath = req.body?.relative_path;
    const content = req.body?.content;
    const approvalId = typeof req.body?.approval_id === "string" ? req.body.approval_id : undefined;

    if (typeof relativePath !== "string" || !relativePath.trim()) {
      res.status(400).json({ error: "Missing required string 'relative_path'." });
      return;
    }
    if (typeof content !== "string") {
      res.status(400).json({ error: "Missing required string 'content'." });
      return;
    }

    const result = await writeFile(relativePath, content, approvalId);
    res.json({ success: true, status: "success", message: result.message, path: result.path });
  } catch (err) {
    handleOperationError(err, res);
  }
});

// Delete file - Approval Gated
restApi.post("/files/delete", async (req, res) => {
  try {
    if (config.blockRemoteMutations) {
      res.status(403).json({
        error: "Mutating operations are safely disabled (CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS=true). Only read operations are permitted during Quick Tunnel testing.",
        success: false,
        status: "blocked_by_safe_mode",
      });
      return;
    }

    const relativePath = req.body?.relative_path;
    const approvalId = typeof req.body?.approval_id === "string" ? req.body.approval_id : undefined;

    if (typeof relativePath !== "string" || !relativePath.trim()) {
      res.status(400).json({ error: "Missing required string 'relative_path'." });
      return;
    }

    const result = await deleteFile(relativePath, approvalId);
    res.json({ success: true, status: "success", message: result.message, path: result.path });
  } catch (err) {
    handleOperationError(err, res);
  }
});

// Run project command - Approval Gated
restApi.post("/commands/run", async (req, res) => {
  try {
    if (config.blockRemoteMutations) {
      res.status(403).json({
        error: "Command execution is safely disabled (CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS=true). Only read operations are permitted during Quick Tunnel testing.",
        success: false,
        status: "blocked_by_safe_mode",
      });
      return;
    }

    const command = req.body?.command as AllowedCommand;
    const approvalId = typeof req.body?.approval_id === "string" ? req.body.approval_id : undefined;

    if (!ALLOWED_COMMANDS.includes(command)) {
      res.status(400).json({
        error: `Invalid command: '${command}'. Allowed commands: ${ALLOWED_COMMANDS.join(", ")}`,
      });
      return;
    }

    const result = await runProjectCommand(command, approvalId);
    res.json({ success: true, status: "success", ...result });
  } catch (err) {
    handleOperationError(err, res);
  }
});
