import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
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
} from "./operations.js";

const text = (value: unknown) => ({ content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }] });

export function createMcpServer(): McpServer {
  const server = new McpServer(
    { name: "Code Bridge", version: "1.0.0" },
    {
      instructions:
        "Use read-only tools first. Explain every write, delete, or command and wait for human approval via `npm run approve` before retrying with the approval_id. Never access paths outside the configured workspace.",
    }
  );

  server.tool("editor_context", "Get the active VS Code file, selection, and workspace context.", {}, async () => {
    return text(await getEditorContext());
  });

  server.tool("editor_diagnostics", "Get current VS Code errors and warnings.", {}, async () => {
    return text(await getEditorDiagnostics());
  });

  server.tool(
    "list_files",
    "List files under the approved workspace.",
    { relative_path: z.string().default("."), max_depth: z.number().int().min(0).max(5).default(2) },
    async ({ relative_path, max_depth }) => {
      return text(await listFiles(relative_path, max_depth));
    }
  );

  server.tool(
    "read_file",
    "Read a UTF-8 text file in the approved workspace.",
    { relative_path: z.string(), max_chars: z.number().int().min(1).max(100000).default(30000) },
    async ({ relative_path, max_chars }) => {
      const { content } = await readFile(relative_path, max_chars);
      return text(content);
    }
  );

  server.tool(
    "search_code",
    "Search text in workspace files. Skips dependencies, Git metadata, and credential files.",
    { query: z.string().min(1), max_results: z.number().int().min(1).max(100).default(30) },
    async ({ query, max_results }) => {
      return text(await searchCode(query, max_results));
    }
  );

  server.tool(
    "write_file",
    "Create or replace a workspace file with new content. Requires human approval via `npm run approve`.",
    { relative_path: z.string(), content: z.string(), approval_id: z.string().optional() },
    async ({ relative_path, content, approval_id }) => {
      const result = await writeFile(relative_path, content, approval_id);
      return text(result.message);
    }
  );

  server.tool(
    "delete_file",
    "Delete a workspace file. Requires human approval via `npm run approve`.",
    { relative_path: z.string(), approval_id: z.string().optional() },
    async ({ relative_path, approval_id }) => {
      const result = await deleteFile(relative_path, approval_id);
      return text(result.message);
    }
  );

  server.tool(
    "run_project_command",
    "Run an allowlisted project command. Requires human approval via `npm run approve`. Allowed commands: npm test, npm run build, npm run lint, npm run typecheck.",
    { command: z.enum(ALLOWED_COMMANDS), approval_id: z.string().optional() },
    async ({ command, approval_id }) => {
      const result = await runProjectCommand(command, approval_id);
      return text(result);
    }
  );

  return server;
}
