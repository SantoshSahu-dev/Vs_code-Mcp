import { fileURLToPath } from "node:url";
import path from "node:path";
import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { audit } from "./audit.js";
import { config } from "./config.js";
import { createMcpServer } from "./mcp-server.js";
import { restApi } from "./rest-api.js";
import { constantTimeTokenMatch } from "./safety.js";
import { workspaceManager } from "./workspace-manager.js";
import { editorClient } from "./editor-client.js";
import {
  getBaseUrl,
  getProtectedResourceMetadata,
  getAuthorizationServerMetadata,
  isValidOAuthToken,
  oauthRouter,
  handleClientRegistration
} from "./oauth.js";

export { createMcpServer } from "./mcp-server.js";
export { restApi } from "./rest-api.js";
export { oauthRouter, isValidOAuthToken, handleClientRegistration } from "./oauth.js";
export const app = express();
app.disable("x-powered-by");

const TRUSTED_AI_ORIGINS = new Set([
  "https://chatgpt.com",
  "https://chat.openai.com",
  "https://platform.openai.com",
  "https://claude.ai",
  "https://gemini.google.com",
  "https://aistudio.google.com",
]);

export function loopbackRequestGuard(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const host = (req.hostname || "").toLowerCase();
  const isAllowedHost =
    host === "127.0.0.1" ||
    host === "localhost" ||
    host === "[::1]" ||
    config.allowedHosts.some(allowed => host === allowed || host.endsWith("." + allowed));
  if (!isAllowedHost) { res.status(403).json({ error: "Invalid Host header" }); return; }

  const origin = req.headers.origin;
  const isLoopbackHost = host === "127.0.0.1" || host === "localhost" || host === "[::1]";

  if (origin) {
    const isAllowedOrigin = TRUSTED_AI_ORIGINS.has(origin.toLowerCase()) || !isLoopbackHost;
    if (!isAllowedOrigin) {
      res.status(403).json({ error: "Cross-origin requests are not allowed" });
      return;
    }
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, x-code-bridge-token, Accept");
    res.setHeader("Access-Control-Max-Age", "86400");
  }

  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, x-code-bridge-token, Accept");
    res.setHeader("Access-Control-Max-Age", "86400");
    res.status(204).end();
    return;
  }

  next();
}
app.use(loopbackRequestGuard);
app.use(express.json({ limit: "1mb", strict: true, type: "application/json" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

export function getOpenApiSpec(serverUrl: string) {
  return {
    openapi: "3.0.3",
    info: {
      title: "Code Bridge Local Workspace API",
      version: "1.0.0",
      description: "Secure, approval-gated bridge between web AI chats and local VS Code workspaces.",
      contact: { name: "Code Bridge Support" }
    },
    servers: [{ url: serverUrl, description: "Code Bridge Server" }],
    security: [{ BearerAuth: [] }],
    tags: [
      { name: "Health", description: "Server health and status endpoints" },
      { name: "Editor", description: "VS Code editor context and diagnostics" },
      { name: "Files", description: "Workspace file listing, reading, searching, writing, and deletion" },
      { name: "Commands", description: "Allowlisted project command execution" }
    ],
    paths: {
      "/health": {
        get: {
          summary: "Health check",
          description: "Returns health status, active workspace name, and verification of security settings.",
          operationId: "getHealth",
          tags: ["Health"],
          responses: {
            "200": {
              description: "Server status",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["ok", "workspace", "writesAutoApproved"],
                    properties: {
                      ok: { type: "boolean" },
                      workspace: { type: "string" },
                      writesAutoApproved: { type: "boolean" },
                      remoteMutationsBlocked: { type: "boolean" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/editor/context": {
        get: {
          summary: "Get active VS Code editor context",
          description: "Returns active open file, selection, and workspace status from the local VS Code extension.",
          operationId: "getEditorContext",
          tags: ["Editor"],
          responses: {
            "200": {
              description: "Editor state",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      workspaceOpen: { type: "boolean" },
                      activeFile: { type: "string", nullable: true, description: "Active file in editor, or null if none." },
                      selection: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/editor/diagnostics": {
        get: {
          summary: "Get current VS Code problems and errors",
          description: "Returns compiler errors, warnings, and linter diagnostics for workspace files.",
          operationId: "getEditorDiagnostics",
          tags: ["Editor"],
          responses: {
            "200": {
              description: "Diagnostic reports",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["diagnostics"],
                    properties: {
                      diagnostics: {
                        type: "array",
                        items: {
                          type: "object",
                          required: ["file", "diagnostics"],
                          properties: {
                            file: { type: "string" },
                            diagnostics: { type: "array", items: { type: "object" } }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/files/list": {
        post: {
          summary: "List workspace files",
          description: "Lists files within the approved workspace. Omit relative_path to list the workspace root.",
          operationId: "listFiles",
          tags: ["Files"],
          requestBody: {
            required: false,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    relative_path: { type: "string", default: ".", description: "Directory path relative to workspace root." },
                    max_depth: { type: "integer", default: 2, minimum: 0, maximum: 5, description: "Maximum directory recursion depth." }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "List of relative file paths",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["files"],
                    properties: {
                      files: { type: "array", items: { type: "string" } }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/files/read": {
        post: {
          summary: "Read a workspace text file",
          description: "Reads UTF-8 content of a regular workspace file. Secret files (.env, credentials, keys) are strictly denied.",
          operationId: "readFile",
          tags: ["Files"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["relative_path"],
                  properties: {
                    relative_path: { type: "string", description: "Path relative to workspace root." },
                    max_chars: { type: "integer", default: 30000, description: "Maximum number of characters to read." }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "File content and character count",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["content", "characters"],
                    properties: {
                      content: { type: "string" },
                      characters: { type: "integer" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/files/search": {
        post: {
          summary: "Search text across workspace files",
          description: "Searches code for matching lines, skipping hidden/secret files.",
          operationId: "searchCode",
          tags: ["Files"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["query"],
                  properties: {
                    query: { type: "string", description: "Search term or substring." },
                    max_results: { type: "integer", default: 30, description: "Maximum search results to return." }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Matching lines with file and line number",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["matches"],
                    properties: {
                      matches: { type: "array", items: { type: "string" } }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/files/write": {
        post: {
          summary: "Create or update a workspace file (Approval Gated)",
          description: "Creates or modifies a workspace file. If approval_id is omitted, returns pending_approval status with an approval_id. The user must run 'npm run approve' in their terminal. Once approved, repeat this call with approval_id.",
          operationId: "writeFile",
          tags: ["Files"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["relative_path", "content"],
                  properties: {
                    relative_path: { type: "string", description: "Target file path relative to workspace root." },
                    content: { type: "string", description: "Full file content to write." },
                    approval_id: { type: "string", description: "Single-use approval request ID returned from a prior call." }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Result of write request",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "status"],
                    properties: {
                      success: { type: "boolean" },
                      status: { type: "string", enum: ["success", "pending_approval", "blocked_by_safe_mode"] },
                      approval_id: { type: "string" },
                      message: { type: "string" },
                      instructions: { type: "string" },
                      path: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/files/delete": {
        post: {
          summary: "Delete a workspace file (Approval Gated)",
          description: "Deletes a workspace file. Requires human approval via 'npm run approve'.",
          operationId: "deleteFile",
          tags: ["Files"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["relative_path"],
                  properties: {
                    relative_path: { type: "string", description: "Path of regular file to delete relative to workspace root." },
                    approval_id: { type: "string", description: "Single-use approval request ID returned from a prior call." }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Result of delete request",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "status"],
                    properties: {
                      success: { type: "boolean" },
                      status: { type: "string", enum: ["success", "pending_approval", "blocked_by_safe_mode"] },
                      approval_id: { type: "string" },
                      message: { type: "string" },
                      path: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      },
      "/api/commands/run": {
        post: {
          summary: "Run an allowlisted project command (Approval Gated)",
          description: "Executes an allowlisted npm command (npm test, npm run build, npm run lint, npm run typecheck). Requires human approval via 'npm run approve'.",
          operationId: "runProjectCommand",
          tags: ["Commands"],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["command"],
                  properties: {
                    command: {
                      type: "string",
                      enum: ["npm test", "npm run build", "npm run lint", "npm run typecheck"],
                      description: "Allowlisted npm command to execute."
                    },
                    approval_id: { type: "string", description: "Single-use approval request ID returned from a prior call." }
                  }
                }
              }
            }
          },
          responses: {
            "200": {
              description: "Command execution output",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["success", "status"],
                    properties: {
                      success: { type: "boolean" },
                      status: { type: "string", enum: ["success", "pending_approval", "blocked_by_safe_mode"] },
                      approval_id: { type: "string" },
                      stdout: { type: "string" },
                      stderr: { type: "string" },
                      code: { type: "integer" },
                      message: { type: "string" },
                      instructions: { type: "string" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "Enter your CODE_BRIDGE_TOKEN from .env"
        }
      }
    }
  };
}

// Public OpenAPI specification endpoint for schema import
app.get(["/openapi.json", "/api/openapi.json"], (req, res) => {
  const host = req.headers.host || `127.0.0.1:${config.port}`;
  const proto = req.secure || req.headers["x-forwarded-proto"] === "https" ? "https" : "http";
  const serverUrl = `${proto}://${host}`;
  res.json(getOpenApiSpec(serverUrl));
});

// OAuth 2.1 Protected Resource Metadata & Authorization Server Discovery (RFC 9728, RFC 8414)
app.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json(getProtectedResourceMetadata(baseUrl));
});

app.get(["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"], (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json(getAuthorizationServerMetadata(baseUrl));
});

// OAuth 2.1 Authorization and Token Endpoints
app.use("/oauth", oauthRouter);
app.post("/register", handleClientRegistration);

export function authenticateRequest(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const tokenHeader = req.header("x-code-bridge-token");
  const authHeader = req.header("authorization");
  const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : undefined;
  const token = tokenHeader ?? bearerToken;
  const baseUrl = getBaseUrl(req);
  const expectedResource = `${baseUrl}/mcp`;
  if (constantTimeTokenMatch(token) || (token && isValidOAuthToken(token, expectedResource))) {
    next();
    return;
  }
  void audit("authentication_failed", { method: req.method, route: req.path });
  const resourceMetadataUrl = `${baseUrl}/.well-known/oauth-protected-resource`;
  if (res.setHeader) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="Code Bridge", error="invalid_token", error_description="Missing or invalid credentials", resource_metadata="${resourceMetadataUrl}"`
    );
  }
  res.status(401).json({
    error: "Missing or invalid credentials",
    resource_metadata: resourceMetadataUrl
  });
}
app.use(authenticateRequest);

app.use("/api", restApi);

app.post("/mcp", async (req, res) => {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => { void transport.close(); });
  try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
  catch (error) { await audit("mcp_request_failed", { message: error instanceof Error ? error.name : "unknown" }); if (!res.headersSent) res.status(500).json({ error: "MCP request failed" }); }
});
app.all("/mcp", (_req, res) => res.status(405).json({ error: "Use POST for Streamable HTTP MCP requests" }));
app.post("/workspace/sync", (req, res) => {
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
app.get("/health", (_req, res) => {
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
app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = (error as { type?: string })?.type === "entity.too.large" ? 413 : 400;
  res.status(status).json({ error: status === 413 ? "Request body is too large" : "Invalid JSON request body" });
});
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

let httpServer: import("node:http").Server | undefined;
const isDirectExecution = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (process.env.NODE_ENV !== "test" && isDirectExecution) {
  httpServer = app.listen(config.port, "127.0.0.1", () => {
    console.log(`Code Bridge is listening on loopback at http://127.0.0.1:${config.port}/mcp`);
    console.log(`VS Code service remains loopback-only at 127.0.0.1:${config.editorPort}`);
    void audit("server_started", { port: config.port });
    void editorClient.getWorkspaces().catch(() => undefined);
  });
  const shutdown = (signal: string) => { void audit("server_stopped", { signal }).finally(() => httpServer?.close(() => process.exit(0))); };
  process.once("SIGINT", () => shutdown("SIGINT"));
  process.once("SIGTERM", () => shutdown("SIGTERM"));
}
