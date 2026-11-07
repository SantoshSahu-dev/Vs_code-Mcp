# Code Bridge MCP

> **A local, approval-first Model Context Protocol (MCP) server connecting AI assistants with your local VS Code workspace.**

[![CI Pipeline](https://github.com/YOUR_GITHUB_USERNAME/code-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/code-bridge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D22.5.0-brightgreen)](https://nodejs.org)
[![MCP Protocol Version](https://img.shields.io/badge/MCP-2025--03--26-blueviolet)](https://modelcontextprotocol.io)

---

## 1. Project Title & Overview

**Code Bridge MCP** is an open-source, approval-first Model Context Protocol server that bridges AI chat assistants (such as Google Antigravity IDE, Claude Web, Claude Desktop, ChatGPT Custom MCP, and Gemini Custom Apps) to a developer's local VS Code project.

> [!IMPORTANT]
> **Zero Shared Cloud Infrastructure**: This repository provides source code and templates for running your own independent instance. There is **no shared central backend, no hosted tunnel, and no shared credentials**. Every developer operates their own private Code Bridge instance, configures their own local workspace directory, sets their own high-entropy authentication token, and manages their own private tunnel when remote access is required.

---

## 2. Project Description

Code Bridge enables modern AI agents to interact with a real development environment while keeping the human operator firmly in control. AI clients can discover project structure, read permitted source files, query real-time compiler diagnostics, and search codebases. However, whenever an AI attempts to mutate state—by creating a file, overwriting existing code, deleting a resource, or executing a shell command—Code Bridge pauses execution and requires an explicit, cryptographic human decision via an out-of-band interactive terminal prompt.

---

## 3. The Problem Code Bridge Solves

Developers frequently collaborate with web-based or desktop AI assistants. However, traditional AI-editor integrations present serious trade-offs:

1. **Blind Copy-Pasting**: Developers manually copy files back and forth, losing active editor context, compiler errors, and line numbers.
2. **Excessive Unchecked Permissions**: Traditional agent bridges often execute shell commands or overwrite files automatically without human inspection, risking accidental data loss or execution of unsafe scripts.
3. **Vendor Cloud Lock-in**: Many proprietary extensions send entire codebases to closed vendor backends.
4. **Credential Exposure Risk**: Exposing local servers through public tunnels without strict host validation, path traversal guards, and constant-time token comparison exposes developers to remote attacks.

**Code Bridge solves this** by providing a standards-compliant MCP Streamable HTTP interface that:
- Runs locally on loopback (`127.0.0.1`).
- Enforces strict filesystem confinement and denies credential files.
- Strips child-process environment variables so secrets never leak to executed commands.
- Enforces a human-in-the-loop approval gate for every single file mutation or command execution.

---

## 4. Key Features

- **MCP Streamable HTTP Transport**: Direct JSON-RPC endpoint at `/mcp` supporting tools discovery and execution according to the Model Context Protocol specification.
- **Approval-Gated Mutation Pipeline**: Every `write_file`, `delete_file`, and `run_project_command` call generates a temporary, single-use `approval_id` (`req_...`) bound to the SHA-256 hash of the exact payload. Operations are rejected until the operator reviews the diff and approves it via `npm run approve`.
- **Zero Automatic Approvals**: `CODE_BRIDGE_AUTO_APPROVE_WRITES=true` is rejected at startup by architectural design.
- **Atomic Single-Use Redemption**: Approvals are consumed atomically (`O_CREAT | O_EXCL`) preventing replay attacks and race conditions.
- **Strict Filesystem Confinement**: Absolute path validation, symlink traversal rejection, and NTFS junction blocking keep the AI inside your approved workspace folder.
- **Automatic Secret Redaction**: Credential and secret files (`.env*`, `.npmrc`, `.pypirc`, `id_rsa`, `*.pem`, `*.key`, `credentials*`) cannot be read, listed, searched, or written.
- **Child-Process Environment Isolation**: Commands executed via `run_project_command` are strictly allowlisted (`npm test`, `npm run build`, `npm run lint`, `npm run typecheck`) and execute with host secrets stripped from the environment.
- **OAuth 2.1 & Web AI Interoperability**: Full support for RFC 9728 Protected Resource Metadata, RFC 8414 Authorization Server Metadata, RFC 7591 Dynamic Client Registration, and PKCE S256 for ChatGPT, Claude Web, and Google Gemini.
- **Encrypted Local State**: OAuth persistence uses SQLite in WAL mode with record-level AES-256-GCM encryption.
- **VS Code Extension Integration**: Provides active file name, cursor selection, and real-time language server diagnostics (`editor_context`, `editor_diagnostics`).

---

## 5. Prerequisites & Environment Requirements

Before installing Code Bridge, ensure your development workstation meets these requirements:

1. **Operating System**:
   - Windows 10 / 11 (PowerShell 5.1+ or PowerShell 7+).
   - macOS 12+ (Apple Silicon or Intel).
   - Linux (Ubuntu 20.04+, Debian 11+, Fedora, Arch).
2. **Node.js Runtime**:
   - **Node.js v22.5.0 or later** (Node.js 22 LTS or Node.js 24 recommended; requires built-in `node:sqlite` support).
   - Check your installed version: `node --version`.
   - npm v10.0.0 or later.
3. **Editor Integration (Optional but Recommended)**:
   - Visual Studio Code v1.102.0 or later.
4. **Local Execution Context**:
   > [!IMPORTANT]
   > **Browser AI Access Limitation**: A browser-based AI chat assistant (such as ChatGPT Web, Claude Web, or Gemini Web) runs inside remote cloud infrastructure and **cannot directly discover, configure, or start software on your personal computer**.  
   > Setting up Code Bridge requires either:
   > - **Manual Terminal Execution**: You run the commands in your local terminal (PowerShell, Bash, or Zsh); OR
   > - **Local AI Coding Agent**: You use an agent running with local system access (such as Google Antigravity IDE) to automate the setup steps.

---

## 6. Screenshots & User Experience

```
+-----------------------------------------------------------------------------------------+
|                                  AI CLIENT (Claude / Gemini)                            |
|                                                                                         |
|  AI: "I need to update src/utils.ts to add the new validation helper."                 |
|  AI calls tool: write_file(relative_path: "src/utils.ts", content: "...")              |
|                                                                                         |
|  Code Bridge Response:                                                                  |
|  "Approval required. Review request req_xK91LmP0... by running 'npm run approve'        |
|   in the Code Bridge terminal. Once confirmed, repeat call with approval_id."          |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                              LOCAL DEVELOPER TERMINAL                                   |
|                                                                                         |
|  $ npm run approve                                                                      |
|  ========================================================================               |
|  Write file: src/utils.ts   [req_xK91LmP0..., expires in ~10 min]                       |
|    Target path: src/utils.ts                                                            |
|    Workspace: /home/dev/projects/my-app                                                 |
|    Size: 142 characters (6 lines)                                                      |
|  ------------------------------------------------------------------------               |
|    + export function isValidEmail(email: string): boolean {                             |
|    +   return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);                                 |
|    + }                                                                                  |
|  ========================================================================               |
|  Approve this exact request? [y] approve / [n] deny / [Enter] skip: y                   |
|  Approved.                                                                              |
+-----------------------------------------------------------------------------------------+
                                             │
                                             ▼
+-----------------------------------------------------------------------------------------+
|                                  AI CLIENT RETRY                                        |
|                                                                                         |
|  AI calls tool: write_file(..., approval_id: "req_xK91LmP0...")                         |
|  Code Bridge Response: "Wrote src/utils.ts."                                            |
+-----------------------------------------------------------------------------------------+
```

*(Screenshots of the OAuth consent screen and VS Code status pill are available in the documentation guides).*

---

## 7. Architecture Overview

Code Bridge consists of two decoupled components communicating over local loopback (`127.0.0.1`):

1. **Code Bridge Server (`src/server.ts`)**:
   An Express application hosting:
   - The MCP Streamable HTTP endpoint (`POST /mcp`).
   - The REST API router (`/api/*`) for HTTP-based AI integrations.
   - OAuth 2.1 PKCE authorization and discovery endpoints (`/oauth/*`, `/.well-known/*`).
   - The approval management engine (`src/approvals.ts`).
   - Policy and safety guards (`src/policy.ts`, `src/safety.ts`).
2. **Code Bridge VS Code Extension (`vscode-extension/`)**:
   A lightweight extension that runs inside VS Code and listens strictly on loopback port `3334`. It exposes editor context (active file, selection) and diagnostics to the local server over an authenticated HTTP connection.

---

## 8. Mermaid Architecture Diagram

```mermaid
flowchart TD
    subgraph External["External Network (AI Clients)"]
        WebAI["Web AI Clients<br/>(Claude Web / Gemini Gems / ChatGPT)"]
        DesktopAI["Desktop AI Clients<br/>(Claude Desktop / Antigravity IDE)"]
    end

    subgraph Tunnel["Remote Ingress (User-Configured)"]
        CF["Cloudflare Tunnel<br/>(cloudflared)<br/>Forwarding port 3333 ONLY"]
    end

    subgraph Localhost["Local Machine (127.0.0.1)"]
        subgraph Server["Code Bridge MCP Server (:3333)"]
            Guard["Host & Origin Guard<br/>(loopbackRequestGuard)"]
            Auth["Token & OAuth Auth<br/>(constant-time & PKCE)"]
            Policy["Workspace Policy Guard<br/>(src/policy.ts & safety.ts)"]
            MCP["MCP Server Protocol Engine<br/>(Streamable HTTP / stdio)"]
            ApprMgr["Approval Manager<br/>(src/approvals.ts)"]
            ExecMgr["Command Exec Manager<br/>(src/operations.ts)"]
        end

        subgraph LocalState["External State Folder (~/.code-bridge)"]
            ApprFiles["Pending Approvals<br/>req_*.json"]
            OAuthDB["Encrypted SQLite<br/>oauth.db (AES-256-GCM)"]
        end

        subgraph VSCode["VS Code Environment"]
            Ext["Code Bridge Extension<br/>(127.0.0.1:3334)"]
            Editor["Active Editor Context &<br/>Language Diagnostics"]
        end

        subgraph Workspace["Authorized Workspace Folder"]
            Src["Source Code & Project Files"]
            Secret["Protected Files (.env, keys)<br/>*BLOCKED FROM AI*"]
        end

        Operator["Human Developer<br/>(Terminal: npm run approve)"]
    end

    WebAI -->|HTTPS| CF
    CF -->|HTTP Forward| Guard
    DesktopAI -->|Local HTTP / stdio| Guard
    Guard --> Auth
    Auth --> Policy
    Policy --> MCP
    MCP --> ApprMgr
    MCP --> ExecMgr
    ApprMgr <--> LocalState
    Operator <-->|Review & Approve| ApprFiles
    MCP <-->|Loopback IPC (:3334)| Ext
    Ext <--> Editor
    MCP <-->|Permitted CRUD| Src
    Policy -.->|DENIED| Secret
```

---

## 9. Project Directory Structure

```
code-bridge/
├── .github/                         # GitHub Actions CI & issue templates
│   ├── workflows/ci.yml             # Automated multi-OS build & test workflow
│   ├── dependabot.yml               # Automated dependency maintenance
│   ├── ISSUE_TEMPLATE/              # Bug report and feature request templates
│   └── pull_request_template.md     # Pull request verification checklist
├── docs/                            # Deep-dive guides & architecture
│   └── ARCHITECTURE.md              # Deep architectural specification & sequence flows
├── mcpb/                            # MCPB package manifest for Claude Desktop
│   └── manifest.json
├── scripts/                         # Operational helper scripts
│   ├── diagnose-connection.mjs      # Connectivity and OAuth diagnostic utility
│   ├── generate-oauth-credentials.mjs # OAuth 2.1 client credential generator
│   ├── package-mcpb.mjs             # MCPB extension bundler
│   └── test-mcpb.mjs                # MCPB bundle automated stdio test
├── src/                             # Code Bridge server source code
│   ├── approvals.ts                 # Cryptographic approval engine (TTL & single-use)
│   ├── approve-cli.ts               # Human interactive approval terminal CLI
│   ├── audit.ts                     # Append-only metadata audit logger
│   ├── config-rules.ts              # Pure configuration validation rules
│   ├── config.ts                    # Environment loader and configuration state
│   ├── editor-client.ts             # Loopback IPC client for VS Code extension
│   ├── mcp-server.ts                # Model Context Protocol tool declarations
│   ├── oauth-store.ts               # Encrypted SQLite storage for OAuth 2.1 state
│   ├── oauth.ts                     # OAuth 2.1 endpoints, PKCE validation & UI
│   ├── operations.ts                # Workspace file CRUD and command execution
│   ├── policy.ts                    # File classification, secret blocking & permissions
│   ├── rest-api.ts                  # REST API endpoints for web connectors
│   ├── safety.ts                    # Path traversal, symlink & junction guards
│   ├── server.ts                    # Main Express server and transport adapter
│   ├── stdio.ts                     # Stdio transport entrypoint
│   └── workspace-manager.ts         # Dynamic and multi-root workspace tracking
├── test/                            # Comprehensive automated test suite
│   ├── approvals.test.ts            # Approval lifecycle, replay, & concurrency tests
│   ├── config-rules.test.ts         # Token rules & host parsing tests
│   ├── diagnose.test.ts             # Diagnostic tool test suite
│   ├── mcp-e2e.test.ts              # End-to-end MCP protocol tests
│   ├── oauth-store.test.ts          # SQLite encryption, rotation, and persistence tests
│   ├── oauth.test.ts                # OAuth 2.1 PKCE flow & rate-limiting tests
│   ├── providers-oauth.test.ts      # Multi-provider isolation tests (Claude/ChatGPT/Gemini)
│   ├── rest-api.test.ts             # REST endpoint and CORS tests
│   ├── safety.test.ts               # Path traversal, NTFS junction & symlink tests
│   └── workspace-sync.test.ts       # Dynamic VS Code workspace synchronization tests
├── vscode-extension/                # Companion VS Code extension
│   ├── src/extension.ts             # Extension activation, status & diagnostics server
│   ├── package.json                 # Extension manifest & settings declarations
│   ├── tsconfig.json                # Extension TypeScript configuration
│   ├── .vscodeignore                # Extension build packaging exclusions
│   └── LICENSE                      # MIT License
├── .env.example                     # Safe configuration template with placeholders
├── .gitignore                       # Strict git ignore rules
├── CHANGELOG.md                     # Version release history
├── cloudflared-config.example.yml   # Template for Cloudflare Tunnel configuration
├── CODE_OF_CONDUCT.md               # Contributor Covenant v2.1
├── CONTRIBUTING.md                  # Development guidelines and security invariants
├── LICENSE                          # MIT License
├── package.json                     # Root project configuration and npm scripts
├── package-lock.json                # Deterministic dependency lockfile
├── README.md                        # Master documentation
├── SECURITY.md                      # Security policy, threat model & disclosure
├── setup-and-test.ps1               # Automated Windows verification & test runner
├── setup-and-test.sh                # Automated Linux/macOS verification & test runner
├── start-cloudflared.ps1            # Validated Cloudflare Tunnel launcher
├── start-quick-tunnel.ps1           # Temporary Quick Tunnel launcher
└── tsconfig.json                    # Root TypeScript configuration
```

### Documentation Map

| Document | Description | Target Audience |
|:---|:---|:---|
| [README.md](README.md) | Master guide: overview, prerequisites, installation, config, usage & client setups | All Users & Developers |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Deep architectural specification, trust boundaries & sequence diagrams | Architects & Engineers |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy, threat model & defense-in-depth guarantees | Security Researchers |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guidelines, testing expectations & PR rules | Open-Source Contributors |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant v2.1 community standards | All Participants |
| [CHANGELOG.md](CHANGELOG.md) | Release history & version notes | Release Watchers |

---

## 10. Technology Stack

- **Runtime**: Node.js (v22.5.0+ LTS or Node.js 24) using ES Modules (`"type": "module"`).
- **Language**: TypeScript (v5.8+) with strict type checking enabled.
- **Protocol**: Model Context Protocol (`@modelcontextprotocol/sdk`).
- **Server Framework**: Express (`v5.1+`) with disabled `x-powered-by`, strict JSON parsing, and body size limits.
- **Storage & Crypto**:
  - Node.js built-in `node:sqlite` (`DatabaseSync`) in WAL mode with normal synchronization.
  - AES-256-GCM encryption with HKDF key derivation.
  - SHA-256 for approval payload hashing and PKCE S256 verification.
- **Schema Validation**: Zod (`v3.24+`).
- **Tooling & Bundling**:
  - `tsx` for fast TypeScript execution and testing.
  - `esbuild` for MCPB bundle compilation.
  - `@vscode/vsce` for extension packaging.

---

## 11. Security Architecture

Code Bridge implements defense-in-depth security:

1. **Least Privilege**: The AI starts with read-only access. Write, delete, and command capabilities are locked behind human review.
2. **Defense Against SSRF & DNS Rebinding**: `loopbackRequestGuard` rejects requests with unrecognized `Host` headers.
3. **Fail-Closed Design**: If a workspace folder is closed, or credentials fail to match, or a path appears suspicious, the operation immediately throws and denies access.
4. **Out-of-Workspace State**: Approval records (`req_...`) and the OAuth database reside in `~/.code-bridge`, outside the workspace tree. The AI cannot see, modify, or approve its own pending requests.

---

## 12. Authentication Mechanism

Authentication is required for all sensitive endpoints (`/mcp`, `/api/*`, `/health`):

- **Static Token Authentication**:
  - Provided via HTTP header `x-code-bridge-token: <TOKEN>` or `Authorization: Bearer <TOKEN>`.
  - Validated using `crypto.timingSafeEqual` to eliminate timing attacks.
  - Minimum token length of 32 characters, with automatic entropy and placeholder rejection.
- **OAuth 2.1 with PKCE (S256)**:
  - Supported for web AI platforms (Gemini Custom Apps, Claude Web, ChatGPT Custom MCP).
  - Uses RFC 7636 PKCE S256 (plain code challenges are strictly rejected).
  - Rate-limited to prevent brute-forcing `CODE_BRIDGE_TOKEN` on the consent page.
  - Tokens and client secrets are encrypted on disk with AES-256-GCM.

---

## 13. Workspace Isolation

- **Canonical Path Resolution**: `fs.realpathSync` resolves junctions, symlinks, and aliases before any operation.
- **Traversal Prevention**: Relative paths containing `..`, null bytes (`\0`), drive letters (`:`), or UNC prefixes (`\\`) are immediately rejected.
- **Case-Insensitive Normalization**: Path containment checks account for Windows case-insensitivity to avoid false-positive boundary rejections while strictly preventing escapes.
- **Sensitive File Denylist**: AI access to the following is permanently blocked:
  - Directories: `.git`, `.ssh`, `.aws`, `.gnupg`, `.azure`, `.kube`, `.docker`, `.code-bridge`.
  - Credentials: `.env*` (except `.env.example`), `.npmrc`, `.pypirc`, `.netrc`, `credentials*`, `secrets*`.
  - Keys: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `id_rsa`, `id_ed25519`.

---

## 14. Approval-Based Writes & Deletions

Every mutation requires human authorization:

1. **Trigger**: An AI client calls `write_file` or `delete_file` without an `approval_id`.
2. **Payload Hash**: The server canonicalizes the arguments (sorting JSON keys) and computes a SHA-256 hash.
3. **Pending Record**: A record is saved to `~/.code-bridge/approvals/req_<random>.json`.
4. **Halt**: The server throws an informative error returning the `approval_id`.
5. **Operator Decision**: The developer runs `npm run approve` in their terminal, reviews the preview and warnings, and approves (`y`) or denies (`n`).
6. **Redemption**: The AI repeats the exact call with `approval_id`.
7. **Atomic Consumption**: The server renames the approval to `.used` via `flag: "wx"`. The file write or deletion executes, and the approval record is permanently deleted.

---

## 15. Command Execution Restrictions

Arbitrary shell execution is impossible in Code Bridge:

- **Strict Allowlist**: Only 4 exact commands may be executed:
  - `npm test`
  - `npm run build`
  - `npm run lint`
  - `npm run typecheck`
- **Fixed Invocation**: Executed via `child_process.execFile` (not `exec`), preventing shell string interpolation or command injection (`&&`, `;`, `|`).
- **Environment Scrubbing**: Only essential execution variables (`PATH`, `NODE_ENV`, `HOME`, etc.) are passed to child processes. Secrets matching `CODE_BRIDGE_*`, `AWS_*`, `GITHUB_*`, etc., are stripped.
- **Limits**: 120-second execution timeout and 1MB maximum buffer output.
- **Approval Required**: Operator must approve each command execution via `npm run approve`.

---

## 16. Local Deployment (Recommended)

When using Code Bridge with local AI tools (such as Antigravity IDE or Claude Desktop), **no public tunnel is needed**. The entire communication remains on loopback `127.0.0.1`.

---

## 17. Remote Deployment via User-Owned Cloudflare Tunnel

When using web AI assistants (Claude Web, ChatGPT Custom GPTs, Gemini Custom Apps) that run in the cloud:

1. You must run your own Cloudflare Tunnel using your own Cloudflare account.
2. The tunnel forwards traffic exclusively to port `3333` (the MCP server).
3. **Port 3334 (VS Code service) must NEVER be forwarded.**
4. Your tunnel hostname must be added to `CODE_BRIDGE_ALLOWED_HOSTS` in `.env`.

---

## 18. Supported MCP Client Configuration

Code Bridge provides first-class support for both desktop-local AI coding environments and remote web AI assistants.

### 18.1 Google Antigravity IDE (Local Loopback — Verified & Recommended)

Google Antigravity IDE connects to Code Bridge entirely over local loopback (`127.0.0.1:3333`). **No public tunnel or external domain is required.**

1. Ensure Code Bridge is running locally (`npm start` or `.\setup-and-test.ps1 -KeepRunning`).
2. Open or create your Antigravity MCP configuration file:
   - **Windows**: `%USERPROFILE%\.gemini\config\mcp_config.json`
   - **macOS / Linux**: `~/.gemini/config/mcp_config.json`
3. Add the `code-bridge` entry:
   ```json
   {
     "mcpServers": {
       "code-bridge": {
         "serverUrl": "http://127.0.0.1:3333/mcp",
         "headers": {
           "x-code-bridge-token": "YOUR_CODE_BRIDGE_TOKEN_FROM_ENV",
           "Accept": "application/json, text/event-stream"
         }
       }
     }
   }
   ```
4. Restart Antigravity IDE or reload MCP servers in the Agent panel. Confirm that the 8 tools appear (`list_files`, `read_file`, `search_code`, `write_file`, `delete_file`, `run_project_command`, `editor_context`, `editor_diagnostics`).
5. **Recommended Initial Prompts for Antigravity**:
   - **Read-Only Test**:
     > *"Use Code Bridge to list top-level files in the workspace and inspect package.json. Do not modify any files."*
   - **Approval-Gated Mutation Test**:
     > *"Use Code Bridge to write a file named test-safe.txt with content 'approved test'. Explain what you want to write and wait for my approval."*
     The tool call will pause with a pending `approval_id`. In your terminal, run `npm run approve` and press `y` to confirm.

---

### 18.2 Claude Desktop (Local Stdio via MCPB or Config)

Claude Desktop runs locally on your computer and supports two local integration paths:

#### Method A: MCPB Extension Bundle (Recommended)
1. Package the MCPB bundle:
   ```bash
   npm run package:mcpb
   ```
2. In Claude Desktop, navigate to **Settings → Extensions → Advanced settings → Install Extension…** and select the generated `code-bridge.mcpb`.
3. Claude Desktop prompts for two parameters:
   - **Approved workspace**: Select your local project directory.
   - **Code Bridge token**: Enter your `CODE_BRIDGE_TOKEN` from `.env`.
4. The extension runs over local stdio with zero network port exposure.

#### Method B: Legacy Developer Stdio Config (`claude_desktop_config.json`)
If your Claude Desktop version exposes manual developer MCP configuration, add this entry to your config file (`%APPDATA%\Claude\claude_desktop_config.json` on Windows or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
```json
{
  "mcpServers": {
    "code-bridge": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/code-bridge/dist/stdio.js"],
      "env": {
        "CODE_BRIDGE_WORKSPACE": "/ABSOLUTE/PATH/TO/your-project",
        "CODE_BRIDGE_TOKEN": "YOUR_CODE_BRIDGE_TOKEN_FROM_ENV",
        "CODE_BRIDGE_AUTO_APPROVE_WRITES": "false"
      }
    }
  }
}
```

---

### 18.3 Claude Web (`claude.ai` Custom Connectors)

Claude Web runs in Anthropic's cloud infrastructure. To connect it to your local workspace, you must expose port 3333 via a user-owned Cloudflare Tunnel.

1. Start your Cloudflare Tunnel pointing to `http://127.0.0.1:3333` (e.g. `https://code-bridge.yourdomain.com`).
2. In `.env`, ensure your tunnel domain is allowed:
   ```env
   CODE_BRIDGE_ALLOWED_HOSTS=yourdomain.com,trycloudflare.com
   ```
3. In Claude Web, navigate to **Settings → Integrations → Add Custom Connector**:
   - **Server URL**: `https://code-bridge.yourdomain.com/mcp`
   - **Authentication**:
     - **Option 1 (OAuth 2.1 — Recommended)**: Select **OAuth**. Claude discovers Code Bridge's RFC 9728 metadata (`/.well-known/oauth-protected-resource`). The Code Bridge consent page loads in your browser; enter your `CODE_BRIDGE_TOKEN` to authorize.
     - **Option 2 (Manual Header)**: If selecting **No sign-in**, you **MUST** configure a custom request header:
       - Header Name: `Authorization`
       - Header Value: `Bearer YOUR_CODE_BRIDGE_TOKEN`
       *(Leaving headers empty when selecting "No sign-in" will result in `HTTP 401 Unauthorized` because Code Bridge strictly denies unauthenticated requests).*

---

### 18.4 Google Gemini Custom Apps / Gems (`gemini.google.com`)

Gemini Custom Apps (Gems) support external OAuth 2.1-protected MCP tools:

1. Generate random OAuth client credentials in your Code Bridge terminal:
   ```bash
   npm run oauth:generate
   ```
   This automatically appends `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, and `OAUTH_ALLOWED_REDIRECT_URIS` to your `.env` (gitignored).
2. Ensure `https://vertexaisearch.cloud.google.com/oauth-redirect` is listed in `OAUTH_ALLOWED_REDIRECT_URIS`.
3. In your Gemini Custom App (Gem) configuration:
   - **MCP Server URL**: `https://<your-tunnel-domain>/mcp`
   - **Authorization URL**: `https://<your-tunnel-domain>/oauth/authorize`
   - **Token URL**: `https://<your-tunnel-domain>/oauth/token`
   - **Client ID**: Paste `OAUTH_CLIENT_ID` from `.env`
   - **Client Secret**: Paste `OAUTH_CLIENT_SECRET` from `.env`
   - **Scopes**: `mcp:all`
4. When initiating the connection, Code Bridge's local consent screen prompts you for your `CODE_BRIDGE_TOKEN` and completes the authorization code exchange using PKCE S256.

---

### 18.5 ChatGPT Custom GPTs (`chatgpt.com`)

ChatGPT Custom GPTs connect to Code Bridge via its OpenAPI 3.0.3 specification:

1. In OpenAI's GPT Editor, navigate to **Configure → Actions → Create new action**.
2. Click **Import from URL** and enter:
   ```
   https://<your-tunnel-domain>/openapi.json
   ```
   ChatGPT parses the schema and loads the available endpoints (`/api/files/*`, `/api/commands/*`).
3. Click **Authentication** settings:
   - **Authentication Type**: `API Key`
   - **Auth Type**: `Bearer`
   - **API Key**: Enter your `CODE_BRIDGE_TOKEN` from `.env`.
4. Any mutation (`/api/files/write`, `/api/commands/run`) pauses with a requirement for human approval in your Code Bridge terminal.

---

## 19. VS Code Extension Setup

1. Package the extension:
   ```bash
   npm run package:extension
   ```
2. In VS Code, press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) and run:
   **Extensions: Install from VSIX...**
   Select the generated `code-bridge-vscode.vsix`.
3. In VS Code settings (`settings.json`), set:
   ```json
   {
     "codeBridge.token": "YOUR_CODE_BRIDGE_TOKEN_HERE",
     "codeBridge.port": 3334,
     "codeBridge.serverPort": 3333
   }
   ```
4. The extension automatically synchronizes open workspace folders with the server.

---

## 20. Environment Variables Reference

| Variable | Required | Default | Description |
|:---|:---:|:---:|:---|
| `CODE_BRIDGE_WORKSPACE` | **Yes** | — | Absolute path to authorized local project folder. |
| `CODE_BRIDGE_TOKEN` | **Yes** | — | High-entropy secret (>= 32 chars). |
| `PORT` | No | `3333` | TCP port for Code Bridge MCP server. |
| `CODE_BRIDGE_EDITOR_PORT` | No | `3334` | Loopback port for VS Code extension IPC. |
| `CODE_BRIDGE_ALLOWED_HOSTS` | No | `""` | Comma-separated external Host headers allowed. |
| `CODE_BRIDGE_BLOCK_REMOTE_MUTATIONS` | No | `false` | When `true`, enforces strict read-only safe mode. |
| `CODE_BRIDGE_AUTO_APPROVE_WRITES` | No | `false` | Must be `false`. Setting `true` crashes startup. |
| `CODE_BRIDGE_ALLOW_READ_GENERATED` | No | `false` | Set to `true` to allow reading `node_modules` or `dist`. |
| `CODE_BRIDGE_STATE_DIR` | No | `~/.code-bridge` | Storage folder for approvals and SQLite DB. |
| `CODE_BRIDGE_AUDIT_LOG` | No | `logs/audit.jsonl`| Path to append-only JSONL audit log. |
| `OAUTH_CLIENT_ID` | No | — | Static OAuth client ID. |
| `OAUTH_CLIENT_SECRET` | No | — | Static OAuth client secret. |
| `OAUTH_ALLOWED_REDIRECT_URIS` | No | — | Comma-separated allowed OAuth callback URLs. |

---

## 21. Complete Windows Setup

### Step-by-Step PowerShell:
```powershell
# 1. Clone repository
git clone https://github.com/<your-username>/code-bridge.git
cd code-bridge

# 2. Install dependencies
npm install

# 3. Configure environment from safe template
Copy-Item .env.example .env

# 4. Generate a cryptographically secure 32+ character token:
$token = [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
Write-Host "Generated Token: $token"

# 5. Open .env and set CODE_BRIDGE_WORKSPACE and CODE_BRIDGE_TOKEN:
notepad .env
# Set CODE_BRIDGE_WORKSPACE=C:\path\to\your\actual\project
# Set CODE_BRIDGE_TOKEN=<generated_token>

# 6. Build server & extension
npm run build
npm run build:extension
npm run package:extension

# 7. Configure VS Code extension:
# Install the generated code-bridge-vscode.vsix in VS Code.
# In VS Code Settings (Ctrl+,), search for "Code Bridge" and enter your generated token.

# 8. Run full automated verification suite:
powershell -File .\setup-and-test.ps1 -KeepRunning
```

---

## 22. Linux & macOS Setup

### Step-by-Step Bash / Zsh:
```bash
# 1. Clone repository
git clone https://github.com/<your-username>/code-bridge.git
cd code-bridge

# 2. Install dependencies
npm install

# 3. Configure environment from safe template
cp .env.example .env

# 4. Generate a cryptographically secure 32+ character token:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# 5. Open .env and configure workspace and token:
nano .env
# Set CODE_BRIDGE_WORKSPACE=/absolute/path/to/your/project
# Set CODE_BRIDGE_TOKEN=<generated_token>

# 6. Build server & extension
npm run build
npm run build:extension
npm run package:extension

# 7. Configure VS Code extension:
# Install code-bridge-vscode.vsix in VS Code.
# In VS Code settings.json, configure:
#   "codeBridge.token": "<generated_token>"

# 8. Run full automated verification suite:
chmod +x ./setup-and-test.sh
./setup-and-test.sh --keep-running
```

---

## 23. Verification & Diagnostic Commands

Verify your Code Bridge server locally using standard `curl` commands:

### 1. Authenticated Health Check (`200 OK`):
```bash
curl -sS -H "x-code-bridge-token: YOUR_TOKEN" http://127.0.0.1:3333/health
# Response: {"ok":true,"workspace":"...","editorConnected":true,...}
```

### 2. Bearer Authentication Test (`200 OK`):
```bash
curl -sS -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:3333/health
```

### 3. Unauthenticated Rejection Test (`401 Unauthorized`):
```bash
curl -sS -i http://127.0.0.1:3333/health
# Response: HTTP/1.1 401 Unauthorized with WWW-Authenticate header
```

### 4. MCP Streamable HTTP JSON-RPC Initialize Handshake:
```bash
curl -sS -X POST http://127.0.0.1:3333/mcp \
  -H "x-code-bridge-token: YOUR_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}'
# Response: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26",...}}
```

### 5. Automated Connectivity & OAuth Self-Diagnostics:
```bash
npm run diagnose
```

---

## 24. Usage Examples

### Listing Workspace Files:
```bash
curl -s -X POST http://127.0.0.1:3333/api/files/list \
  -H "Content-Type: application/json" \
  -H "x-code-bridge-token: YOUR_TOKEN" \
  -d '{"relative_path": ".", "max_depth": 2}'
```

### Reading a File:
```bash
curl -s -X POST http://127.0.0.1:3333/api/files/read \
  -H "Content-Type: application/json" \
  -H "x-code-bridge-token: YOUR_TOKEN" \
  -d '{"relative_path": "package.json"}'
```

### Searching Code:
```bash
curl -s -X POST http://127.0.0.1:3333/api/files/search \
  -H "Content-Type: application/json" \
  -H "x-code-bridge-token: YOUR_TOKEN" \
  -d '{"query": "createMcpServer"}'
```

---

## 25. Available MCP Tools & Parameters

| Tool Name | Parameters | Return Type | Description |
|:---|:---|:---:|:---|
| `list_files` | `relative_path` (string, default: `"."`)<br/>`max_depth` (int, 0–5, default: `2`) | `string[]` | List files within the authorized workspace. |
| `read_file` | `relative_path` (string, required)<br/>`max_chars` (int, 1–100000, default: `30000`) | `string` | Read UTF-8 text from a regular workspace file. |
| `search_code` | `query` (string, required)<br/>`max_results` (int, 1–100, default: `30`) | `string[]` | Search code for matching substring lines (`file:line: text`). |
| `write_file` | `relative_path` (string, required)<br/>`content` (string, required)<br/>`approval_id` (string, optional) | `string` | Create or replace a workspace file. Requires human approval. |
| `delete_file` | `relative_path` (string, required)<br/>`approval_id` (string, optional) | `string` | Delete a workspace file. Requires human approval. |
| `run_project_command` | `command` (`"npm test"` \| `"npm run build"` \| `"npm run lint"` \| `"npm run typecheck"`)<br/>`approval_id` (string, optional) | `object` | Run allowlisted project script with sanitized environment. Requires approval. |
| `editor_context` | *(none)* | `object` | Get active open file, cursor selection, and workspace status from VS Code. |
| `editor_diagnostics` | *(none)* | `object[]` | Get real-time language server compiler errors and linter diagnostics. |

---

## 26. Example Tool Workflows

### Safe Code Refactoring Workflow:
1. **Context Discovery**: AI calls `editor_context` to inspect your active file and cursor selection.
2. **Error Diagnosis**: AI calls `editor_diagnostics` to read current compile/lint errors.
3. **Code Search**: AI calls `search_code` with query `"calculateTax"` to find definitions and references.
4. **File Inspection**: AI calls `read_file` on `src/tax.ts` to inspect current implementation.
5. **Modification Proposal**: AI calls `write_file` with updated code.
6. **Human Gate**: Code Bridge returns pending approval status with ID `req_...`.
7. **Operator Review**: In terminal, developer runs `npm run approve` and selects `[y]`.
8. **Execution**: AI repeats `write_file` with the `approval_id`. The change is applied atomically and synced to VS Code.
9. **Verification**: AI calls `run_project_command` with `"npm test"`. Developer approves the test run. Tests pass.

---

## 27. Security Limitations & Threat Model

- **Project Script Integrity**: Code Bridge allowlists `npm test` and `npm run build`, but what those scripts actually execute is determined by your project's `package.json`. Always inspect third-party project manifests before approving commands.
- **Physical Machine Trust Boundary**: Code Bridge assumes the local machine operator running `npm run approve` is the legitimate owner of the workspace.
- **Secret Keeping**: Never commit `.env` or share your `CODE_BRIDGE_TOKEN`.

---

## 28. Troubleshooting Guide

### 1. `HTTP 401 Unauthorized`
- **Cause**: Missing or incorrect `x-code-bridge-token` or Bearer header.
- **Fix**: Check `CODE_BRIDGE_TOKEN` in `.env` and verify exact match in client headers.

### 2. `HTTP 403 Invalid Host header`
- **Cause**: Accessing the server through a domain not listed in `CODE_BRIDGE_ALLOWED_HOSTS`.
- **Fix**: Add your tunnel domain (e.g. `trycloudflare.com` or `code-bridge.example.com`) to `CODE_BRIDGE_ALLOWED_HOSTS` in `.env` and restart the server.

### 3. `Path escapes the approved workspace`
- **Cause**: Passing an absolute path or path with `..` escaping the configured project root.
- **Fix**: Pass workspace-relative paths (e.g. `src/index.ts` instead of `/home/user/app/src/index.ts`).

### 4. `VS Code extension is not running or unreachable on 127.0.0.1:3334`
- **Cause**: VS Code is closed or the extension failed to activate.
- **Fix**: Ensure VS Code is open with a project folder and `"codeBridge.token"` is configured in VS Code settings.

---

## 29. FAQ

**Q: Do I need an OpenAI, Anthropic, or Gemini API key to run Code Bridge?**  
A: **No.** Code Bridge is purely an MCP protocol server and adapter. It consumes no LLM tokens itself and requires zero proprietary model API keys.

**Q: Does Code Bridge send my code to any central cloud server?**  
A: **No.** Code Bridge contains zero tracking, zero telemetry, and zero third-party cloud backends. All code stays strictly on your machine.

**Q: Can I use Code Bridge without VS Code?**  
A: **Yes.** The core MCP tools (`read_file`, `write_file`, `delete_file`, `list_files`, `search_code`, `run_project_command`) work independently. The VS Code extension is only required for `editor_context` and `editor_diagnostics`.

---

## 30. Development Guide

To run Code Bridge in development mode with auto-reload:
```bash
npm run dev
```

Run diagnostics to check your local server, tunnel, and OAuth store health:
```bash
npm run diagnose
```

---

## 31. Testing Instructions

Execute the complete test suite:
```bash
npm test
```
To verify the packaged MCPB Claude Desktop bundle over stdio:
```bash
npm run test:mcpb
```

---

## 32. Contribution Guidelines

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before submitting pull requests.

---

## 33. Planned Roadmap

The following improvements are planned for future releases (evaluated by priority and complexity):

| Feature | Description | Priority | Complexity |
|:---|:---|:---:|:---:|
| **File Diff Preview Before Approval** | Terminal side-by-side or unified colored git-style diff preview in `approve-cli.ts`. | High | Medium |
| **File Rollback & Version History** | Automatic pre-write snapshotting allowing one-command rollbacks (`npm run rollback`). | High | Medium |
| **Per-Tool Permission Management** | Fine-grained configuration to allow certain read-only tools without a token. | Medium | Low |
| **Workspace Profiles** | Switch between pre-configured workspace paths via CLI (`code-bridge use <profile>`). | Medium | Medium |
| **Multiple Authorized Workspaces** | Native multi-workspace configuration file without needing VS Code active window sync. | Medium | High |
| **Windows Background Service** | Native Windows Service integration via `winsw` or NSSM. | Medium | Medium |
| **Linux Systemd Service Unit** | Systemd unit template for headless Linux servers and VMs. | Medium | Low |
| **macOS LaunchAgent Support** | LaunchAgent plist generator for automatic startup on macOS. | Low | Low |
| **Security Event Webhooks** | Real-time webhook notifications on failed authentication spikes or approval requests. | Low | Medium |
| **Configurable Approval Policies** | Custom approval rules (e.g. require approval for `*.ts` but auto-permit `*.tmp`). | Low | High |

---

## 34. License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 35. Security Vulnerability Reporting

Please review our [SECURITY.md](SECURITY.md) for vulnerability disclosure guidelines. **Do not report security vulnerabilities via public GitHub issues.**
