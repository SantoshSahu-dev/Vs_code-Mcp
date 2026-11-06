# Security Policy — Code Bridge MCP

The Code Bridge project takes security and local system integrity seriously. Because Code Bridge bridges external AI models and web clients to your local development environment, defense-in-depth security mechanisms are enforced at every protocol and execution layer.

---

## 1. Supported Versions

Security updates and patches are provided for the following releases:

| Version | Supported | Notes |
|:---|:---:|:---|
| 1.0.x | :white_check_mark: | Current active release |
| < 1.0 | :x: | Legacy/prototype versions — please upgrade |

---

## 2. Threat Model & Security Architecture

Code Bridge operates on an **approval-first, zero-implicit-trust** model:

```
[ Remote AI Client (Claude / ChatGPT / Gemini) ]
                     │  (Streamable HTTP / HTTPS Tunnel)
                     ▼
       ┌───────────────────────────────┐
       │   Host & CORS Origin Guard   │  (Rejects unauthorized hosts & origins)
       └──────────────┬────────────────┘
                      ▼
       ┌───────────────────────────────┐
       │ Constant-Time Token & OAuth   │  (Bearer token / RFC 9728 OAuth 2.1 PKCE)
       └──────────────┬────────────────┘
                      ▼
       ┌───────────────────────────────┐
       │     Workspace Policy Guard    │  (Strict root boundary, blocks .env / keys)
       └──────────────┬────────────────┘
                      ▼
         ┌───────────────────────────┐
         │ Is this a mutating tool?  │
         │ (write, delete, command)  │
         └─────────────┬─────────────┘
                No │         │ Yes
                   ▼         ▼
             [ Execute ]  [ Generate req_ approval ID ]
                                 │
                                 ▼  (Human review via terminal)
                          [ npm run approve ]
                                 │
                                 ▼  (Atomic single-use redemption)
                            [ Execute ]
```

### Key Security Guarantees:
1. **Loopback-Only Binding by Default**:
   Both the MCP server (port `3333`) and the VS Code companion extension (port `3334`) bind exclusively to `127.0.0.1`.
2. **VS Code Port Isolation**:
   Port `3334` is strictly for local IPC between the server and the local editor. It must **never** be exposed through a reverse proxy or public tunnel.
3. **No Automatic Mutation Approval**:
   `CODE_BRIDGE_AUTO_APPROVE_WRITES=true` is rejected at startup. Every file write, file deletion, and shell command execution halts and requires explicit human verification via `npm run approve`.
4. **Single-Use, Nonce-Bound Approvals**:
   Approval tokens (`req_...`) expire after 10 minutes, are cryptographically bound to the SHA-256 hash of the exact payload, and are consumed atomically (`O_CREAT | O_EXCL`) to prevent replay and race conditions.
5. **Path Traversal & Symlink Confinement**:
   Every path is resolved against canonical workspace roots (`fs.realpathSync`). Symlinks and NTFS junctions are rejected recursively.
6. **Credential Redaction**:
   Secret configuration files (`.env*`, `.npmrc`, `.pypirc`, `id_rsa`, `*.pem`, `*.key`, `credentials*`) cannot be read, listed, or modified by AI tools.
7. **Environment Variable Sanitization for Child Processes**:
   Commands executed via `run_project_command` are strictly allowlisted (`npm test`, `npm run build`, `npm run lint`, `npm run typecheck`). The child process environment is stripped of all host secrets (e.g. `AWS_*`, `GITHUB_*`, `CODE_BRIDGE_*`).

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability or potential exploit in Code Bridge, please report it responsibly:

> [!IMPORTANT]
> **DO NOT file a public GitHub issue for security vulnerabilities.**

### Reporting Procedure:
1. Open a **Private Security Advisory** on GitHub via the **Security → Advisories → Report a vulnerability** tab of the repository.
2. If private advisories are unavailable, email the maintainers directly with the subject line `[SECURITY] Code Bridge Vulnerability Report`.
3. Include:
   - A detailed description of the vulnerability.
   - Exact affected files and functions.
   - Proof-of-concept (PoC) steps or script to reproduce the issue safely.
   - Potential impact and suggested mitigations.

### Response Timelines:
- **Initial Response**: Within 48 hours acknowledging receipt of your report.
- **Triage & Assessment**: Within 5 business days confirming severity and remediation plan.
- **Patch & Advisory**: Coordinated public disclosure after a verified patch is released.

---

## 4. Honest Assessment of Residual Risks

No software can claim absolute security. When operating Code Bridge, be aware of the following residual risks:

1. **Approved Command Consequences**:
   While `run_project_command` allowlists specific npm scripts and sanitizes environment variables, the script executed (`npm test`, `npm run build`) is defined in your project's `package.json`. If you approve a build or test command on untrusted third-party code that contains malicious scripts, that script will execute within your user permissions. Always inspect project scripts before approving.
2. **Tunnel Exposure**:
   If you choose to expose port `3333` via a Cloudflare Tunnel or reverse proxy, your server is reachable from the internet. Although protected by constant-time token verification and OAuth 2.1 PKCE, you are responsible for keeping your `CODE_BRIDGE_TOKEN` confidential and rotating it immediately if exposed.
3. **Multi-Root Workspace Visibility**:
   When multi-root workspaces are authorized in VS Code, all authorized workspace folders become readable to the connected AI client. Be sure not to open unrelated sensitive folders in the same VS Code window.

