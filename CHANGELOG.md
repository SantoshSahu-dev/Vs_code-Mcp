# Changelog

All notable changes to the Code Bridge project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-04

### Added
- **Model Context Protocol (MCP) Streamable HTTP Transport**: Direct JSON-RPC MCP endpoint at `/mcp` supporting tools discovery and execution.
- **8 Core MCP Tools**:
  - `list_files`: Recursive workspace file discovery with depth limiting.
  - `read_file`: Safe UTF-8 file reading with secret redaction.
  - `search_code`: Workspace text search excluding generated code and credentials.
  - `write_file`: Atomic, approval-gated file creation and updating.
  - `delete_file`: Approval-gated file deletion.
  - `run_project_command`: Allowlisted command execution (`npm test`, `npm run build`, `npm run lint`, `npm run typecheck`) with environment isolation.
  - `editor_context`: Active open file, selection, and workspace context from VS Code.
  - `editor_diagnostics`: Real-time compiler errors, warnings, and linter reports.
- **Approval Engine (`src/approvals.ts`)**:
  - Out-of-workspace state directory isolation (`~/.code-bridge`).
  - Cryptographic payload hashing (SHA-256 canonicalized).
  - Single-use, atomic redemption (`O_CREAT | O_EXCL`) preventing replay and race conditions.
  - 10-minute expiration TTL and interactive CLI (`npm run approve`).
- **OAuth 2.1 & Web AI Interoperability**:
  - RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`).
  - RFC 8414 Authorization Server Metadata (`/.well-known/oauth-authorization-server`).
  - RFC 7591 Dynamic Client Registration (`/oauth/register`, `/register`).
  - RFC 7636 PKCE S256 verification and RFC 9207 `iss` parameter support.
  - Encrypted SQLite store (`oauth-store.ts`) in WAL mode with AES-256-GCM record-level encryption.
  - In-memory rate limiting on authorization attempts to prevent token brute-forcing.
- **VS Code Extension (`code-bridge-vscode`)**:
  - Real-time workspace synchronization and multi-root workspace support.
  - Strict loopback binding (`127.0.0.1:3334`).
  - Token-authenticated IPC.
- **Comprehensive Automated Test Suite**:
  - 96 automated security, integration, OAuth, and diagnostic tests (95 passed, 1 skipped on Windows due to symlink privilege, 0 failed).
- **Packaging Toolchains**:
  - MCPB Claude Desktop extension bundle (`npm run package:mcpb`).
  - Cross-platform VS Code extension package (`npm run package:extension`).
- **Open-Source Infrastructure**:
  - GitHub Actions CI workflow for Node.js 20 & 22.
  - Security policy (`SECURITY.md`), Code of Conduct (`CODE_OF_CONDUCT.md`), and Contribution guidelines (`CONTRIBUTING.md`).

### Fixed
- Fixed sequential test runner configuration (`--test-concurrency=1`) preventing state crosstalk in integration tests.
- Fixed cross-platform extension packaging script in `package.json` to eliminate Windows `.cmd` dependency.
- Fixed case-insensitive path boundary checks on Windows platforms in `safePath`.
- Fixed persistent OAuth storage constructor to reject missing secret keys in production environments.

