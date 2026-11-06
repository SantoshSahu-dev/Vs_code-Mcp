# Contributing to Code Bridge MCP

Thank you for your interest in contributing to Code Bridge! We welcome contributions that improve security, protocol compliance, reliability, and developer experience.

---

## 1. Security Invariants (Non-Negotiable)

When contributing code, the following security invariants must **never** be broken or bypassed:

1. **Approval-First Operations**:
   Every mutating operation (`write_file`, `delete_file`, `run_project_command`) must strictly require human operator approval. Never add automatic approvals, bypass flags, or silent write mechanisms.
2. **Workspace Containment**:
   All filesystem reads and writes must remain confined to the authorized workspace folder(s). Never relax symlink checks, NTFS junction checks, or path traversal guards.
3. **Loopback Isolation**:
   The VS Code extension IPC service must bind exclusively to `127.0.0.1` and must never be exposed publicly.
4. **Credential Redaction**:
   Credential files (`.env`, private keys, SSH tokens, credentials) must remain unreadable to AI clients.
5. **No Hardcoded Secrets or Default Credentials**:
   Never check in personal paths, test secrets, or environment credentials.

---

## 2. Development Setup

### Prerequisites:
- **Node.js**: v20.x or later (LTS recommended)
- **npm**: v10.x or later
- **VS Code**: v1.102.0 or later (for extension development)

### Getting Started:
1. Clone your fork of the repository:
   ```bash
   git clone https://github.com/<your-username>/code-bridge.git
   cd code-bridge
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up a local test environment:
   ```bash
   cp .env.example .env
   # On Windows PowerShell:
   # Copy-Item .env.example .env
   ```
   Set `CODE_BRIDGE_WORKSPACE` to a temporary test folder and generate a random `CODE_BRIDGE_TOKEN` (at least 32 characters).

---

## 3. Build & Test Commands

Run the full verification suite before submitting any pull request:

```bash
# Typecheck TypeScript (zero errors required)
npm run typecheck

# Build the MCP server
npm run build

# Build the VS Code extension
npm run build:extension

# Run transport and security test suite
npm test

# Test stdio adapter & MCPB bundle
npm run test:mcpb

# Package VS Code extension (.vsix)
npm run package:extension

# Package MCPB bundle (.mcpb)
npm run package:mcpb
```

---

## 4. Coding Standards

- **Language**: Modern TypeScript (ESM, strict mode).
- **Architecture**:
  - `src/policy.ts`: Pure classification logic without filesystem side effects.
  - `src/safety.ts`: Path traversal, symlink detection, and constant-time token comparison.
  - `src/approvals.ts`: Approval creation, TTL expiry, and atomic redemption.
  - `src/operations.ts`: Workspace file operations and child process execution.
  - `src/mcp-server.ts`: MCP tool declarations using `@modelcontextprotocol/sdk`.
  - `src/oauth-store.ts`: Encrypted SQLite token store for OAuth 2.1 state.
  - `src/server.ts`: Express application, CORS, Host guards, and transport attachment.
- **Error Handling**: Use descriptive, user-friendly error messages. Avoid exposing internal system paths or raw stack traces.
- **Dependency Hygiene**: Avoid adding heavy external dependencies. Audit all packages for vulnerabilities.

---

## 5. Submitting a Pull Request

1. Create a feature or bugfix branch:
   ```bash
   git checkout -b fix/path-normalization
   ```
2. Ensure all 94+ automated tests pass cleanly (`npm test`).
3. Add unit or integration tests in `test/` covering any new functionality or bug fixes.
4. Update documentation in `README.md` or related markdown guides if configuration or behavior changed.
5. Push your branch to GitHub and open a Pull Request against `main`.
6. Fill out the PR template describing the motivation, implementation, and security review.

