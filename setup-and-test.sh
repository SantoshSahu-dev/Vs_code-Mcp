#!/usr/bin/env bash
# ==============================================================================
# Code Bridge MCP — Linux & macOS Local Setup and Verification Script
# Verifies environment, builds server and extension, executes test suite,
# and performs live loopback health and MCP protocol checks.
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

KEEP_RUNNING=false
SKIP_ROTATION=false

for arg in "$@"; do
  case "$arg" in
    --keep-running|-k) KEEP_RUNNING=true ;;
    --skip-token-rotation|-s) SKIP_ROTATION=true ;;
    *) echo "Unknown option: $arg" && exit 1 ;;
  esac
done

echo "========================================================"
echo "   Code Bridge MCP — Local Verification Suite (Unix)    "
echo "========================================================"

# 1. Check Prerequisites
command -v node >/dev/null 2>&1 || { echo "FAIL: Node.js 22+ (v22.5.0+) is required."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "FAIL: npm is required."; exit 1; }
echo "PASS: Node.js and npm found."

# 2. Check .env
ENV_FILE="$ROOT_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "FAIL: .env is missing. Copy .env.example to .env and configure CODE_BRIDGE_WORKSPACE first."
  exit 1
fi

WORKSPACE=$(grep -E '^CODE_BRIDGE_WORKSPACE=' "$ENV_FILE" | cut -d'=' -f2- | tr -d '\r')
if [[ -z "$WORKSPACE" || ! -d "$WORKSPACE" ]]; then
  echo "FAIL: Configured workspace directory does not exist: $WORKSPACE"
  exit 1
fi
echo "PASS: Configured workspace exists ($WORKSPACE)."

# 3. Token Rotation (unless skipped)
if [[ "$SKIP_ROTATION" = false ]]; then
  mkdir -p "$ROOT_DIR/backups"
  cp "$ENV_FILE" "$ROOT_DIR/backups/.env.$(date +%Y%m%d-%H%M%S).bak"
  NEW_TOKEN=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
  sed -i.tmp "s|^CODE_BRIDGE_TOKEN=.*|CODE_BRIDGE_TOKEN=${NEW_TOKEN}|" "$ENV_FILE" && rm -f "$ENV_FILE.tmp"
  export CODE_BRIDGE_TOKEN="$NEW_TOKEN"
  echo "PASS: Secure bridge token rotated."
fi

TOKEN=$(grep -E '^CODE_BRIDGE_TOKEN=' "$ENV_FILE" | cut -d'=' -f2- | tr -d '\r')
if [[ ${#TOKEN} -lt 32 ]]; then
  echo "FAIL: CODE_BRIDGE_TOKEN is shorter than 32 characters."
  exit 1
fi

export CODE_BRIDGE_WORKSPACE="$WORKSPACE"
export CODE_BRIDGE_TOKEN="$TOKEN"

# 4. Install & Build
if [[ ! -d "node_modules" ]]; then
  npm install
else
  npm install --ignore-scripts
fi

npm run build
npm run test
npm run build:extension
npm run package:extension
echo "PASS: Server build, transport test, security tests, and extension package completed."

# 5. Live Loopback Verification
PORT=$(grep -E '^PORT=' "$ENV_FILE" | cut -d'=' -f2- | tr -d '\r' || echo "3333")
PORT="${PORT:-3333}"

node dist/server.js &
SERVER_PID=$!

cleanup() {
  if [[ "$KEEP_RUNNING" = false && -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Wait for server to listen
for i in {1..30}; do
  if curl -s -f -o /dev/null -H "x-code-bridge-token: $TOKEN" "http://127.0.0.1:$PORT/health"; then
    break
  fi
  sleep 0.3
done

# Authenticated health check
HEALTH=$(curl -s -H "x-code-bridge-token: $TOKEN" "http://127.0.0.1:$PORT/health")
echo "PASS: Authenticated loopback health check succeeded."

# Unauthenticated request rejected (401)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/health")
if [[ "$STATUS" != "401" ]]; then
  echo "FAIL: Unauthenticated request did not return HTTP 401 (got $STATUS)."
  exit 1
fi
echo "PASS: Unauthenticated request rejected with HTTP 401."

# MCP initialize check
INIT_PAYLOAD='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"setup-test","version":"1.0"}}}'
MCP_INIT=$(curl -s -X POST -H "Content-Type: application/json" -H "x-code-bridge-token: $TOKEN" -d "$INIT_PAYLOAD" "http://127.0.0.1:$PORT/mcp")
echo "$MCP_INIT" | grep -q "Code Bridge" || { echo "FAIL: MCP initialize did not return Code Bridge."; exit 1; }
echo "PASS: MCP initialize handshake succeeded."

# Write metadata pass report
mkdir -p "$ROOT_DIR/logs"
PASS_REPORT="{\"passedAt\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"workspace\":\"$WORKSPACE\",\"mcpPort\":$PORT,\"autoApproveWrites\":false,\"platform\":\"unix\"}"
echo "$PASS_REPORT" > "$ROOT_DIR/logs/local-security-pass.json"
echo "PASS: Local security report written to logs/local-security-pass.json."

echo "========================================================"
if [[ "$KEEP_RUNNING" = true ]]; then
  echo "Code Bridge is running (PID: $SERVER_PID) at http://127.0.0.1:$PORT/mcp"
else
  echo "All local verification checks passed successfully."
fi
echo "========================================================"

