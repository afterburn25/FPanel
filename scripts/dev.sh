#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="${PRIVORA_DEV_RUNTIME:-/tmp/privora-panel-dev}"
SOCKET="$RUNTIME/agent.sock"
AUDIT="$RUNTIME/audit.jsonl"
STATE="$RUNTIME/agent-state.json"
MOCKROOT="$RUNTIME/mock-root"
PANELSTATE="$RUNTIME/panel-state.json"
TOKEN="${PRIVORA_AGENT_TOKEN:-$(openssl rand -hex 32)}"
PANEL_KEY="${PRIVORA_PANEL_ENCRYPTION_KEY:-$(openssl rand -hex 32)}"
PASSWORD="${PRIVORA_DEV_PASSWORD:-}"
if [[ -z "$PASSWORD" ]]; then
  echo "Set PRIVORA_DEV_PASSWORD to a 12+ character development admin password." >&2
  exit 2
fi
mkdir -p "$RUNTIME"
PRIVORA_PANEL_STATE="$PANELSTATE" php "$ROOT/scripts/init-panel.php" admin "$PASSWORD"
if [[ -n "${PRIVORA_DEV_CUSTOMER_PASSWORD:-}" && -n "${PRIVORA_DEV_CUSTOMER_ACCOUNT:-}" ]]; then
  PRIVORA_PANEL_STATE="$PANELSTATE" php "$ROOT/scripts/init-panel.php" customer "$PRIVORA_DEV_CUSTOMER_PASSWORD" hosting-user "$PRIVORA_DEV_CUSTOMER_ACCOUNT"
fi
(
  cd "$ROOT/agent"
  PRIVORA_AGENT_TOKEN="$TOKEN" go run ./cmd/privora-agent --mock --socket "$SOCKET" --audit "$AUDIT" --state "$STATE" --mock-root "$MOCKROOT"
) &
AGENT_PID=$!
trap 'kill "$AGENT_PID" 2>/dev/null || true' EXIT
sleep 0.8
cd "$ROOT"
echo "Privora Panel development server: http://127.0.0.1:8080"
echo "User: admin"
PRIVORA_AGENT_TOKEN="$TOKEN" PRIVORA_AGENT_SOCKET="$SOCKET" PRIVORA_PANEL_STATE="$PANELSTATE" PRIVORA_PANEL_ENCRYPTION_KEY="$PANEL_KEY" php -S 127.0.0.1:8080 -t panel/public
