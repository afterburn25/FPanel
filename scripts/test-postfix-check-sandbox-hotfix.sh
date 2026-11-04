#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
MAIL="$ROOT/agent/internal/hostadapter/mail_auth.go"
SVC="$ROOT/agent/privora-panel-agent.service"
ISO="$ROOT/agent/internal/hostadapter/isolated_exec.go"
grep -Fq 'validatePostfixCheck(ctx)' "$MAIL"
grep -Fq 'runIsolatedRootCommand(ctx, "privora-postfix-check"' "$MAIL"
grep -Fq '2*time.Minute' "$MAIL"
grep -Fq 'NoNewPrivileges=true' "$SVC"
grep -Fq 'RestrictSUIDSGID=true' "$SVC"
grep -Fq -- '--property=NoNewPrivileges=no' "$ISO"
grep -Fq -- '--property=User=root' "$ISO"
echo 'PASS: Postfix check uses an isolated root operation while the long-running Agent sandbox remains locked down.'
