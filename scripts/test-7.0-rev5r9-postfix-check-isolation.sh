#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
FILE="$ROOT/agent/internal/hostadapter/mail_secure.go"
[[ -f "$FILE" ]] || { echo "FAIL: missing $FILE" >&2; exit 1; }
grep -Fq 'if err := a.validatePostfixCheck(ctx); err != nil {' "$FILE"
if grep -Fq 'a.run(ctx, "postfix", "check")' "$FILE"; then
  echo "FAIL: secure-mail renderer still invokes postfix check inside hardened Agent sandbox" >&2
  exit 1
fi
grep -Fq 'runIsolatedRootCommand(ctx, "privora-postfix-check"' "$ROOT/agent/internal/hostadapter/mail_auth.go"
echo "PASS: Rev5 Rev9 secure-mail Postfix validation uses isolated-root execution."
