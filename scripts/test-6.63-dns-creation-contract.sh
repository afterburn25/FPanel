#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="$ROOT/agent/internal/api/server.go"
APP="$ROOT/panel/public/assets/app.js"
grep -Fq 'ensureConfiguredNameserverGlue' "$AGENT"
grep -Fq 'CONFIGURED VIA PARENT' "$APP"
grep -Fq 'PARENT RECORD MISSING' "$APP"
grep -Fq 'longestHostedParent' "$AGENT"
(
  cd "$ROOT/agent"
  go test ./internal/api -run 'TestConfiguredInBailiwickNameserverGlueIsAddedToNewRootZone|TestConfiguredExternalNameserversDoNotInjectForeignGlue|TestLongestHostedParentUsesExistingZone' -count=1
)
echo 'PASS: 6.63 DNS creation contract regression gate'
