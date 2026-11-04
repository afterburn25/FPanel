#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
grep -Fq 'Agent unavailable after retry' "$ROOT/panel/src/AgentClient.php"
grep -Fq 'for ($attempt = 1; $attempt <= 12; $attempt++)' "$ROOT/panel/src/AgentClient.php"
grep -Fq "'/v1/health'" "$ROOT/scripts/privora-dns-reconcile-postupdate.php"
grep -Fq "'agent-readiness'" "$ROOT/scripts/privora-dns-reconcile-postupdate.php"
grep -Fq "dns-reconcile-last.json" "$ROOT/scripts/privora-dns-reconcile-postupdate.php"
grep -Fq 'Hosted DNS repair results' "$ROOT/panel/public/admin.php"
grep -Fq 'bind_rndc_fallback' "$ROOT/agent/internal/hostadapter/inventory.go"
php -l "$ROOT/panel/src/AgentClient.php" >/dev/null
php -l "$ROOT/scripts/privora-dns-reconcile-postupdate.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js"
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter -run 'TestDiscoverDNSInventoryFallsBackToRNDCForLoadedHostedRootZone' -count=1
)
echo 'PASS: 6.64 agent/DNS handoff and loaded-zone fallback regression gate'
