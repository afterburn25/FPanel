#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="$ROOT/panel/public/api.php"
UPD="$ROOT/scripts/privora-update.sh"
AGENT="$ROOT/agent/internal/api/server.go"
DNS="$ROOT/agent/internal/hostadapter/nameserver_status.go"
INV="$ROOT/agent/internal/hostadapter/inventory.go"

# Update Center status must fail soft locally and always emit HTTP 200 after auth.
grep -Fq 'function degradedUpdateCenter(string $reason, bool $mfaRequired=false)' "$API"
grep -Fq "if((\$r['_status']??500)>=300){out(degradedUpdateCenter" "$API"
grep -Fq 'out(degradedUpdateCenter($e->getMessage(),$mfaRequired),200)' "$API"
grep -Fq "if(is_array(\$local))out(['transaction'=>\$local,'degraded'=>true,'source'=>'local-journal'],200)" "$API"
! grep -Fq 'degradedUpdateCenter(string $reason, Auth $auth)' "$API"

# Migrations are bounded and routine updates gracefully reload an active PCC FPM runtime.
grep -Fq 'run_timed 90s "$stage/scripts/migrate.sh" --preflight' "$UPD"
grep -Fq 'run_timed 180s "$stage/scripts/migrate.sh" --apply' "$UPD"
grep -Fq 'gracefully reloading PCC PHP-FPM code workers' "$UPD"
if grep -Fq 'systemctl restart "$panel_fpm"' "$UPD"; then
  echo 'routine updater still restarts active PCC PHP-FPM' >&2; exit 1
fi

# Known domains remain visible in DNS manager even if authoritative discovery fails.
grep -Fq '"status": "not-configured"' "$AGENT"
grep -Fq '"source": "known-hosted-domain"' "$AGENT"
grep -Fq 'dns_known_without_local_zone' "$AGENT"

# Local authoritative discovery must not assume 127.0.0.1 only.
grep -Fq 'rndcZoneStatus' "$DNS"
grep -Fq 'localDNSProbeServers()' "$DNS"
grep -Fq '"local-authoritative-server:" + server' "$DNS"

# Legacy website fallback uses the recorded document root against active nginx -T blocks.
grep -Fq 'InspectKnownSite(domain, expectedRoot string)' "$INV"
grep -Fq 'domain-vhost-root-reconciled' "$INV"

php -l "$API" >/dev/null
bash -n "$UPD"
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter ./internal/api -count=1
)
echo 'PASS: 6.62 updater reliability and live-domain reconciliation gate'
