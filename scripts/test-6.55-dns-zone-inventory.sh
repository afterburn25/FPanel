#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
grep -Fq 'effectiveBINDZones' "$ROOT/agent/internal/hostadapter/inventory.go"
grep -Fq 'named-checkconf", "-p"' "$ROOT/agent/internal/hostadapter/inventory.go"
grep -Fq 'bind effective config' "$ROOT/agent/internal/hostadapter/inventory.go"
grep -Fq 'ReadBINDZoneFile' "$ROOT/agent/internal/hostadapter/dns.go"
grep -Fq 'reconciled-live-host' "$ROOT/agent/internal/api/server.go"
grep -Fq 'Recorded in Privora but no loaded authoritative BIND zone was confirmed.' "$ROOT/agent/internal/api/server.go"
grep -Fq 'Authoritative zone is loaded locally but its zone file was not discovered; shown read-only.' "$ROOT/agent/internal/api/server.go"
grep -Fq "x.managed===false?'View':'Manage'" "$ROOT/panel/public/assets/app.js"
grep -Fq "External zone · read only" "$ROOT/panel/public/assets/app.js"
grep -Fq "if(el.id!=='dnsRecordDomain')el.disabled=!managed" "$ROOT/panel/public/assets/app.js"
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter -run 'TestEffectiveBINDZonesDiscoversLegacyZoneOutsidePrivoraDirectory|TestDiscoverInventoryIncludesEffectiveBINDLegacyZone|TestReadBINDZoneFileShowsExternalRecordsReadOnly' -count=1
)
echo 'PASS: 6.55 DNS Zone Manager reconciles effective BIND zones and exposes external zones read-only'
