#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
server="$ROOT/agent/internal/api/server.go"
resources="$ROOT/agent/internal/resources/resources.go"
php="$ROOT/panel/public/api.php"
js="$ROOT/panel/public/assets/app.js"
admin="$ROOT/panel/public/admin.php"
dns="$ROOT/agent/internal/hostadapter/dns.go"
grep -Fq 'NameserverAssignments map[string]string' "$resources"
grep -Fq 'AssignedNameservers(domain)' "$server"
! grep -A12 -F 'func (s *Server) nameserversForDomain' "$server" | grep -Fq 'NameserverSets()'
grep -Fq 'POST /v1/dns/nameserver-assignment' "$server"
grep -Fq "nameserver-assignment-set" "$php"
grep -Fq 'nameserverAssignmentForm' "$admin"
grep -Fq 'nameserverAssignmentSet' "$js"
grep -Fq 'RewriteBINDZoneNameservers(ctx, domain, ns.Primary, ns.Secondary, hostRecords)' "$server"
grep -Fq 'oldGlueLabels' "$dns"
grep -Fq "core.status==='rejected'?core.value" "$js" || grep -Fq "core.status==='fulfilled'?core.value:(d?" "$js"
(
  cd "$ROOT/agent"
  go test ./internal/resources ./internal/api ./internal/hostadapter -count=1
)
echo 'PASS: 6.66 explicit domain nameserver assignment / authoritative rewrite / core-status fail-soft gate'
