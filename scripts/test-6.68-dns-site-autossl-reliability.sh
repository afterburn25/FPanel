#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACME="$ROOT/agent/internal/hostadapter/acme.go"
DNS="$ROOT/agent/internal/hostadapter/dns.go"
NS="$ROOT/agent/internal/hostadapter/nameserver_status.go"
API="$ROOT/agent/internal/api/server.go"
PAPI="$ROOT/panel/public/api.php"
APP="$ROOT/panel/public/assets/app.js"
ADMIN="$ROOT/panel/public/admin.php"

grep -Fq 'cp.Proxy = nil' "$ACME"
grep -Fq 'Status: "http-local-ready"' "$ACME"
grep -Fq 'public self-probe is advisory' "$ACME"
grep -Fq 'os.Chmod(dir, 0755)' "$ACME"
grep -Fq 'os.Chmod(challengePath, 0644)' "$ACME"
grep -Fq 'PreflightOnly bool' "$API"
grep -Fq '"preflight_only": in.PreflightOnly' "$API"
grep -Fq 'ReplaceBINDRecord' "$DNS"
grep -Fq 'SOA and authoritative root NS records are protected' "$DNS"
grep -Fq 'GlueIPv4Registered' "$NS"
grep -Fq 'GlueIPv6Registered' "$NS"
grep -Fq 'oldDefault :=' "$API"
grep -Fq 'SetNameserverAssignment(domain, oldDefault)' "$API"
grep -Fq 'HasLocalAuthoritativeDNSZone' "$API"
grep -Fq 'RepairSiteNginx' "$API"
grep -Fq 'POST /v1/sites/{domain}/repair' "$API"
grep -Fq 'POST /v1/dns/zones/{domain}/records/replace' "$API"
grep -Fq "route==='site-repair'" "$PAPI"
grep -Fq "route==='dns-record-replace'" "$PAPI"
grep -Fq 'data-site-repair' "$APP"
grep -Fq 'dnsEditOriginal' "$APP"
grep -Fq 'dnsRecordCancel' "$ADMIN"
node --check "$APP"
php -l "$PAPI" >/dev/null
php -l "$ADMIN" >/dev/null
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter -run 'TestACMEProductionProbeBypassesEnvironmentProxy|TestACMEInjectedHTTPTransportAlsoBypassesProxy|TestACMEHTTP01PreflightAcceptsLocalProofWhenPublicSelfProbe404|TestACMEHTTP01PreflightNormalizesPermissionsUnderAgentUmask|TestReplaceBINDRecordChangesIdentityAndPreservesRootNS|TestReplaceBINDRecordRejectsRootAuthority|TestInspectNameserverSetupTreatsIPv6GlueAsOptionalWhenIPv4IsConfirmed' -count=1
)
echo 'PASS: 6.68 DNS/site/AutoSSL reliability gate'
