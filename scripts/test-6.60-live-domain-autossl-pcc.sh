#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Exact production dig invocation order: name before record type.
grep -Fq 'cfg.BaseDomain, "NS"' "$ROOT/agent/internal/hostadapter/nameserver_status.go"
grep -Fq 'cfg.Primary, "A"' "$ROOT/agent/internal/hostadapter/nameserver_status.go"
grep -Fq 'cfg.Secondary, "A"' "$ROOT/agent/internal/hostadapter/nameserver_status.go"
grep -Fq 'HasLocalAuthoritativeDNSZone' "$ROOT/agent/internal/api/server.go"
grep -Fq 'dns_local_authoritative_fallbacks' "$ROOT/agent/internal/api/server.go"
grep -Fq 'nginxDumpHasServerName' "$ROOT/agent/internal/hostadapter/inventory.go"
grep -Fq '/etc/nginx/sites-enabled/*' "$ROOT/scripts/reconcile-site-panel-shortcuts.sh"
grep -Fq 'readlink -f -- "$entry"' "$ROOT/scripts/reconcile-site-panel-shortcuts.sh"
if grep -Fq '"NS", cfg.BaseDomain' "$ROOT/agent/internal/hostadapter/nameserver_status.go"; then
  echo 'legacy reversed dig NS argument order returned' >&2; exit 1
fi

# AutoSSL must distinguish DNS pending, HTTP challenge blocking, and true issuance failures.
grep -Fq 'PreflightLetsEncryptHTTP01' "$ROOT/agent/internal/hostadapter/acme.go"
grep -Fq 'ACME HTTP-01 preflight blocked' "$ROOT/agent/internal/hostadapter/acme.go"
grep -Fq 'Let'"'"'s Encrypt detail:' "$ROOT/agent/internal/hostadapter/acme.go"
grep -Fq '"blocked": blocked' "$ROOT/agent/internal/api/server.go"
grep -Fq 'HTTP blocked' "$ROOT/panel/public/assets/app.js"
grep -Fq 'HTTP blocked' "$ROOT/panel/public/assets/customer.js"

# New HTTP vhosts must always allow HTTP-01 before the hidden-file deny rule.
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter -run 'TestACME|TestRenderNginxSite' -count=1
)

# Existing/legacy managed vhosts must be reconciled idempotently.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/legacy-privategather.conf" <<'CONF'
server {
    listen 80;
    server_name demo.privategather.com;
    root /home/privoralabsweb/domains/demo.privategather.com/public;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ /\. { deny all; }
}
CONF
python3 "$ROOT/scripts/reconcile-site-panel-shortcuts.py" --admin-port 8443 --hosting-port 2443 "$tmp/legacy-privategather.conf" >/dev/null
[[ "$(grep -Fc 'location ^~ /.well-known/acme-challenge/' "$tmp/legacy-privategather.conf")" == 1 ]]
[[ "$(grep -Fc 'location = /pcc {' "$tmp/legacy-privategather.conf")" == 1 ]]
[[ "$(grep -Fc 'location = /ppanel {' "$tmp/legacy-privategather.conf")" == 1 ]]
python3 "$ROOT/scripts/reconcile-site-panel-shortcuts.py" --admin-port 8443 --hosting-port 2443 "$tmp/legacy-privategather.conf" >/dev/null
[[ "$(grep -Fc 'location ^~ /.well-known/acme-challenge/' "$tmp/legacy-privategather.conf")" == 1 ]]
[[ "$(grep -Fc 'location = /pcc {' "$tmp/legacy-privategather.conf")" == 1 ]]
[[ "$(grep -Fc 'location = /ppanel {' "$tmp/legacy-privategather.conf")" == 1 ]]

# PCC brand title is a single line above the logo row.
grep -Fq 'brand-pcc-title">Privora Command Center</strong><div class="brand-pcc-row">' "$ROOT/panel/public/admin.php"
grep -Fq '.brand-pcc-title{font-size:15px!important;line-height:1.15;white-space:nowrap' "$ROOT/panel/public/assets/app.css"

echo 'PASS: 6.60 live-domain DNS, AutoSSL HTTP-01, and PCC header regression gate'
