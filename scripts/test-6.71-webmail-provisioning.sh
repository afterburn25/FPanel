#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
need(){ grep -Fq -- "$2" "$ROOT/$1" || { echo "FAIL: $1 missing: $2" >&2; exit 1; }; }
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[1-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo 'FAIL: VERSION is not a supported 6.71+ cumulative core' >&2; exit 1; }

need scripts/configure-webmail.sh 'roundcube-core roundcube-sqlite3 sqlite3'
need scripts/configure-webmail.sh 'PRIVORA_WEBMAIL_URL=/webmail/'
need scripts/configure-webmail.sh '[privora-webmail]'
need scripts/configure-webmail.sh 'systemctl is-active --quiet postfix'
need scripts/configure-webmail.sh 'systemctl is-active --quiet dovecot'
need scripts/render-panel-nginx.py 'route=webmail-auth'
need scripts/render-panel-nginx.py 'location /webmail/'
need scripts/render-panel-nginx.py 'auth_request /_privora_webmail_auth;'
need scripts/render-panel-nginx.py 'location ~ ^/webmail/installer(?:/|$) {{ deny all; }}'
need panel/public/api.php "route==='webmail-auth'"
need panel/public/api.php "requireCustomerFeature(\$store,\$client,\$customerScope,'webmail')"
need panel/public/admin.php 'id="installWebmailBtn"'
need panel/public/assets/app.js "id:'roundcube-webmail'"
need agent/internal/hostadapter/components.go 'ID: "roundcube-webmail"'
need agent/internal/hostadapter/components.go 'Special: "roundcube-webmail"'
need agent/internal/hostadapter/components.go 'configureRoundcubeWebmail(ctx, true)'
need agent/internal/hostadapter/webmail.go 'func (a *Adapter) configureRoundcubeWebmail(ctx context.Context, installPackages bool)'
need agent/internal/hostadapter/webmail.go 'func (a *Adapter) webmailCapability()'
need agent/internal/hostadapter/webmail.go 'return true, true, "Roundcube · launch=/webmail/ · panel-session gated"'
need install/privora-install.sh 'configure_webmail()'
need install/privora-install.sh 'phpmyadmin webmail site_panel_shortcuts'

# The PPanel post-create database refresh must not regress to the undefined symbol.
! grep -Fq 'applyDatabaseCapabilities' "$ROOT/panel/public/assets/customer.js" || { echo 'FAIL: stale applyDatabaseCapabilities call remains' >&2; exit 1; }
need panel/public/assets/customer.js 'f.reset(); renderDatabaseEngines();'

echo 'PASS: Privora 6.71 Roundcube provisioning + database UI regression contract.'
