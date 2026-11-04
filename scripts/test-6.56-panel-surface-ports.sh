#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$V" =~ ^5\.0\.0-dev\.6\.[0-9]+$ || "$V" == "5.0.0-dev.7.0" ]]

grep -Fq 'WEB_PORT="${PRIVORA_ADMIN_PANEL_PORT:-8443}"' "$ROOT/install/privora-install.sh"
grep -Fq 'HOSTING_PORT="${PRIVORA_HOSTING_PANEL_PORT:-2443}"' "$ROOT/install/privora-install.sh"
grep -Fq -- '--hosting-port PORT' "$ROOT/install/privora-install.sh"
grep -Fq 'tcp dport { 22, 80, 443, $WEB_PORT, $HOSTING_PORT$mail_ports } accept' "$ROOT/install/privora-install.sh"
grep -Fq 'selected $HOSTING_PORT instead' "$ROOT/install/privora-install.sh"
grep -Fq 'render-panel-nginx.py' "$ROOT/install/privora-install.sh"
grep -Fq 'openHostingPanelLink' "$ROOT/panel/public/admin.php"
grep -Fq 'PRIVORA_HOSTING_PANEL_PORT' "$ROOT/panel/public/admin.php"
grep -Fq 'privora_pcc_session' "$ROOT/panel/src/Auth.php"
grep -Fq 'privora_ppanel_session' "$ROOT/panel/src/Auth.php"
grep -Fq "'wrong_surface'" "$ROOT/panel/src/Auth.php"
grep -Fq 'surfaceAllowsUser' "$ROOT/panel/src/Auth.php"
grep -Fq 'PRIVORA_PANEL_SURFACE {surface}' "$ROOT/scripts/render-panel-nginx.py"
grep -Fq 'Privora Panel (PPanel) port $requested is occupied' "$ROOT/scripts/apply-recovery-vhost.sh"
grep -Fq 'PRIVORA_HOSTING_PANEL_PORT=$hosting_port' "$ROOT/scripts/apply-recovery-vhost.sh"

# Validate the renderer itself, including port separation and direct-entrypoint blocking.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 "$ROOT/scripts/render-panel-nginx.py" --admin-port 8443 --hosting-port 2443 --server-name panel.example.test --fpm-socket /run/php/privora-panel.sock >"$tmp/panel.conf"
[[ "$(grep -Fc 'server {' "$tmp/panel.conf")" -eq 2 ]]
grep -Fq 'listen 8443 ssl http2;' "$tmp/panel.conf"
grep -Fq 'listen 2443 ssl http2;' "$tmp/panel.conf"
[[ "$(grep -Fc 'location = /admin.php { return 404; }' "$tmp/panel.conf")" -eq 2 ]]
[[ "$(grep -Fc 'location = /customer.php { return 404; }' "$tmp/panel.conf")" -eq 2 ]]

# Prove session cookies are separated by surface and role admission is enforced.
AUTH="$ROOT/panel/src/Auth.php"
php -d session.save_path="$tmp" -r '$_SERVER["PRIVORA_PANEL_SURFACE"]="admin"; require $argv[1]; Auth::startSession(); if(session_name()!=="privora_pcc_session") exit(2); if(!Auth::surfaceAllowsUser(["role"=>"root-admin"])) exit(3); if(Auth::surfaceAllowsUser(["role"=>"hosting-user"])) exit(4);' "$AUTH"
php -d session.save_path="$tmp" -r '$_SERVER["PRIVORA_PANEL_SURFACE"]="hosting"; require $argv[1]; Auth::startSession(); if(session_name()!=="privora_ppanel_session") exit(2); if(!Auth::surfaceAllowsUser(["role"=>"hosting-user"])) exit(3); if(Auth::surfaceAllowsUser(["role"=>"server-admin"])) exit(4);' "$AUTH"

echo 'PASS: PCC 8443 / PPanel 2443 split, fallback, link and session isolation'
