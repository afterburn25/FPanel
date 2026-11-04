#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ADAPTER="$ROOT/agent/internal/hostadapter/adapter.go"
API="$ROOT/panel/public/api.php"
ADMIN="$ROOT/panel/public/assets/app.js"
CUSTOMER="$ROOT/panel/public/assets/customer.js"
CUSTOMER_PHP="$ROOT/panel/public/customer.php"
RENDER="$ROOT/scripts/render-panel-nginx.py"
CFG="$ROOT/scripts/configure-phpmyadmin.sh"
grep -Fq 'phpMyAdminCapability' "$ADAPTER"
grep -Fq 'launch=/phpmyadmin/; panel-session-gated' "$ADAPTER"
grep -Fq "route==='phpmyadmin-auth'" "$API"
grep -Fq "requireCustomerFeature(\$store,\$client,\$customerScope,'phpmyadmin')" "$API"
grep -Fq "requirePermission('resources.write')" "$API"
grep -Fq 'phpMyAdmin READY' "$ADMIN"
grep -Fq 'id="phpMyAdminTile"' "$CUSTOMER_PHP"
grep -Fq "window.open(launchUrl, '_blank', 'noopener')" "$CUSTOMER"
grep -Fq 'location /phpmyadmin/' "$RENDER"
grep -Fq 'auth_request /_privora_phpmyadmin_auth;' "$RENDER"
grep -Fq 'fastcgi_param HTTP_COOKIE $http_cookie;' "$RENDER"
grep -Fq 'phpmyadmin-fpm-socket' "$RENDER"
grep -Fq 'phpmyadmin phpmyadmin/dbconfig-install boolean false' "$CFG"
grep -Fq '[privora-phpmyadmin]' "$CFG"
grep -Fq "AllowRoot" "$CFG"
grep -Fq "AllowArbitraryServer" "$CFG"
grep -Fq 'unauthenticated phpMyAdmin route is not fail-closed' "$CFG"
python3 "$RENDER" --admin-port 8443 --hosting-port 2443 --server-name panel.example.test --fpm-socket /run/php/privora-panel.sock --phpmyadmin-fpm-socket /run/php/php8.4-fpm-privora-phpmyadmin.sock >"${TMPDIR:-/tmp}/privora-669-pma-nginx.$$"
OUT="${TMPDIR:-/tmp}/privora-669-pma-nginx.$$"
[[ "$(grep -Fc 'location /phpmyadmin/' "$OUT")" -eq 2 ]]
[[ "$(grep -Fc 'auth_request /_privora_phpmyadmin_auth;' "$OUT")" -eq 4 ]]
[[ "$(grep -Fc 'fastcgi_pass unix:/run/php/php8.4-fpm-privora-phpmyadmin.sock;' "$OUT")" -eq 2 ]]
rm -f "$OUT"
echo 'PASS: 6.69 first-class panel-gated phpMyAdmin integration'
