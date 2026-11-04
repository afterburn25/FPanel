#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
v="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$v" =~ ^5\.0\.0-dev\.6\.(7[7-9]|8[0-9]|90)$ || "$v" == "5.0.0-dev.7.0" ]]
for route in 'GET /v1/ssl/{domain}/inspect' 'POST /v1/ssl/{domain}/csr' 'POST /v1/ssl/{domain}/custom' 'POST /v1/ssl/{domain}/revoke'; do grep -Fq "$route" "$ROOT/agent/internal/api/server.go"; done
grep -Fq 'certificate and private key do not match' "$ROOT/agent/internal/hostadapter/certificate_admin.go"
grep -Fq 'certificate does not cover the requested domain' "$ROOT/agent/internal/hostadapter/certificate_admin.go"
grep -Fq 'private key is written mode 0600' "$ROOT/panel/public/admin.php"
grep -Fq 'restore an HTTP-only vhost' "$ROOT/panel/public/assets/app.js"
(cd "$ROOT/agent" && go test ./...)
php -l "$ROOT/panel/public/api.php" >/dev/null
php -l "$ROOT/panel/public/admin.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js"
echo 'PASS: 6.77 Stage D certificate lifecycle'
