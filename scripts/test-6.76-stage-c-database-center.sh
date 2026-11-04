#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[6-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]
grep -Fq 'GET /v1/databases/{name}/inspect' "$ROOT/agent/internal/api/server.go"
grep -Fq 'POST /v1/databases/{name}/maintenance' "$ROOT/agent/internal/api/server.go"
grep -Fq 'POST /v1/databases/{name}/export' "$ROOT/agent/internal/api/server.go"
grep -Fq 'POST /v1/databases/{name}/import' "$ROOT/agent/internal/api/server.go"
grep -Fq 'import source must remain inside the hosting account home directory' "$ROOT/agent/internal/hostadapter/database_admin.go"
grep -Fq '2 GiB safety limit' "$ROOT/agent/internal/hostadapter/database_admin.go"
grep -Fq 'single-transaction' "$ROOT/agent/internal/hostadapter/database_admin.go"
grep -Fq 'data-db-inspect' "$ROOT/panel/public/assets/app.js"
grep -Fq 'data-db-export' "$ROOT/panel/public/assets/app.js"
(cd "$ROOT/agent" && go test ./...)
php -l "$ROOT/panel/public/api.php" >/dev/null
php -l "$ROOT/panel/public/admin.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js"
echo 'PASS: 6.76 Stage C Database Center'
