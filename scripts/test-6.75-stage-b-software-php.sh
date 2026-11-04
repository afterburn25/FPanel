#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[5-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]
grep -Fq 'GET /v1/components/presets' "$ROOT/agent/internal/api/server.go"
grep -Fq 'POST /v1/components/presets/{id}/apply' "$ROOT/agent/internal/api/server.go"
grep -Fq 'GET /v1/php/versions' "$ROOT/agent/internal/api/server.go"
grep -Fq 'GET /v1/php/extensions' "$ROOT/agent/internal/api/server.go"
grep -Fq 'PHP 8.4 is protected because Privora control-plane services depend on it' "$ROOT/agent/internal/hostadapter/software_center.go"
grep -Fq 'Bundled with PHP' "$ROOT/panel/public/assets/app.js"
grep -Fq 'WordPress' "$ROOT/agent/internal/hostadapter/software_center.go"
grep -Fq 'WooCommerce' "$ROOT/agent/internal/hostadapter/software_center.go"
grep -Fq 'Video Processing' "$ROOT/agent/internal/hostadapter/software_center.go"
(cd "$ROOT/agent" && go test ./internal/hostadapter ./internal/api)
php -l "$ROOT/panel/public/api.php" >/dev/null
php -l "$ROOT/panel/public/admin.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js"
echo 'PASS: 6.75 Stage B Software Center / MultiPHP / presets'
