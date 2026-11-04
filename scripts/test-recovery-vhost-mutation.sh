#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 -m py_compile "$ROOT/scripts/render-panel-nginx.py"
python3 "$ROOT/scripts/render-panel-nginx.py" \
  --admin-port 8443 --hosting-port 2443 \
  --server-name panel.example.test \
  --fpm-socket /run/php/privora-panel.sock \
  --panel-root /opt/privora-panel >"$tmp/privora-panel.conf"

grep -Fq '# Privora Panel dual-surface control plane' "$tmp/privora-panel.conf"
grep -Fq 'listen 8443 ssl http2;' "$tmp/privora-panel.conf"
grep -Fq 'listen 2443 ssl http2;' "$tmp/privora-panel.conf"
grep -Fq 'fastcgi_param PRIVORA_PANEL_SURFACE admin;' "$tmp/privora-panel.conf"
grep -Fq 'fastcgi_param PRIVORA_PANEL_SURFACE hosting;' "$tmp/privora-panel.conf"
[[ "$(grep -Fc 'fastcgi_intercept_errors off;' "$tmp/privora-panel.conf")" -ge 2 ]]
[[ "$(grep -Fc 'fastcgi_intercept_errors on;' "$tmp/privora-panel.conf")" -eq 2 ]]
[[ "$(grep -Fc 'Privora API temporarily unavailable' "$tmp/privora-panel.conf")" -eq 2 ]]
grep -Fq 'location = /admin.php { return 404; }' "$tmp/privora-panel.conf"
grep -Fq 'location = /customer.php { return 404; }' "$tmp/privora-panel.conf"
echo 'recovery-safe dual-surface Nginx rendering PASS'
