#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo "FAIL: expected supported 6.80+ cumulative lineage through 7.0, got $ver" >&2; exit 1; }
INDEX="$ROOT/panel/public/index.php"; ADMIN="$ROOT/panel/public/admin.php"; CUSTOMER="$ROOT/panel/public/customer.php"; NGINX="$ROOT/scripts/render-panel-nginx.py"; JS="$ROOT/panel/public/assets/app.js"; CUSTOMER_JS="$ROOT/panel/public/assets/customer.js"; CSS="$ROOT/panel/public/assets/app.css"
grep -Fq 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' "$INDEX"
if [[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[2-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]; then
  grep -Fq "header('X-Privora-Build: '.\$privoraBuild);" "$INDEX"
  grep -Fq 'app.css?v=<?=$privoraAssetVersion?>' "$INDEX"
  grep -Fq 'app.css?v=<?=$privoraAssetVersion?>' "$ADMIN"
  grep -Fq 'app.js?v=<?=$privoraAssetVersion?>' "$ADMIN"
  grep -Fq 'data-privora-build="<?=htmlspecialchars($privoraBuild,ENT_QUOTES)?>"' "$ADMIN"
  grep -Fq 'app.css?v=<?=$privoraAssetVersion?>' "$CUSTOMER"
  grep -Fq 'customer.js?v=<?=$privoraAssetVersion?>' "$CUSTOMER"
  grep -Fq 'data-privora-build="<?=htmlspecialchars($privoraBuild,ENT_QUOTES)?>"' "$CUSTOMER"
  grep -Fq "const PRIVORA_UI_BUILD=document.body?.dataset?.privoraBuild||'unknown';" "$JS"
  grep -Fq "const PRIVORA_PPANEL_UI_BUILD=document.body?.dataset?.privoraBuild||'unknown';" "$CUSTOMER_JS"
else
  grep -Fq "X-Privora-Build: $ver" "$INDEX"
  grep -Fq "app.css?v=$ver" "$INDEX"
  grep -Fq "app.css?v=$ver" "$ADMIN"
  grep -Fq "app.js?v=$ver" "$ADMIN"
  grep -Fq "data-privora-build=\"$ver\"" "$ADMIN"
  grep -Fq "app.css?v=$ver" "$CUSTOMER"
  grep -Fq "customer.js?v=$ver" "$CUSTOMER"
  grep -Fq "data-privora-build=\"$ver\"" "$CUSTOMER"
  grep -Fq "const PRIVORA_UI_BUILD='$ver';" "$JS"
  grep -Fq "const PRIVORA_PPANEL_UI_BUILD='$ver';" "$CUSTOMER_JS"
fi
grep -Fq '6.80 runtime UI cache convergence' "$CSS"
grep -Fq 'add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;' "$NGINX"
grep -Fq 'function renderPhp(rows)' "$JS"
grep -Fq 'function renderInventoryDiagnostics(' "$JS"
grep -Fq 'componentCategoryTabs' "$ADMIN"
grep -Fq 'componentSearch' "$ADMIN"
grep -Fq 'data-view="presets"' "$ADMIN"
grep -Fq "if(page==='presets')refreshSmartPresets()" "$JS"
php -l "$INDEX" >/dev/null
php -l "$ADMIN" >/dev/null
php -l "$CUSTOMER" >/dev/null
node --check "$JS" >/dev/null
node --check "$CUSTOMER_JS" >/dev/null
python3 -m py_compile "$NGINX"
printf 'PASS: 6.80 runtime UI cache/convergence contract retained on %s\n' "$ver"
