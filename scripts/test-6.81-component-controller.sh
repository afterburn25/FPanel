#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[1-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo "FAIL: expected supported 6.81+ cumulative lineage through 7.0, got $ver" >&2; exit 1; }
ADMIN="$ROOT/panel/public/admin.php"; APP="$ROOT/panel/public/assets/app.js"; CTRL="$ROOT/panel/public/assets/components.js"; API="$ROOT/panel/public/api.php"
[[ -s "$CTRL" ]] || { echo "FAIL: dedicated component controller missing" >&2; exit 1; }
node --check "$CTRL" >/dev/null
node --check "$APP" >/dev/null
if [[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[2-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]; then
  grep -Fq 'components.js?v=<?=$privoraAssetVersion?>' "$ADMIN"
  grep -Fq "document.addEventListener('click',event=>{const installButton" "$CTRL"
else
  grep -Fq 'components.js?v=5.0.0-dev.6.81' "$ADMIN"
  grep -Fq "catalog.addEventListener('click'" "$CTRL"
fi
grep -Fq 'window.PrivoraComponents={active:true' "$CTRL"
grep -Fq "search?.addEventListener('input',render)" "$CTRL"
grep -Fq "tabs?.addEventListener('click'" "$CTRL"
if [[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[3-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]; then
  grep -Fq "request('software-job-start',{method:'POST'" "$CTRL"
  grep -Fq "pollJob(job)" "$CTRL"
else
  grep -Fq "request('component-install',{method:'POST'" "$CTRL"
  grep -Fq "request('component-remove',{method:'POST'" "$CTRL"
fi
grep -Fq "refreshButton?.addEventListener('click'" "$CTRL"
grep -Fq 'if(componentControl&&window.PrivoraComponents?.active)return' "$APP"
grep -Fq "if(!window.PrivoraComponents?.active&&e.target.matches('#componentSearch'))" "$APP"
grep -Fq "if(\$route==='component-install')" "$API"
grep -Fq "if(\$route==='component-remove')" "$API"
printf 'PASS: 6.81 dedicated Extensions & Components controller contract retained on %s\n' "$ver"
