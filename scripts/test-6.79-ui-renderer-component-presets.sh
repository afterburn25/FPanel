#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$ver" =~ ^5\.0\.0-dev\.6\.(79|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo "FAIL: expected supported 6.79+ cumulative lineage through 7.0, got $ver" >&2; exit 1; }
JS="$ROOT/panel/public/assets/app.js"
ADMIN="$ROOT/panel/public/admin.php"
CSS="$ROOT/panel/public/assets/app.css"

node --check "$JS" >/dev/null
php -l "$ADMIN" >/dev/null

# Every renderX() call in PCC JavaScript must have an actual function definition.
python3 - "$JS" <<'PY'
import re, sys
s=open(sys.argv[1],encoding='utf-8').read()
calls=set(re.findall(r'\b(render[A-Z][A-Za-z0-9_]*)\s*\(',s))
defs=set(re.findall(r'function\s+(render[A-Z][A-Za-z0-9_]*)\s*\(',s))
missing=sorted(calls-defs)
if missing:
    raise SystemExit('FAIL: undefined PCC renderers: '+', '.join(missing))
for required in ('renderPhp','renderInventoryDiagnostics','renderSites','renderComponents'):
    if required not in defs:
        raise SystemExit('FAIL: required renderer missing: '+required)
print('renderer completeness PASS:', len(calls), 'renderers')
PY

grep -Fq 'function renderPhp(rows)' "$JS"
grep -Fq 'function renderInventoryDiagnostics(inv,accounts,sites)' "$JS"
grep -Fq 'function setComponentCategory(category)' "$JS"
grep -Fq 'function clearComponentFilters()' "$JS"
if [[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[1-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]; then
  CTRL="$ROOT/panel/public/assets/components.js"
  grep -Fq "search?.addEventListener('input',render)" "$CTRL"
  grep -Fq "search?.addEventListener('search',render)" "$CTRL"
  grep -Fq "tabs?.addEventListener('click'" "$CTRL"
  grep -Fq "clear?.addEventListener('click'" "$CTRL"
else
  grep -Fq "document.addEventListener('input',e=>{if(e.target.matches('#componentSearch'))renderComponents()})" "$JS"
  grep -Fq "document.addEventListener('search',e=>{if(e.target.matches('#componentSearch'))renderComponents()})" "$JS"
  grep -Fq "const componentTab=e.target.closest('#componentCategoryTabs [data-component-category]')" "$JS"
  grep -Fq "if(e.target.closest('#componentClearFilter'))" "$JS"
fi
grep -Fq 'aria-selected' "$JS"
grep -Fq 'componentResultCount' "$ADMIN"
grep -Fq 'data-page="presets"' "$ADMIN"
grep -Fq 'data-view="presets"' "$ADMIN"
grep -Fq '<h2>Smart Presets</h2>' "$ADMIN"
grep -Fq "presets:'Smart presets'" "$JS"
grep -Fq "if(page==='presets')refreshSmartPresets()" "$JS"
grep -Fq "\$('refreshSmartPresets')?.addEventListener('click',refreshSmartPresets)" "$JS"
grep -Fq '6.79 component catalog interaction/layout recovery' "$CSS"

# The installable component catalog must appear before secondary PHP inventory cards.
python3 - "$ADMIN" <<'PY'
import re, sys
s=open(sys.argv[1],encoding='utf-8').read()
m=re.search(r'<section class="page" data-view="components">(.*?)</section>\s*<section class="page" data-view="presets">',s,re.S)
if not m:
    raise SystemExit('FAIL: components and presets pages are not separated')
body=m.group(1)
for forbidden in ('id="softwarePresetList"','<h3>Smart presets</h3>'):
    if forbidden in body:
        raise SystemExit('FAIL: Smart Presets are still mixed into Extensions & Components')
positions={
    'toolbar':body.find('id="componentCategoryTabs"'),
    'catalog':body.find('id="componentCatalog"'),
    'php':body.find('id="phpVersionCatalog"'),
}
if min(positions.values()) < 0 or not (positions['toolbar'] < positions['catalog'] < positions['php']):
    raise SystemExit('FAIL: component install cards are not positioned directly above secondary PHP inventory')
print('component page ordering PASS')
PY

printf 'PASS: 6.79 renderer completeness / component filters / Smart Presets separation\n'
