#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
API="$ROOT/panel/public/api.php"
STORE="$ROOT/panel/src/Store.php"

grep -Fq "in_array(\$rawPackage,['automatic','detected','discovered'],true)" "$API" || { echo "FAIL: detected/discovered capacity bypass missing" >&2; exit 1; }
grep -Fq "Database user','sites'=>'Website" "$API" || { echo "FAIL: precise quota labels missing" >&2; exit 1; }
grep -Fq "limit reached ('" "$API" || { echo "FAIL: precise used/limit quota error missing" >&2; exit 1; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/state.json" <<'JSON'
{"users":[],"feature_lists":[{"name":"Default","features":["databases"]}],"packages":[{"name":"Starter","sites":2},{"name":"LegacyCustom","sites":3,"database_users":7}],"settings":{},"events":[]}
JSON
php -r '
require $argv[1];
$s=new Store($argv[2]); $s->ensurePackageDefaults();
$p=[]; foreach($s->packages() as $x){$p[$x["name"]]=$x;}
if(($p["Starter"]["databases"]??-1)!==5) {fwrite(STDERR,"Starter databases backfill failed\n");exit(1);}
if(($p["Starter"]["database_users"]??-1)!==5) {fwrite(STDERR,"Starter database_users backfill failed\n");exit(1);}
if(($p["LegacyCustom"]["databases"]??-1)!==7) {fwrite(STDERR,"custom databases backfill failed\n");exit(1);}
' "$STORE" "$tmp/state.json"
echo "PASS: Rev5R2 database package capacity compatibility gate"
