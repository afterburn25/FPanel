#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
fail(){ echo "FAIL: $*" >&2; exit 1; }
v="$(tr -d '[:space:]' < "$ROOT/VERSION")"; [[ "$v" == "5.0.0-dev.6.90" || "$v" == "5.0.0-dev.7.0" ]] || fail "VERSION is not supported 6.90+ cumulative lineage through 7.0"
for f in panel/public/admin.php panel/public/customer.php panel/public/api.php panel/public/assets/app.js panel/public/assets/customer.js panel/public/assets/app.css install/privora-install.sh; do
  [[ -s "$ROOT/$f" ]] || fail "missing $f"
done
php -l "$ROOT/panel/public/admin.php" >/dev/null
php -l "$ROOT/panel/public/customer.php" >/dev/null
php -l "$ROOT/panel/public/api.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js" >/dev/null
node --check "$ROOT/panel/public/assets/customer.js" >/dev/null
bash -n "$ROOT/install/privora-install.sh"

# PCC/PPanel must not expose dead navigation destinations or duplicate DOM IDs.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re,sys
r=Path(sys.argv[1])
checks=[('panel/public/admin.php',r'data-page="([^"]+)"',r'data-view="([^"]+)"',30),('panel/public/customer.php',r'data-cp-nav="([^"]+)"',r'data-cp-view="([^"]+)"',40)]
for rel,navpat,viewpat,minimum in checks:
 t=(r/rel).read_text()
 nav=set(re.findall(navpat,t)); views=set(re.findall(viewpat,t))
 missing=sorted(nav-views)
 if missing: raise SystemExit(f'{rel}: dead navigation targets: {missing}')
 if len(nav)<minimum: raise SystemExit(f'{rel}: navigation unexpectedly shrank: {len(nav)} < {minimum}')
 ids=re.findall(r'\bid="([^"]+)"',t)
 dup=sorted({x for x in ids if ids.count(x)>1})
 if dup: raise SystemExit(f'{rel}: duplicate ids: {dup}')
 print(f'{rel}: navigation={len(nav)} views={len(views)} duplicate_ids=0')
PY

# Missing WHM/PCC destinations are now real pages or intentionally consolidated.
grep -Fq 'data-view="firewall"' "$ROOT/panel/public/admin.php" || fail "Firewall Manager page missing"
grep -Fq 'Firewall Manager' "$ROOT/panel/public/admin.php" || fail "Firewall Manager heading missing"
grep -Fq 'data-view="resellers"' "$ROOT/panel/public/admin.php" || fail "Reseller Center page missing"
grep -Fq 'Reseller Center' "$ROOT/panel/public/admin.php" || fail "Reseller Center heading missing"
grep -Fq 'Fleet, cloud, automation & fabric' "$ROOT/panel/public/admin.php" || fail "consolidated Platform Labs missing"
for dead in 'data-page="fleet"' 'data-page="cloud"' 'data-page="automation"' 'data-page="fabric"'; do
  ! grep -Fq "$dead" "$ROOT/panel/public/admin.php" || fail "legacy dead PCC destination remains: $dead"
done

# Existing secure TOTP backend must be reachable from both shells, not duplicated.
grep -Fiq 'Two-factor authentication' "$ROOT/panel/public/admin.php" || fail "PCC 2FA UI missing"
grep -Fiq 'Two-factor authentication' "$ROOT/panel/public/customer.php" || fail "PPanel 2FA UI missing"
for route in mfa-status mfa-begin mfa-confirm mfa-disable; do grep -Fq "route==='${route}'" "$ROOT/panel/public/api.php" || fail "API route missing: $route"; done
grep -Fq "api('mfa-begin'" "$ROOT/panel/public/assets/app.js" || fail "PCC 2FA begin binding missing"
grep -Fq "api('mfa-begin'" "$ROOT/panel/public/assets/customer.js" || fail "PPanel 2FA begin binding missing"
grep -Fq 'verifyMfaCode' "$ROOT/panel/src/Auth.php" || fail "TOTP verifier backend missing"

# PPanel Disk Usage is a Files capability with its own scoped route, not a Metrics-only 403 trap.
grep -Fq 'data-cp-view="disk-usage"' "$ROOT/panel/public/customer.php" || fail "Disk Usage page missing"
grep -Fq "route==='customer-disk-usage'" "$ROOT/panel/public/api.php" || fail "Disk Usage API route missing"
grep -Fq "requireCustomerFeature(\$store,\$client,\$customerScope,'files')" "$ROOT/panel/public/api.php" || fail "Disk Usage route is not account Files-scoped"
grep -Fq "'disk-usage':'files'" "$ROOT/panel/public/assets/customer.js" || fail "Disk Usage feature visibility mapping missing"
grep -Fq "api('customer-disk-usage')" "$ROOT/panel/public/assets/customer.js" || fail "Disk Usage frontend does not use dedicated route"

# Goal-based efficiency and actionable PCC status.
grep -Fq 'cp-goal-strip' "$ROOT/panel/public/customer.php" || fail "PPanel quick-start strip missing"
grep -Fiq 'needs attention' "$ROOT/panel/public/admin.php" || fail "PCC Needs Attention workspace missing"
grep -Fq 'commandSynonyms' "$ROOT/panel/public/assets/app.js" || fail "PCC command search synonyms missing"
grep -Fq "e.key==='/'" "$ROOT/panel/public/assets/customer.js" || fail "PPanel slash-search shortcut missing"

# Prevent recurrence of the exact 6.89 runtime-version/HTTP-503 permission incident.
grep -Fq 'chmod 0755 "$PANEL_ROOT" "$PANEL_ROOT/panel"' "$ROOT/install/privora-install.sh" || fail "Nginx traversal repair missing"
grep -Fq 'chown root:privora-panel "$PANEL_ROOT/VERSION"' "$ROOT/install/privora-install.sh" || fail "VERSION ownership reconciliation missing"
grep -Fq 'chmod 0640 "$PANEL_ROOT/VERSION"' "$ROOT/install/privora-install.sh" || fail "VERSION protected readability missing"
grep -Fq 'runuser -u privora-panel -- test -r "$PANEL_ROOT/VERSION"' "$ROOT/install/privora-install.sh" || fail "VERSION readability certification missing"
grep -Fq 'runuser -u "$webuser" -- test -r "$PANEL_ROOT/panel/public/index.php"' "$ROOT/install/privora-install.sh" || fail "Nginx public-tree certification missing"
grep -Fq 'chown root:privora-panel "$PANEL_ROOT/VERSION.new"' "$ROOT/install/privora-install.sh" || fail "atomic VERSION commit ownership missing"
grep -Fq 'chmod 0640 "$PANEL_ROOT/VERSION.new"' "$ROOT/install/privora-install.sh" || fail "atomic VERSION commit mode missing"

# Static frontend API route strings must all be represented in api.php.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re,sys
r=Path(sys.argv[1]); api=(r/'panel/public/api.php').read_text()
for rel in ['panel/public/assets/app.js','panel/public/assets/customer.js']:
 t=(r/rel).read_text(); routes=sorted(set(re.findall(r"\bapi\('([^']+)'",t)))
 bases=sorted({re.split(r'[&?]',x,maxsplit=1)[0] for x in routes})
 missing=[x for x in bases if x not in api]
 if missing: raise SystemExit(f'{rel}: frontend API route strings missing from api.php: {missing}')
 print(f'{rel}: static_api_routes={len(bases)} all represented')
PY

echo 'PASS: 6.90 panel coverage / efficiency / three-pass UX polish regression gate'
