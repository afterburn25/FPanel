#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
fail(){ echo "FAIL: $*" >&2; exit 1; }
[[ "$(tr -d '[:space:]' < "$ROOT/VERSION")" == "5.0.0-dev.7.0" ]] || fail "VERSION is not 7.0"
grep -Fq 'currentVersion = "5.0.0-dev.7.0"' "$ROOT/agent/internal/api/version.go" || fail "Agent API version is not 7.0"
grep -Fq 'PRIVORA_VERSION="5.0.0-dev.7.0"' "$ROOT/install/privora-install.sh" || fail "installer version is not 7.0"
grep -Fq "'privora_version'=>'5.0.0-dev.7.0'" "$ROOT/install/privora-install.sh" || fail "host profile version is not 7.0"

for f in panel/public/admin.php panel/public/customer.php panel/public/api.php panel/public/external-api.php panel/public/assets/app.js panel/public/assets/customer.js panel/public/assets/v7-admin.js panel/public/assets/v7-customer.js panel/public/assets/app.css agent/internal/api/server_v7.go agent/internal/platform/v7.go install/privora-install.sh; do
  [[ -s "$ROOT/$f" ]] || fail "missing $f"
done
php -l "$ROOT/panel/public/admin.php" >/dev/null
php -l "$ROOT/panel/public/customer.php" >/dev/null
php -l "$ROOT/panel/public/api.php" >/dev/null
php -l "$ROOT/panel/public/external-api.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js" >/dev/null
node --check "$ROOT/panel/public/assets/customer.js" >/dev/null
node --check "$ROOT/panel/public/assets/v7-admin.js" >/dev/null
node --check "$ROOT/panel/public/assets/v7-customer.js" >/dev/null
bash -n "$ROOT/install/privora-install.sh"

# Pass 1: structural/function coverage; no dead destinations or duplicated IDs.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re,sys
r=Path(sys.argv[1])
checks=[('panel/public/admin.php',r'data-page="([^"]+)"',r'data-view="([^"]+)"',30),('panel/public/customer.php',r'data-cp-nav="([^"]+)"',r'data-cp-view="([^"]+)"',40)]
for rel,navpat,viewpat,expected in checks:
    t=(r/rel).read_text(); nav=set(re.findall(navpat,t)); views=set(re.findall(viewpat,t))
    if nav != views: raise SystemExit(f'{rel}: navigation/view mismatch missing={sorted(nav-views)} orphan={sorted(views-nav)}')
    if len(nav) != expected: raise SystemExit(f'{rel}: expected {expected} destinations, got {len(nav)}')
    ids=re.findall(r'\bid="([^"]+)"',t); dup=sorted({x for x in ids if ids.count(x)>1})
    if dup: raise SystemExit(f'{rel}: duplicate IDs: {dup}')
    print(f'{rel}: navigation={len(nav)}/{len(views)} duplicate_ids=0')
PY

# 6.91–7.0 host/API train is registered.
for needle in \
 'GET /v1/mail/queue' 'GET /v1/mail/delivery' 'GET /v1/mail/filters' \
 'POST /v1/backup/policies' 'POST /v1/backup/policies/{id}/run' \
 'GET /v1/monitoring/live' 'GET /v1/security/advisor' \
 'POST /v1/sites/{domain}/policy' 'GET /v1/databases/activity' \
 'GET /v1/apps/discover' 'GET /v1/dns/zones/{domain}/dnssec' 'GET /v1/dns/templates' \
 'GET /v1/readiness' 'POST /v1/readiness/repair'; do
  grep -Fq "$needle" "$ROOT/agent/internal/api/server.go" || fail "Agent route missing: $needle"
done

# All new JS bridge routes must exist in api.php.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re,sys
r=Path(sys.argv[1]); api=(r/'panel/public/api.php').read_text()
for rel in ['panel/public/assets/v7-admin.js','panel/public/assets/v7-customer.js']:
    t=(r/rel).read_text(); calls=sorted(set(re.findall(r"\bapi\('([^']+)'",t)))
    bases=sorted({re.split(r'[&?]',x,maxsplit=1)[0] for x in calls})
    missing=[x for x in bases if f"'{x}'" not in api]
    if missing: raise SystemExit(f'{rel}: missing api.php routes: {missing}')
    print(f'{rel}: routes={len(bases)} all represented')
PY

# Pass 1 truthfulness: no legacy fake/placeholder primary workflows.
for bad in 'Mock-certified foundation' 'SAFE MOCK FILES' 'DEPLOYMENT SIM' 'Backup Restore'; do
  ! grep -Fq "$bad" "$ROOT/panel/public/admin.php" "$ROOT/panel/public/customer.php" || fail "legacy primary UI placeholder remains: $bad"
done
! grep -Fq 'data-cp-view="restore"' "$ROOT/panel/public/customer.php" || fail "legacy restore request view remains"
! grep -Fq 'data-cp-nav="restore"' "$ROOT/panel/public/customer.php" || fail "legacy restore navigation remains"
grep -Fq 'Fleet, cloud, automation & fabric' "$ROOT/panel/public/admin.php" || fail "explicit Platform Labs capability-gated workspace missing"

# Pass 2: background work and executable policy boundaries.
grep -Fq 'agentServer.StartBackground(bgCtx)' "$ROOT/agent/cmd/privora-agent/main.go" || fail "Agent background worker is not started"
grep -Fq 'func (s *Server) StartBackground' "$ROOT/agent/internal/api/server_v7.go" || fail "background worker missing"
grep -Fq 'map[string]bool{"site": true, "account": true}' "$ROOT/agent/internal/platform/v7.go" || fail "backup policy accepts unsupported scopes"
grep -Fq 'scheduled live backup supports account or site scope' "$ROOT/agent/internal/api/server_v7.go" || fail "backup executor scope fail-closed check missing"
grep -Fq 'customer-backup-policy-run' "$ROOT/panel/public/api.php" || fail "PPanel backup Run now route missing"

# Pass 2 customer ownership/safety boundaries.
for route in customer-mail-delivery customer-mail-filters customer-backup-policy-save customer-api-key-create customer-site-policy-save customer-database-activity customer-apps-discover customer-dnssec-status; do
  grep -Fq "route==='${route}'" "$ROOT/panel/public/api.php" || fail "customer route missing: $route"
done
grep -Fq 'requireCustomerDomain' "$ROOT/panel/public/api.php" || fail "customer domain ownership helper missing"
grep -Fq 'customerDatabaseNames' "$ROOT/panel/public/api.php" || fail "customer database ownership filtering missing"

# Security Advisor must not offer/apply SSH hardening that can strand the administrator.
grep -Fq 'func hasAdministrativeSSHKeyV7' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail "SSH-key safety preflight missing"
grep -Fq 'if !hasAdministrativeSSHKeyV7()' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail "SSH hardening lockout guard missing"

# 7.0 Repair All must be a real backend action surfaced in PCC.
grep -Fq 'if in.Action == "repair-all"' "$ROOT/agent/internal/api/server_v7.go" || fail "repair-all backend missing"
grep -Fq 'Repair all safe items' "$ROOT/panel/public/admin.php" || fail "Repair All PCC control missing"
grep -Fq "action:'repair-all'" "$ROOT/panel/public/assets/v7-admin.js" || fail "Repair All frontend binding missing"

# Pass 3: v7 workbenches/assets and critical permission hardening survive cumulative train.
grep -Fq '/assets/v7-admin.js' "$ROOT/panel/public/admin.php" || fail "v7 admin asset missing"
grep -Fq '/assets/v7-customer.js' "$ROOT/panel/public/customer.php" || fail "v7 customer asset missing"
grep -Fq 'chmod 0755 "$PANEL_ROOT" "$PANEL_ROOT/panel"' "$ROOT/install/privora-install.sh" || fail "Nginx traversal hardening missing"
grep -Fq 'chown root:privora-panel "$PANEL_ROOT/VERSION"' "$ROOT/install/privora-install.sh" || fail "VERSION ownership hardening missing"
grep -Fq 'chmod 0640 "$PANEL_ROOT/VERSION"' "$ROOT/install/privora-install.sh" || fail "VERSION mode hardening missing"
grep -Fq 'runuser -u "$webuser" -- test -r "$PANEL_ROOT/panel/public/index.php"' "$ROOT/install/privora-install.sh" || fail "Nginx path certification missing"

# Release docs must cover each sequential release.
for v in 6.91 6.92 6.93 6.94 6.95 6.96 6.97 6.98 6.99 7.0; do [[ -s "$ROOT/RELEASE-$v.md" ]] || fail "missing RELEASE-$v.md"; done

echo 'PASS: 7.0 cumulative 6.91–7.0 functionality + three-polish-pass regression gate'
