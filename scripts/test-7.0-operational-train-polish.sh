#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
fail(){ echo "FAIL: $*" >&2; exit 1; }
v="$(tr -d '[:space:]' < "$ROOT/VERSION")"; [[ "$v" == "5.0.0-dev.7.0" ]] || fail "VERSION must be 5.0.0-dev.7.0"
for f in panel/public/admin.php panel/public/customer.php panel/public/api.php panel/public/external-api.php panel/public/assets/app.js panel/public/assets/customer.js panel/public/assets/v7-admin.js panel/public/assets/v7-customer.js panel/public/assets/app.css agent/internal/api/server_v7.go agent/internal/api/server_v7_test.go agent/internal/hostadapter/v7_mail_backup_monitor.go agent/internal/hostadapter/v7_site_db_app_dns.go agent/internal/platform/v7.go; do [[ -s "$ROOT/$f" ]] || fail "missing $f"; done
php -l "$ROOT/panel/public/admin.php" >/dev/null
php -l "$ROOT/panel/public/customer.php" >/dev/null
php -l "$ROOT/panel/public/api.php" >/dev/null
php -l "$ROOT/panel/public/external-api.php" >/dev/null
node --check "$ROOT/panel/public/assets/app.js" >/dev/null
node --check "$ROOT/panel/public/assets/customer.js" >/dev/null
node --check "$ROOT/panel/public/assets/v7-admin.js" >/dev/null
node --check "$ROOT/panel/public/assets/v7-customer.js" >/dev/null

# 3-pass structural polish: no dead navigation, no duplicate IDs, goal organization remains intact.
python3 - "$ROOT" <<'PY2'
from pathlib import Path
import re,sys
r=Path(sys.argv[1])
for rel,navpat,viewpat,minimum in [('panel/public/admin.php',r'data-page="([^"]+)"',r'data-view="([^"]+)"',30),('panel/public/customer.php',r'data-cp-nav="([^"]+)"',r'data-cp-view="([^"]+)"',40)]:
 t=(r/rel).read_text(); nav=set(re.findall(navpat,t)); views=set(re.findall(viewpat,t)); missing=sorted(nav-views)
 if missing: raise SystemExit(f'{rel}: dead navigation targets {missing}')
 if len(nav)<minimum: raise SystemExit(f'{rel}: navigation shrank unexpectedly')
 ids=re.findall(r'\bid="([^"]+)"',t); dup=sorted({x for x in ids if ids.count(x)>1})
 if dup: raise SystemExit(f'{rel}: duplicate ids {dup}')
 print(f'{rel}: navigation={len(nav)} views={len(views)} duplicate_ids=0')
PY2

# 6.91 Mail operations.
for s in 'Postfix queue & delivery trace' 'Track delivery' 'Mailbox filtering rules'; do grep -Fiq "$s" "$ROOT/panel/public/admin.php" || fail "6.91 PCC UI missing: $s"; done
grep -Fq 'v7MailQueue' "$ROOT/panel/public/assets/v7-admin.js" || fail '6.91 queue workflow missing'
grep -Fq 'v7MailDelivery' "$ROOT/panel/public/assets/v7-admin.js" || fail '6.91 delivery workflow missing'
grep -Fq 'ApplyMailboxSieve' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail '6.91 Sieve adapter missing'

# 6.92 Backup Center 2.0 + actual background scheduler.
grep -Fq 'StartBackground' "$ROOT/agent/cmd/privora-agent/main.go" || fail 'production background worker not started'
grep -Fq 'time.NewTicker(time.Minute)' "$ROOT/agent/internal/api/server_v7.go" || fail 'background scheduler ticker missing'
grep -Fq 'executeBackupPolicyV7' "$ROOT/agent/internal/api/server_v7.go" || fail 'scheduled backup execution missing'
grep -Fq 'VerifyLocalBackup' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail 'backup verification adapter missing'

# 6.93 scoped API token lifecycle and account-scoped surface.
for s in "v7APIKeyRotate" "v7APIKeyRevoke"; do grep -Fq "$s" "$ROOT/agent/internal/api/server_v7.go" || fail "6.93 API lifecycle missing: $s"; done
grep -Fq 'data-cp-view="api-tokens"' "$ROOT/panel/public/customer.php" || fail 'PPanel API Token UI missing'
grep -Fq 'customer-api-key-create' "$ROOT/panel/public/api.php" || fail 'PPanel API Token bridge missing'

# 6.94 monitoring persistence, alert evaluation and incident lifecycle.
grep -Fq 'CollectLiveMetrics' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail 'live metrics adapter missing'
grep -Fq 'EvaluateAlertRules' "$ROOT/agent/internal/api/server_v7.go" || fail 'alert evaluation missing'
grep -Fq 'v7IncidentResolve' "$ROOT/agent/internal/api/server_v7.go" || fail 'incident lifecycle missing'

# 6.95 security advisor + allow-listed fixes.
grep -Fq 'SecurityAdvice' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail 'security advisor adapter missing'
grep -Fq 'ApplySecurityFix' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail 'security fix adapter missing'
grep -Fiq 'Security Advisor' "$ROOT/panel/public/admin.php" || fail 'Security Advisor UI missing'

# 6.96 site policy reconciliation with nginx validation/rollback.
grep -Fq 'ApplySitePolicy' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'site policy adapter missing'
grep -Fiq 'ADVANCED WEBSITE POLICY' "$ROOT/panel/public/admin.php" || fail 'site policy UI missing'
grep -Fq 'customer-site-policy-save' "$ROOT/panel/public/api.php" || fail 'PPanel site policy bridge missing'

# 6.97 database activity and scoped session termination.
grep -Fq 'DatabaseActivity' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'database activity adapter missing'
grep -Fq 'KillDatabaseSession' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'database session termination adapter missing'
grep -Fq 'customer-database-session-kill' "$ROOT/panel/public/api.php" || fail 'PPanel database session bridge missing'

# 6.98 application lifecycle discovery/actions.
grep -Fq 'DiscoverApplication' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'application discovery missing'
grep -Fq 'RunApplicationAction' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'application action adapter missing'
grep -Fiq 'Application Lifecycle Center' "$ROOT/panel/public/admin.php" || fail 'application lifecycle UI missing'

# 6.99 DNSSEC/templates/dynamic DNS guidance.
grep -Fq 'DNSSECStatus' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'DNSSEC status adapter missing'
grep -Fq 'SetDNSSEC' "$ROOT/agent/internal/hostadapter/v7_site_db_app_dns.go" || fail 'DNSSEC mutation adapter missing'
grep -Fiq 'Dynamic DNS' "$ROOT/panel/public/customer.php" || fail 'Dynamic DNS guidance missing'
grep -Fq 'dns-template-apply' "$ROOT/panel/public/api.php" || fail 'DNS template bridge missing'

# 7.0 readiness/repair and exact 6.89/6.90 runtime-permission hardening retained.
grep -Fq 'calculateReadiness' "$ROOT/agent/internal/api/server_v7.go" || fail 'readiness planner missing'
grep -Fq 'repair-all' "$ROOT/agent/internal/api/server_v7.go" || fail 'Repair All engine missing'
grep -Fiq 'SERVER READINESS' "$ROOT/panel/public/admin.php" || fail 'readiness UI missing'
grep -Fq 'chmod 0755 "$PANEL_ROOT" "$PANEL_ROOT/panel"' "$ROOT/install/privora-install.sh" || fail 'nginx traversal hardening regression'
grep -Fq 'chmod 0640 "$PANEL_ROOT/VERSION"' "$ROOT/install/privora-install.sh" || fail 'VERSION permission hardening regression'

# 7.0 Rev2: runtime UID/GID transitions must leave the hardened long-running Agent.
grep -Fq 'NoNewPrivileges=true' "$ROOT/agent/privora-panel-agent.service" || fail 'Agent NoNewPrivileges hardening was weakened'
grep -Fq 'RestrictSUIDSGID=true' "$ROOT/agent/privora-panel-agent.service" || fail 'Agent RestrictSUIDSGID hardening was weakened'
grep -Fq 'runIsolatedUserIO' "$ROOT/agent/internal/hostadapter/isolated_exec.go" || fail 'isolated target-user execution helper missing'
grep -Fq '"--property=User=" + userName' "$ROOT/agent/internal/hostadapter/isolated_exec.go" || fail 'transient target-user identity missing'
grep -Fq '"--property=NoNewPrivileges=yes"' "$ROOT/agent/internal/hostadapter/isolated_exec.go" || fail 'transient user unit hardening missing'
grep -Fq 'name == "runuser" && !a.cfg.CertificationMode' "$ROOT/agent/internal/hostadapter/adapter.go" || fail 'legacy runuser output path is not isolated'
grep -Fq 'name == "runuser" && !a.cfg.CertificationMode' "$ROOT/agent/internal/hostadapter/database.go" || fail 'legacy runuser stdin path is not isolated'
grep -Fq 'runPostfixQueueTool' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail 'Postfix queue isolation helper missing'
! grep -Eq 'a\.run\(ctx, "post(super|queue)"' "$ROOT/agent/internal/hostadapter/v7_mail_backup_monitor.go" || fail 'direct Postfix queue execution remains in hardened Agent'
grep -Fq 'runAsSystemUserIO' "$ROOT/agent/internal/hostadapter/database_admin.go" || fail 'PostgreSQL import/export isolation missing'
grep -Fq 'runAsSystemUserIO' "$ROOT/agent/internal/hostadapter/appinstaller.go" || fail 'application bootstrap user isolation missing'

# Every static route referenced by both base and 7.x frontends must exist in api.php.
python3 - "$ROOT" <<'PY2'
from pathlib import Path
import re,sys
r=Path(sys.argv[1]); api=(r/'panel/public/api.php').read_text()
for rel in ['panel/public/assets/app.js','panel/public/assets/customer.js','panel/public/assets/v7-admin.js','panel/public/assets/v7-customer.js']:
 t=(r/rel).read_text(); routes=sorted(set(re.findall(r"\bapi\('([^']+)'",t))); bases=sorted({re.split(r'[&?]',x,maxsplit=1)[0] for x in routes}); missing=[x for x in bases if x not in api]
 if missing: raise SystemExit(f'{rel}: API routes missing from api.php: {missing}')
 print(f'{rel}: static_api_routes={len(bases)} all represented')
PY2

if [[ "${PRIVORA_SKIP_GO_TESTS:-0}" != "1" ]]; then
  (cd "$ROOT/agent" && go test ./internal/api ./internal/hostadapter ./internal/platform >/dev/null)
fi
echo 'PASS: 6.91 -> 7.0 operational train + three-pass product polish regression gate'
