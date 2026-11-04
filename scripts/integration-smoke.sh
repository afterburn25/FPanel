#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PRIVORA_SMOKE_PORT:-18082}"
RUN="${PRIVORA_SMOKE_RUNTIME:-$(mktemp -d /tmp/privora-panel-smoke.XXXXXX)}"
BASE="http://127.0.0.1:${PORT}"
TOKEN="$(openssl rand -hex 32)"
PANEL_KEY="$(openssl rand -hex 32)"
ADMIN_PASS='Privora-Smoke-Admin-2026!'
CUSTOMER_PASS='Privora-Smoke-Customer-2026!'
AGENT_PID=''; PHP_PID=''
cleanup(){ [[ -n "$PHP_PID" ]] && kill "$PHP_PID" 2>/dev/null || true; [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true; rm -rf "$RUN"; }
trap cleanup EXIT
mkdir -p "$RUN" "$RUN/update-uploads"
"$ROOT/scripts/build-agent.sh" >/dev/null
PRIVORA_PANEL_STATE="$RUN/panel.json" php "$ROOT/scripts/init-panel.php" admin "$ADMIN_PASS" root-admin >/dev/null
PRIVORA_PANEL_STATE="$RUN/panel.json" php "$ROOT/scripts/init-panel.php" customer "$CUSTOMER_PASS" hosting-user acmeweb >/dev/null
PRIVORA_AGENT_TOKEN="$TOKEN" "$ROOT/dist/privora-agent" --mock --socket "$RUN/agent.sock" --audit "$RUN/audit.jsonl" --state "$RUN/agent.json" --mock-root "$RUN/mock" >"$RUN/agent.log" 2>&1 & AGENT_PID=$!
for _ in $(seq 1 60); do [[ -S "$RUN/agent.sock" ]] && break; sleep .1; done
PRIVORA_AGENT_TOKEN="$TOKEN" PRIVORA_AGENT_SOCKET="$RUN/agent.sock" PRIVORA_PANEL_STATE="$RUN/panel.json" PRIVORA_PANEL_ENCRYPTION_KEY="$PANEL_KEY" PRIVORA_UPDATE_UPLOAD_INBOX="$RUN/update-uploads" php -S "127.0.0.1:${PORT}" -t "$ROOT/panel/public" >"$RUN/php.log" 2>&1 & PHP_PID=$!
for _ in $(seq 1 60); do curl -fsS "$BASE/" >/dev/null 2>&1 && break; sleep .1; done
csrf_form(){ grep -o 'name="csrf" value="[^"]*"' "$1" | head -n1 | sed 's/.*value="//;s/"$//'; }
csrf_meta(){ grep -o 'meta name="csrf-token" content="[^"]*"' "$1" | head -n1 | sed 's/.*content="//;s/"$//'; }
# Admin login.
curl -fsS -c "$RUN/admin.cookies" "$BASE/" -o "$RUN/login.html"
CSRF="$(csrf_form "$RUN/login.html")"
curl -fsS -L -b "$RUN/admin.cookies" -c "$RUN/admin.cookies" -d "csrf=$CSRF&username=admin&password=$ADMIN_PASS&mfa_code=&login=1" "$BASE/" -o "$RUN/admin.html"
grep -q 'Privora Command Center' "$RUN/admin.html"
ACSRF="$(csrf_meta "$RUN/admin.html")"
post_admin(){ curl -sS -b "$RUN/admin.cookies" -H "X-CSRF-Token: $ACSRF" -H 'Content-Type: application/json' -X POST "$BASE/api.php?route=$1" --data "$2" -w '\n%{http_code}'; }
# One-command/update-center control-plane paths.
code="$(curl -sS -b "$RUN/admin.cookies" "$BASE/api.php?route=update-center" -o "$RUN/update-center.json" -w '%{http_code}')"; [[ "$code" == 200 ]]; grep -q 'privora-maintenance.timer' "$RUN/update-center.json"; grep -q 'signed_release_required' "$RUN/update-center.json"
grep -q 'upload_update_supported' "$RUN/update-center.json"; grep -q 'root_reauth_required' "$RUN/update-center.json"; grep -q 'updateUploadForm' "$RUN/admin.html"
{ printf 'PK\003\004PrivoraSmoke'; dd if=/dev/zero bs=1 count=2048 status=none; } >"$RUN/mock-update.zip"
resp="$(curl -sS -b "$RUN/admin.cookies" -H "X-CSRF-Token: $ACSRF" -F "package=@$RUN/mock-update.zip;filename=privora-panel-smoke.zip;type=application/zip" -X POST "$BASE/api.php?route=update-upload-prepare" -w '\n%{http_code}')"; [[ "${resp##*$'\n'}" == 201 ]]; UPLOAD_ID="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["upload"]["upload_id"])' <<<"${resp%$'\n'*}")"
resp="$(post_admin update-upload-start "{\"upload_id\":\"$UPLOAD_ID\",\"root_password\":\"smoke-root-password\"}")"; [[ "${resp##*$'\n'}" == 202 ]]; grep -q 'root_reauthorized' <<<"${resp%$'\n'*}"
code="$(curl -sS -b "$RUN/admin.cookies" "$BASE/api.php?route=update-status&id=$UPLOAD_ID" -o "$RUN/update-status.json" -w '%{http_code}')"; [[ "$code" == 200 ]]; grep -q '"phase":"health"' "$RUN/update-status.json"
resp="$(post_admin update-policy-set '{"channel":"stable","security_auto":true,"package_auto":true,"major_versions_manual":true,"reboot_window":"Sun 03:00"}')"; [[ "${resp##*$'\n'}" == 200 ]]; grep -q '"package_auto":true' <<<"${resp%$'\n'*}"
resp="$(post_admin update-run '{"mode":"security","channel":"stable","release_url":""}')"; [[ "${resp##*$'\n'}" == 202 ]]; grep -q '"status":"accepted"' <<<"${resp%$'\n'*}"
resp="$(post_admin account-create '{"username":"acmeweb","primary_domain":"acme.test","package":"Business"}')"; [[ "${resp##*$'\n'}" == 201 ]]
resp="$(post_admin site-create '{"domain":"www.acme.test","username":"acmeweb","php_version":"8.4"}')"; [[ "${resp##*$'\n'}" == 201 ]]
resp="$(post_admin host-plan '{"kind":"site-config","username":"acmeweb","domain":"www.acme.test","php_version":"8.4"}')"; [[ "${resp##*$'\n'}" == 200 ]]; grep -q '"executable":false' <<<"${resp%$'\n'*}"
resp="$(post_admin api-key-create '{"name":"smoke","scopes":["health.read","accounts.read"]}')"; [[ "${resp##*$'\n'}" == 201 ]]; SECRET="$(python3 -c 'import json,sys;print(json.loads(sys.stdin.read())["secret_once"])' <<<"${resp%$'\n'*}")"
# External scoped API.
code="$(curl -sS -H "Authorization: Bearer $SECRET" "$BASE/external-api.php?resource=accounts" -o "$RUN/ext.json" -w '%{http_code}')"; [[ "$code" == 200 ]]; grep -q 'acmeweb' "$RUN/ext.json"
code="$(curl -sS -H "Authorization: Bearer $SECRET" -H 'Content-Type: application/json' -X POST "$BASE/external-api.php?resource=accounts" --data '{"username":"nope","primary_domain":"nope.test"}' -o "$RUN/ext-deny.json" -w '%{http_code}')"; [[ "$code" == 403 ]]
# Customer login and isolation.
curl -fsS -c "$RUN/customer.cookies" "$BASE/" -o "$RUN/customer-login.html"; CCSRF="$(csrf_form "$RUN/customer-login.html")"
curl -fsS -L -b "$RUN/customer.cookies" -c "$RUN/customer.cookies" -d "csrf=$CCSRF&username=customer&password=$CUSTOMER_PASS&mfa_code=&login=1" "$BASE/" -o "$RUN/customer.html"; grep -q 'Privora Panel' "$RUN/customer.html"
code="$(curl -sS -b "$RUN/customer.cookies" "$BASE/api.php?route=customer-summary" -o "$RUN/customer-summary.json" -w '%{http_code}')"; [[ "$code" == 200 ]]; grep -q 'acmeweb' "$RUN/customer-summary.json"
code="$(curl -sS -b "$RUN/customer.cookies" "$BASE/api.php?route=summary" -o "$RUN/customer-deny.json" -w '%{http_code}')"; [[ "$code" == 403 ]]
# Expanded PPanel controls and curated installer stay account-scoped.
CCMETA="$(csrf_meta "$RUN/customer.html")"
post_customer(){ curl -sS -b "$RUN/customer.cookies" -H "X-CSRF-Token: $CCMETA" -H 'Content-Type: application/json' -X POST "$BASE/api.php?route=$1" --data "$2" -w '\n%{http_code}'; }
code="$(curl -sS -b "$RUN/customer.cookies" "$BASE/api.php?route=customer-resources" -o "$RUN/customer-resources.json" -w '%{http_code}')"; [[ "$code" == 200 ]]; grep -q '"slug":"wordpress"' "$RUN/customer-resources.json"; grep -q '"slug":"joomla"' "$RUN/customer-resources.json"
resp="$(post_customer customer-control-create '{"kind":"redirect","domain":"www.acme.test","name":"/old","value":"/new"}')"; [[ "${resp##*$'\n'}" == 201 ]]; grep -q 'policy-recorded-host-adapter-gated' <<<"${resp%$'\n'*}"
resp="$(post_customer customer-control-create '{"kind":"redirect","domain":"other.test","name":"/old","value":"/new"}')"; [[ "${resp##*$'\n'}" == 403 ]]
resp="$(post_customer customer-app-install '{"template":"wordpress","domain":"www.acme.test","path":"blog","database":"mariadb"}')"; [[ "${resp##*$'\n'}" == 201 ]]; grep -q 'install-plan-ready-adapter-gated' <<<"${resp%$'\n'*}"
resp="$(post_customer customer-app-install '{"template":"joomla","domain":"other.test","path":"."}')"; [[ "${resp##*$'\n'}" == 403 ]]
curl -fsS -b "$RUN/customer.cookies" "$BASE/api.php?route=customer-resources" -o "$RUN/customer-resources-after.json"
python3 - "$RUN/customer-resources-after.json" <<'PY2'
import json,sys
p=json.load(open(sys.argv[1]))
assert any(x['kind']=='redirect' and x['domain']=='www.acme.test' for x in p['account_controls'])
assert any(x['template']=='wordpress' and x['domain']=='www.acme.test' for x in p['app_installs'])
assert all(x.get('owner')=='acmeweb' for x in p['account_controls'])
assert all(x.get('owner')=='acmeweb' for x in p['app_installs'])
PY2
# Audit and horizon state.
curl -fsS -b "$RUN/admin.cookies" "$BASE/api.php?route=advanced-all" -o "$RUN/advanced.json"
python3 - "$RUN/advanced.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))
assert p['audit_verify']['ok'] is True
assert [x['major'] for x in p['horizons']] == [1,2,3,4,5]
assert all(x['certification']=='blocked' for x in p['horizons'])
PY
echo 'Privora live integration smoke PASS'
