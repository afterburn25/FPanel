#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo '[1/8] Go tests'
(cd "$ROOT/agent" && go test ./...)
echo '[2/8] PHP syntax'
while IFS= read -r -d '' f; do php -l "$f" >/dev/null; done < <(find "$ROOT/panel" "$ROOT/scripts" -name '*.php' -print0)
php -l "$ROOT/cli/privora" >/dev/null
echo '[3/8] JavaScript syntax'
node --check "$ROOT/panel/public/assets/app.js"
node --check "$ROOT/panel/public/assets/customer.js"
echo '[4/8] Shell/bootstrap syntax'

# DNS installer must emit a quoted BIND include path; the unquoted form is invalid named.conf syntax.
grep -Fq 'directive="include \"$index\";"' "$ROOT/install/privora-install.sh"
if grep -Fq 'directive="include "$index";"' "$ROOT/install/privora-install.sh"; then echo 'invalid unquoted BIND include directive regression' >&2; exit 1; fi
for f in "$ROOT/install/privora-install.sh" "$ROOT/scripts/privora-update.sh" "$ROOT/scripts/privora-update-rollback.sh" "$ROOT/scripts/vps-host-certify.sh" "$ROOT/scripts/build-signed-release.sh" "$ROOT/scripts/verify-signed-release.sh" "$ROOT/scripts/sign-app-release-manifest.sh" "$ROOT/scripts/test-release-pipeline.sh" "$ROOT/release/key-ceremony-offline.sh" "$ROOT/release/set-production-public-keys.sh" "$ROOT/release/prepare-delivery-root.sh" "$ROOT/scripts/build-upload-update-zip.sh" "$ROOT/scripts/test-upload-update-pipeline.sh"; do bash -n "$f"; done
echo '[4b/8] nftables bootstrap safety invariants'
grep -q 'nft -c -f /etc/privora-panel/nftables-bootstrap.nft' "$ROOT/install/privora-install.sh"
grep -q 'iifname "lo" accept' "$ROOT/install/privora-install.sh"
grep -q 'nft delete table inet privora_bootstrap' "$ROOT/install/privora-install.sh"
if grep -q 'flush ruleset' "$ROOT/install/privora-install.sh"; then
  echo 'installer must not flush the global nftables ruleset' >&2
  exit 1
fi
echo '[4c/8] nftables certification probe invariants'
grep -q 'table inet privora_cert_test {' "$ROOT/scripts/vps-host-certify.sh"
grep -q 'nft -c -f "$TMP/nft"' "$ROOT/scripts/vps-host-certify.sh"
if grep -q "echo 'table inet privora_cert_test { chain input" "$ROOT/scripts/vps-host-certify.sh"; then
  echo 'certification must not use fragile one-line nftables syntax' >&2
  exit 1
fi
echo '[4d/8] runtime state permission invariants'
grep -q 'install -d -o root -g privora-panel -m0750 /var/lib/privora-panel' "$ROOT/install/privora-install.sh"
grep -q 'runuser -u privora-panel -- test -w /var/lib/privora-panel/web' "$ROOT/install/privora-install.sh"
grep -q 'PRIVORA_PHP_BOOTSTRAP_OK' "$ROOT/install/privora-install.sh"
grep -q 'mktemp /var/tmp/privora-php-bootstrap' "$ROOT/install/privora-install.sh"
if grep -Eq 'runuser[^[:cntrl:]]*php[[:space:]][^[:cntrl:]]*-r([[:space:]]|$)' "$ROOT/install/privora-install.sh"; then
  echo 'installer health bootstrap must not use inline php -r quoting' >&2
  exit 1
fi
echo '[4e/8] CSP / CSRF frontend invariants'
grep -q "Content-Security-Policy: default-src 'self'; script-src 'self'" "$ROOT/panel/src/bootstrap.php"
if grep -Eq '<script[^>]*>[^<]*window\.PRIVORA' "$ROOT/panel/public/admin.php"; then
  echo 'admin page must not use CSP-blocked inline Privora bootstrap' >&2
  exit 1
fi
grep -Fq "document.querySelector('meta[name=\\\"csrf-token\\\"]')" "$ROOT/panel/public/assets/app.js"
grep -q "X-CSRF-Token" "$ROOT/panel/public/assets/app.js"
if grep -q 'window.PRIVORA.csrf' "$ROOT/panel/public/assets/app.js"; then
  echo 'admin app must not depend on CSP-blocked window.PRIVORA bootstrap' >&2
  exit 1
fi
echo '[4f/8] production API bridge + live Nginx inventory invariants'
grep -q -- '--socket-group privora-panel' "$ROOT/install/privora-install.sh"
grep -q 'PRIVORA_AGENT_BRIDGE_OK' "$ROOT/install/privora-install.sh"
grep -Fq "return \$this->request('GET',\$path,null,20);" "$ROOT/panel/src/AgentClient.php"
grep -Fq "new URL('api.php',document.baseURI)" "$ROOT/panel/public/assets/app.js"
grep -Fq "new URL('api.php', document.baseURI)" "$ROOT/panel/public/assets/customer.js"
grep -Fq 'filepath.Join(availableDir, "*")' "$ROOT/agent/internal/hostadapter/inventory.go"
grep -Fq 'filepath.Join(confDDir, "*.conf")' "$ROOT/agent/internal/hostadapter/inventory.go"
echo '[4g/8] WHM uploaded update-center security invariants'
python3 -m py_compile "$ROOT/scripts/verify-upload-update.py"
grep -q 'update-upload-prepare' "$ROOT/panel/public/api.php"
grep -q 'update-upload-start' "$ROOT/panel/public/api.php"
grep -q 'Upload Privora update ZIP' "$ROOT/panel/public/admin.php"
grep -q 'pamtester' "$ROOT/agent/internal/hostadapter/updater.go"
grep -q 'verifyMfaCode' "$ROOT/panel/src/Auth.php"
grep -q 'mfa_required' "$ROOT/panel/public/api.php"
grep -q 'updateMfaCode' "$ROOT/panel/public/admin.php"
grep -q 'transaction-bound root reauthorization' "$ROOT/scripts/privora-update.sh"
grep -q 'update-upload-staging' "$ROOT/agent/internal/hostadapter/adapter.go"
grep -q 'update-uploads' "$ROOT/install/privora-install.sh"
grep -q 'client_max_body_size 520m' "$ROOT/install/privora-install.sh"
grep -q 'php_admin_value\[upload_max_filesize\] = 512M' "$ROOT/install/privora-install.sh"
if grep -R --exclude=verify.sh -q -- '--root-password' "$ROOT/agent" "$ROOT/scripts"; then echo 'root password must never be passed on a command line' >&2; exit 1; fi
if grep -En '(localStorage|sessionStorage).*?(root_password|updateRootPassword)|(root_password|updateRootPassword).*?(localStorage|sessionStorage)' "$ROOT/panel/public/assets/app.js" >/dev/null; then echo 'root update credential must not be persisted in browser storage' >&2; exit 1; fi
"$ROOT/scripts/test-upload-update-pipeline.sh" >/dev/null
echo '[4h/8] PCC update progress / stall observability invariants'
grep -q 'phase_started_at' "$ROOT/scripts/privora-update.sh"
grep -q 'started_at' "$ROOT/scripts/privora-update.sh"
grep -q 'set_operation "Creating pre-update snapshot"' "$ROOT/scripts/privora-update.sh"
grep -q 'updateProgressPercent' "$ROOT/panel/public/admin.php"
grep -q 'updateStageElapsed' "$ROOT/panel/public/admin.php"
grep -q 'updateStallWarning' "$ROOT/panel/public/admin.php"
grep -q 'POTENTIAL STALL' "$ROOT/panel/public/admin.php"
grep -q 'updateStallAfter' "$ROOT/panel/public/assets/app.js"
grep -q 'SLOW / CHECK' "$ROOT/panel/public/assets/app.js"
grep -q 'update_progress_observability' "$ROOT/install/privora-install.sh"
echo '[4i/8] update launch / truthful preflight invariants'
grep -q 'phase.: .launch' "$ROOT/agent/internal/hostadapter/updater.go" || grep -q '"phase": "launch"' "$ROOT/agent/internal/hostadapter/updater.go"
grep -q 'Launching privileged update worker' "$ROOT/agent/internal/hostadapter/updater.go"
grep -q 'Blocked by another update transaction' "$ROOT/scripts/privora-update.sh"
grep -q 'timeout --signal=KILL 20s python3' "$ROOT/scripts/privora-update.sh"
grep -q "launch:2" "$ROOT/panel/public/assets/app.js"
grep -q "phase:'launch'" "$ROOT/panel/public/assets/app.js"
grep -q 'update_launch_recovery' "$ROOT/install/privora-install.sh"
echo '[4j/8] coherent core baseline / terminal updater invariants'
grep -q 'core_baseline_reconcile' "$ROOT/install/privora-install.sh"
grep -q 'Commit VERSION last' "$ROOT/install/privora-install.sh"
grep -q 'Core baseline reconciled atomically' "$ROOT/install/privora-install.sh"
grep -q 'stale running transaction recovered during core baseline reconciliation' "$ROOT/install/privora-install.sh"
grep -q 'updater exited before terminal state' "$ROOT/scripts/privora-update.sh"
grep -q 'trap on_update_exit EXIT' "$ROOT/scripts/privora-update.sh"
grep -q 'authorization verification PASS' "$ROOT/scripts/privora-update.sh"
echo '[4k/8] installer-discovered hosting environment + package-free website UX invariants'
grep -q 'A hosting package is not required to add a website' "$ROOT/panel/public/admin.php"
! grep -q 'siteNewAccountFields' "$ROOT/panel/public/admin.php"
! grep -q 'siteNewPackage' "$ROOT/panel/public/admin.php"
grep -q 'Automatic dedicated hosting account' "$ROOT/panel/public/assets/app.js"
grep -q 'requiresOwner' "$ROOT/panel/public/assets/app.js"
grep -q "api('site-create'" "$ROOT/panel/public/assets/app.js"
grep -q "api('account-create'" "$ROOT/panel/public/assets/app.js"
grep -q 'resolveSiteOwner' "$ROOT/agent/internal/api/server.go"
grep -q 'AdoptDiscoveredAccount' "$ROOT/agent/internal/hosting/hosting.go"
grep -q 'POST /v1/host/reconcile' "$ROOT/agent/internal/api/server.go"
grep -q 'existing home' "$ROOT/agent/internal/hostadapter/inventory.go"
grep -q 'host-profile.json' "$ROOT/install/privora-install.sh"
grep -q 'privora-host-profile-v1' "$ROOT/install/privora-install.sh"

echo '[4h/8] transaction-bound uploaded-update authorization invariants'
! grep -R --line-number -- '--authorization-token' "$ROOT/agent" "$ROOT/scripts/privora-update.sh" >/dev/null
grep -Fq 'auth_file="$auth_root/$TXN_ID.json"' "$ROOT/scripts/privora-update.sh"
grep -Fq 'filepath.Join(a.cfg.UpdateAuthRoot, in.UploadID+".json")' "$ROOT/agent/internal/hostadapter/updater.go"
grep -Fq '"--", a.cfg.UpdaterPath' "$ROOT/agent/internal/hostadapter/updater.go"
grep -Fq 'authorization verification FAIL:' "$ROOT/scripts/privora-update.sh"
grep -Fq 'transaction_auth_recovery' "$ROOT/install/privora-install.sh"
echo '[5/8] Auth cryptography self-test'
PRIVORA_PANEL_ENCRYPTION_KEY='development-test-key-that-is-at-least-32-bytes-long' php "$ROOT/scripts/test-auth.php"
echo '[6/8] One-command installer + updater non-destructive dry-runs'
"$ROOT/install/privora-install.sh" --dry-run --source-dir "$ROOT" --hostname panel.example.test --admin-email admin@example.test --mode full >/dev/null
if "$ROOT/install/privora-install.sh" --dry-run --source-dir /definitely/not/a/privora/tree --mode full >/dev/null 2>&1; then
  echo 'installer incorrectly masked a failing source phase' >&2
  exit 1
fi
PRIVORA_PANEL_ROOT="$ROOT" PRIVORA_UPDATE_BACKUP_ROOT=/tmp/privora-verify-backups PRIVORA_UPDATE_STATE_ROOT=/tmp/privora-verify-state PRIVORA_UPDATE_LOG=/tmp/privora-verify-update.log "$ROOT/scripts/privora-update.sh" --security-only --dry-run >/dev/null
cat >/tmp/privora-verify-update-policy.env <<'POLICY'
PRIVORA_SECURITY_AUTO=1
PRIVORA_PACKAGE_AUTO=1
PRIVORA_MAJOR_VERSIONS_MANUAL=1
PRIVORA_AUTO_REBOOT=0
PRIVORA_UPDATE_CHANNEL=stable
PRIVORA_UPDATE_RELEASE_URL=
POLICY
PRIVORA_PANEL_ROOT="$ROOT" PRIVORA_UPDATE_POLICY_FILE=/tmp/privora-verify-update-policy.env PRIVORA_UPDATE_BACKUP_ROOT=/tmp/privora-verify-backups PRIVORA_UPDATE_STATE_ROOT=/tmp/privora-verify-state PRIVORA_UPDATE_LOG=/tmp/privora-verify-update.log "$ROOT/scripts/privora-update.sh" --automatic --dry-run >/dev/null
cat >/tmp/privora-verify-reboot-policy.env <<POLICY
PRIVORA_SECURITY_AUTO=1
PRIVORA_PACKAGE_AUTO=1
PRIVORA_MAJOR_VERSIONS_MANUAL=1
PRIVORA_AUTO_REBOOT=1
PRIVORA_UPDATE_CHANNEL=stable
PRIVORA_UPDATE_RELEASE_URL=
PRIVORA_REBOOT_WINDOW="$(date +%a) $(date +%H):00"
POLICY
touch /tmp/privora-verify-reboot-required
PRIVORA_PANEL_ROOT="$ROOT" PRIVORA_UPDATE_POLICY_FILE=/tmp/privora-verify-reboot-policy.env PRIVORA_REBOOT_REQUIRED_FILE=/tmp/privora-verify-reboot-required PRIVORA_UPDATE_BACKUP_ROOT=/tmp/privora-verify-backups PRIVORA_UPDATE_STATE_ROOT=/tmp/privora-verify-state PRIVORA_UPDATE_LOG=/tmp/privora-verify-update.log "$ROOT/scripts/privora-update.sh" --automatic --dry-run | grep -q 'systemctl reboot'
rm -f /tmp/privora-verify-update-policy.env /tmp/privora-verify-reboot-policy.env /tmp/privora-verify-reboot-required
echo '[7/8] Signed release delivery tamper test'
"$ROOT/scripts/test-release-pipeline.sh" >/dev/null
echo '[7z/8] phpMyAdmin integration gate'
"$ROOT/scripts/test-6.69-phpmyadmin-integration.sh" "$ROOT"

echo '[8/8] Agent + precompiled certification builds'
"$ROOT/scripts/build-agent.sh"
(cd "$ROOT/dist" && sha256sum -c privora-agent.sha256 >/dev/null)
[[ "$(awk 'NR==1{print $2}' "$ROOT/dist/privora-agent.sha256")" == "privora-agent" ]]
! grep -Eq '[[:space:]]+/' "$ROOT/dist/privora-agent.sha256"
grep -Fq 'DEFAULT_UPDATE_CHANNEL="developer"' "$ROOT/install/privora-install.sh"
"$ROOT/scripts/build-cert-binaries.sh"
for f in privora-hostadapter-cert.test privora-api-cert.test; do test -x "$ROOT/dist/$f"; (cd "$ROOT/dist" && sha256sum -c "$f.sha256" >/dev/null); done
"$ROOT/dist/privora-hostadapter-cert.test" -test.run TestSignedAppManifest -test.count=1 >/dev/null
"$ROOT/dist/privora-api-cert.test" -test.run TestSummary -test.count=1 >/dev/null || true
if grep -Eq '(^|[;&()[:space:]])go[[:space:]]+(test|run|build)' "$ROOT/scripts/vps-host-certify.sh"; then echo 'production VPS certification must not invoke Go toolchain' >&2; exit 1; fi
# Installer runtime reconciliation invariants.

grep -q 'reconcile_panel_runtime' install/privora-install.sh
grep -q 'systemctl restart "\$fpm_service"' install/privora-install.sh
grep -q 'Nginx is not listening on Privora Command Center (PCC) port' install/privora-install.sh
grep -q 'Nginx is not listening on Privora Privora Panel (PPanel) port' install/privora-install.sh

# PHP-FPM/Nginx socket permission invariants.
grep -q 'nginx_user=www-data' install/privora-install.sh
grep -q 'listen.group = \$nginx_group' install/privora-install.sh
grep -q 'Recovery-safe socket ownership reconciliation' install/privora-install.sh
grep -q 'health_check(){' install/privora-install.sh
grep -q 'reconcile_panel_code_permissions' install/privora-install.sh
grep -q 'chmod 0755 "$PANEL_ROOT" "$PANEL_ROOT/panel"' install/privora-install.sh
grep -q 'chown -R root:privora-panel "$PANEL_ROOT/panel/src"' install/privora-install.sh
grep -q 'Privora health returned HTTP' install/privora-install.sh
echo "[4f/8] live-host / MySQL / branding invariants"
[[ -r panel/public/assets/privora-labs-full.png && -r panel/public/assets/privora-labs-mark.png ]]
grep -q 'privora-labs-full.png' panel/public/index.php
grep -q 'privora-labs-mark.png' panel/public/admin.php
grep -q 'privora-labs-mark.png' panel/public/customer.php
! grep -Rqs 'brand-full.svg\|brand-mark.svg' panel/public
grep -q 'database_engines' agent/internal/api/server_platform.go
grep -q 'ProvisionMySQL' agent/internal/api/server.go
grep -q 'live-host' agent/internal/api/server.go
grep -q -- '--sql-family mariadb|mysql' install/privora-install.sh
grep -q 'live_host_reconcile' install/privora-install.sh
echo '[4l/8] website transaction, DNS, service visibility and operator UI invariants'
grep -q 'privora-panel-fpm.service' install/privora-install.sh
grep -q 'configure_panel_fpm_isolation' install/privora-install.sh
grep -q 'configure_dns_foundation' install/privora-install.sh
grep -q 'InvalidateInventory' agent/internal/hostadapter/inventory.go
grep -q 'autoProvisionSiteDNS' agent/internal/api/server.go
grep -q 'managed-created' agent/internal/api/server.go
grep -q 'service is not installed on this host' agent/internal/api/server.go
grep -q 'LoadState' agent/internal/api/server.go
! grep -q 'Build Train' panel/public/admin.php
! grep -q 'BUILD STATUS' panel/public/admin.php
! grep -q 'Build horizon' panel/public/admin.php
! grep -q 'data-view="roadmap"' panel/public/admin.php
! grep -q 'data-page="roadmap"' panel/public/admin.php
! grep -q "roadmap:'Build train'" panel/public/assets/app.js
grep -q "DNS / SSL</small>" panel/public/assets/app.js
grep -q 'non-JSON response' panel/public/assets/app.js
grep -q 'preflightSiteCreate' agent/internal/api/server.go
grep -q 'DELETE /v1/sites/{domain}' agent/internal/api/server.go
grep -q 'DeleteSite' agent/internal/hostadapter/provision.go
grep -q 'DeleteBINDZone' agent/internal/hostadapter/dns.go
grep -q 'EnsureDNSFoundation' agent/internal/hostadapter/dns.go
grep -q 'ProvisionBINDZoneWithNameservers' agent/internal/hostadapter/dns.go
grep -q 'GET /v1/config-files' agent/internal/api/server.go
grep -q 'WriteEditableConfig' agent/internal/hostadapter/configfiles.go
grep -q 'GET /v1/dns/nameservers' agent/internal/api/server.go
grep -q 'data-view="config"' panel/public/admin.php
grep -q 'data-view="nameservers"' panel/public/admin.php
grep -q 'data-site-delete' panel/public/assets/app.js
grep -q "api('site-delete'" panel/public/assets/app.js
grep -q "api('config-write'" panel/public/assets/app.js
grep -q "api('nameservers-set'" panel/public/assets/app.js
grep -q 'GET /v1/dns/zones/{domain}' agent/internal/api/server.go
grep -q 'POST /v1/dns/zones/{domain}/records' agent/internal/api/server.go
grep -q 'DELETE /v1/dns/zones/{domain}/records' agent/internal/api/server.go
grep -q 'DELETE /v1/dns/nameservers' agent/internal/api/server.go
grep -q 'ReadBINDZone' agent/internal/hostadapter/dns.go
grep -q 'DeleteBINDRecord' agent/internal/hostadapter/dns.go
grep -q 'SyncRegistrarGlue' agent/internal/hostadapter/registrar.go
grep -q 'DeleteRegistrarGlue' agent/internal/hostadapter/registrar.go
grep -q "api('dns-record-save'" panel/public/assets/app.js
grep -q "api('dns-record-delete'" panel/public/assets/app.js
grep -q "api('nameservers-delete'" panel/public/assets/app.js
grep -q 'local-glue-ready' agent/internal/api/server.go
! grep -Rqs 'registrar-glue-required' agent panel install

echo '[4o/8] atomic core promotion / recovery-root invariants'
grep -Fq 'atomic_exchange_dirs "$PANEL_ROOT" "$stage"' scripts/privora-update.sh
grep -Fq 'record promotion atomic-exchange' scripts/privora-update.sh
grep -Fq 'restore_snapshot_state_only' scripts/privora-update.sh
grep -Fq -- "--exclude='opt/privora-panel'" scripts/privora-update.sh
grep -Fq 'snapshot_verified yes' scripts/privora-update.sh
grep -Fq 'stage_verified yes' scripts/privora-update.sh
grep -Fq 'atomic_exchange_dirs /opt/privora-panel "$previous"' scripts/privora-update-rollback.sh
grep -Fq -- "--exclude='opt/privora-panel'" scripts/privora-update-rollback.sh
grep -Fq 'Privora Recovery Mode' scripts/migrate.sh
grep -Fq 'fastcgi_intercept_errors on' scripts/render-panel-nginx.py
grep -Fq '/_privora_recovery.html' install/privora-install.sh
python3 - <<'PYATOMIC'
import ctypes,os,tempfile,pathlib
with tempfile.TemporaryDirectory() as td:
    a=pathlib.Path(td)/'a'; b=pathlib.Path(td)/'b'; a.mkdir(); b.mkdir(); (a/'A').write_text('a'); (b/'B').write_text('b')
    libc=ctypes.CDLL(None,use_errno=True); fn=getattr(libc,'renameat2',None); assert fn is not None
    fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]; fn.restype=ctypes.c_int
    assert fn(-100,os.fsencode(a),-100,os.fsencode(b),2)==0
    assert (a/'B').read_text()=='b' and (b/'A').read_text()=='a'
PYATOMIC
echo 'Privora verification PASS'
echo '[4m/8] updater health observability / readiness invariants'
grep -Fq 'Restart: gracefully reloading PCC PHP-FPM code workers' scripts/privora-update.sh
grep -Fq 'Health: waiting for panel PHP-FPM socket' scripts/privora-update.sh
grep -Fq 'Health: HTTPS probe attempt' scripts/privora-update.sh
grep -Fq 'did not become healthy (HTTP' scripts/privora-update.sh
grep -Fq -- '--connect-timeout 4 --max-time 12' scripts/privora-update.sh
grep -Fq '\.example(/|$)' scripts/privora-update.sh
grep -Fq 'record operation "Failed: ${failed_operation:-$failed_cmd}"' scripts/privora-update.sh
grep -Fq "tx.failed_operation||tx.operation" panel/public/assets/app.js

# 6.32 updater liveness regression gates.
grep -Fq 'agent_refresh deferred-until-after-pass' scripts/privora-update.sh
grep -Fq 'privora-agent-refresh-$TXN_ID' scripts/privora-update.sh
! grep -Fq 'run_timed 45s systemctl restart privora-panel-agent.service' scripts/privora-update.sh
! grep -Fxq 'systemctl restart privora-panel-agent.service' scripts/privora-update-rollback.sh
grep -Fq 'privora-agent-rollback-refresh-$id' scripts/privora-update-rollback.sh
grep -Fq 'ExecStart=/usr/local/libexec/privora-agent ' agent/privora-panel-agent.service
echo '[4n/8] updater no-synchronous-agent-restart invariant'
if grep -En '^[[:space:]]*(run(_timed)?[[:space:]]+)?systemctl[[:space:]]+restart[[:space:]]+privora-panel-agent\.service([[:space:]]|$)' scripts/privora-update.sh scripts/privora-update-rollback.sh; then
  echo 'FAIL synchronous Privora agent restart remains in updater transaction path' >&2
  exit 1
fi
grep -Fq 'privora-agent-snapshot-refresh-$TXN_ID' scripts/privora-update.sh

echo '[8b/8] snapshot verification invariants'
grep -Fq 'snapshot-files.raw' scripts/privora-update.sh
grep -Fq 'snapshot-files.list' scripts/privora-update.sh
grep -Fq "sed -e 's#^\\./##' -e 's#^/##'" scripts/privora-update.sh
grep -Fq "grep -Fxq 'opt/privora-panel/panel/public/index.php' \"\$BACKUP/snapshot-files.list\"" scripts/privora-update.sh
! grep -Fq "tar --zstd -tf \"\$BACKUP/privora-files.tar.zst\" | grep -q" scripts/privora-update.sh

# dev.6.36 validation isolation invariants
grep -q 'Validation: checking live Nginx configuration' "$ROOT/scripts/privora-update.sh"
grep -q 'validation_file' "$ROOT/scripts/privora-update.sh"
grep -q 'install_recovery_page' "$ROOT/scripts/migrate.sh"
! grep -q '^apply_recovery_vhost' "$ROOT/scripts/migrate.sh"
test -x "$ROOT/scripts/apply-recovery-vhost.sh"
grep -q 'scheduled-after-pass' "$ROOT/scripts/privora-update.sh"

echo '[8c/8] update extraction permissions / promoted-version truth invariants'
grep -Fq 'os.makedirs(dest,mode=0o755,exist_ok=True); os.chmod(dest,0o755)' scripts/verify-upload-update.py
grep -Fq 'os.chmod(target, 0o755 if mode & 0o111 else 0o644)' scripts/verify-upload-update.py
grep -Fq 'find "$stage" -type d -exec chmod 0755 {} +' scripts/privora-update.sh
grep -Fq 'staged panel index.php is not readable by privora-panel' scripts/privora-update.sh
grep -Fq 'promoted VERSION mismatch' scripts/privora-update.sh
grep -Fq 'Health: verifying installed Privora version' scripts/privora-update.sh
grep -Fq 'installed VERSION mismatch after health' scripts/privora-update.sh
grep -Fq 'Restart: detecting panel PHP-FPM service' scripts/privora-update.sh
grep -Fq 'systemctl show "$1" --property=LoadState --value' scripts/privora-update.sh
! grep -Fq 'list-unit-files --type=service --no-legend 2>/dev/null' scripts/privora-update.sh
echo 'dev.6.37 permission/version-truth invariants PASS'

# 6.38 release-staging parent traversal invariant.
grep -Fq 'run install -d -m0755 "$stage_parent"' scripts/privora-update.sh
grep -Fq "release staging parent is not traversable" scripts/privora-update.sh
grep -Fq 'runuser -u privora-panel -- test -x "$stage_parent"' scripts/privora-update.sh


echo '[8d/8] dev.6.40 nameserver / website / account / subdomain invariants'
grep -Fq 'NameserverSets() []NameserverConfig' agent/internal/resources/resources.go
grep -Fq 'nameservers must be children of the base domain' agent/internal/resources/resources.go
grep -Fq 'data-nameserver-delete' panel/public/assets/app.js
grep -Fq 'Delete set</button>' panel/public/assets/app.js
grep -Fq 'class="site-list"' panel/public/admin.php
grep -Fq 'cpSitesGrid" class="site-list"' panel/public/customer.php
grep -Fq 'DELETE /v1/hosting/accounts/{user}' agent/internal/api/server.go
grep -Fq 'account must be suspended before deletion' agent/internal/api/server.go
grep -Fq 'POST /v1/subdomains' agent/internal/api/server.go
grep -Fq 'autoProvisionSubdomainDNS' agent/internal/api/server.go
grep -Fq 'deleteSubdomainDNS' agent/internal/api/server.go
grep -Fq 'customer-subdomain-create' panel/public/api.php
grep -Fq 'data-modal="subdomain"' panel/public/admin.php
grep -Fq 'data-cp-modal="subdomain"' panel/public/customer.php
grep -Fq 'Subdomain of ${esc(s.parent_domain' panel/public/assets/app.js
grep -Fq 'Subdomain of ${esc(s.parent_domain' panel/public/assets/customer.js
echo 'dev.6.40 hosting UX/domain lifecycle invariants PASS'


echo '[8e/8] dev.6.41 PCC expansion invariants'
grep -Fq 'feature_lists' panel/src/Store.php
grep -Fq 'SetAccountPackage' agent/internal/hosting/hosting.go
grep -Fq 'POST /v1/hosting/accounts/{user}/package' agent/internal/api/server.go
grep -Fq 'GET /v1/php/runtimes' agent/internal/api/server.go
grep -Fq 'GET /v1/control-suite' agent/internal/api/server.go
grep -Fq 'phpmyadmin' agent/internal/hostadapter/adapter.go
grep -Fq 'fail2ban' agent/internal/hostadapter/adapter.go
grep -Fq 'modsecurity' agent/internal/hostadapter/adapter.go
grep -Fq 'clamav' agent/internal/hostadapter/adapter.go
grep -Fq 'BackupByID' agent/internal/resources/resources.go
grep -Fq 'RestoreLocalBackup' agent/internal/hostadapter/resources.go
grep -Fq 'backup integrity check failed' agent/internal/hostadapter/resources.go
grep -Fq 'POST /v1/backups/{id}/restore' agent/internal/api/server.go
grep -Fq 'RotateDatabasePassword' agent/internal/hostadapter/database.go
grep -Fq 'DELETE /v1/databases/{name}' agent/internal/api/server.go
grep -Fq 'POST /v1/ssl/autossl' agent/internal/api/server.go
grep -Fq "webhook-create" panel/public/api.php
grep -Fq 'data-view="packages"' panel/public/admin.php
grep -Fq 'data-view="features"' panel/public/admin.php
grep -Fq 'data-view="serveradmin"' panel/public/admin.php
grep -Fq 'data-view="transfers"' panel/public/admin.php
grep -Fq 'data-view="developer"' panel/public/admin.php
grep -Fq 'data-view="cluster"' panel/public/admin.php
grep -Fq 'applyFeatureVisibility' panel/public/assets/customer.js
grep -Fq 'data-customer-backup-restore' panel/public/assets/customer.js
grep -Fq 'data-db-password' panel/public/assets/app.js
grep -Fq 'autoSSLForm' panel/public/admin.php
grep -Fq 'mailCapabilityTable' panel/public/admin.php
grep -Fq 'data-cp-nav="webmail"' panel/public/customer.php
grep -Fq 'data-cp-view="webmail"' panel/public/customer.php
grep -Fq 'value="webmail"' panel/public/admin.php
grep -Fq "'webmail'" panel/src/Store.php
grep -Fq '{"webmail", "roundcube"}' agent/internal/hostadapter/adapter.go
grep -Fq 'PRIVORA_WEBMAIL_URL=' agent/internal/hostadapter/webmail.go
grep -Fq 'renderWebmailAvailability' panel/public/assets/customer.js
grep -Fq 'securityCapabilityTable' panel/public/admin.php
echo 'dev.6.41 PCC core expansion invariants PASS'

echo '[8f/8] dev.6.42 professional UX / settings invariants'
grep -Fq 'data-view="settings"' panel/public/admin.php
grep -Fq 'Panel Preferences' panel/public/admin.php
grep -Fq 'modal-card-wide professional-form' panel/public/admin.php
grep -Fq 'Provisioning summary' panel/public/admin.php
grep -Fq 'enhanceSidebarNavigation' panel/public/assets/app.js
grep -Fq 'privora.admin.preferences.v1' panel/public/assets/app.js
grep -Fq 'refreshSitePhpSelectors' panel/public/assets/app.js
grep -Fq 'data-cp-view="preferences"' panel/public/customer.php
grep -Fq 'cpPhpSettingValue' panel/public/customer.php
grep -Fq 'upgradeCustomerDomainInputs' panel/public/assets/customer.js
grep -Fq 'phpSettingChoices' panel/public/assets/customer.js
grep -Fq 'privora.customer.preferences.v1' panel/public/assets/customer.js
grep -Fq 'Errors stay until explicitly dismissed' panel/public/assets/customer.js
grep -Fq '.sidebar .nav-group' panel/public/assets/app.css
grep -Fq '.professional-form' panel/public/assets/app.css
echo 'dev.6.42 professional UX / settings invariants PASS' ''


echo '[8g/8] dev.6.43 friendly identity / website visibility / subdomain builder invariants'
grep -Fq 'mergeWebsiteInventory' agent/internal/api/server.go
grep -Fq 'PrimaryDomain' agent/internal/api/server.go
grep -Fq 'Status: "missing"' agent/internal/api/server.go
grep -Fq 'accountLabel' panel/public/assets/app.js
grep -Fq 'Needs attention' panel/public/assets/app.js
grep -Fq 'subdomain-builder' panel/public/admin.php
grep -Fq 'subdomain-builder' panel/public/customer.php
grep -Fq "s.kind==='subdomain'" panel/public/assets/app.js
grep -Fq "s.kind==='subdomain'" panel/public/assets/customer.js
grep -Fq 'len(v) > 63' agent/internal/api/server.go
grep -Fq 'one DNS label only' agent/internal/api/server.go
echo 'dev.6.43 friendly identity / website visibility / subdomain builder invariants PASS'


echo "[8h/8] dev.6.44 stable release trust / automatic Let's Encrypt invariants"
grep -Fq 'autoProvisionSiteSSL' agent/internal/api/server.go
grep -Fq 'PreflightLetsEncryptDomain' agent/internal/hostadapter/acme.go
grep -Fq 'InstallLetsEncryptNginxTLS' agent/internal/hostadapter/acme.go
grep -Fq 'RenderNginxSiteTLS' agent/internal/hostadapter/adapter.go
grep -Fq 'certbot' install/privora-install.sh
grep -Fq 'privora-autossl.timer' install/privora-install.sh
grep -Fq '/v1/ssl/autossl' scripts/privora-autossl-retry.php
grep -Fq 'SSL ${ssl}' panel/public/assets/app.js
echo "dev.6.44 stable release trust / automatic Let's Encrypt invariants PASS"


echo "[8i/8] dev.6.46 recovery-safe API mutation invariants"
grep -Fq 'location = /api.php' scripts/render-panel-nginx.py
grep -Fq 'fastcgi_intercept_errors off;' scripts/render-panel-nginx.py
grep -Fq '@privora_api_unavailable_' scripts/render-panel-nginx.py
grep -Fq 'location = /api.php' scripts/render-panel-nginx.py
grep -Fq 'PRIVORA_PANEL_SURFACE' scripts/render-panel-nginx.py
grep -Fq 'Privora is temporarily in Recovery Mode' panel/public/assets/app.js
bash scripts/test-recovery-vhost-mutation.sh
echo "dev.6.46 recovery-safe API mutation invariants PASS"

echo "[8j/8] dev.6.48 standard domain selectors / website editor invariants"
"$ROOT/scripts/test-6.47-domain-selector-website-editor.sh"
echo "[8k/8] dev.6.48 AutoSSL feedback / certificate inventory invariants"
"$ROOT/scripts/test-6.48-autossl-certificate-inventory.sh"
echo '[8l/8] dev.6.49 nameserver readiness / registrar workflow invariants'
./scripts/test-6.49-nameserver-readiness.sh

echo '[8m/8] dev.6.52 domain/vhost reconciliation invariants'
"$ROOT/scripts/test-6.52-domain-vhost-reconciliation.sh"

echo '[6.56] runtime version truth'
bash scripts/test-6.56-version-truth.sh
echo '[6.54] DNS zone readiness reconciliation'
bash scripts/test-6.54-dns-zone-readiness.sh


echo '[6.55] DNS Zone Manager effective BIND inventory reconciliation'
bash scripts/test-6.55-dns-zone-inventory.sh


echo '[6.56] split WHM / PPanel listener invariants'
bash scripts/test-6.56-panel-surface-ports.sh

echo "[6.59] Update Center partial-failure resilience"
bash scripts/test-6.59-update-center-resilience.sh
echo "[6.60] live-domain DNS / AutoSSL HTTP-01 / PCC header regression"
bash scripts/test-6.60-live-domain-autossl-pcc.sh
echo "[6.62] updater reliability / live-domain reconciliation"
bash scripts/test-6.62-update-dns-reliability.sh
echo "All Privora verification checks passed."

bash "$ROOT/scripts/test-6.63-dns-creation-contract.sh"
echo '[6.64] agent handoff / hosted-DNS retry / loaded-zone truth'
bash scripts/test-6.64-agent-dns-handoff.sh

echo '[6.65] per-domain nameserver selection / package inventory resilience'
bash scripts/test-6.65-domain-ns-selection-package-inventory.sh

echo '[6.65] PPanel custom usernames / primary-domain login alias'
bash scripts/test-6.65-ppanel-usernames.sh

echo '[6.66] explicit domain nameserver assignment / apex NS rewrite / core-status fail-soft'
bash scripts/test-6.66-explicit-nameserver-assignment-core-status.sh

echo '[6.67] package hard deadline / state-write race / direct DNS create'
bash scripts/test-6.67-package-dns-state-reliability.sh
echo 'All Privora verification checks including 6.67 passed.'

echo '[6.68] DNS/site/AutoSSL reliability'
bash scripts/test-6.68-dns-site-autossl-reliability.sh
echo 'All Privora verification checks including 6.68 passed.'

echo '[6.73] account termination preflight / fail-closed stale-plan guard'
bash scripts/test-6.73-account-termination-preflight.sh
echo 'All Privora verification checks including 6.73 passed.'

echo '[6.74] Stage A account lifecycle / package enforcement / feature policy / reseller scope'
bash scripts/test-6.74-stage-a-account-package-reseller.sh
echo 'All Privora verification checks including 6.74 passed.'

bash scripts/test-6.75-stage-b-software-php.sh "$ROOT"

bash scripts/test-6.76-stage-c-database-center.sh "$ROOT"

bash scripts/test-6.77-stage-d-certificate-lifecycle.sh "$ROOT"

bash scripts/test-6.78-ui-component-apt-hotfix.sh "$ROOT"
bash scripts/test-6.79-ui-renderer-component-presets.sh "$ROOT"

bash scripts/test-6.80-runtime-ui-convergence.sh "$ROOT"

"$ROOT/scripts/test-6.81-component-controller.sh"

bash "$ROOT/scripts/test-6.82-component-installability-version-truth.sh" "$ROOT"

bash "$ROOT/scripts/test-6.83-software-job-progress.sh" "$ROOT"


bash "$ROOT/scripts/test-6.84-package-policy-secure-mail.sh" "$ROOT"

echo '[6.85] professional Mail Center / mailbox and forwarder lifecycle'
bash "$ROOT/scripts/test-6.85-professional-mail-center.sh" "$ROOT"

echo '[6.86] editable subdomain document root / shared-root deletion safety'
bash "$ROOT/scripts/test-6.86-subdomain-document-root.sh"

echo '[6.87] mail-domain live configuration / DKIM TXT rendering'
bash "$ROOT/scripts/test-6.87-mail-domain-config.sh" "$ROOT"

echo '[6.88] live mail readiness / authentication lifecycle'
bash "$ROOT/scripts/test-6.88-mail-domain-readiness-auth-delete.sh" "$ROOT"

echo '[6.89] virtual-mail passwd-file authentication / auth-worker access / SMTP AUTH'
bash "$ROOT/scripts/test-6.89-virtual-mail-auth.sh" "$ROOT"

echo '[6.90] panel coverage / efficiency / three-pass UX polish'
bash "$ROOT/scripts/test-6.90-panel-coverage-polish.sh" "$ROOT"

echo '[7.0] cumulative 6.91-7.0 functional train / three-pass product polish'
bash "$ROOT/scripts/test-7.0-release-train-polish.sh" "$ROOT"

echo "[7.0 Rev5 Rev7] manual mail TLS routing"
bash scripts/test-7.0-rev5r7-manual-mail-tls-routing.sh
