#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.."&&pwd)"
OUT="${PRIVORA_CERT_OUTPUT:-/var/lib/privora-panel/certifications/host-adapter-certification.json}"
ROLE="${PRIVORA_CERT_ROLE:-full}"
SQL_FAMILY="${PRIVORA_SQL_FAMILY:-mariadb}"
[[ "$SQL_FAMILY" =~ ^(mariadb|mysql)$ ]] || { echo "invalid PRIVORA_SQL_FAMILY" >&2; exit 2; }
REQUIRE_FULL="${PRIVORA_CERT_REQUIRE_FULL:-0}"
TMP="$(mktemp -d)";trap 'rm -rf "$TMP"' EXIT
((EUID==0))||{ echo 'root required' >&2; exit 2; }
[[ "$ROLE" =~ ^(full|web|db|mail|dns|backup)$ ]]||{ echo 'invalid certification role' >&2; exit 2; }
mkdir -p "$(dirname "$OUT")";:>"$TMP/passed";:>"$TMP/log"
log(){ echo "[cert] $*"|tee -a "$TMP/log";};pass(){ echo "$1">>"$TMP/passed";log "PASS $1";};has(){ grep -qxF "$1" "$TMP/passed"; }
log 'Precompiled host-adapter live certification tests'
HOST_CERT_BIN="$ROOT/dist/privora-hostadapter-cert.test"
API_CERT_BIN="$ROOT/dist/privora-api-cert.test"
verify_cert_binary(){
  local bin="$1" sha="${1}.sha256" expected actual
  [[ -x "$bin" ]] || { log "FAIL missing precompiled certification executable: $bin"; exit 1; }
  [[ -r "$sha" ]] || { log "FAIL missing certification checksum: $sha"; exit 1; }
  expected="$(awk 'NR==1{print $1}' "$sha")"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { log "FAIL invalid certification checksum file: $sha"; exit 1; }
  actual="$(sha256sum "$bin" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || { log "FAIL certification executable checksum mismatch: $bin"; exit 1; }
  log "Verified $(basename "$bin") SHA-256 $actual"
}
verify_cert_binary "$HOST_CERT_BIN"
verify_cert_binary "$API_CERT_BIN"
PRIVORA_LIVE_HOST_TEST=1 "$HOST_CERT_BIN" -test.v -test.run 'TestLiveLinuxUserLifecycle|TestNginxRealParserWhenAvailable|TestLocalBackup|TestInspectCPanelBackup|TestDNSAndDatabaseRenderers|TestSignedAppManifest|TestExtractZipRejectsSymlinkAndTraversal|TestExtractTarRejectsLinks|TestAppTargetContainment|TestCuratedAppEndToEndSignedTLSPublish|TestCuratedJoomlaHeadlessBootstrapUsesStdin' | tee -a "$TMP/log"
PRIVORA_LIVE_HOST_TEST=1 "$API_CERT_BIN" -test.v -test.run 'TestLiveProductionAccountProvision|TestLiveProductionAccountBackup|TestLiveProductionAccountFiles' | tee -a "$TMP/log"
for x in linux-users nginx local-backup account-files cpanel-inspector cpanel-stager dns-renderer database-renderer;do pass "$x";done
# Application installer core is certified separately from any particular third-party release.
if command -v openssl >/dev/null && command -v php >/dev/null && [[ -r "$ROOT/install/app-release-public-key.pem" ]]; then pass app-installer; fi
if command -v php-fpm8.4 >/dev/null&&php-fpm8.4 -tt >/dev/null 2>&1;then pass php-fpm;elif command -v php-fpm >/dev/null&&php-fpm -tt >/dev/null 2>&1;then pass php-fpm;fi
# Database probes use disposable names and immediately roll back.
if command -v mariadb >/dev/null;then
  db="privora_cert_$RANDOM"; u="pcert_$RANDOM";
  if mariadb --protocol=socket --batch -e "CREATE DATABASE \`$db\`; CREATE USER '$u'@'localhost' IDENTIFIED BY 'Temporary-Cert-Only-42!'; GRANT ALL ON \`$db\`.* TO '$u'@'localhost'; DROP USER '$u'@'localhost'; DROP DATABASE \`$db\`;" >/dev/null 2>&1;then pass mariadb;fi
fi
if command -v mysql >/dev/null;then
  mysql_ident="$(mysql --protocol=socket --batch --skip-column-names -e "SELECT CONCAT(@@version,' ',@@version_comment)" 2>/dev/null || true)"
  if [[ -n "$mysql_ident" && "${mysql_ident,,}" != *mariadb* ]]; then
    db="privora_cert_$RANDOM"; u="pcert_$RANDOM";
    if mysql --protocol=socket --batch -e "CREATE DATABASE \`$db\`; CREATE USER '$u'@'localhost' IDENTIFIED BY 'Temporary-Cert-Only-42!'; GRANT ALL ON \`$db\`.* TO '$u'@'localhost'; DROP USER '$u'@'localhost'; DROP DATABASE \`$db\`;" >/dev/null 2>&1;then pass mysql;fi
  fi
fi
if command -v psql >/dev/null && command -v runuser >/dev/null;then
  db="privora_cert_$RANDOM";u="pcert_$RANDOM";
  if runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 -c "CREATE ROLE \"$u\" LOGIN PASSWORD 'Temporary-Cert-Only-42!';" >/dev/null 2>&1 && runuser -u postgres -- createdb -O "$u" "$db" >/dev/null 2>&1;then runuser -u postgres -- dropdb "$db" >/dev/null 2>&1||true;runuser -u postgres -- psql --no-psqlrc --set=ON_ERROR_STOP=1 -c "DROP ROLE IF EXISTS \"$u\";" >/dev/null 2>&1||true;pass postgresql;fi
fi
if command -v named-checkzone >/dev/null;then cat >"$TMP/zone" <<'ZONE'
$TTL 300
@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 900 604800 300 )
@ IN NS ns1.example.test.
ns1 IN A 192.0.2.1
ZONE
named-checkzone example.test "$TMP/zone" >/dev/null 2>&1&&pass authoritative-dns||true;fi
# ACME certification proves a usable client exists. Domain issuance remains a per-domain challenge/health test.
command -v certbot >/dev/null&&certbot --version >/dev/null 2>&1&&pass acme||true
if command -v nft >/dev/null; then
  cat >"$TMP/nft" <<'NFT'
table inet privora_cert_test {
  chain input {
    type filter hook input priority 10; policy accept;
  }
}
NFT
  if nft -c -f "$TMP/nft" >/dev/null 2>&1; then
    pass nftables
  else
    log "nftables certification probe failed: candidate syntax/check rejected"
  fi
fi
command -v postconf >/dev/null&&postfix check >/dev/null 2>&1&&pass postfix||true
command -v doveconf >/dev/null&&doveconf -n >/dev/null 2>&1&&pass dovecot||true
command -v rspamadm >/dev/null&&rspamadm configtest >/dev/null 2>&1&&pass rspamd||true
command -v sshd >/dev/null&&sshd -t >/dev/null 2>&1&&pass openssh-sftp||true
if command -v setquota >/dev/null&&findmnt -no OPTIONS /|grep -Eq '(^|,)(usrquota|uquota|prjquota)(,|$)';then pass filesystem-quota;fi
[[ -r /sys/fs/cgroup/cgroup.controllers&&-w /sys/fs/cgroup ]]&&pass cgroup-v2||true
if [[ -x /usr/local/sbin/privora-update ]]&&PRIVORA_PANEL_ROOT="$ROOT" /usr/local/sbin/privora-update --security-only --dry-run >/dev/null;then pass privora-updater;elif [[ -x "$ROOT/scripts/privora-update.sh" ]]&&PRIVORA_PANEL_ROOT="$ROOT" "$ROOT/scripts/privora-update.sh" --security-only --dry-run >/dev/null;then pass privora-updater;fi
sort -u "$TMP/passed" -o "$TMP/passed"
case "$ROLE" in
 full) required=(linux-users nginx php-fpm "$SQL_FAMILY" postgresql authoritative-dns acme nftables postfix dovecot rspamd openssh-sftp filesystem-quota cgroup-v2 privora-updater app-installer local-backup account-files);;
 web) required=(linux-users nginx php-fpm acme nftables openssh-sftp filesystem-quota cgroup-v2 privora-updater app-installer local-backup account-files);;
 db) required=("$SQL_FAMILY" postgresql privora-updater);;
 mail) required=(postfix dovecot rspamd nftables privora-updater);;
 dns) required=(authoritative-dns nftables privora-updater);;
 backup) required=(openssh-sftp local-backup privora-updater);;
esac
missing=();for x in "${required[@]}";do has "$x"||missing+=("$x");done
status=PASS
if (( ${#missing[@]} ));then status=PARTIAL; if [[ "$REQUIRE_FULL" == 1 ]];then status=FAIL;fi; fi
python3 - "$TMP/passed" "$TMP/log" "$OUT" "$status" "$ROLE" "$(IFS=,;echo "${missing[*]}")" <<'PY'
import datetime,hashlib,json,os,platform,sys
pp,lp,out,status,role,missing=sys.argv[1:]
try: mid=open('/etc/machine-id','rb').read().strip()
except OSError: mid=os.environ.get('HOSTNAME','unknown').encode()
log=open(lp,'rb').read();obj={'profile':'privora-panel-host-adapter-certification-v1','status':status,'role':role,'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'machine_id_sha256':hashlib.sha256(mid).hexdigest(),'certified_adapters':[x.strip() for x in open(pp) if x.strip()],'missing_required_adapters':[x for x in missing.split(',') if x],'host':{'platform':platform.platform(),'machine':platform.machine()},'certification_log_sha256':hashlib.sha256(log).hexdigest(),'notes':'Machine-bound. Never copy to another VPS. Full installer promotion requires status PASS.'};open(out,'w').write(json.dumps(obj,indent=2)+'\n')
PY
sha256sum "$OUT"
if [[ "$status" == FAIL ]];then log "FAIL role=$ROLE missing=$(IFS=,;echo "${missing[*]}")";exit 1;fi
if [[ "$status" == PARTIAL ]];then log "PARTIAL role=$ROLE missing=$(IFS=,;echo "${missing[*]}")";else log "PASS role=$ROLE complete";fi
echo "Privora VPS host certification $status: $OUT"
