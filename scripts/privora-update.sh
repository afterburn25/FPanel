#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

PANEL_ROOT="${PRIVORA_PANEL_ROOT:-/opt/privora-panel}"
DEFAULT_UPDATE_CHANNEL="stable"
if [[ -r "$PANEL_ROOT/VERSION" ]] && grep -q -- '-dev\.' "$PANEL_ROOT/VERSION"; then DEFAULT_UPDATE_CHANNEL="developer"; fi
CHANNEL="${PRIVORA_UPDATE_CHANNEL:-$DEFAULT_UPDATE_CHANNEL}"
RELEASE_URL="${PRIVORA_UPDATE_RELEASE_URL:-}"
APP_MANIFEST_URL="${PRIVORA_APP_MANIFEST_URL:-}"
SECURITY_ONLY=0
AUTOMATIC=0
DRY_RUN=0
UPLOADED_ZIP=""
FORCED_TXN_ID=""
BACKUP_ROOT="${PRIVORA_UPDATE_BACKUP_ROOT:-/var/backups/privora-panel/update-transactions}"
STATE_ROOT="${PRIVORA_UPDATE_STATE_ROOT:-/var/lib/privora-panel/update-transactions}"
PUBKEY="${PRIVORA_RELEASE_PUBLIC_KEY:-$PANEL_ROOT/install/release-public-key.pem}"
LOG="${PRIVORA_UPDATE_LOG:-/var/log/privora-panel/update.log}"
CURRENT_PHASE=init
CURRENT_OPERATION=""
UPDATE_TERMINAL=0

usage(){ echo 'Usage: privora-update [--release-url HTTPS_URL | --uploaded-zip PATH] [--transaction-id ID] [--channel stable|early-access|developer] [--security-only] [--automatic] [--dry-run]'; }
while (($#)); do
  case "$1" in
    --release-url) RELEASE_URL="${2:-}"; shift 2;;
    --uploaded-zip) UPLOADED_ZIP="${2:-}"; shift 2;;
    --transaction-id) FORCED_TXN_ID="${2:-}"; shift 2;;
    --channel) CHANNEL="${2:-}"; shift 2;;
    --security-only) SECURITY_ONLY=1; shift;;
    --automatic) AUTOMATIC=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option $1" >&2; exit 2;;
  esac
done
[[ "$CHANNEL" =~ ^(stable|early-access|developer)$ ]] || { echo 'invalid update channel' >&2; exit 2; }
if [[ -n "$RELEASE_URL" && -n "$UPLOADED_ZIP" ]]; then echo 'choose release URL or uploaded ZIP, not both' >&2; exit 2; fi
if [[ -n "$FORCED_TXN_ID" ]]; then
  [[ "$FORCED_TXN_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$ ]] || { echo 'invalid transaction id' >&2; exit 2; }
  TXN_ID="$FORCED_TXN_ID"
else
  TXN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
TXN="$STATE_ROOT/$TXN_ID"
BACKUP="$BACKUP_ROOT/$TXN_ID"
(( DRY_RUN || EUID == 0 )) || { echo 'root required' >&2; exit 1; }

run(){ if ((DRY_RUN)); then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; else "$@"; fi; }
run_timed(){ local limit="$1"; shift; if ((DRY_RUN)); then printf '[dry-run timeout %s]' "$limit"; printf ' %q' "$@"; printf '\n'; else timeout --signal=TERM --kill-after=5s "$limit" "$@"; fi; }
shrun(){ if ((DRY_RUN)); then echo "[dry-run] $*"; else bash -o pipefail -c "$*"; fi; }
log(){ printf '[%s] txn=%s phase=%s %s\n' "$(date -u +%FT%TZ)" "$TXN_ID" "$CURRENT_PHASE" "$*" | tee -a "$LOG"; }
record(){ ((DRY_RUN)) && return 0; mkdir -p "$TXN"; printf '%s=%q\n' "$1" "$2" >>"$TXN/journal.env"; }
now_utc(){ date -u +%FT%TZ; }
mark_activity(){ record activity_at "$(now_utc)"; }
set_operation(){ CURRENT_OPERATION="$1"; record operation "$1"; mark_activity; }
clear_operation(){ CURRENT_OPERATION=""; record operation ""; mark_activity; }
set_phase(){ CURRENT_PHASE="$1"; CURRENT_OPERATION=""; record phase "$1"; record status running; record phase_started_at "$(now_utc)"; record operation ""; mark_activity; }
die(){ echo "$*" >&2; return 1; }
unit_exists(){
  local state
  state="$(timeout --signal=TERM --kill-after=1s 5s systemctl show "$1" --property=LoadState --value 2>/dev/null || true)"
  [[ -n "$state" && "$state" != "not-found" ]]
}

atomic_exchange_dirs(){
  local left="$1" right="$2"
  [[ -d "$left" && -d "$right" ]] || { echo "atomic exchange requires two directories: $left <-> $right" >&2; return 1; }
  python3 - "$left" "$right" <<'PYEXCHANGE'
import ctypes, errno, os, sys
left,right=sys.argv[1:]
libc=ctypes.CDLL(None, use_errno=True)
fn=getattr(libc,'renameat2',None)
if fn is None:
    raise SystemExit('renameat2 is unavailable; refusing non-atomic panel promotion')
AT_FDCWD=-100
RENAME_EXCHANGE=2
fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
fn.restype=ctypes.c_int
rc=fn(AT_FDCWD,os.fsencode(left),AT_FDCWD,os.fsencode(right),RENAME_EXCHANGE)
if rc != 0:
    e=ctypes.get_errno()
    raise OSError(e, os.strerror(e), f'{left} <-> {right}')
PYEXCHANGE
}

restore_snapshot_state_only(){
  local archive="$1"
  [[ -f "$archive" ]] || return 1
  # Never overwrite /opt/privora-panel during recovery. The live core is handled
  # only by atomic directory exchange; this restores mutable config/state only.
  tar --zstd -xpf "$archive" -C / --exclude='opt/privora-panel' --exclude='opt/privora-panel/**'
}

consume_upload_authorization(){
  [[ -n "$UPLOADED_ZIP" ]] || return 0
  ((DRY_RUN)) && { echo '[dry-run] consume transaction-bound root reauthorization'; return 0; }
  local auth_root="${PRIVORA_UPDATE_AUTH_ROOT:-/run/privora-panel/update-auth}"
  local auth_file="$auth_root/$TXN_ID.json"
  local auth_error=""
  [[ -r "$auth_file" ]] || {
    auth_error='transaction-bound update authorization is missing or expired'
    record error "$auth_error"; log "authorization verification FAIL: $auth_error"; die "$auth_error"; return 1;
  }
  log 'authorization verification begin'
  if ! auth_error="$(timeout --signal=KILL 20s python3 - "$auth_file" "$TXN_ID" "$UPLOADED_ZIP" 2>&1 <<'PYAUTH'
import datetime,hashlib,json,os,re,sys
p,txn,zp=sys.argv[1:]
try:
    d=json.load(open(p,encoding='utf-8'))
    if d.get('upload_id') != txn: raise ValueError('transaction id mismatch')
    if not re.fullmatch(r'[0-9a-f]{64}',d.get('zip_sha256','')): raise ValueError('invalid authorized ZIP hash')
    exp=datetime.datetime.fromisoformat(d['expires_at'].replace('Z','+00:00'))
    if datetime.datetime.now(datetime.timezone.utc) > exp: raise ValueError('authorization expired')
    real=os.path.realpath(zp); root=os.path.realpath('/var/lib/privora-panel/update-upload-staging')
    if os.path.commonpath([real,root]) != root or not os.path.isfile(real) or os.path.islink(real): raise ValueError('staged ZIP path is invalid')
    h=hashlib.sha256()
    with open(real,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    if h.hexdigest() != d['zip_sha256']: raise ValueError('staged ZIP hash mismatch')
except Exception as e:
    print(str(e))
    raise SystemExit(1)
PYAUTH
)"; then
    [[ -n "$auth_error" ]] || auth_error='authorization validation failed'
    record error "$auth_error"
    log "authorization verification FAIL: $auth_error"
    die "$auth_error"
    return 1
  fi
  rm -f -- "$auth_file"
  record authorization root-password-reauthenticated
  log 'authorization verification PASS'
}

refresh_app_catalog(){
  [[ -n "$APP_MANIFEST_URL" ]] || return 0
  local key="/etc/privora-panel/apps/app-release-public-key.pem" dst="/etc/privora-panel/apps" tmp="/var/tmp/privora-app-catalog-update-$TXN_ID"
  [[ -r "$key" ]] || key="$PANEL_ROOT/install/app-release-public-key.pem"
  if [[ "$APP_MANIFEST_URL" =~ ^https://[^/]+\.example(/|$) ]]; then
    log "signed app catalog refresh skipped for non-live development target $APP_MANIFEST_URL"
    return 0
  fi
  if ((DRY_RUN)); then echo "[dry-run] refresh signed app catalog from $APP_MANIFEST_URL"; return 0; fi
  [[ -r "$key" ]] || { log 'WARN app catalog public key missing; catalog refresh skipped'; return 0; }
  set_operation "Health: refreshing signed app catalog"
  rm -rf "$tmp"; mkdir -p "$tmp" "$dst"
  if ! curl -fL --connect-timeout 4 --max-time 12 --proto '=https' --tlsv1.2 "$APP_MANIFEST_URL" -o "$tmp/releases.json" || ! curl -fL --connect-timeout 4 --max-time 12 --proto '=https' --tlsv1.2 "${APP_MANIFEST_URL}.sig" -o "$tmp/releases.json.sig"; then
    log 'WARN signed app catalog download failed or timed out; existing catalog retained'; rm -rf "$tmp"; mark_activity; return 0
  fi
  if ! openssl dgst -sha256 -verify "$key" -signature "$tmp/releases.json.sig" "$tmp/releases.json" >/dev/null; then log 'WARN app catalog signature rejected; existing catalog retained'; rm -rf "$tmp"; mark_activity; return 0; fi
  if ! python3 - "$tmp/releases.json" <<'PYAPP'
import json,re,sys,urllib.parse
p=sys.argv[1]
try:
 d=json.load(open(p,encoding='utf-8')); assert d.get('schema')=='privora-app-release-manifest-v1'; rels=d.get('releases'); assert isinstance(rels,list) and len(rels)<=512
 current={}; templates=set()
 for r in rels:
  assert re.fullmatch(r'[a-z0-9][a-z0-9-]{1,47}',r['template']); templates.add(r['template']); u=urllib.parse.urlparse(r['url']); assert u.scheme=='https' and u.netloc and not u.username; assert re.fullmatch(r'[0-9a-f]{64}',r['sha256']); assert r['archive'] in ('zip','tar.gz'); assert r['bootstrap'] in ('wordpress','joomla','guided-web','none'); assert 1024 <= int(r['max_bytes']) <= 1073741824
  if r.get('current') is True: current[r['template']]=current.get(r['template'],0)+1
 assert all(current.get(t)==1 for t in templates)
except Exception as e:
 print(e,file=sys.stderr); raise SystemExit(1)
PYAPP
  then log 'WARN app catalog schema rejected; existing catalog retained'; rm -rf "$tmp"; mark_activity; return 0; fi
  install -m0644 "$key" "$dst/app-release-public-key.pem"
  install -m0644 "$tmp/releases.json" "$dst/releases.json"
  install -m0644 "$tmp/releases.json.sig" "$dst/releases.json.sig"
  rm -rf "$tmp"; mark_activity; log 'signed app catalog refreshed'
}

maybe_reboot(){
  ((AUTOMATIC)) || return 0
  [[ "${PRIVORA_AUTO_REBOOT:-0}" == 1 ]] || return 0
  local marker="${PRIVORA_REBOOT_REQUIRED_FILE:-/var/run/reboot-required}" window="${PRIVORA_REBOOT_WINDOW:-Sun 03:00}"
  [[ -f "$marker" ]] || return 0
  if [[ ! "$window" =~ ^(Sun|Mon|Tue|Wed|Thu|Fri|Sat)[[:space:]]([0-2][0-9]):([0-5][0-9])$ ]]; then log "Reboot required but maintenance window is invalid: $window"; return 0; fi
  if [[ "$(date +%a)" == "${BASH_REMATCH[1]}" && "$(date +%H)" == "${BASH_REMATCH[2]}" ]]; then set_phase reboot; record reboot scheduled; log "Reboot required and maintenance window $window is active"; run systemctl reboot
  else record reboot pending; log "Reboot required; waiting for maintenance window $window"; fi
}

if ((DRY_RUN)); then
  LOG=/tmp/privora-update-dry-run.log; :>"$LOG"
else
  install -d -m0750 "$STATE_ROOT" "$BACKUP_ROOT" "$(dirname "$LOG")" /run/privora-panel
  touch "$LOG"; chmod 0640 "$LOG"
  exec 9>/run/privora-panel/update.lock
  if ! flock -n 9; then
    CURRENT_PHASE=launch
    record phase launch
    record status failed
    record phase_started_at "$(now_utc)"
    record activity_at "$(now_utc)"
    record operation "Blocked by another update transaction"
    record error "another Privora update transaction is already running"
    log 'FAIL another Privora update transaction is already running'
    exit 75
  fi
fi
restore_pre_promotion_snapshot(){
  [[ -f "$BACKUP/privora-files.tar.zst" && -f "$BACKUP/privora-files.tar.zst.sha256" ]] || return 0
  (cd "$BACKUP" && sha256sum -c privora-files.tar.zst.sha256 >/dev/null) || return 1
  restore_snapshot_state_only "$BACKUP/privora-files.tar.zst"
  nginx -t >/dev/null 2>&1 || return 1
  systemctl reload nginx >/dev/null 2>&1 || true
  record status rolled-back
  record phase rollback
  record result pre-promotion-snapshot-restored
  # Preserve the active status API until rollback is terminal. Refresh the agent asynchronously afterwards.
  systemd-run --unit="privora-agent-snapshot-refresh-$TXN_ID" --collect --on-active=2s --property=TimeoutStartSec=45s -- /bin/systemctl restart privora-panel-agent.service >/dev/null 2>&1 || true
}
on_update_error(){
  local rc=$? line=${BASH_LINENO[0]:-unknown} failed_phase="$CURRENT_PHASE" failed_cmd="${BASH_COMMAND:-unknown}" failed_operation="${CURRENT_OPERATION:-}"
  trap - ERR
  UPDATE_TERMINAL=1
  local failure="phase=$failed_phase rc=$rc line=$line cmd=$failed_cmd"
  record status failed
  record failed_phase "$failed_phase"
  record failed_operation "$failed_operation"
  record failed_command "$failed_cmd"
  record failed_rc "$rc"
  record failed_error "$failure"
  record error "$failure"
  record operation "Failed: ${failed_operation:-$failed_cmd}"
  log "FAIL rc=$rc line=$line phase=$failed_phase operation=${failed_operation:-none} cmd=$failed_cmd"
  if ((DRY_RUN==0)) && [[ -f "$TXN/journal.env" ]]; then
    if grep -q '^previous=' "$TXN/journal.env"; then
      /usr/local/sbin/privora-update-rollback "$TXN_ID" 2>/dev/null || true
    elif [[ "$failed_phase" == migrations || "$failed_phase" == validate ]]; then
      restore_pre_promotion_snapshot || true
    fi
  fi
  exit "$rc"
}
on_update_exit(){
  local rc=$?
  ((DRY_RUN)) && return 0
  ((UPDATE_TERMINAL)) && return 0
  [[ -f "$TXN/journal.env" ]] || return 0
  local last_status
  last_status=$(awk -F= '$1=="status"{v=$2} END{gsub(/\\ /," ",v); print v}' "$TXN/journal.env" 2>/dev/null || true)
  if [[ "$last_status" == running ]]; then
    CURRENT_PHASE=${CURRENT_PHASE:-unknown}
    record status failed
    record error "updater exited before terminal state rc=$rc phase=$CURRENT_PHASE"
    record operation "Updater terminated before completion"
    log "FAIL updater exited before terminal state rc=$rc"
  fi
}
trap on_update_error ERR
trap on_update_exit EXIT

policy="${PRIVORA_UPDATE_POLICY_FILE:-/etc/privora-panel/update-policy.env}"
if [[ -f "$policy" ]]; then
  . "$policy"
  CHANNEL="${PRIVORA_UPDATE_CHANNEL:-$CHANNEL}"
  [[ -n "$RELEASE_URL" ]] || RELEASE_URL="${PRIVORA_UPDATE_RELEASE_URL:-}"
  APP_MANIFEST_URL="${PRIVORA_APP_MANIFEST_URL:-$APP_MANIFEST_URL}"
fi
if ((AUTOMATIC)); then
  [[ "${PRIVORA_SECURITY_AUTO:-1}" == 1 || "${PRIVORA_PACKAGE_AUTO:-0}" == 1 ]] || exit 0
  [[ "${PRIVORA_PACKAGE_AUTO:-0}" == 1 ]] || SECURITY_ONLY=1
fi

record started_at "$(now_utc)"
set_phase preflight
set_operation "Checking installed Privora and one-time authorization"
[[ -d "$PANEL_ROOT" && -f "$PANEL_ROOT/VERSION" ]] || die 'Privora not found'
record old_version "$(tr -d '\r\n' < "$PANEL_ROOT/VERSION")"
log "preflight current=$(tr -d '\r\n' < "$PANEL_ROOT/VERSION") channel=$CHANNEL security_only=$SECURITY_ONLY uploaded=$([[ -n "$UPLOADED_ZIP" ]]&&echo yes||echo no)"
consume_upload_authorization
clear_operation

set_phase backup
set_operation "Creating pre-update snapshot"
run mkdir -p "$BACKUP"
if ((DRY_RUN)); then echo '[dry-run] snapshot Privora/config/state'; else
  tar --zstd -cpf "$BACKUP/privora-files.tar.zst" "$PANEL_ROOT" /etc/privora-panel /var/lib/privora-panel/web /etc/nginx 2>"$BACKUP/snapshot-tar.stderr"
  sha256sum "$BACKUP/privora-files.tar.zst" >"$BACKUP/privora-files.tar.zst.sha256"
  (cd "$BACKUP" && sha256sum -c privora-files.tar.zst.sha256 >/dev/null)
  # Persist the complete archive listing first. Do not pipe tar directly into grep -q under pipefail:
  # grep may terminate early after a match and make an otherwise valid tar producer look failed.
  tar --zstd -tf "$BACKUP/privora-files.tar.zst" >"$BACKUP/snapshot-files.raw"
  sed -e 's#^\./##' -e 's#^/##' "$BACKUP/snapshot-files.raw" >"$BACKUP/snapshot-files.list"
  grep -Fxq 'opt/privora-panel/panel/public/index.php' "$BACKUP/snapshot-files.list" || die 'snapshot is missing panel/public/index.php'
  grep -Fxq 'opt/privora-panel/panel/public/admin.php' "$BACKUP/snapshot-files.list" || die 'snapshot is missing panel/public/admin.php'
  record snapshot_verified yes
fi
record backup "$BACKUP"
clear_operation

# Browser-uploaded Privora core packages intentionally do not trigger an OS-wide
# package upgrade.  Security/package maintenance remains a separate Update Center action.
if [[ -z "$UPLOADED_ZIP" ]]; then
  set_phase os-packages
  if command -v apt-get >/dev/null; then
    run env DEBIAN_FRONTEND=noninteractive apt-get update
    if ((SECURITY_ONLY)); then run env DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades; run unattended-upgrade -d; else run env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade; fi
  elif command -v dnf >/dev/null; then
    if ((SECURITY_ONLY)); then run dnf -y upgrade --security; else run dnf -y upgrade; fi
  fi
fi

if ((SECURITY_ONLY)); then set_phase health; run nginx -t; run systemctl is-active --quiet privora-panel-agent.service; refresh_app_catalog; record result security-update-pass; record status pass; record phase complete; UPDATE_TERMINAL=1; log PASS; maybe_reboot; exit 0; fi
if ((AUTOMATIC)) && [[ -z "$RELEASE_URL" ]]; then set_phase health; run nginx -t; run systemctl is-active --quiet privora-panel-agent.service; refresh_app_catalog; record result package-update-pass; record status pass; record phase complete; UPDATE_TERMINAL=1; log 'Automatic package/library maintenance PASS; no Privora release endpoint configured'; maybe_reboot; exit 0; fi

set_phase release
set_operation "Verifying and extracting signed release"
[[ -r "$PUBKEY" ]] || die "missing release public key $PUBKEY"
tmp="/var/tmp/privora-update-$TXN_ID"
run rm -rf "$tmp"
run mkdir -p "$tmp/src"

if [[ -n "$UPLOADED_ZIP" ]]; then
  [[ -x "$PANEL_ROOT/scripts/verify-upload-update.py" ]] || die 'uploaded-update verifier is not installed'
  if ((DRY_RUN)); then
    new='5.0.0-dry-run'; meta_channel="$CHANNEL"; echo '[dry-run] verify signed uploaded ZIP and extract payload'; record new_version "$new"
  else
    meta_json="$("$PANEL_ROOT/scripts/verify-upload-update.py" "$UPLOADED_ZIP" --public-key "$PUBKEY" --extract-to "$tmp/src")"
    read -r new meta_channel min_version < <(python3 - "$meta_json" <<'PYUPMETA'
import json,sys
d=json.loads(sys.argv[1]);print(d['version'],d['channel'],d.get('min_version','-') or '-')
PYUPMETA
)
    [[ "$meta_channel" == "$CHANNEL" ]] || die "uploaded update channel $meta_channel does not match requested channel $CHANNEL"
    current="$(tr -d '\r\n' < "$PANEL_ROOT/VERSION")"
    python3 - "$current" "$new" "$min_version" <<'PYVER'
import re,sys
cur,new,minv=sys.argv[1:]
def key(v):
 m=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:[-.](.*))?',v)
 assert m
 base=tuple(map(int,m.group(1,2,3))); suf=m.group(4)
 if suf is None:return base+(1,())
 toks=[]
 for t in re.findall(r'[A-Za-z]+|\d+',suf): toks.append((0,int(t)) if t.isdigit() else (1,t.lower()))
 return base+(0,tuple(toks))
assert key(new)>key(cur), f'update {new} is not newer than installed {cur}'
if minv not in ('','-'): assert key(cur)>=key(minv), f'installed {cur} is older than required {minv}'
PYVER
    [[ -f "$tmp/src/VERSION" && "$(tr -d '\r\n' < "$tmp/src/VERSION")" == "$new" ]] || die 'uploaded release VERSION mismatch'
    record new_version "$new"
  fi
else
  [[ -n "$RELEASE_URL" ]] || die 'full update requires signed release URL or uploaded package'
  shrun "curl -fL --proto '=https' --tlsv1.2 '$RELEASE_URL' -o '$tmp/release.tar.zst'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.sha256' -o '$tmp/release.tar.zst.sha256'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.sig' -o '$tmp/release.tar.zst.sig'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.json' -o '$tmp/release.tar.zst.json'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.json.sig' -o '$tmp/release.tar.zst.json.sig'"
  shrun "openssl dgst -sha256 -verify '$PUBKEY' -signature '$tmp/release.tar.zst.sig' '$tmp/release.tar.zst'"
  shrun "openssl dgst -sha256 -verify '$PUBKEY' -signature '$tmp/release.tar.zst.json.sig' '$tmp/release.tar.zst.json'"
  if ((DRY_RUN)); then
    new='5.0.0-dry-run'; echo '[dry-run] validate release metadata, containment and VERSION'; record new_version "$new"
  else
    read -r expected_sha expected_size new meta_channel < <(python3 - "$tmp/release.tar.zst.json" "$CHANNEL" <<'PYMETA'
import json,re,sys
p,channel=sys.argv[1:];d=json.load(open(p,encoding='utf-8'));assert d.get('schema')=='privora-release-v1';assert d.get('channel')==channel;assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.]+)?',d.get('version',''));assert re.fullmatch(r'[0-9a-f]{64}',d.get('sha256',''));size=d.get('size_bytes');assert isinstance(size,int) and 1024<=size<=536870912;print(d['sha256'],size,d['version'],d['channel'])
PYMETA
)
    [[ "$(stat -c %s "$tmp/release.tar.zst")" == "$expected_size" ]] || die 'release size mismatch'
    [[ "$(sha256sum "$tmp/release.tar.zst"|awk '{print $1}')" == "$expected_sha" ]] || die 'release digest mismatch'
    [[ "$(awk 'NR==1{print $1}' "$tmp/release.tar.zst.sha256")" == "$expected_sha" ]] || die 'release checksum sidecar mismatch'
    zstd -dc "$tmp/release.tar.zst" >"$tmp/release.tar"
    python3 - "$tmp/release.tar" "$new" <<'PYTAR'
import pathlib,sys,tarfile
p,version=sys.argv[1:];expected='privora-panel-'+version
with tarfile.open(p,'r:') as tf:
 m=tf.getmembers(); assert 0<len(m)<=100000; total=0
 for x in m:
  name=x.name; assert name and not name.startswith('/') and '\\' not in name and '\x00' not in name; parts=pathlib.PurePosixPath(name).parts; assert parts and parts[0]==expected and '..' not in parts; assert not (x.issym() or x.islnk() or x.isdev() or x.isfifo()); total += x.size if x.isfile() else 0; assert total<=1073741824
PYTAR
    tar -xf "$tmp/release.tar" -C "$tmp/src" --strip-components=1 --no-same-owner --no-same-permissions
    [[ -f "$tmp/src/VERSION" && "$(tr -d '\r\n' < "$tmp/src/VERSION")" == "$new" ]] || die 'release VERSION mismatch'
    record new_version "$new"
  fi
fi
clear_operation

set_phase dependencies
set_operation "Verifying release dependencies and binaries"
if [[ -f "$tmp/src/composer.json" ]]; then shrun "cd '$tmp/src'&&composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader"; fi
if [[ -f "$tmp/src/package-lock.json" ]]; then shrun "cd '$tmp/src'&&npm ci --omit=dev"; fi
if [[ -f "$tmp/src/agent/go.mod" ]]; then
  for f in privora-agent privora-hostadapter-cert.test privora-api-cert.test; do
    [[ -x "$tmp/src/dist/$f" && -r "$tmp/src/dist/$f.sha256" ]] || die "signed release missing prebuilt $f"
    (cd "$tmp/src/dist" && sha256sum -c "$f.sha256")
  done
fi
clear_operation

set_phase stage
set_operation "Staging new Privora release"
stage="$PANEL_ROOT.releases/$new-$TXN_ID"
stage_parent="$(dirname "$stage")"
run install -d -m0755 "$stage_parent"
[[ "$(stat -c '%a' "$stage_parent")" == 755 ]] || die 'release staging parent is not traversable'
if ((DRY_RUN)); then echo "[dry-run] stage $stage"; else rsync -a --delete --exclude panel/storage "$tmp/src/" "$stage/"; fi
record stage "$stage"
if ((DRY_RUN==0)); then
  for critical in VERSION panel/public/index.php panel/public/admin.php panel/public/api.php scripts/privora-update.sh scripts/privora-update-rollback.sh dist/privora-agent; do
    [[ -f "$stage/$critical" ]] || die "staged release missing critical file $critical"
  done
  [[ "$(tr -d '\r\n' < "$stage/VERSION")" == "$new" ]] || die 'staged release VERSION mismatch'
  # Normalize release-code permissions independently of archive extraction umask.
  find "$stage" -type d -exec chmod 0755 {} +
  find "$stage" -type f ! -perm /111 -exec chmod 0644 {} +
  chmod 0755 "$stage/scripts/privora-update.sh" "$stage/scripts/privora-update-rollback.sh" "$stage/dist/privora-agent"
  [[ "$(stat -c '%a' "$stage")" == 755 ]] || die 'staged release root is not traversable'
  if id privora-panel >/dev/null 2>&1; then
    runuser -u privora-panel -- test -x "$stage_parent" || die 'release staging parent is not traversable by privora-panel'
    runuser -u privora-panel -- test -r "$stage/panel/public/index.php" || die 'staged panel index.php is not readable by privora-panel'
    runuser -u privora-panel -- test -r "$stage/panel/public/api.php" || die 'staged panel api.php is not readable by privora-panel'
  fi
fi
record stage_verified yes
clear_operation

set_phase migrations
if [[ -x "$stage/scripts/migrate.sh" ]]; then
  set_operation "Migrations: preflight"
  run_timed 90s "$stage/scripts/migrate.sh" --preflight
  set_operation "Migrations: applying idempotent server changes"
  run_timed 180s "$stage/scripts/migrate.sh" --apply
else
  set_operation "Migrations: none required"
fi
clear_operation

set_phase validate
set_operation "Validation: checking live Nginx configuration"
if ((DRY_RUN)); then
  run nginx -t
else
  if ! nginx_validation="$(nginx -t 2>&1)"; then
    printf '%s\n' "$nginx_validation" >>"$LOG"
    record validation_component nginx
    record validation_output "$nginx_validation"
    die "Nginx syntax validation failed: $nginx_validation"
  fi
fi
mark_activity

if command -v php >/dev/null; then
  while IFS= read -r -d '' f; do
    rel="${f#$stage/}"
    set_operation "Validation: PHP syntax $rel"
    if ((DRY_RUN)); then
      run php -l "$f" >/dev/null
    else
      if ! php_validation="$(php -l "$f" 2>&1)"; then
        printf '%s\n' "$php_validation" >>"$LOG"
        record validation_component php
        record validation_file "$rel"
        record validation_output "$php_validation"
        die "PHP syntax validation failed for $rel: $php_validation"
      fi
    fi
    mark_activity
  done < <(find "$stage/panel" "$stage/scripts" -name '*.php' -print0)
fi
set_operation "Validation: staged release passed"
record validation_result pass
clear_operation

set_phase promote
set_operation "Atomically promoting new release"
if ((DRY_RUN)); then echo '[dry-run] atomically exchange staged and live release'; else
  previous="$PANEL_ROOT.previous-$TXN_ID"
  [[ ! -e "$previous" ]] || die "previous release path already exists: $previous"
  # Both paths live under /opt, so RENAME_EXCHANGE gives a single atomic namespace
  # switch: /opt/privora-panel is never absent, even if the updater dies here.
  atomic_exchange_dirs "$PANEL_ROOT" "$stage"
  mv "$stage" "$previous"
  record previous "$previous"
  record promotion atomic-exchange
  [[ -f "$PANEL_ROOT/panel/public/index.php" && -f "$PANEL_ROOT/panel/public/admin.php" ]] || die 'promoted panel web root is incomplete'
  promoted_version="$(tr -d '\r\n' < "$PANEL_ROOT/VERSION" 2>/dev/null || true)"
  [[ "$promoted_version" == "$new" ]] || die "promoted VERSION mismatch: expected $new got ${promoted_version:-missing}"
  record promoted_version "$promoted_version"
  if id privora-panel >/dev/null 2>&1; then
    runuser -u privora-panel -- test -r "$PANEL_ROOT/panel/public/index.php" || die 'promoted panel index.php is not readable by privora-panel'
    runuser -u privora-panel -- test -r "$PANEL_ROOT/panel/public/api.php" || die 'promoted panel api.php is not readable by privora-panel'
  fi
  install -d -m0755 /usr/local/libexec /usr/local/bin /usr/local/sbin
  install -m0750 "$PANEL_ROOT/dist/privora-agent" /usr/local/libexec/privora-agent
  install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update
  install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback
fi
clear_operation

set_phase restart
set_operation "Restart: reloading systemd units"
run_timed 30s systemctl daemon-reload
set_operation "Restart: validating promoted Privora agent binary"
run test -x /usr/local/libexec/privora-agent
if [[ -r "$PANEL_ROOT/dist/privora-agent.sha256" ]]; then
  (cd "$PANEL_ROOT/dist" && run sha256sum -c privora-agent.sha256)
fi
record agent_refresh deferred-until-after-pass
panel_fpm=""
set_operation "Restart: detecting panel PHP-FPM service"
if unit_exists privora-panel-fpm.service; then
  panel_fpm=privora-panel-fpm.service
elif unit_exists php8.4-fpm.service; then
  panel_fpm=php8.4-fpm.service
elif unit_exists php-fpm.service; then
  panel_fpm=php-fpm.service
fi
if [[ -n "$panel_fpm" ]]; then
  if systemctl is-active --quiet "$panel_fpm"; then
    # PHP-FPM/opcache workers may retain pre-promotion bytecode after the atomic
    # directory exchange. A graceful reload picks up the promoted code without
    # destroying file-backed PCC/PPanel sessions or hard-killing active requests.
    set_operation "Restart: gracefully reloading PCC PHP-FPM code workers"
    run_timed 45s systemctl reload "$panel_fpm"
    record panel_fpm_refresh graceful-reload
    mark_activity
  else
    set_operation "Restart: starting inactive panel PHP-FPM"
    run_timed 20s systemctl reset-failed "$panel_fpm" || true
    run_timed 45s systemctl start "$panel_fpm"
    record panel_fpm_refresh started-inactive-runtime
  fi
fi
set_operation "Restart: validating Nginx"
run nginx -t
set_operation "Restart: reloading Nginx"
run_timed 30s systemctl reload nginx
clear_operation

set_phase health
set_operation "Health: checking Privora agent"
run systemctl is-active --quiet privora-panel-agent.service
mark_activity

set_operation "Health: validating Nginx configuration"
run nginx -t
mark_activity

if [[ -n "$panel_fpm" ]]; then
  set_operation "Health: waiting for $panel_fpm"
  panel_fpm_ready=0
  for i in $(seq 1 40); do
    if systemctl is-active --quiet "$panel_fpm"; then panel_fpm_ready=1; break; fi
    record operation "Health: waiting for $panel_fpm ($i/40)"; mark_activity; sleep 0.5
  done
  [[ "$panel_fpm_ready" == 1 ]] || die "$panel_fpm did not become active"
fi

if [[ "$panel_fpm" == "privora-panel-fpm.service" ]]; then
  set_operation "Health: waiting for panel PHP-FPM socket"
  socket_ready=0
  for i in $(seq 1 40); do
    if [[ -S /run/php/privora-panel.sock ]]; then socket_ready=1; break; fi
    record operation "Health: waiting for panel socket ($i/40)"; mark_activity; sleep 0.5
  done
  [[ "$socket_ready" == 1 ]] || die "Privora panel PHP-FPM socket did not become ready"
fi

set_operation "Health: probing panel HTTPS endpoint"
panel_http="000"; panel_health_ok=0
for i in $(seq 1 40); do
  panel_http="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 4 "https://127.0.0.1:${PRIVORA_PANEL_PORT:-8443}/" || true)"
  case "$panel_http" in
    200|201|204|301|302|303|307|308|401|403) panel_health_ok=1; break;;
  esac
  record operation "Health: HTTPS probe attempt $i/40 returned HTTP ${panel_http:-000}"; mark_activity; sleep 0.5
done
if [[ "$panel_health_ok" != 1 ]]; then
  log "Health diagnostics: panel HTTP=${panel_http:-000}"
  systemctl status privora-panel-agent.service --no-pager -l >>"$LOG" 2>&1 || true
  [[ -z "$panel_fpm" ]] || systemctl status "$panel_fpm" --no-pager -l >>"$LOG" 2>&1 || true
  ls -l /run/php/privora-panel.sock >>"$LOG" 2>&1 || true
  tail -n 120 /var/log/nginx/error.log >>"$LOG" 2>&1 || true
  tail -n 120 /var/log/privora-panel/php-fpm.log >>"$LOG" 2>&1 || true
  die "Privora panel HTTPS endpoint did not become healthy (HTTP ${panel_http:-000})"
fi
mark_activity

refresh_app_catalog
set_operation "Health: verifying installed Privora version"
installed_version="$(tr -d '\r\n' < "$PANEL_ROOT/VERSION" 2>/dev/null || true)"
[[ "$installed_version" == "$new" ]] || die "installed VERSION mismatch after health: expected $new got ${installed_version:-missing}"
record installed_version "$installed_version"
if id privora-panel >/dev/null 2>&1; then
  runuser -u privora-panel -- test -r "$PANEL_ROOT/panel/public/index.php" || die 'installed panel index.php is not readable by privora-panel'
  runuser -u privora-panel -- test -r "$PANEL_ROOT/panel/public/api.php" || die 'installed panel api.php is not readable by privora-panel'
fi
clear_operation
record result pass
record status pass
record phase complete
UPDATE_TERMINAL=1
if [[ -n "$UPLOADED_ZIP" && $DRY_RUN -eq 0 ]]; then rm -f -- "$UPLOADED_ZIP" "${UPLOADED_ZIP%.zip}.json"; fi
log "Privora update $new PASS"
if ((DRY_RUN==0)); then
  set +e
  if [[ -x "$PANEL_ROOT/scripts/apply-recovery-vhost.sh" ]]; then
    systemd-run --unit="privora-recovery-vhost-$TXN_ID" --collect --on-active=3s --property=TimeoutStartSec=45s -- "$PANEL_ROOT/scripts/apply-recovery-vhost.sh" >/dev/null 2>&1
    recovery_vhost_rc=$?
    if ((recovery_vhost_rc==0)); then record recovery_vhost scheduled-after-pass; else record recovery_vhost schedule-failed; log "WARN could not schedule recovery-vhost activation rc=$recovery_vhost_rc"; fi
  fi
  if [[ -x "$PANEL_ROOT/scripts/reconcile-site-panel-shortcuts.sh" ]]; then
    systemd-run --unit="privora-site-shortcuts-$TXN_ID" --collect --on-active=7s --property=TimeoutStartSec=60s -- "$PANEL_ROOT/scripts/reconcile-site-panel-shortcuts.sh" >/dev/null 2>&1
    panel_shortcuts_rc=$?
    if ((panel_shortcuts_rc==0)); then record panel_shortcuts scheduled-after-pass; else record panel_shortcuts schedule-failed; log "WARN could not schedule PCC/PPanel site-shortcut reconciliation rc=$panel_shortcuts_rc"; fi
  fi
  systemd-run --unit="privora-agent-refresh-$TXN_ID" --collect --on-active=2s --property=TimeoutStartSec=45s -- /bin/systemctl restart privora-panel-agent.service >/dev/null 2>&1
  agent_refresh_rc=$?
  set -e
  if ((agent_refresh_rc==0)); then
    record agent_refresh scheduled-after-pass
    if [[ -x "$PANEL_ROOT/scripts/privora-dns-reconcile-postupdate.php" || -r "$PANEL_ROOT/scripts/privora-dns-reconcile-postupdate.php" ]]; then
      systemd-run --unit="privora-dns-reconcile-$TXN_ID" --collect --on-active=6s --property=TimeoutStartSec=240s -- /bin/bash -lc "set -a; source /etc/privora-panel/agent.env; export PRIVORA_AGENT_SOCKET=/run/privora-panel/agent.sock; exec /usr/bin/php '$PANEL_ROOT/scripts/privora-dns-reconcile-postupdate.php'" >/dev/null 2>&1
      dns_reconcile_rc=$?
      if ((dns_reconcile_rc==0)); then record dns_reconcile scheduled-after-pass; else record dns_reconcile schedule-failed; log "WARN could not schedule post-update hosted DNS reconciliation rc=$dns_reconcile_rc"; fi
    fi
  else
    record agent_refresh schedule-failed
    log "WARN could not schedule deferred Privora agent refresh rc=$agent_refresh_rc; current agent remains active"
  fi
fi
maybe_reboot
