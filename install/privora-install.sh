#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
PRIVORA_VERSION="5.0.0-dev.7.0"; MODE="full"; SQL_FAMILY="${PRIVORA_SQL_FAMILY:-mariadb}"; DEFAULT_UPDATE_CHANNEL="stable"; [[ "$PRIVORA_VERSION" == *-dev.* ]] && DEFAULT_UPDATE_CHANNEL="developer"; CHANNEL="${PRIVORA_UPDATE_CHANNEL:-$DEFAULT_UPDATE_CHANNEL}"; HOSTNAME_ARG=""; ADMIN_EMAIL=""; ADMIN_USER="admin"; ADMIN_PASSWORD=""; SOURCE_DIR="${PRIVORA_SOURCE_DIR:-}"; RELEASE_URL="${PRIVORA_RELEASE_URL:-}"; DRY_RUN=0; WEB_PORT="${PRIVORA_ADMIN_PANEL_PORT:-8443}"; HOSTING_PORT="${PRIVORA_HOSTING_PANEL_PORT:-2443}"; AUTO_RELEASE_URL="${PRIVORA_AUTO_RELEASE_URL:-}"; DOWNLOAD_BASE="${PRIVORA_DOWNLOAD_BASE:-https://downloads.privora.example/releases}"; APP_MANIFEST_URL="${PRIVORA_APP_MANIFEST_URL:-https://downloads.privora.example/apps/releases.json}"; REQUIRE_APP_CATALOG="${PRIVORA_REQUIRE_APP_CATALOG:-0}"
write_embedded_release_key(){ cat <<'PRIVORA_RELEASE_KEY'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqnc+ORC1VSXnT5X1CgZT
OE2TiabSwApY6tqBC8sUINexF0iaFFGjldW9dwl82FamxkCUNyDHW62EJukmboOA
WcI9KgHkLCksvuKwAYibEIz8hJIsDv8AsPb9NB5pObBe34wXBATImexyo1lsey5+
vZmi4UeaU9ZuWGGBq4/wFVuU4BdIPTvxkKKZL9E5fEV3OGVzttt/DC3Qm1mTMsjS
bp7kFcIbphfFVG7G+RdeI0v7+RKkfRvbTtLCmc0q4euIl/f289hr4Zs8WanZhlKR
zMadz8c6GUXQ1BzG4lc0a4+ewV2mtqS5dB2yJLtRFVyBzDyB71ab1GZkcXbcpH9n
sGOyxy4WlIHKqFNSBbRHRrwlJaUoG0u7mvqPbA+RNrhMFdiC8wuevT3991AWNdlh
O6hcTnWpBkbdxNdWnYRLfdqwmp93LicQI5t0TZ1DTKmO2O/YWJLCUCycV54F29rF
3XZ+8k4JiaXbcGWF5TzdwyC6GtXwyvLSG7ENXI490fl3AgMBAAE=
-----END PUBLIC KEY-----
PRIVORA_RELEASE_KEY
}
STATE_DIR="/var/lib/privora-installer"; STATE_FILE="$STATE_DIR/state.env"; LOG_DIR="/var/log/privora-installer"; LOG_FILE="$LOG_DIR/install.log"; PANEL_ROOT="/opt/privora-panel"; AGENT_ENV="/etc/privora-panel/agent.env"; PANEL_ENV="/etc/privora-panel/panel.env"; CERT_DIR="/var/lib/privora-panel/certifications"
usage(){ cat <<USAGE
Privora Panel one-command VPS bootstrap
Usage: $0 [--hostname FQDN] [--admin-email EMAIL] [--admin-user USER] [--admin-password PASS] [--mode full|web|db|mail|dns|backup] [--sql-family mariadb|mysql] [--channel stable|early-access|developer] [--source-dir PATH] [--release-url HTTPS_URL] [--update-release-url HTTPS_URL] [--app-manifest-url HTTPS_URL] [--require-app-catalog] [--web-port PORT] [--hosting-port PORT] [--dry-run]
USAGE
}
while (($#)); do case "$1" in --hostname) HOSTNAME_ARG="${2:-}";shift 2;; --admin-email) ADMIN_EMAIL="${2:-}";shift 2;; --admin-user) ADMIN_USER="${2:-}";shift 2;; --admin-password) ADMIN_PASSWORD="${2:-}";shift 2;; --mode) MODE="${2:-}";shift 2;; --sql-family) SQL_FAMILY="${2:-}";shift 2;; --channel) CHANNEL="${2:-}";shift 2;; --source-dir) SOURCE_DIR="${2:-}";shift 2;; --release-url) RELEASE_URL="${2:-}";shift 2;; --update-release-url) AUTO_RELEASE_URL="${2:-}";shift 2;; --app-manifest-url) APP_MANIFEST_URL="${2:-}";shift 2;; --require-app-catalog) REQUIRE_APP_CATALOG=1;shift;; --web-port) WEB_PORT="${2:-}";shift 2;; --hosting-port) HOSTING_PORT="${2:-}";shift 2;; --dry-run) DRY_RUN=1;shift;; -h|--help) usage;exit 0;; *) echo "Unknown option: $1" >&2; exit 2;; esac; done
[[ "$MODE" =~ ^(full|web|db|mail|dns|backup)$ ]] || { echo "Invalid --mode" >&2; exit 2; }; [[ "$SQL_FAMILY" =~ ^(mariadb|mysql)$ ]] || { echo "Invalid --sql-family" >&2; exit 2; }; [[ "$CHANNEL" =~ ^(stable|early-access|developer)$ ]] || { echo "Invalid --channel" >&2; exit 2; }; [[ "$WEB_PORT" =~ ^[0-9]{2,5}$ ]] || { echo "Invalid --web-port" >&2; exit 2; }; [[ "$HOSTING_PORT" =~ ^[0-9]{2,5}$ ]] || { echo "Invalid --hosting-port" >&2; exit 2; }; ((WEB_PORT>=1 && WEB_PORT<=65535 && HOSTING_PORT>=1 && HOSTING_PORT<=65535 && WEB_PORT!=HOSTING_PORT)) || { echo "Panel ports must be distinct values from 1-65535" >&2; exit 2; }
if [[ -z "$SOURCE_DIR" && -z "$RELEASE_URL" ]]; then RELEASE_URL="$DOWNLOAD_BASE/$CHANNEL/privora-panel-current.tar.zst"; fi
if [[ -z "$AUTO_RELEASE_URL" ]]; then AUTO_RELEASE_URL="${RELEASE_URL:-$DOWNLOAD_BASE/$CHANNEL/privora-panel-current.tar.zst}"; fi
if ((DRY_RUN==0 && EUID!=0)); then echo "Privora bootstrap must be run as root." >&2; exit 1; fi; [[ -r /etc/os-release ]] || { echo "Unsupported OS" >&2; exit 1; }; . /etc/os-release; OS_ID="${ID,,}"; case "$OS_ID" in ubuntu|debian|almalinux|rocky) ;; *) echo "Unsupported OS: $OS_ID" >&2; exit 1;; esac
run(){ if ((DRY_RUN)); then printf '[dry-run]';printf ' %q' "$@";printf '\n'; else "$@"; fi; }; shrun(){ if ((DRY_RUN)); then echo "[dry-run] $*"; else bash -o pipefail -c "$*"; fi; }; log(){ printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG_FILE"; }; secret(){ openssl rand -base64 48|tr -d '\n'|tr '/+' '_-'|cut -c1-${1:-48}; }
if ((DRY_RUN)); then LOG_FILE=/tmp/privora-install-dry-run.log; :>"$LOG_FILE"; else mkdir -p "$STATE_DIR" "$LOG_DIR"; touch "$LOG_FILE"; chmod 0750 "$STATE_DIR" "$LOG_DIR";chmod 0640 "$LOG_FILE"; fi
CURRENT_PHASE=init; trap 'rc=$?; log "ERROR phase=$CURRENT_PHASE line=$LINENO rc=$rc"; exit $rc' ERR
completed(){ [[ -f "$STATE_FILE" ]]&&grep -qxF "phase_$1=done" "$STATE_FILE"; }; mark_done(){ ((DRY_RUN))&&return; touch "$STATE_FILE";grep -v "^phase_$1=" "$STATE_FILE">"$STATE_FILE.tmp"||true;printf 'phase_%s=done\n' "$1">>"$STATE_FILE.tmp";mv "$STATE_FILE.tmp" "$STATE_FILE";chmod 0600 "$STATE_FILE"; }; phase(){ CURRENT_PHASE="$1"; if completed "$1";then log "SKIP $1 (already completed)";return 1;fi;log "BEGIN $1"; }; finish_phase(){ mark_done "$1";log "PASS $1"; }
pkg_update(){ if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then run env DEBIAN_FRONTEND=noninteractive apt-get update;run env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade;else run dnf -y makecache;run dnf -y upgrade;fi; }
pkg_install(){ if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@";else run dnf -y install "$@";fi; }
preflight(){ local mem disk;mem=$(awk '/MemTotal/{print $2}' /proc/meminfo);disk=$(df -Pk /|awk 'NR==2{print $4}');((mem>=1900000))||log "WARN Less than 2GB RAM";((disk>=10000000))||{ echo "At least 10GB free disk required" >&2;exit 1;};command -v systemctl >/dev/null; }
configure_php_repo(){ if [[ "$OS_ID" == ubuntu ]];then pkg_install software-properties-common ca-certificates curl gnupg;run add-apt-repository -y ppa:ondrej/php;run apt-get update;elif [[ "$OS_ID" == debian ]];then pkg_install ca-certificates curl gnupg lsb-release apt-transport-https;if ((DRY_RUN));then echo '[dry-run] configure packages.sury.org PHP repository';else install -d -m0755 /etc/apt/keyrings;curl -fsSL https://packages.sury.org/php/apt.gpg|gpg --dearmor -o /etc/apt/keyrings/sury-php.gpg;chmod 0644 /etc/apt/keyrings/sury-php.gpg;echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ $VERSION_CODENAME main">/etc/apt/sources.list.d/sury-php.list;apt-get update;fi;else pkg_install epel-release dnf-utils;run dnf -y install https://rpms.remirepo.net/enterprise/remi-release-9.rpm;fi; }
install_base_packages(){ if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then pkg_install ca-certificates curl wget gnupg openssl jq zstd tar unzip rsync acl quota git composer nodejs npm python3 python3-venv python3-pip openssh-server nftables cron logrotate php-cli golang-go pamtester;else pkg_install ca-certificates curl wget gnupg2 openssl jq zstd tar unzip rsync acl quota git composer nodejs npm python3 python3-pip openssh-server nftables cronie logrotate php-cli php-fpm golang pamtester;fi; }
install_role_packages(){ local sql_pkg; if [[ "$SQL_FAMILY" == mysql ]]; then sql_pkg=mysql-server; else sql_pkg=mariadb-server; fi; case "$MODE" in full) if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then pkg_install nginx "$sql_pkg" postgresql redis-server bind9 bind9-utils certbot postfix dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sieve rspamd;else pkg_install nginx "$sql_pkg" postgresql-server redis bind bind-utils certbot postfix dovecot rspamd;fi;; web) pkg_install nginx certbot redis-server 2>/dev/null||pkg_install nginx certbot redis;; db) if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then pkg_install "$sql_pkg" postgresql redis-server;else pkg_install "$sql_pkg" postgresql-server redis;fi;; mail) pkg_install postfix dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sieve rspamd 2>/dev/null||pkg_install postfix dovecot dovecot-pigeonhole rspamd;; dns) pkg_install bind9 bind9-utils 2>/dev/null||pkg_install bind bind-utils;; backup) pkg_install zstd rsync openssh-server;; esac; }
install_php_stack(){
  [[ "$MODE" =~ ^(full|web)$ ]]||return
  configure_php_repo
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then
    local v p missing
    local -a pkgs
    for v in 8.2 8.3 8.4 8.5;do
      pkgs=("php$v-fpm" "php$v-cli" "php$v-common" "php$v-curl" "php$v-gd" "php$v-intl" "php$v-mbstring" "php$v-mysql" "php$v-pgsql" "php$v-opcache" "php$v-xml" "php$v-zip")
      missing=0
      for p in "${pkgs[@]}";do apt-cache show "$p" >/dev/null 2>&1 || { missing=1;break; };done
      if ((missing));then log "WARN PHP $v complete package set unavailable; skipping";continue;fi
      pkg_install "${pkgs[@]}"
    done
  fi
}
acquire_source(){
  if [[ -n "$SOURCE_DIR" ]];then [[ -f "$SOURCE_DIR/VERSION"&&-d "$SOURCE_DIR/agent"&&-d "$SOURCE_DIR/panel" ]]||{ echo "Invalid --source-dir" >&2;exit 1;};return;fi
  [[ -n "$RELEASE_URL" ]]||{ echo "Set --source-dir or --release-url" >&2;exit 1;}
  local t=/var/tmp/privora-release keyfile expected_sha expected_size meta_version meta_channel
  run rm -rf "$t";run mkdir -p "$t/src"
  shrun "curl -fL --proto '=https' --tlsv1.2 '$RELEASE_URL' -o '$t/release.tar.zst'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.sha256' -o '$t/release.tar.zst.sha256'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.sig' -o '$t/release.tar.zst.sig'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.json' -o '$t/release.tar.zst.json'"
  shrun "curl -fL --proto '=https' --tlsv1.2 '${RELEASE_URL}.json.sig' -o '$t/release.tar.zst.json.sig'"
  keyfile="$(dirname "$0")/release-public-key.pem";if [[ ! -f "$keyfile" ]];then keyfile="$t/release-public-key.pem";if ((DRY_RUN));then echo "[dry-run] materialize embedded release public key";else write_embedded_release_key >"$keyfile";chmod 0644 "$keyfile";fi;fi
  shrun "openssl dgst -sha256 -verify '$keyfile' -signature '$t/release.tar.zst.sig' '$t/release.tar.zst'"
  shrun "openssl dgst -sha256 -verify '$keyfile' -signature '$t/release.tar.zst.json.sig' '$t/release.tar.zst.json'"
  if ((DRY_RUN));then echo "[dry-run] validate signed release metadata/archive containment and extract";SOURCE_DIR="$t/src";return;fi
  read -r expected_sha expected_size meta_version meta_channel < <(python3 - "$t/release.tar.zst.json" "$CHANNEL" <<'PYMETA'
import json,re,sys
p,channel=sys.argv[1:];d=json.load(open(p,encoding='utf-8'))
assert d.get('schema')=='privora-release-v1'
assert d.get('channel')==channel
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.]+)?',d.get('version',''))
assert re.fullmatch(r'[0-9a-f]{64}',d.get('sha256',''))
size=d.get('size_bytes');assert isinstance(size,int) and 1024 <= size <= 536870912
print(d['sha256'],size,d['version'],d['channel'])
PYMETA
)
  [[ "$(stat -c %s "$t/release.tar.zst")" == "$expected_size" ]]||{ echo 'release size mismatch' >&2;exit 1;}
  [[ "$(sha256sum "$t/release.tar.zst"|awk '{print $1}')" == "$expected_sha" ]]||{ echo 'release digest mismatch' >&2;exit 1;}
  [[ "$(awk 'NR==1{print $1}' "$t/release.tar.zst.sha256")" == "$expected_sha" ]]||{ echo 'release checksum sidecar mismatch' >&2;exit 1;}
  zstd -dc "$t/release.tar.zst" >"$t/release.tar"
  python3 - "$t/release.tar" "$meta_version" <<'PYTAR'
import pathlib,sys,tarfile
p,version=sys.argv[1:];expected='privora-panel-'+version
with tarfile.open(p,'r:') as tf:
    members=tf.getmembers(); assert 0 < len(members) <= 100000
    total=0
    for m in members:
        name=m.name
        assert name and not name.startswith('/') and '\\' not in name and '\x00' not in name
        parts=pathlib.PurePosixPath(name).parts
        assert parts and parts[0]==expected and '..' not in parts
        assert not (m.issym() or m.islnk() or m.isdev() or m.isfifo())
        if m.isfile(): total += m.size
        assert total <= 1073741824
print('release archive containment PASS')
PYTAR
  tar -xf "$t/release.tar" -C "$t/src" --strip-components=1 --no-same-owner --no-same-permissions
  [[ -f "$t/src/VERSION" && "$(tr -d '\r\n' < "$t/src/VERSION")" == "$meta_version" ]]||{ echo 'release VERSION mismatch' >&2;exit 1;}
  SOURCE_DIR="$t/src"
}

install_privora(){
  local arch prebuilt expected actual
  run mkdir -p "$PANEL_ROOT" "$PANEL_ROOT/dist" /etc/privora-panel /var/lib/privora-panel /var/log/privora-panel /var/backups/privora-panel /run/privora-panel "$CERT_DIR" /usr/local/libexec /usr/local/bin /usr/local/sbin
  if ((DRY_RUN)); then
    echo "[dry-run] rsync source to $PANEL_ROOT"
  else
    rsync -a --delete --exclude panel/storage --exclude evidence/sandbox-host-adapter-certification.json "$SOURCE_DIR/" "$PANEL_ROOT/"
    # ZIP extractors such as Python zipfile may not restore Unix executable bits.
    # Normalize bundled runtime executable permissions before validating them.
    for runtime in privora-agent privora-hostadapter-cert.test privora-api-cert.test; do
      [[ -f "$PANEL_ROOT/dist/$runtime" ]] && chmod 0755 "$PANEL_ROOT/dist/$runtime"
    done
    for runtime in scripts/privora-update.sh scripts/privora-update-rollback.sh scripts/verify-upload-update.py cli/privora install/privora-install.sh; do
      [[ -f "$PANEL_ROOT/$runtime" ]] && chmod 0755 "$PANEL_ROOT/$runtime"
    done
  fi

  arch="$(uname -m)"
  prebuilt="$PANEL_ROOT/dist/privora-agent"
  if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
    if ((DRY_RUN)); then
      echo "[dry-run] verify bundled x86-64 Privora agent SHA-256 and install it"
    else
      [[ -x "$prebuilt" ]] || { echo "bundled Privora agent is missing or not executable" >&2; exit 1; }
      [[ -r "$PANEL_ROOT/dist/privora-agent.sha256" ]] || { echo "bundled Privora agent checksum is missing" >&2; exit 1; }
      expected="$(awk 'NR==1{print $1}' "$PANEL_ROOT/dist/privora-agent.sha256")"
      [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid bundled Privora agent checksum" >&2; exit 1; }
      actual="$(sha256sum "$prebuilt" | awk '{print $1}')"
      [[ "$actual" == "$expected" ]] || { echo "bundled Privora agent checksum mismatch" >&2; exit 1; }
      log "Verified bundled Privora agent SHA-256 $actual for $arch"
    fi
  else
    if ((DRY_RUN)); then
      echo "[dry-run] no bundled agent for $arch; compile from source with Go toolchain"
    else
      command -v go >/dev/null 2>&1 || { echo "Go compiler required for unsupported architecture $arch" >&2; exit 1; }
      log "No bundled Privora agent for $arch; compiling with $(go version)"
      (cd "$PANEL_ROOT/agent" && GOTOOLCHAIN=auto go build -trimpath -ldflags='-s -w' -o "$prebuilt" ./cmd/privora-agent)
    fi
  fi

  # Production certification must not depend on a Go toolchain being installed on the VPS.
  # x86-64 releases ship precompiled certification test executables built from the same source.
  if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
    local certbin certsha certexpected certactual
    if ((DRY_RUN)); then
      echo "[dry-run] verify bundled precompiled host-adapter/API certification executables and SHA-256 sidecars"
    else
      for certbin in privora-hostadapter-cert.test privora-api-cert.test; do
        certsha="$PANEL_ROOT/dist/${certbin}.sha256"
        [[ -x "$PANEL_ROOT/dist/$certbin" ]] || { echo "bundled certification executable missing: $certbin" >&2; exit 1; }
        [[ -r "$certsha" ]] || { echo "bundled certification checksum missing: ${certbin}.sha256" >&2; exit 1; }
        certexpected="$(awk 'NR==1{print $1}' "$certsha")"
        [[ "$certexpected" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid bundled certification checksum: $certbin" >&2; exit 1; }
        certactual="$(sha256sum "$PANEL_ROOT/dist/$certbin" | awk '{print $1}')"
        [[ "$certactual" == "$certexpected" ]] || { echo "bundled certification checksum mismatch: $certbin" >&2; exit 1; }
        log "Verified bundled certification executable $certbin SHA-256 $certactual"
      done
    fi
  fi

  run install -m0750 "$prebuilt" /usr/local/libexec/privora-agent
  run install -m0755 "$PANEL_ROOT/cli/privora" /usr/local/bin/privora
  run install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update
  run install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback
}
configure_app_trust(){
  [[ "$MODE" =~ ^(full|web)$ ]] || { log "SKIP app trust for role $MODE"; return 0; }
  local dst=/etc/privora-panel/apps key="$PANEL_ROOT/install/app-release-public-key.pem" tmp=/var/tmp/privora-app-catalog
  if ((DRY_RUN));then echo "[dry-run] install separate app-catalog verification key and fetch signed app manifest from $APP_MANIFEST_URL";return;fi
  [[ -r "$key" ]]||{ echo 'missing app release public key' >&2;exit 1;}
  install -d -m0755 "$dst";install -m0644 "$key" "$dst/app-release-public-key.pem"
  [[ -n "$APP_MANIFEST_URL" ]]||{ log 'WARN no app manifest URL configured; one-click app execution remains disabled';return;}
  if [[ "$REQUIRE_APP_CATALOG" != 1 && "$APP_MANIFEST_URL" =~ ^https://[^/]*\.example(/|$) ]];then
    log "WARN development app catalog endpoint is not live; core panel installation continues with one-click app execution disabled"
    return
  fi
  rm -rf "$tmp";mkdir -p "$tmp"
  if ! curl -fL --proto '=https' --tlsv1.2 "$APP_MANIFEST_URL" -o "$tmp/releases.json" || ! curl -fL --proto '=https' --tlsv1.2 "${APP_MANIFEST_URL}.sig" -o "$tmp/releases.json.sig";then
    if [[ "$REQUIRE_APP_CATALOG" == 1 ]];then echo 'required signed app catalog unavailable' >&2;exit 1;fi
    log 'WARN signed app catalog unavailable; core panel installed but one-click app execution remains disabled';return
  fi
  openssl dgst -sha256 -verify "$dst/app-release-public-key.pem" -signature "$tmp/releases.json.sig" "$tmp/releases.json" >/dev/null
  python3 - "$tmp/releases.json" <<'PYAPP'
import json,re,sys,urllib.parse
p=sys.argv[1];d=json.load(open(p,encoding='utf-8'));assert d.get('schema')=='privora-app-release-manifest-v1'
rels=d.get('releases');assert isinstance(rels,list) and len(rels)<=512
current={};templates=set()
for r in rels:
  assert re.fullmatch(r'[a-z0-9][a-z0-9-]{1,47}',r['template']);templates.add(r['template'])
  u=urllib.parse.urlparse(r['url']);assert u.scheme=='https' and u.netloc and not u.username
  assert re.fullmatch(r'[0-9a-f]{64}',r['sha256'])
  assert r['archive'] in ('zip','tar.gz') and r['bootstrap'] in ('wordpress','joomla','guided-web','none')
  assert 1024 <= int(r['max_bytes']) <= 1073741824
  if r.get('current') is True: current[r['template']]=current.get(r['template'],0)+1
assert all(current.get(t)==1 for t in templates)
print('signed app catalog PASS')
PYAPP
  install -m0644 "$tmp/releases.json" "$dst/releases.json";install -m0644 "$tmp/releases.json.sig" "$dst/releases.json.sig"
}

port_listening(){
  local p="$1"
  command -v ss >/dev/null 2>&1 || return 1
  ss -lntH 2>/dev/null | awk -v needle=":$p" '$4 ~ (needle "$") {found=1} END{exit found?0:1}'
}
privora_config_owns_port(){
  local p="$1" c
  for c in /etc/nginx/sites-available/privora-panel.conf /etc/nginx/conf.d/privora-panel.conf; do
    [[ -f "$c" ]] || continue
    grep -Eq "^[[:space:]]*listen[[:space:]]+(\\[::\\]:)?${p}([[:space:]]|;)" "$c" && return 0
  done
  return 1
}
resolve_panel_ports(){
  if port_listening "$WEB_PORT" && ! privora_config_owns_port "$WEB_PORT"; then
    echo "Privora Command Center (PCC) port $WEB_PORT is already in use. Choose another value with --web-port." >&2
    return 1
  fi
  if port_listening "$HOSTING_PORT" && ! privora_config_owns_port "$HOSTING_PORT"; then
    local requested="$HOSTING_PORT" p found=""
    for p in $(seq $((requested+1)) $((requested+100))); do
      ((p==WEB_PORT)) && continue
      if ! port_listening "$p"; then found="$p"; break; fi
    done
    [[ -n "$found" ]] || { echo "No available Privora Privora Panel (PPanel) port found near $requested" >&2; return 1; }
    HOSTING_PORT="$found"
    log "WARN Privora Panel (PPanel) port $requested is occupied; selected $HOSTING_PORT instead"
  fi
}
set_env_value(){
  local file="$1" key="$2" value="$3" tmp
  tmp="${file}.tmp.$$"
  if [[ -f "$file" ]]; then grep -v "^${key}=" "$file" >"$tmp" || true; else : >"$tmp"; fi
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$file"
}
persist_panel_ports(){
  ((DRY_RUN)) && { echo "[dry-run] persist PCC port $WEB_PORT and Privora Panel (PPanel) port $HOSTING_PORT"; return 0; }
  set_env_value "$PANEL_ENV" PRIVORA_ADMIN_PANEL_PORT "$WEB_PORT"
  set_env_value "$PANEL_ENV" PRIVORA_HOSTING_PANEL_PORT "$HOSTING_PORT"
  cat >/etc/privora-panel/panel-ports.env <<ENV
PRIVORA_ADMIN_PANEL_PORT=$WEB_PORT
PRIVORA_HOSTING_PANEL_PORT=$HOSTING_PORT
ENV
  if getent group privora-panel >/dev/null 2>&1; then chown root:privora-panel "$PANEL_ENV" /etc/privora-panel/panel-ports.env; else chown root:root "$PANEL_ENV" /etc/privora-panel/panel-ports.env; fi
  chmod 0640 "$PANEL_ENV" /etc/privora-panel/panel-ports.env
}
write_secrets(){ local a e p;a=$(secret 64);e=$(secret 64);p="${ADMIN_PASSWORD:-$(secret 24)}";if ((DRY_RUN));then echo '[dry-run] generate protected agent/panel secrets';else install -d -m0750 /etc/privora-panel;cat >"$AGENT_ENV" <<ENV
PRIVORA_AGENT_TOKEN=$a
PRIVORA_REGISTRAR_PROVIDER=${PRIVORA_REGISTRAR_PROVIDER:-}
PRIVORA_REGISTRAR_ADAPTER_URL=${PRIVORA_REGISTRAR_ADAPTER_URL:-}
PRIVORA_REGISTRAR_TOKEN=${PRIVORA_REGISTRAR_TOKEN:-}
ENV
cat >"$PANEL_ENV" <<ENV
PRIVORA_AGENT_TOKEN=$a
PRIVORA_PANEL_ENCRYPTION_KEY=$e
PRIVORA_PANEL_STATE=/var/lib/privora-panel/web/panel-state.json
PRIVORA_AGENT_SOCKET=/run/privora-panel/agent.sock
PRIVORA_ADMIN_PANEL_PORT=$WEB_PORT
PRIVORA_HOSTING_PANEL_PORT=$HOSTING_PORT
ENV
chmod 0600 "$AGENT_ENV" "$PANEL_ENV";printf '%s' "$p">"$STATE_DIR/bootstrap-admin-password";chmod 0600 "$STATE_DIR/bootstrap-admin-password";fi; }
configure_services(){ resolve_panel_ports; persist_panel_ports; [[ -z "$HOSTNAME_ARG" ]]||run hostnamectl set-hostname "$HOSTNAME_ARG";if ((DRY_RUN));then echo '[dry-run] create privora-panel service identity';else getent group privora-panel >/dev/null||groupadd --system privora-panel;id privora-panel >/dev/null 2>&1||useradd --system --gid privora-panel --home-dir /nonexistent --shell /usr/sbin/nologin privora-panel;install -d -o privora-panel -g privora-panel -m0700 /var/lib/privora-panel/web;install -d -o root -g privora-panel -m0750 /run/privora-panel /etc/privora-panel;chgrp privora-panel "$AGENT_ENV" "$PANEL_ENV" /etc/privora-panel/panel-ports.env;chmod 0640 "$AGENT_ENV" "$PANEL_ENV" /etc/privora-panel/panel-ports.env;cat >/etc/systemd/system/privora-panel-agent.service <<UNIT
[Unit]
Description=Privora Panel Privileged Server Agent
After=network.target
[Service]
Type=simple
User=root
Group=privora-panel
EnvironmentFile=/etc/privora-panel/agent.env
ExecStart=/usr/local/libexec/privora-agent --socket /run/privora-panel/agent.sock --socket-group privora-panel --audit /var/log/privora-panel/audit.jsonl --state /var/lib/privora-panel/agent-state.json --host-mutations --host-certification /var/lib/privora-panel/certifications/host-adapter-certification.json --backup-root /var/backups/privora-panel
Restart=on-failure
RestartSec=2
RuntimeDirectory=privora-panel
RuntimeDirectoryMode=0750
UMask=0007
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
[Install]
WantedBy=multi-user.target
UNIT
fi;reconcile_panel_code_permissions;local fpm_conf fpm_service fpm_socket nginx_conf nginx_user nginx_group;if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then fpm_conf=/etc/php/8.4/fpm/pool.d/privora-panel.conf;fpm_service=php8.4-fpm;fpm_socket=/run/php/privora-panel.sock;nginx_conf=/etc/nginx/sites-available/privora-panel.conf;nginx_user=www-data;else fpm_conf=/etc/php-fpm.d/privora-panel.conf;fpm_service=php-fpm;fpm_socket=/run/php-fpm/privora-panel.sock;nginx_conf=/etc/nginx/conf.d/privora-panel.conf;nginx_user=nginx;fi;nginx_group="$(id -gn "$nginx_user" 2>/dev/null || printf '%s' "$nginx_user")";if ((DRY_RUN));then echo "[dry-run] configure dedicated PHP-FPM pool $fpm_conf";else mkdir -p "$(dirname "$fpm_conf")";cat >"$fpm_conf" <<FPM
[privora-panel]
user = privora-panel
group = privora-panel
listen = $fpm_socket
listen.owner = privora-panel
listen.group = $nginx_group
listen.mode = 0660
pm = ondemand
pm.max_children = 12
pm.process_idle_timeout = 20s
php_admin_value[session.save_path] = /var/lib/privora-panel/web/sessions
php_admin_value[upload_tmp_dir] = /var/lib/privora-panel/web/tmp
clear_env = no
php_admin_value[upload_max_filesize] = 512M
php_admin_value[post_max_size] = 520M
php_admin_value[max_file_uploads] = 4
php_admin_value[max_execution_time] = 600
FPM
install -d -o privora-panel -g privora-panel -m0700 /var/lib/privora-panel/web/sessions /var/lib/privora-panel/web/tmp;mkdir -p "/etc/systemd/system/$fpm_service.service.d";cat >"/etc/systemd/system/$fpm_service.service.d/privora-panel.conf" <<DROPIN
[Service]
EnvironmentFile=/etc/privora-panel/panel.env
DROPIN
install -d -m0755 /usr/share/privora-panel/recovery;cat >/usr/share/privora-panel/recovery/_privora_recovery.html <<'RECOVERYHTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Privora Recovery Mode</title><style>body{font-family:system-ui,sans-serif;background:#111827;color:#f9fafb;display:grid;place-items:center;min-height:100vh;margin:0}.c{max-width:680px;padding:32px;border:1px solid #374151;border-radius:16px;background:#1f2937}h1{margin-top:0}code{color:#93c5fd}</style></head><body><main class="c"><h1>Privora Recovery Mode</h1><p>The control-panel application is temporarily unavailable, but the web server is still running.</p><p>Use server recovery tools or SSH to inspect <code>/opt/privora-panel</code> and the latest update transaction.</p></main></body></html>
RECOVERYHTML
chmod 0644 /usr/share/privora-panel/recovery/_privora_recovery.html;install -d -m0700 /etc/privora-panel/tls;[[ -s /etc/privora-panel/tls/panel.key ]]||openssl req -x509 -newkey rsa:3072 -nodes -days 30 -subj "/CN=${HOSTNAME_ARG:-$(hostname)}" -keyout /etc/privora-panel/tls/panel.key -out /etc/privora-panel/tls/panel.crt >/dev/null 2>&1;chmod 0600 /etc/privora-panel/tls/panel.key;if ((DRY_RUN)); then
  echo "[dry-run] render split Privora Command Center (PCC):$WEB_PORT and Hosting:$HOSTING_PORT Nginx listeners"
else
  python3 "$PANEL_ROOT/scripts/render-panel-nginx.py" --admin-port "$WEB_PORT" --hosting-port "$HOSTING_PORT" --server-name "${HOSTNAME_ARG:-_}" --fpm-socket "$fpm_socket" --phpmyadmin-fpm-socket "/run/php/php8.4-fpm-privora-phpmyadmin.sock" --panel-root "$PANEL_ROOT" >"$nginx_conf"
fi
if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then ln -sfn "$nginx_conf" /etc/nginx/sites-enabled/privora-panel.conf;fi;fi;run nginx -t;run systemctl daemon-reload;run systemctl enable "$fpm_service" nginx privora-panel-agent.service;run systemctl reset-failed "$fpm_service";run systemctl restart "$fpm_service";run systemctl reload nginx || run systemctl restart nginx;run systemctl restart privora-panel-agent.service;run install -m0644 "$PANEL_ROOT/install/privora-maintenance.service" /etc/systemd/system/privora-maintenance.service;run install -m0644 "$PANEL_ROOT/install/privora-maintenance.timer" /etc/systemd/system/privora-maintenance.timer;run install -m0644 "$PANEL_ROOT/install/privora-autossl.service" /etc/systemd/system/privora-autossl.service;run install -m0644 "$PANEL_ROOT/install/privora-autossl.timer" /etc/systemd/system/privora-autossl.timer;if ((DRY_RUN));then echo '[dry-run] write automatic maintenance policy';else {
printf 'PRIVORA_SECURITY_AUTO=1\n'
printf 'PRIVORA_PACKAGE_AUTO=1\n'
printf 'PRIVORA_MAJOR_VERSIONS_MANUAL=1\n'
printf 'PRIVORA_AUTO_REBOOT=0\n'
printf 'PRIVORA_UPDATE_CHANNEL=%q\n' "$CHANNEL"
printf 'PRIVORA_UPDATE_RELEASE_URL=%q\n' "$AUTO_RELEASE_URL"
printf 'PRIVORA_APP_MANIFEST_URL=%q\n' "$APP_MANIFEST_URL"
printf 'PRIVORA_REBOOT_WINDOW=%q\n' 'Sun 03:00'
} >/etc/privora-panel/update-policy.env
chmod 0640 /etc/privora-panel/update-policy.env;fi;run systemctl daemon-reload;run systemctl enable --now privora-maintenance.timer privora-autossl.timer
if systemctl list-unit-files --type=timer --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq certbot.timer; then systemctl enable --now certbot.timer || true; fi; }
enable_role_services(){
  local units=()
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then
    case "$MODE" in
      full) units=(mariadb postgresql redis-server bind9 postfix dovecot rspamd ssh nftables);;
      web) units=(redis-server ssh nftables);;
      db) units=(mariadb postgresql redis-server);;
      mail) units=(postfix dovecot rspamd nftables);;
      dns) units=(bind9 nftables);;
      backup) units=(ssh);;
    esac
  else
    case "$MODE" in
      full) units=(mariadb postgresql redis named postfix dovecot rspamd sshd nftables);;
      web) units=(redis sshd nftables);;
      db) units=(mariadb postgresql redis);;
      mail) units=(postfix dovecot rspamd nftables);;
      dns) units=(named nftables);;
      backup) units=(sshd);;
    esac
  fi
  for u in "${units[@]}";do
    if ((DRY_RUN));then echo "[dry-run] enable/start $u if installed (canonical systemd unit resolved at runtime)";continue;fi
    local requested="$u.service" canonical=""
    # systemctl can start an alias but refuses to enable one. Resolve the primary Id first
    # (Ubuntu 24.04 commonly exposes bind9.service as an alias of named.service).
    canonical="$(systemctl show "$requested" -p Id --value 2>/dev/null || true)"
    [[ -n "$canonical" ]] || continue
    if [[ "$canonical" != "$requested" ]];then
      log "Resolved systemd alias $requested -> $canonical"
    fi
    systemctl enable --now "$canonical"
  done
}

configure_dns_foundation(){
  [[ "$MODE" =~ ^(full|dns)$ ]] || return 0
  if ((DRY_RUN)); then echo '[dry-run] configure Privora BIND zone include'; return 0; fi
  local index zone_dir conf service directive
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then
    index=/etc/bind/privora-zones.conf
    zone_dir=/etc/bind/privora-zones
    conf=/etc/bind/named.conf.local
    service=bind9
  else
    index=/etc/named/privora-zones.conf
    zone_dir=/etc/named/privora-zones
    conf=/etc/named.conf
    service=named
  fi
  install -d -m0755 "$zone_dir"
  touch "$index"
  chmod 0644 "$index"
  directive="include \"$index\";"
  grep -Fqx "$directive" "$conf" 2>/dev/null || printf '
%s
' "$directive" >>"$conf"
  named-checkconf
  systemctl reload "$service" || systemctl restart "$service"
}

configure_resource_foundation(){
  [[ "$MODE" =~ ^(full|web)$ ]]||return 0
  if ((DRY_RUN));then echo '[dry-run] enable filesystem user quotas when supported and verify writable cgroup-v2 foundation';return;fi
  [[ -r /sys/fs/cgroup/cgroup.controllers ]]||{ log 'WARN cgroup v2 not available; full certification will fail'; }
  local fs opts fstab_backup=/etc/fstab.privora-prequota
  fs="$(findmnt -no FSTYPE / 2>/dev/null||true)"; opts="$(findmnt -no OPTIONS / 2>/dev/null||true)"
  if [[ "$opts" =~ (^|,)(usrquota|uquota)(,|$) ]];then quotaon / >/dev/null 2>&1||true;return;fi
  case "$fs" in
    ext4)
      cp -a /etc/fstab "$fstab_backup"
      python3 - /etc/fstab <<'PYFSTAB'
import sys
p=sys.argv[1]; lines=open(p).read().splitlines(); out=[]; changed=False
for line in lines:
 s=line.strip()
 if not s or s.startswith('#'): out.append(line); continue
 parts=line.split()
 if len(parts)>=4 and parts[1]=='/' and 'usrquota' not in parts[3].split(','):
  parts[3]=parts[3]+',usrquota'; line='\t'.join(parts); changed=True
 out.append(line)
if not changed: raise SystemExit(3)
open(p+'.tmp','w').write('\n'.join(out)+'\n')
PYFSTAB
      if [[ -f /etc/fstab.tmp ]];then mv /etc/fstab.tmp /etc/fstab;fi
      if ! mount -o remount,usrquota /;then cp -a "$fstab_backup" /etc/fstab;log 'WARN unable to remount root filesystem with usrquota';return;fi
      quotacheck -cum / >/dev/null 2>&1||true;quotaon / >/dev/null 2>&1||true
      ;;
    xfs)
      log 'WARN XFS quota enablement must be present at mount time; full certification will verify uquota and fail if absent'
      ;;
    *) log "WARN filesystem $fs does not have automatic Privora quota enablement yet; full certification will fail";;
  esac
}

configure_firewall(){
  local mail_ports=""
  if [[ "$MODE" == "full" || "$MODE" == "mail" ]]; then mail_ports=", 25, 465, 587, 993, 995"; fi
  if ((DRY_RUN));then
    echo "[dry-run] render/validate/apply dedicated nftables bootstrap rules"
    return
  fi
  install -d -m 0755 /etc/privora-panel
  cat >/etc/privora-panel/nftables-bootstrap.nft <<NFT
table inet privora_bootstrap {
    chain input {
        type filter hook input priority -5; policy accept;
        ct state established,related accept
        iifname "lo" accept
        tcp dport { 22, 80, 443, $WEB_PORT, $HOSTING_PORT$mail_ports } accept
    }
}
NFT
  # Validate the complete replacement ruleset before touching the live table.
  nft -c -f /etc/privora-panel/nftables-bootstrap.nft
  # The bootstrap table is Privora-owned. Remove only that table when replacing it;
  # never flush the host's global nftables ruleset or another panel's tables.
  if nft list table inet privora_bootstrap >/dev/null 2>&1; then
    nft delete table inet privora_bootstrap
  fi
  nft -f /etc/privora-panel/nftables-bootstrap.nft
  nft list table inet privora_bootstrap >/dev/null
}
initialize_panel(){ local p="${ADMIN_PASSWORD:-}";[[ -n "$p" ]]||{ if ((DRY_RUN));then p=DRY-RUN-PASSWORD;else p=$(cat "$STATE_DIR/bootstrap-admin-password");fi;};if ((DRY_RUN));then echo "[dry-run] initialize root admin $ADMIN_USER";else PRIVORA_PANEL_STATE=/var/lib/privora-panel/web/panel-state.json php "$PANEL_ROOT/scripts/init-panel.php" "$ADMIN_USER" "$p" root-admin "" "$ADMIN_EMAIL";chown privora-panel:privora-panel /var/lib/privora-panel/web/panel-state.json;chmod 0600 /var/lib/privora-panel/web/panel-state.json;fi; }
reconcile_panel_code_permissions(){
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  if ((DRY_RUN)); then
    echo "[dry-run] reconcile production panel source permissions for Nginx + PHP-FPM"
    return 0
  fi
  [[ -d "$PANEL_ROOT/panel/public" && -d "$PANEL_ROOT/panel/src" ]] || { echo "Privora panel source tree missing under $PANEL_ROOT/panel" >&2; return 1; }
  # /opt/privora-panel itself is created under umask 027.  On a clean host that
  # can leave the root-owned release tree at 0750, preventing both www-data and
  # the dedicated privora-panel PHP-FPM identity from traversing it.  Keep
  # secrets outside /opt and expose only the code paths each runtime needs.
  chown root:root "$PANEL_ROOT" "$PANEL_ROOT/panel"
  chmod 0755 "$PANEL_ROOT" "$PANEL_ROOT/panel"
  # VERSION is not served by Nginx, but PHP-FPM reads it to render the active
  # build label. Keep it protected while guaranteeing the privora-panel group
  # can read it after fresh install, atomic promotion, ZIP extraction or rollback.
  if [[ -f "$PANEL_ROOT/VERSION" ]]; then
    chown root:privora-panel "$PANEL_ROOT/VERSION"
    chmod 0640 "$PANEL_ROOT/VERSION"
  fi
  find "$PANEL_ROOT/panel/public" -type d -exec chmod 0755 {} +
  find "$PANEL_ROOT/panel/public" -type f -exec chmod 0644 {} +
  chown -R root:privora-panel "$PANEL_ROOT/panel/src"
  find "$PANEL_ROOT/panel/src" -type d -exec chmod 0750 {} +
  find "$PANEL_ROOT/panel/src" -type f -exec chmod 0640 {} +
  # Prove both runtime identities can traverse/read what they actually need.
  local webuser=nginx
  [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]] && webuser=www-data
  id privora-panel >/dev/null 2>&1 || { echo "Privora panel service identity missing" >&2; return 1; }
  id "$webuser" >/dev/null 2>&1 || { echo "Nginx worker identity missing: $webuser" >&2; return 1; }
  runuser -u privora-panel -- test -r "$PANEL_ROOT/VERSION" || { echo "Privora PHP-FPM identity cannot read VERSION" >&2; return 1; }
  runuser -u privora-panel -- test -r "$PANEL_ROOT/panel/public/index.php"
  runuser -u privora-panel -- test -r "$PANEL_ROOT/panel/src/bootstrap.php"
  runuser -u "$webuser" -- test -r "$PANEL_ROOT/panel/public/index.php" || { echo "Nginx worker cannot read Privora public tree" >&2; return 1; }
}
reconcile_panel_state_permissions(){
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  if ((DRY_RUN)); then
    echo "[dry-run] reconcile Privora panel runtime-state traversal/write permissions"
    return 0
  fi
  # The parent /var/lib/privora-panel is created early under umask 027 as root:root.
  # A later privora-panel-owned /var/lib/privora-panel/web directory is not reachable
  # through that root-only parent, causing the production PHP worker to fail with HTTP 500.
  install -d -o root -g privora-panel -m0750 /var/lib/privora-panel
  install -d -o privora-panel -g privora-panel -m0700 /var/lib/privora-panel/web
  install -d -o privora-panel -g privora-panel -m0700 /var/lib/privora-panel/web/sessions /var/lib/privora-panel/web/tmp
  [[ -f /var/lib/privora-panel/web/panel-state.json ]] && {
    chown privora-panel:privora-panel /var/lib/privora-panel/web/panel-state.json
    chmod 0600 /var/lib/privora-panel/web/panel-state.json
  }
  runuser -u privora-panel -- test -x /var/lib/privora-panel
  runuser -u privora-panel -- test -w /var/lib/privora-panel/web
  runuser -u privora-panel -- test -w /var/lib/privora-panel/web/sessions
  runuser -u privora-panel -- test -w /var/lib/privora-panel/web/tmp
}
reconcile_panel_runtime(){
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  reconcile_panel_code_permissions
  reconcile_panel_state_permissions
  local fpm_conf fpm_service fpm_socket nginx_conf nginx_user nginx_group
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then
    fpm_conf=/etc/php/8.4/fpm/pool.d/privora-panel.conf
    fpm_service=php8.4-fpm
    fpm_socket=/run/php/privora-panel.sock
    nginx_conf=/etc/nginx/sites-available/privora-panel.conf
    nginx_user=www-data
  else
    fpm_conf=/etc/php-fpm.d/privora-panel.conf
    fpm_service=php-fpm
    fpm_socket=/run/php-fpm/privora-panel.sock
    nginx_conf=/etc/nginx/conf.d/privora-panel.conf
    nginx_user=nginx
  fi
  nginx_group="$(id -gn "$nginx_user" 2>/dev/null || printf '%s' "$nginx_user")"
  if ((DRY_RUN)); then
    echo "[dry-run] reconcile Privora PHP-FPM/Nginx runtime before certification"
    return 0
  fi
  [[ -s "$fpm_conf" ]] || { echo "Privora PHP-FPM pool missing: $fpm_conf" >&2; return 1; }
  # Recovery-safe socket ownership reconciliation. Nginx workers must be able to
  # connect to the Privora PHP-FPM socket; older recovery builds used the
  # privora-panel group for both owner/group, which yields HTTP 502 on Ubuntu.
  if ! getent passwd "$nginx_user" >/dev/null 2>&1; then
    echo "Nginx worker identity missing: $nginx_user" >&2; return 1
  fi
  sed -Ei "s|^listen\.group[[:space:]]*=.*$|listen.group = $nginx_group|" "$fpm_conf"
  grep -Eq "^listen\.group[[:space:]]*=[[:space:]]*$nginx_group$" "$fpm_conf" || { echo "Unable to reconcile PHP-FPM socket group" >&2; return 1; }
  [[ -s "$nginx_conf" ]] || { echo "Privora Nginx site missing: $nginx_conf" >&2; return 1; }
  [[ -s /etc/privora-panel/tls/panel.crt && -s /etc/privora-panel/tls/panel.key ]] || { echo "Privora bootstrap TLS material missing" >&2; return 1; }
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then
    ln -sfn "$nginx_conf" /etc/nginx/sites-enabled/privora-panel.conf
  fi
  php-fpm8.4 -t >/dev/null 2>&1 || php8.4-fpm -t >/dev/null 2>&1 || { echo "PHP-FPM configuration validation failed" >&2; return 1; }
  nginx -t
  systemctl daemon-reload
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  systemctl reload nginx || systemctl restart nginx
  systemctl is-active --quiet "$fpm_service"
  systemctl is-active --quiet nginx
  for _ in $(seq 1 20); do
    [[ -S "$fpm_socket" ]] && break
    sleep 0.25
  done
  [[ -S "$fpm_socket" ]] || { echo "Privora PHP-FPM socket did not appear: $fpm_socket" >&2; return 1; }
  ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${WEB_PORT}$" || { echo "Nginx is not listening on Privora Command Center (PCC) port $WEB_PORT after reload" >&2; return 1; }; ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${HOSTING_PORT}$" || { echo "Nginx is not listening on Privora Privora Panel (PPanel) port $HOSTING_PORT after reload" >&2; return 1; }
  # Exercise the actual PHP bootstrap as the production FPM identity before HTTP health.
  # Use a temporary PHP file rather than php -r so shell/PHP quoting cannot corrupt the probe.
  # Load panel.env in a root-owned shell, preserve only that environment into runuser, and
  # never print secret values.
  local php_probe php_probe_out
  php_probe=$(mktemp /var/tmp/privora-php-bootstrap.XXXXXX.php)
  php_probe_out=$(mktemp /var/tmp/privora-php-bootstrap-out.XXXXXX)
  cat >"$php_probe" <<'PHP'
<?php
require '/opt/privora-panel/panel/src/bootstrap.php';
echo "PRIVORA_PHP_BOOTSTRAP_OK\n";
PHP
  chmod 0644 "$php_probe"
  if ! (
    set -a
    . /etc/privora-panel/panel.env
    set +a
    runuser -u privora-panel --preserve-environment -- php -d display_errors=1 "$php_probe"
  ) >"$php_probe_out" 2>&1; then
    echo "Privora PHP bootstrap failed under privora-panel identity" >&2
    cat "$php_probe_out" >&2 || true
    rm -f "$php_probe" "$php_probe_out"
    return 1
  fi
  if ! grep -qx 'PRIVORA_PHP_BOOTSTRAP_OK' "$php_probe_out"; then
    echo "Privora PHP bootstrap returned unexpected output" >&2
    cat "$php_probe_out" >&2 || true
    rm -f "$php_probe" "$php_probe_out"
    return 1
  fi
  rm -f "$php_probe" "$php_probe_out"

}

host_certify(){
  reconcile_panel_runtime
  if ((DRY_RUN));then
    echo "[dry-run] refresh precompiled certification runner/binaries and run machine-bound VPS host certification role=$MODE require-full=1"
  else
    # Recovery-safe refresh: certification may be the first unfinished phase while
    # privora_files is already journaled done from an older installer build.
    # Refresh only the certification runner + precompiled test executables from the
    # currently supplied, user-verified source tree; do not replay earlier host phases.
    install -m0750 "$SOURCE_DIR/scripts/vps-host-certify.sh" "$PANEL_ROOT/scripts/vps-host-certify.sh"
    for f in privora-hostadapter-cert.test privora-api-cert.test; do
      [[ -r "$SOURCE_DIR/dist/$f" && -r "$SOURCE_DIR/dist/$f.sha256" ]] || { echo "recovery source missing $f or checksum" >&2; exit 1; }
      (cd "$SOURCE_DIR/dist" && sha256sum -c "$f.sha256" >/dev/null) || { echo "recovery certification checksum failed: $f" >&2; exit 1; }
      install -m0755 "$SOURCE_DIR/dist/$f" "$PANEL_ROOT/dist/$f"
      install -m0644 "$SOURCE_DIR/dist/$f.sha256" "$PANEL_ROOT/dist/$f.sha256"
    done
    PRIVORA_CERT_OUTPUT="$CERT_DIR/host-adapter-certification.json" PRIVORA_CERT_ROLE="$MODE" PRIVORA_CERT_REQUIRE_FULL=1 PRIVORA_SQL_FAMILY="$SQL_FAMILY" "$PANEL_ROOT/scripts/vps-host-certify.sh"
    chmod 0600 "$CERT_DIR/host-adapter-certification.json"
    systemctl restart privora-panel-agent.service
  fi
}
refresh_frontend_csp(){
  local src_admin="$SOURCE_DIR/panel/public/admin.php"
  local src_app="$SOURCE_DIR/panel/public/assets/app.js"
  local dst_admin="$PANEL_ROOT/panel/public/admin.php"
  local dst_app="$PANEL_ROOT/panel/public/assets/app.js"
  if ((DRY_RUN)); then
    echo "[dry-run] refresh CSP-safe admin.php and app.js frontend assets"
    return 0
  fi
  [[ -r "$src_admin" && -r "$src_app" ]] || { echo "Recovery source is missing CSP-safe frontend assets" >&2; return 1; }
  # The admin page must not rely on inline JS because bootstrap.php enforces script-src 'self'.
  if grep -Eq '<script[^>]*>[^<]*window\.PRIVORA' "$src_admin"; then
    echo "CSP-unsafe inline Privora bootstrap still present in recovery source" >&2
    return 1
  fi
  grep -q 'meta\[name=' "$src_app" || { echo "CSP-safe CSRF meta lookup missing from app.js" >&2; return 1; }
  grep -q 'X-CSRF-Token' "$src_app" || { echo "CSRF request header logic missing from app.js" >&2; return 1; }
  install -o root -g root -m0644 "$src_admin" "$dst_admin"
  install -o root -g root -m0644 "$src_app" "$dst_app"
  php -l "$dst_admin" >/dev/null
  node --check "$dst_app" >/dev/null
  # Clear any PHP opcode cache by restarting the dedicated pool. Static JS is cache-busted in admin.php.
  if systemctl list-unit-files php8.4-fpm.service >/dev/null 2>&1; then
    systemctl reset-failed php8.4-fpm.service >/dev/null 2>&1 || true
    systemctl restart php8.4-fpm.service
  elif systemctl list-unit-files php-fpm.service >/dev/null 2>&1; then
    systemctl restart php-fpm.service
  fi
  systemctl reload nginx || systemctl restart nginx
}

refresh_live_host_reconcile(){
  local src="$SOURCE_DIR/panel/public" dst="$PANEL_ROOT/panel/public" arch prebuilt expected actual fpm_service
  if ((DRY_RUN)); then
    echo "[dry-run] refresh live-host agent/API/UI plus Privora Labs full/compact branding"
    return 0
  fi
  for f in admin.php customer.php index.php api.php assets/app.js assets/customer.js assets/app.css assets/privora-labs-full.png assets/privora-labs-mark.png; do
    [[ -r "$src/$f" ]] || { echo "Live-host recovery source missing $f" >&2; return 1; }
    install -D -o root -g root -m0644 "$src/$f" "$dst/$f"
  done
  php -l "$dst/admin.php" >/dev/null; php -l "$dst/customer.php" >/dev/null; php -l "$dst/index.php" >/dev/null; php -l "$dst/api.php" >/dev/null
  node --check "$dst/assets/app.js" >/dev/null; node --check "$dst/assets/customer.js" >/dev/null
  arch="$(uname -m)"; prebuilt="$SOURCE_DIR/dist/privora-agent"
  [[ "$arch" == x86_64 || "$arch" == amd64 ]] || { echo "dev.6.15 recovery requires bundled amd64 agent on this path" >&2; return 1; }
  expected="$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")"; actual="$(sha256sum "$prebuilt"|awk '{print $1}')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo "Live-host agent checksum mismatch" >&2; return 1; }
  install -m0750 "$prebuilt" /usr/local/libexec/privora-agent
  systemctl restart privora-panel-agent.service
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then fpm_service=php8.4-fpm;else fpm_service=php-fpm;fi
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  nginx -t >/dev/null
  systemctl reload nginx || systemctl restart nginx
  reconcile_panel_runtime
}

refresh_whm_update_center(){
  local src_panel="$SOURCE_DIR/panel" dst_panel="$PANEL_ROOT/panel" fpm_service fpm_conf nginx_conf arch expected actual
  if ((DRY_RUN)); then
    echo "[dry-run] install WHM uploaded ZIP Update Center, PAM root reauthorization, signed verifier and rollback engine"
    return 0
  fi
  command -v pamtester >/dev/null 2>&1 || pkg_install pamtester
  for f in public/admin.php public/api.php public/assets/app.js public/assets/app.css src/AgentClient.php; do
    [[ -r "$src_panel/$f" ]] || { echo "PCC updater recovery source missing panel/$f" >&2; return 1; }
    install -D -o root -g root -m0644 "$src_panel/$f" "$dst_panel/$f"
  done
  for f in scripts/privora-update.sh scripts/privora-update-rollback.sh scripts/verify-upload-update.py install/release-public-key.pem; do
    [[ -r "$SOURCE_DIR/$f" ]] || { echo "PCC updater recovery source missing $f" >&2; return 1; }
    mode=0644; [[ "$f" == scripts/* ]] && mode=0750
    install -D -o root -g root -m"$mode" "$SOURCE_DIR/$f" "$PANEL_ROOT/$f"
  done
  install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update
  install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback
  install -d -o privora-panel -g privora-panel -m0700 /var/lib/privora-panel/web/update-uploads
  install -d -o root -g root -m0700 /var/lib/privora-panel/update-upload-staging /run/privora-panel/update-auth
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then
    fpm_service=php8.4-fpm; fpm_conf=/etc/php/8.4/fpm/pool.d/privora-panel.conf; nginx_conf=/etc/nginx/sites-available/privora-panel.conf
  else
    fpm_service=php-fpm; fpm_conf=/etc/php-fpm.d/privora-panel.conf; nginx_conf=/etc/nginx/conf.d/privora-panel.conf
  fi
  python3 - "$fpm_conf" <<'PYFPMUP'
import re,sys
p=sys.argv[1];s=open(p).read()
for k,v in [('upload_max_filesize','512M'),('post_max_size','520M'),('max_file_uploads','4')]:
 pat=re.compile(r'^php_admin_value\['+re.escape(k)+r'\]\s*=.*$',re.M)
 line=f'php_admin_value[{k}] = {v}'
 s=pat.sub(line,s) if pat.search(s) else s.rstrip()+"\n"+line+"\n"
open(p+'.tmp','w').write(s)
PYFPMUP
  mv "$fpm_conf.tmp" "$fpm_conf"
  sed -i -E 's/client_max_body_size[[:space:]]+[0-9]+[mM];/client_max_body_size 520m;/' "$nginx_conf"
  grep -q 'client_max_body_size 520m;' "$nginx_conf" || sed -i '/server_name/a\ client_max_body_size 520m;' "$nginx_conf"
  php -l "$dst_panel/public/admin.php" >/dev/null
  php -l "$dst_panel/public/api.php" >/dev/null
  php -l "$dst_panel/src/AgentClient.php" >/dev/null
  node --check "$dst_panel/public/assets/app.js" >/dev/null
  python3 -m py_compile "$PANEL_ROOT/scripts/verify-upload-update.py"
  bash -n "$PANEL_ROOT/scripts/privora-update.sh"
  bash -n "$PANEL_ROOT/scripts/privora-update-rollback.sh"
  arch="$(uname -m)"; [[ "$arch" == x86_64 || "$arch" == amd64 ]] || { echo 'PCC updater recovery currently requires bundled amd64 agent' >&2; return 1; }
  expected="$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")"; actual="$(sha256sum "$SOURCE_DIR/dist/privora-agent"|awk '{print $1}')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo 'PCC updater agent checksum mismatch' >&2; return 1; }
  install -m0750 "$SOURCE_DIR/dist/privora-agent" /usr/local/libexec/privora-agent
  systemctl daemon-reload
  systemctl restart privora-panel-agent.service
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  nginx -t >/dev/null
  systemctl reload nginx || systemctl restart nginx
  reconcile_panel_runtime
}

verify_agent_bridge_as_panel(){
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  if ((DRY_RUN)); then
    echo "[dry-run] verify privileged-agent bridge from privora-panel PHP identity"
    return 0
  fi
  local socket=/run/privora-panel/agent.sock probe out group mode
  [[ -S "$socket" ]] || { echo "Privora agent socket is missing: $socket" >&2; return 1; }
  group=$(stat -c '%G' "$socket")
  mode=$(stat -c '%a' "$socket")
  [[ "$group" == privora-panel ]] || { echo "Privora agent socket group is $group, expected privora-panel" >&2; return 1; }
  [[ "$mode" == 660 ]] || { echo "Privora agent socket mode is $mode, expected 660" >&2; return 1; }
  probe=$(mktemp /var/tmp/privora-agent-bridge.XXXXXX.php)
  out=$(mktemp /var/tmp/privora-agent-bridge-out.XXXXXX)
  cat >"$probe" <<'PHPBRIDGE'
<?php
require '/opt/privora-panel/panel/src/AgentClient.php';
$client = new AgentClient(getenv('PRIVORA_AGENT_SOCKET') ?: '/run/privora-panel/agent.sock', getenv('PRIVORA_AGENT_TOKEN') ?: '', 'installer:bridge-health');
$r = $client->get('/v1/health');
if (($r['_status'] ?? 0) !== 200) { fwrite(STDERR, "agent health status mismatch\n"); exit(2); }
echo "PRIVORA_AGENT_BRIDGE_OK\n";
PHPBRIDGE
  chmod 0644 "$probe"
  if ! (
    set -a
    . /etc/privora-panel/panel.env
    set +a
    runuser -u privora-panel --preserve-environment -- php -d display_errors=1 "$probe"
  ) >"$out" 2>&1; then
    echo "Privora PHP-to-agent bridge failed under privora-panel identity" >&2
    cat "$out" >&2 || true
    rm -f "$probe" "$out"
    return 1
  fi
  if ! grep -qx 'PRIVORA_AGENT_BRIDGE_OK' "$out"; then
    echo "Privora PHP-to-agent bridge returned unexpected output" >&2
    cat "$out" >&2 || true
    rm -f "$probe" "$out"
    return 1
  fi
  rm -f "$probe" "$out"
}

verify_live_inventory_as_panel(){
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  if ((DRY_RUN)); then
    echo "[dry-run] discover/reconcile hosting environment and capture canonical host profile from privora-panel PHP identity"
    return 0
  fi
  local probe out
  probe=$(mktemp /var/tmp/privora-live-inventory.XXXXXX.php)
  out=$(mktemp /var/tmp/privora-live-inventory-out.XXXXXX)
  cat >"$probe" <<'PHPINVENTORY'
<?php
require '/opt/privora-panel/panel/src/AgentClient.php';
$client = new AgentClient(getenv('PRIVORA_AGENT_SOCKET') ?: '/run/privora-panel/agent.sock', getenv('PRIVORA_AGENT_TOKEN') ?: '', 'installer:live-inventory');
$reconcile = $client->postLong('/v1/host/reconcile', [], 30);
if (($reconcile['_status'] ?? 0) !== 200 || !($reconcile['ok'] ?? false)) {
    fwrite(STDERR, "live host reconciliation failed
"); exit(2);
}
$r = $client->get('/v1/host/inventory');
if (($r['_status'] ?? 0) !== 200 || ($r['source'] ?? '') !== 'live-host' || !isset($r['inventory']) || !is_array($r['inventory'])) {
    fwrite(STDERR, "live inventory response mismatch
"); exit(2);
}
$i=$r['inventory'];
$profile=[
    'schema'=>'privora-host-profile-v1',
    'privora_version'=>'5.0.0-dev.7.0',
    'captured_at'=>gmdate('c'),
    'accounts_imported'=>(int)($reconcile['accounts_imported']??0),
    'sites_imported'=>(int)($reconcile['sites_imported']??0),
    'reconcile_notices'=>$reconcile['reconcile_notices']??[],
    'inventory'=>$i,
];
$path='/var/lib/privora-panel/web/host-profile.json'; $tmp=$path.'.tmp';
$json=json_encode($profile, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."
";
if(file_put_contents($tmp,$json,LOCK_EX)===false || !@chmod($tmp,0600) || !@rename($tmp,$path)) { @unlink($tmp); fwrite(STDERR,"host profile snapshot write failed
"); exit(3); }
$env=$i['environment']??[];
printf("PRIVORA_LIVE_INVENTORY_OK accounts=%d sites=%d databases=%d warnings=%d panel=%s web=%s imported_accounts=%d imported_sites=%d
", count($i['accounts']??[]), count($i['sites']??[]), count($i['databases']??[]), count($i['warnings']??[]), (string)($env['control_panel']??'none'), (string)($env['web_server']??'unknown'), (int)($reconcile['accounts_imported']??0), (int)($reconcile['sites_imported']??0));
PHPINVENTORY
  chmod 0644 "$probe"
  if ! (
    set -a
    . /etc/privora-panel/panel.env
    set +a
    runuser -u privora-panel --preserve-environment -- php -d display_errors=1 "$probe"
  ) >"$out" 2>&1; then
    echo "Privora live-host inventory failed under privora-panel identity" >&2
    cat "$out" >&2 || true
    rm -f "$probe" "$out"
    return 1
  fi
  grep -q '^PRIVORA_LIVE_INVENTORY_OK ' "$out" || { echo "Privora live inventory returned unexpected output" >&2; cat "$out" >&2 || true; rm -f "$probe" "$out"; return 1; }
  cat "$out"
  rm -f "$probe" "$out"
}

refresh_agent_bridge_live_inventory(){
  local unit=/etc/systemd/system/privora-panel-agent.service expected actual fpm_service
  if ((DRY_RUN)); then
    echo "[dry-run] harden agent socket ownership, refresh local API bridge and broaden live Nginx inventory discovery"
    return 0
  fi
  getent group privora-panel >/dev/null || { echo 'privora-panel group is missing' >&2; return 1; }
  [[ -r "$SOURCE_DIR/dist/privora-agent" && -r "$SOURCE_DIR/dist/privora-agent.sha256" ]] || { echo 'dev.6.15 agent/checksum missing' >&2; return 1; }
  expected=$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")
  actual=$(sha256sum "$SOURCE_DIR/dist/privora-agent" | awk '{print $1}')
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo 'dev.6.15 agent checksum mismatch' >&2; return 1; }
  install -m0750 "$SOURCE_DIR/dist/privora-agent" /usr/local/libexec/privora-agent

  # Existing dev.6.x units already run root with the privora-panel primary group,
  # but enforce both the service group and socket-group flag so the API bridge is
  # not dependent on implicit process-group inheritance.
  [[ -f "$unit" ]] || { echo "Privora agent systemd unit missing: $unit" >&2; return 1; }
  if ! grep -q '^Group=privora-panel$' "$unit"; then
    if grep -q '^Group=' "$unit"; then sed -i 's/^Group=.*/Group=privora-panel/' "$unit"; else sed -i '/^User=root$/a Group=privora-panel' "$unit"; fi
  fi
  if ! grep -q -- '--socket-group privora-panel' "$unit"; then
    sed -i -E 's#(--socket[[:space:]]+/run/privora-panel/agent\.sock)([[:space:]])#\1 --socket-group privora-panel\2#' "$unit"
  fi
  grep -q -- '--socket-group privora-panel' "$unit" || { echo 'Unable to add explicit Privora socket-group ownership to agent unit' >&2; return 1; }

  for f in panel/src/AgentClient.php panel/public/assets/app.js panel/public/assets/customer.js; do
    [[ -r "$SOURCE_DIR/$f" ]] || { echo "Agent bridge recovery source missing $f" >&2; return 1; }
  done
  install -o root -g privora-panel -m0640 "$SOURCE_DIR/panel/src/AgentClient.php" "$PANEL_ROOT/panel/src/AgentClient.php"
  install -o root -g root -m0644 "$SOURCE_DIR/panel/public/assets/app.js" "$PANEL_ROOT/panel/public/assets/app.js"
  install -o root -g root -m0644 "$SOURCE_DIR/panel/public/assets/customer.js" "$PANEL_ROOT/panel/public/assets/customer.js"
  php -l "$PANEL_ROOT/panel/src/AgentClient.php" >/dev/null
  node --check "$PANEL_ROOT/panel/public/assets/app.js" >/dev/null
  node --check "$PANEL_ROOT/panel/public/assets/customer.js" >/dev/null

  systemctl daemon-reload
  systemctl restart privora-panel-agent.service
  for _ in $(seq 1 30); do [[ -S /run/privora-panel/agent.sock ]] && break; sleep .2; done
  systemctl is-active --quiet privora-panel-agent.service
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then fpm_service=php8.4-fpm; else fpm_service=php-fpm; fi
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  nginx -t >/dev/null
  systemctl reload nginx || systemctl restart nginx
  verify_agent_bridge_as_panel
}

refresh_authoritative_inventory(){
  local expected actual fpm_service
  if ((DRY_RUN)); then
    echo "[dry-run] refresh authoritative host inventory engine, diagnostics UI and production identity verification"
    return 0
  fi
  [[ -r "$SOURCE_DIR/dist/privora-agent" && -r "$SOURCE_DIR/dist/privora-agent.sha256" ]] || { echo 'dev.6.16 agent/checksum missing' >&2; return 1; }
  expected=$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")
  actual=$(sha256sum "$SOURCE_DIR/dist/privora-agent" | awk '{print $1}')
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo 'dev.6.16 agent checksum mismatch' >&2; return 1; }
  install -m0750 "$SOURCE_DIR/dist/privora-agent" /usr/local/libexec/privora-agent
  for f in panel/public/api.php panel/public/admin.php panel/public/assets/app.js panel/src/AgentClient.php; do
    [[ -r "$SOURCE_DIR/$f" ]] || { echo "Authoritative inventory recovery source missing $f" >&2; return 1; }
  done
  install -o root -g privora-panel -m0640 "$SOURCE_DIR/panel/public/api.php" "$PANEL_ROOT/panel/public/api.php"
  install -o root -g privora-panel -m0640 "$SOURCE_DIR/panel/public/admin.php" "$PANEL_ROOT/panel/public/admin.php"
  install -o root -g root -m0644 "$SOURCE_DIR/panel/public/assets/app.js" "$PANEL_ROOT/panel/public/assets/app.js"
  install -o root -g privora-panel -m0640 "$SOURCE_DIR/panel/src/AgentClient.php" "$PANEL_ROOT/panel/src/AgentClient.php"
  php -l "$PANEL_ROOT/panel/public/api.php" >/dev/null
  php -l "$PANEL_ROOT/panel/public/admin.php" >/dev/null
  php -l "$PANEL_ROOT/panel/src/AgentClient.php" >/dev/null
  node --check "$PANEL_ROOT/panel/public/assets/app.js" >/dev/null
  systemctl daemon-reload
  systemctl restart privora-panel-agent.service
  for _ in $(seq 1 30); do [[ -S /run/privora-panel/agent.sock ]] && break; sleep .2; done
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then fpm_service=php8.4-fpm; else fpm_service=php-fpm; fi
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  nginx -t >/dev/null
  systemctl reload nginx || systemctl restart nginx
  verify_agent_bridge_as_panel
  verify_live_inventory_as_panel
}

refresh_update_progress_observability(){
  local expected actual fpm_service
  if ((DRY_RUN)); then
    echo "[dry-run] refresh PCC update progress monitor, updater transaction timing and stall diagnostics"
    return 0
  fi
  [[ -r "$SOURCE_DIR/dist/privora-agent" && -r "$SOURCE_DIR/dist/privora-agent.sha256" ]] || { echo 'dev.6.17 agent/checksum missing' >&2; return 1; }
  expected=$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")
  actual=$(sha256sum "$SOURCE_DIR/dist/privora-agent" | awk '{print $1}')
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo 'dev.6.17 agent checksum mismatch' >&2; return 1; }
  install -m0750 "$SOURCE_DIR/dist/privora-agent" /usr/local/libexec/privora-agent
  for f in panel/public/admin.php panel/public/assets/app.js panel/public/assets/app.css scripts/privora-update.sh scripts/privora-update-rollback.sh; do
    [[ -r "$SOURCE_DIR/$f" ]] || { echo "Update progress recovery source missing $f" >&2; return 1; }
  done
  install -o root -g privora-panel -m0640 "$SOURCE_DIR/panel/public/admin.php" "$PANEL_ROOT/panel/public/admin.php"
  install -o root -g root -m0644 "$SOURCE_DIR/panel/public/assets/app.js" "$PANEL_ROOT/panel/public/assets/app.js"
  install -o root -g root -m0644 "$SOURCE_DIR/panel/public/assets/app.css" "$PANEL_ROOT/panel/public/assets/app.css"
  install -o root -g root -m0750 "$SOURCE_DIR/scripts/privora-update.sh" "$PANEL_ROOT/scripts/privora-update.sh"
  install -o root -g root -m0750 "$SOURCE_DIR/scripts/privora-update-rollback.sh" "$PANEL_ROOT/scripts/privora-update-rollback.sh"
  install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update
  install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback
  php -l "$PANEL_ROOT/panel/public/admin.php" >/dev/null
  node --check "$PANEL_ROOT/panel/public/assets/app.js" >/dev/null
  bash -n "$PANEL_ROOT/scripts/privora-update.sh"
  bash -n "$PANEL_ROOT/scripts/privora-update-rollback.sh"
  systemctl daemon-reload
  systemctl restart privora-panel-agent.service
  for _ in $(seq 1 30); do [[ -S /run/privora-panel/agent.sock ]] && break; sleep .2; done
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then fpm_service=php8.4-fpm; else fpm_service=php-fpm; fi
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  nginx -t >/dev/null
  systemctl reload nginx || systemctl restart nginx
  verify_agent_bridge_as_panel
}

refresh_update_launch_recovery(){
  local expected actual fpm_service
  if ((DRY_RUN)); then
    echo "[dry-run] refresh update launch journaling, bounded preflight authorization and truthful PCC launch status"
    return 0
  fi
  [[ -r "$SOURCE_DIR/dist/privora-agent" && -r "$SOURCE_DIR/dist/privora-agent.sha256" ]] || { echo 'dev.6.18 agent/checksum missing' >&2; return 1; }
  expected=$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")
  actual=$(sha256sum "$SOURCE_DIR/dist/privora-agent" | awk '{print $1}')
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo 'dev.6.18 agent checksum mismatch' >&2; return 1; }
  install -m0750 "$SOURCE_DIR/dist/privora-agent" /usr/local/libexec/privora-agent
  for f in panel/public/admin.php panel/public/assets/app.js scripts/privora-update.sh scripts/privora-update-rollback.sh; do
    [[ -r "$SOURCE_DIR/$f" ]] || { echo "Update launch recovery source missing $f" >&2; return 1; }
  done
  install -o root -g privora-panel -m0640 "$SOURCE_DIR/panel/public/admin.php" "$PANEL_ROOT/panel/public/admin.php"
  install -o root -g root -m0644 "$SOURCE_DIR/panel/public/assets/app.js" "$PANEL_ROOT/panel/public/assets/app.js"
  install -o root -g root -m0750 "$SOURCE_DIR/scripts/privora-update.sh" "$PANEL_ROOT/scripts/privora-update.sh"
  install -o root -g root -m0750 "$SOURCE_DIR/scripts/privora-update-rollback.sh" "$PANEL_ROOT/scripts/privora-update-rollback.sh"
  install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update
  install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback
  php -l "$PANEL_ROOT/panel/public/admin.php" >/dev/null
  node --check "$PANEL_ROOT/panel/public/assets/app.js" >/dev/null
  bash -n "$PANEL_ROOT/scripts/privora-update.sh"
  bash -n "$PANEL_ROOT/scripts/privora-update-rollback.sh"
  systemctl daemon-reload
  systemctl restart privora-panel-agent.service
  for _ in $(seq 1 30); do [[ -S /run/privora-panel/agent.sock ]] && break; sleep .2; done
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then fpm_service=php8.4-fpm; else fpm_service=php-fpm; fi
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service"
  nginx -t >/dev/null
  systemctl reload nginx || systemctl restart nginx
  verify_agent_bridge_as_panel
}

refresh_core_baseline_reconcile(){
  local new_version old_version stage previous failed fpm_service expected actual certbin certexpected certactual unit
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  if ((DRY_RUN)); then
    echo "[dry-run] atomically reconcile complete Privora core baseline to $PRIVORA_VERSION and commit VERSION only after production health"
    return 0
  fi
  [[ -n "$SOURCE_DIR" && -d "$SOURCE_DIR" && -f "$SOURCE_DIR/VERSION" ]] || { echo 'Core baseline reconciliation requires a complete --source-dir source tree' >&2; return 1; }
  new_version="$(tr -d '\r\n' < "$SOURCE_DIR/VERSION")"
  [[ "$new_version" == "$PRIVORA_VERSION" ]] || { echo "Core baseline source VERSION $new_version does not match installer $PRIVORA_VERSION" >&2; return 1; }
  old_version="$(tr -d '\r\n' < "$PANEL_ROOT/VERSION" 2>/dev/null || printf unknown)"

  # Fresh installs already have the complete current tree. Prove the critical
  # runtime binary matches before treating the baseline as coherent.
  if [[ "$old_version" == "$new_version" ]]; then
    expected="$(awk 'NR==1{print $1}' "$SOURCE_DIR/dist/privora-agent.sha256")"
    actual="$(sha256sum "$PANEL_ROOT/dist/privora-agent" 2>/dev/null | awk '{print $1}')"
    if [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]]; then
      log "Core baseline already coherent at $new_version"
      verify_agent_bridge_as_panel
      verify_live_inventory_as_panel
      return 0
    fi
    log "WARN VERSION is current but core binary differs; forcing complete baseline reconciliation"
  fi

  stage="${PANEL_ROOT}.reconcile-${new_version//[^A-Za-z0-9._-]/_}-$$"
  previous="${PANEL_ROOT}.baseline-previous-$(date -u +%Y%m%dT%H%M%SZ)"
  failed="${PANEL_ROOT}.baseline-failed-$$"
  rm -rf "$stage" "$failed"
  mkdir -p "$stage"
  rsync -a --delete --exclude panel/storage --exclude evidence/sandbox-host-adapter-certification.json "$SOURCE_DIR/" "$stage/"
  if [[ -d "$PANEL_ROOT/panel/storage" ]]; then
    mkdir -p "$stage/panel/storage"
    rsync -a "$PANEL_ROOT/panel/storage/" "$stage/panel/storage/"
  fi

  # Validate the staged full core before touching the live tree.
  [[ -x "$stage/dist/privora-agent" && -r "$stage/dist/privora-agent.sha256" ]] || { echo 'Staged Privora agent/checksum missing' >&2; rm -rf "$stage"; return 1; }
  expected="$(awk 'NR==1{print $1}' "$stage/dist/privora-agent.sha256")"
  actual="$(sha256sum "$stage/dist/privora-agent" | awk '{print $1}')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || { echo 'Staged Privora agent checksum mismatch' >&2; rm -rf "$stage"; return 1; }
  for certbin in privora-hostadapter-cert.test privora-api-cert.test; do
    [[ -x "$stage/dist/$certbin" && -r "$stage/dist/$certbin.sha256" ]] || { echo "Staged certification binary/checksum missing: $certbin" >&2; rm -rf "$stage"; return 1; }
    certexpected="$(awk 'NR==1{print $1}' "$stage/dist/$certbin.sha256")"
    certactual="$(sha256sum "$stage/dist/$certbin" | awk '{print $1}')"
    [[ "$certexpected" =~ ^[0-9a-f]{64}$ && "$certactual" == "$certexpected" ]] || { echo "Staged certification checksum mismatch: $certbin" >&2; rm -rf "$stage"; return 1; }
  done
  while IFS= read -r -d '' f; do php -l "$f" >/dev/null || { rm -rf "$stage"; return 1; }; done < <(find "$stage/panel" "$stage/scripts" -type f -name '*.php' -print0)
  while IFS= read -r -d '' f; do node --check "$f" >/dev/null || { rm -rf "$stage"; return 1; }; done < <(find "$stage/panel/public/assets" -type f -name '*.js' -print0)
  bash -n "$stage/scripts/privora-update.sh"
  bash -n "$stage/scripts/privora-update-rollback.sh"
  python3 -m py_compile "$stage/scripts/verify-upload-update.py"
  nginx -t >/dev/null

  # Do not claim the new baseline until the staged tree has been promoted and
  # proven through the real production PHP/agent/HTTP path.
  printf '%s\n' "$new_version" > "$stage/.VERSION.pending"
  printf '%s\n' "$old_version" > "$stage/VERSION"

  [[ -d "$PANEL_ROOT" ]] || { echo "Existing Privora root missing: $PANEL_ROOT" >&2; rm -rf "$stage"; return 1; }
  [[ ! -e "$previous" ]] || { echo "Core baseline rollback path already exists: $previous" >&2; rm -rf "$stage"; return 1; }
  mv "$PANEL_ROOT" "$previous"
  mv "$stage" "$PANEL_ROOT"

  core_baseline_restore(){
    local rc=${1:-1}
    log "Core baseline validation failed; restoring previous core $old_version"
    rm -rf "$failed"
    [[ -d "$PANEL_ROOT" ]] && mv "$PANEL_ROOT" "$failed" || true
    [[ -d "$previous" ]] && mv "$previous" "$PANEL_ROOT" || true
    if [[ -x "$PANEL_ROOT/dist/privora-agent" ]]; then install -m0750 "$PANEL_ROOT/dist/privora-agent" /usr/local/libexec/privora-agent || true; fi
    [[ -x "$PANEL_ROOT/scripts/privora-update.sh" ]] && install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update || true
    [[ -x "$PANEL_ROOT/scripts/privora-update-rollback.sh" ]] && install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback || true
    systemctl daemon-reload || true
    systemctl restart privora-panel-agent.service || true
    if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then fpm_service=php8.4-fpm; else fpm_service=php-fpm; fi
    systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service" || true
    nginx -t >/dev/null 2>&1 && (systemctl reload nginx || systemctl restart nginx) || true
    rm -rf "$failed"
    return "$rc"
  }

  # Refresh executable entry points from the now-live coherent tree.
  install -d -m0755 /usr/local/libexec /usr/local/bin /usr/local/sbin
  install -m0750 "$PANEL_ROOT/dist/privora-agent" /usr/local/libexec/privora-agent || { core_baseline_restore 1; return 1; }
  install -m0755 "$PANEL_ROOT/cli/privora" /usr/local/bin/privora || { core_baseline_restore 1; return 1; }
  install -m0750 "$PANEL_ROOT/scripts/privora-update.sh" /usr/local/sbin/privora-update || { core_baseline_restore 1; return 1; }
  install -m0750 "$PANEL_ROOT/scripts/privora-update-rollback.sh" /usr/local/sbin/privora-update-rollback || { core_baseline_restore 1; return 1; }

  # Enforce the production PHP-to-agent socket contract on recovery systems.
  unit=/etc/systemd/system/privora-panel-agent.service
  [[ -f "$unit" ]] || { echo "Privora agent unit missing: $unit" >&2; core_baseline_restore 1; return 1; }
  if ! grep -q '^Group=privora-panel$' "$unit"; then
    if grep -q '^Group=' "$unit"; then sed -i 's/^Group=.*/Group=privora-panel/' "$unit"; else sed -i '/^User=root$/a Group=privora-panel' "$unit"; fi
  fi
  if ! grep -q -- '--socket-group privora-panel' "$unit"; then
    sed -i -E 's#(--socket[[:space:]]+/run/privora-panel/agent\.sock)([[:space:]])#\1 --socket-group privora-panel\2#' "$unit"
  fi
  grep -q -- '--socket-group privora-panel' "$unit" || { echo 'Unable to enforce Privora socket-group contract' >&2; core_baseline_restore 1; return 1; }

  systemctl daemon-reload || { core_baseline_restore 1; return 1; }
  systemctl restart privora-panel-agent.service || { core_baseline_restore 1; return 1; }
  for _ in $(seq 1 40); do [[ -S /run/privora-panel/agent.sock ]] && break; sleep .25; done
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then fpm_service=php8.4-fpm; else fpm_service=php-fpm; fi
  systemctl reset-failed "$fpm_service" >/dev/null 2>&1 || true
  systemctl restart "$fpm_service" || { core_baseline_restore 1; return 1; }
  nginx -t >/dev/null || { core_baseline_restore 1; return 1; }
  systemctl reload nginx || systemctl restart nginx || { core_baseline_restore 1; return 1; }

  reconcile_panel_runtime || { core_baseline_restore 1; return 1; }
  verify_agent_bridge_as_panel || { core_baseline_restore 1; return 1; }
  verify_live_inventory_as_panel || { core_baseline_restore 1; return 1; }
  if ! curl -kfsS --max-time 12 "https://127.0.0.1:$WEB_PORT/" -o /dev/null; then
    echo 'Privora HTTP health failed after complete core baseline promotion' >&2
    core_baseline_restore 1
    return 1
  fi

  # Commit VERSION last, atomically, only after the coherent core is healthy.
  printf '%s\n' "$new_version" > "$PANEL_ROOT/VERSION.new"
  chown root:privora-panel "$PANEL_ROOT/VERSION.new"
  chmod 0640 "$PANEL_ROOT/VERSION.new"
  mv "$PANEL_ROOT/VERSION.new" "$PANEL_ROOT/VERSION"
  rm -f "$PANEL_ROOT/.VERSION.pending"
  sync
  log "Core baseline reconciled atomically: $old_version -> $new_version"

  # Reconcile a phantom running transaction left by older updater builds only when
  # no real updater owns the global lock. This repairs the exact dev.6.16 failure
  # mode without racing an active update.
  local latest_txn_dir latest_status
  latest_txn_dir="$(find /var/lib/privora-panel/update-transactions -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)"
  if [[ -n "$latest_txn_dir" && -f "$latest_txn_dir/journal.env" ]]; then
    latest_status="$(awk -F= '$1=="status"{v=$2} END{print v}' "$latest_txn_dir/journal.env" 2>/dev/null || true)"
    if [[ "$latest_status" == running ]]; then
      exec 8>/run/privora-panel/update.lock
      if flock -n 8; then
        printf 'phase=%q\nstatus=%q\nerror=%q\noperation=%q\nactivity_at=%q\n' \
          recovery failed 'stale running transaction recovered during core baseline reconciliation' \
          'Recovered stale transaction; no updater lock holder existed' "$(date -u +%FT%TZ)" >> "$latest_txn_dir/journal.env"
        flock -u 8
        log "Marked stale update transaction $(basename "$latest_txn_dir") failed because no updater lock holder exists"
      fi
      exec 8>&-
    fi
  fi

  # Retain one rollback copy for forensic/manual recovery; it contains code only,
  # while secrets and user runtime data remain outside /opt and were never copied.
  printf '%s\n' "$previous" > /var/lib/privora-panel/last-core-baseline-rollback-path
  chmod 0600 /var/lib/privora-panel/last-core-baseline-rollback-path
}

refresh_transaction_auth_recovery(){
  # dev.6.21 must install as one coherent core because dev.6.20 browser update
  # failed before promotion. Reuse the atomic full-core baseline reconciler.
  refresh_core_baseline_reconcile
}


configure_panel_fpm_isolation(){
  [[ "$MODE" =~ ^(full|web)$ ]] || return 0
  if ((DRY_RUN)); then echo '[dry-run] isolate Privora control panel on privora-panel-fpm.service'; return 0; fi
  local shared_pool fpm_bin shared_service socket nginx_group
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]]; then
    shared_pool=/etc/php/8.4/fpm/pool.d/privora-panel.conf
    fpm_bin=/usr/sbin/php-fpm8.4
    shared_service=php8.4-fpm.service
    socket=/run/php/privora-panel.sock
    nginx_group=www-data
  else
    shared_pool=/etc/php-fpm.d/privora-panel.conf
    fpm_bin=/usr/sbin/php-fpm
    shared_service=php-fpm.service
    socket=/run/php-fpm/privora-panel.sock
    nginx_group=nginx
  fi
  [[ -x "$fpm_bin" ]] || { echo "PHP-FPM binary unavailable: $fpm_bin" >&2; return 1; }
  install -d -o root -g root -m0750 /etc/privora-panel/fpm /var/log/privora-panel
  if [[ -s "$shared_pool" ]]; then
    install -o root -g root -m0640 "$shared_pool" /etc/privora-panel/fpm/privora-panel.conf
  elif [[ ! -s /etc/privora-panel/fpm/privora-panel.conf ]]; then
    cat >/etc/privora-panel/fpm/privora-panel.conf <<FPM
[privora-panel]
user = privora-panel
group = privora-panel
listen = $socket
listen.owner = privora-panel
listen.group = $nginx_group
listen.mode = 0660
pm = ondemand
pm.max_children = 12
pm.process_idle_timeout = 20s
php_admin_value[session.save_path] = /var/lib/privora-panel/web/sessions
php_admin_value[upload_tmp_dir] = /var/lib/privora-panel/web/tmp
clear_env = no
php_admin_value[upload_max_filesize] = 512M
php_admin_value[post_max_size] = 520M
php_admin_value[max_file_uploads] = 4
php_admin_value[max_execution_time] = 600
FPM
    chmod 0640 /etc/privora-panel/fpm/privora-panel.conf
  fi
  cat >/etc/privora-panel/fpm/php-fpm.conf <<EOF
[global]
pid = /run/php/privora-panel-fpm.pid
error_log = /var/log/privora-panel/php-fpm.log
daemonize = no
include=/etc/privora-panel/fpm/privora-panel.conf
EOF
  chmod 0640 /etc/privora-panel/fpm/php-fpm.conf
  cat >/etc/systemd/system/privora-panel-fpm.service <<EOF
[Unit]
Description=Privora Panel Dedicated PHP-FPM
After=network.target
[Service]
Type=simple
EnvironmentFile=/etc/privora-panel/panel.env
ExecStart=$fpm_bin -F -y /etc/privora-panel/fpm/php-fpm.conf
ExecReload=/bin/kill -USR2 \$MAINPID
KillSignal=SIGQUIT
TimeoutStopSec=30
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  "$fpm_bin" -t -y /etc/privora-panel/fpm/php-fpm.conf >/dev/null
  if [[ -s "$shared_pool" ]]; then
    mv -f "$shared_pool" /etc/privora-panel/fpm/privora-panel.shared-master.backup.conf
  fi
  rm -f /etc/systemd/system/php8.4-fpm.service.d/privora-panel.conf /etc/systemd/system/php-fpm.service.d/privora-panel.conf
  "$fpm_bin" -t >/dev/null
  systemctl daemon-reload
  systemctl reset-failed "$shared_service" >/dev/null 2>&1 || true
  systemctl restart "$shared_service"
  rm -f "$socket"
  systemctl enable --now privora-panel-fpm.service
  for _ in $(seq 1 40); do [[ -S "$socket" ]] && break; sleep .25; done
  [[ -S "$socket" ]] || { echo "Privora dedicated FPM socket missing: $socket" >&2; return 1; }
  nginx -t
  systemctl reload nginx
  systemctl is-active --quiet "$shared_service"
  systemctl is-active --quiet privora-panel-fpm.service
  systemctl reload "$shared_service"
  sleep 1
  systemctl is-active --quiet privora-panel-fpm.service
  [[ -S "$socket" ]] || { echo 'Privora panel socket disappeared after website FPM reload' >&2; return 1; }
  local code
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' "https://127.0.0.1:$WEB_PORT/" || true)"
  [[ "$code" =~ ^(200|301|302|303|307|308|401|403)$ ]] || { echo "Privora HTTP probe failed after FPM isolation (HTTP $code)" >&2; return 1; }
}

configure_mail_auth_foundation(){
  [[ "$MODE" == "full" || "$MODE" == "mail" ]] || return 0
  if ((DRY_RUN)); then
    echo '[dry-run] reconcile Dovecot passwd-file virtual-mail authentication and Postfix SMTP AUTH'
    return 0
  fi
  [[ -x "$PANEL_ROOT/scripts/reconcile-mail-auth.sh" ]] || { echo 'Privora mail-auth reconciler is missing' >&2; return 1; }
  PRIVORA_MAIL_STATE_DIR=/etc/privora-mail PRIVORA_MAIL_AUTH_GROUP=privora-panel "$PANEL_ROOT/scripts/reconcile-mail-auth.sh"
}

configure_phpmyadmin(){
  [[ "$MODE" == "full" ]] || return 0
  if ((DRY_RUN)); then echo '[dry-run] install and configure panel-gated phpMyAdmin'; return 0; fi
  PRIVORA_PANEL_ROOT="$PANEL_ROOT" "$PANEL_ROOT/scripts/configure-phpmyadmin.sh"
}

configure_webmail(){
  [[ "$MODE" == "full" || "$MODE" == "mail" ]] || return 0
  if ((DRY_RUN)); then echo '[dry-run] install and configure panel-gated Roundcube webmail'; return 0; fi
  PRIVORA_PANEL_ROOT="$PANEL_ROOT" "$PANEL_ROOT/scripts/configure-webmail.sh"
}

configure_site_panel_shortcuts(){
  if ((DRY_RUN)); then
    echo "[dry-run] reconcile hosted-domain /pcc -> PCC:$WEB_PORT and /ppanel -> PPanel:$HOSTING_PORT shortcuts"
    return 0
  fi
  PRIVORA_PANEL_ROOT="$PANEL_ROOT" PRIVORA_ADMIN_PANEL_PORT="$WEB_PORT" PRIVORA_HOSTING_PANEL_PORT="$HOSTING_PORT" "$PANEL_ROOT/scripts/reconcile-site-panel-shortcuts.sh"
}

health_check(){
  reconcile_panel_runtime
  verify_agent_bridge_as_panel
  verify_live_inventory_as_panel
  run nginx -t
  run systemctl is-active --quiet privora-panel-agent.service
  local fpm_service
  if [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]];then fpm_service=php8.4-fpm;else fpm_service=php-fpm;fi
  if systemctl cat privora-panel-fpm.service >/dev/null 2>&1; then
    run systemctl is-active --quiet privora-panel-fpm.service
  else
    run systemctl is-active --quiet "$fpm_service"
  fi
  if ((DRY_RUN)); then
    run curl -kfsS --max-time 5 "https://127.0.0.1:$WEB_PORT/" -o /dev/null
    run curl -kfsS --max-time 5 "https://127.0.0.1:$HOSTING_PORT/" -o /dev/null
    return 0
  fi
  local body=/var/tmp/privora-health-body headers=/var/tmp/privora-health-headers
  rm -f "$body" "$headers"
  if ! curl -ksS --max-time 8 -D "$headers" "https://127.0.0.1:$WEB_PORT/" -o "$body"; then
    echo "Privora health transport failed" >&2
    tail -n 40 /var/log/nginx/error.log 2>/dev/null >&2 || true
    journalctl -u "$fpm_service" -n 40 --no-pager 2>/dev/null >&2 || true
    return 1
  fi
  local code
  code=$(awk 'toupper($1) ~ /^HTTP\// {c=$2} END{print c}' "$headers")
  [[ "$code" =~ ^2[0-9][0-9]$|^3[0-9][0-9]$ ]] || {
    echo "Privora health returned HTTP ${code:-unknown}" >&2
    tail -n 40 /var/log/nginx/error.log 2>/dev/null >&2 || true
    journalctl -u "$fpm_service" -n 40 --no-pager 2>/dev/null >&2 || true
    return 1
  }
  grep -qi 'Privora' "$body" || { echo "Privora health response did not contain expected panel marker" >&2; return 1; }
  local hosting_code
  hosting_code="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 8 "https://127.0.0.1:$HOSTING_PORT/" || true)"
  [[ "$hosting_code" =~ ^(200|301|302|303|307|308|401|403)$ ]] || { echo "Privora Panel (PPanel) health returned HTTP ${hosting_code:-000}" >&2; return 1; }
}
for ph in preflight system_update base_packages role_packages php_stack source privora_files app_trust secrets services role_services mail_auth_foundation dns_foundation resource_foundation firewall administrator certification health frontend_csp live_host_reconcile whm_update_center agent_bridge_live_inventory authoritative_inventory update_progress_observability update_launch_recovery core_baseline_reconcile transaction_auth_recovery panel_fpm_isolation phpmyadmin webmail site_panel_shortcuts; do
  case "$ph" in
    preflight) fn=preflight;; system_update) fn=pkg_update;; base_packages) fn=install_base_packages;; role_packages) fn=install_role_packages;; php_stack) fn=install_php_stack;; source) fn=acquire_source;; privora_files) fn=install_privora;; app_trust) fn=configure_app_trust;; secrets) fn=write_secrets;; services) fn=configure_services;; role_services) fn=enable_role_services;; mail_auth_foundation) fn=configure_mail_auth_foundation;; dns_foundation) fn=configure_dns_foundation;; resource_foundation) fn=configure_resource_foundation;; firewall) fn=configure_firewall;; administrator) fn=initialize_panel;; certification) fn=host_certify;; health) fn=health_check;; frontend_csp) fn=refresh_frontend_csp;; live_host_reconcile) fn=refresh_live_host_reconcile;; whm_update_center) fn=refresh_whm_update_center;; agent_bridge_live_inventory) fn=refresh_agent_bridge_live_inventory;; authoritative_inventory) fn=refresh_authoritative_inventory;; update_progress_observability) fn=refresh_update_progress_observability;; update_launch_recovery) fn=refresh_update_launch_recovery;; core_baseline_reconcile) fn=refresh_core_baseline_reconcile;; transaction_auth_recovery) fn=refresh_transaction_auth_recovery;; panel_fpm_isolation) fn=configure_panel_fpm_isolation;; phpmyadmin) fn=configure_phpmyadmin;; webmail) fn=configure_webmail;; site_panel_shortcuts) fn=configure_site_panel_shortcuts;;
  esac
  CURRENT_PHASE="$ph"
  if completed "$ph"; then log "SKIP $ph (already completed)"; continue; fi
  log "BEGIN $ph"
  "$fn"
  finish_phase "$ph"
done
if ((DRY_RUN));then echo "Privora Panel $PRIVORA_VERSION dry-run complete. No host changes were made.";else login_host="${HOSTNAME_ARG:-$(hostname -f 2>/dev/null||hostname -I|awk '{print $1}')}";echo "Privora Panel $PRIVORA_VERSION installation complete";echo "Privora Command Center (PCC): https://$login_host:$WEB_PORT";echo "Privora Panel (PPanel): https://$login_host:$HOSTING_PORT";echo "Administrator: $ADMIN_USER";[[ -n "$ADMIN_PASSWORD" ]]||echo "Generated password: $(cat "$STATE_DIR/bootstrap-admin-password")";echo "Log: $LOG_FILE";fi
