#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
ROOT="${PRIVORA_PANEL_ROOT:-/opt/privora-panel}"
VERIFY_ONLY=0
CONFIG_ONLY=0
case "${1:-}" in
  --verify-only) VERIFY_ONLY=1 ;;
  --configure-only) CONFIG_ONLY=1 ;;
  "") ;;
  *) echo "Webmail: unknown option ${1:-}" >&2; exit 2 ;;
esac
log(){ printf '[webmail] %s\n' "$*"; }
die(){ echo "Webmail: $*" >&2; exit 1; }
((EUID==0)) || die 'root required'
[[ -r /etc/os-release ]] || die '/etc/os-release missing'
. /etc/os-release
[[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || die "automatic Roundcube provisioning is currently certified for Debian/Ubuntu only (found ${ID:-unknown})"

PHPV=8.4
FPM_BIN="/usr/sbin/php-fpm${PHPV}"
FPM_SERVICE="php${PHPV}-fpm.service"
FPM_POOL="/etc/php/${PHPV}/fpm/pool.d/privora-webmail.conf"
WEBMAIL_SOCKET="/run/php/php${PHPV}-fpm-privora-webmail.sock"
WEBMAIL_ROOT="/usr/share/roundcube"
WEBMAIL_CONF="/etc/roundcube/config.inc.php"
WEBMAIL_ENV="/etc/privora-panel/webmail.env"
WEBMAIL_TMP="/var/lib/roundcube/temp"
WEBMAIL_LOG="/var/log/roundcube"
NGINX_CONF="/etc/nginx/sites-available/privora-panel.conf"
[[ -d /etc/nginx/sites-available ]] || NGINX_CONF="/etc/nginx/conf.d/privora-panel.conf"
PANEL_SOCKET="/run/php/privora-panel.sock"
PMA_SOCKET="/run/php/php${PHPV}-fpm-privora-phpmyadmin.sock"
PORTS=/etc/privora-panel/panel-ports.env
ADMIN_PORT=8443
HOSTING_PORT=2443
if [[ -r "$PORTS" ]]; then
  # shellcheck disable=SC1090
  . "$PORTS"
  ADMIN_PORT="${PRIVORA_ADMIN_PANEL_PORT:-$ADMIN_PORT}"
  HOSTING_PORT="${PRIVORA_HOSTING_PANEL_PORT:-$HOSTING_PORT}"
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/backups/privora-panel/webmail-${STAMP}"
mkdir -p "$BACKUP"
backup_one(){
  local path="$1" key="$2"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a "$path" "$BACKUP/$key"
    printf 'present\n' >"$BACKUP/$key.state"
  else
    printf 'absent\n' >"$BACKUP/$key.state"
  fi
}
restore_one(){
  local path="$1" key="$2"
  if [[ "$(cat "$BACKUP/$key.state" 2>/dev/null || echo absent)" == present ]]; then
    rm -rf "$path"
    cp -a "$BACKUP/$key" "$path"
  else
    rm -rf "$path"
  fi
}
rollback(){
  local rc="${1:-1}"
  log "configuration failed; restoring managed webmail/Nginx files"
  restore_one "$NGINX_CONF" nginx
  restore_one "$FPM_POOL" fpm-pool
  restore_one "$WEBMAIL_CONF" roundcube-config
  restore_one "$WEBMAIL_ENV" webmail-env
  "$FPM_BIN" -t >/dev/null 2>&1 && systemctl restart "$FPM_SERVICE" >/dev/null 2>&1 || true
  nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  exit "$rc"
}

install_packages(){
  command -v apt-get >/dev/null || die 'apt-get is required on this host'
  command -v debconf-set-selections >/dev/null || die 'debconf-set-selections is required'
  # Roundcube is kept independent from Apache/lighttpd. dbconfig-common owns only
  # Roundcube's internal SQLite metadata database; mailbox passwords remain in Dovecot.
  printf '%s\n' \
    'roundcube-core roundcube/reconfigure-webserver multiselect' \
    'roundcube-core roundcube/restart-webserver boolean false' \
    'roundcube-core roundcube/dbconfig-install boolean true' \
    'roundcube-core roundcube/database-type select sqlite3' \
    'roundcube-core roundcube/hosts string' \
    | debconf-set-selections
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  pkgs=(roundcube-core roundcube-sqlite3 sqlite3)
  for pkg in php8.4-sqlite3 php8.4-mbstring php8.4-xml php8.4-intl php8.4-curl php8.4-zip php8.4-gd; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then pkgs+=("$pkg"); fi
  done
  apt-get -o Dpkg::Lock::Timeout=60 install -y --no-install-recommends "${pkgs[@]}"
}

roundcube_db_include(){
  for p in /etc/roundcube/debian-db-roundcube.php /etc/roundcube/debian-db.php; do
    if [[ -r "$p" ]]; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

configure_files(){
  [[ -x "$FPM_BIN" ]] || die "$FPM_BIN not found"
  [[ -f "$WEBMAIL_ROOT/index.php" ]] || die "$WEBMAIL_ROOT/index.php missing after package installation"
  local dbinc
  dbinc="$(roundcube_db_include)" || die 'Roundcube dbconfig-common database include is missing'
  install -d -o www-data -g www-data -m0750 "$WEBMAIL_TMP" "$WEBMAIL_LOG"
  install -d -o root -g root -m0755 "$(dirname "$FPM_POOL")" /etc/privora-panel /etc/roundcube

  local deskey=''
  if [[ -r "$WEBMAIL_CONF" ]]; then
    deskey="$(sed -n "s/^[[:space:]]*\$config\['des_key'\][[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$WEBMAIL_CONF" | head -1 || true)"
  fi
  if [[ ${#deskey} -ne 24 ]]; then
    command -v openssl >/dev/null || die 'openssl is required to create the Roundcube encryption key'
    deskey="$(openssl rand -hex 12)"
  fi
  [[ ${#deskey} -eq 24 ]] || die 'could not create a valid Roundcube encryption key'

  cat >"$FPM_POOL" <<POOL
[privora-webmail]
user = www-data
group = www-data
listen = $WEBMAIL_SOCKET
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 12
pm.process_idle_timeout = 30s
clear_env = yes
php_admin_value[session.save_path] = /var/lib/php/sessions
php_admin_value[upload_tmp_dir] = $WEBMAIL_TMP
php_admin_value[open_basedir] = /usr/share/roundcube:/etc/roundcube:/var/lib/roundcube:/var/log/roundcube:/var/lib/php/sessions:/tmp
php_admin_flag[display_errors] = off
php_admin_value[max_execution_time] = 300
php_admin_value[memory_limit] = 256M
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 68M
POOL
  chmod 0644 "$FPM_POOL"

  cat >"$WEBMAIL_CONF" <<PHP
<?php
/* Privora-managed Roundcube policy. Mailbox credentials are never stored by Privora. */
\$config = [];
include('${dbinc}');
\$config['imap_host'] = 'localhost:143';
\$config['smtp_host'] = 'localhost:587';
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['product_name'] = 'Privora Webmail';
\$config['des_key'] = '${deskey}';
\$config['skin'] = 'elastic';
\$config['enable_spellcheck'] = false;
\$config['plugins'] = [];
\$config['session_lifetime'] = 30;
\$config['ip_check'] = false;
\$config['login_autocomplete'] = 2;
PHP
  chown root:www-data "$WEBMAIL_CONF"
  chmod 0640 "$WEBMAIL_CONF"

  cat >"$WEBMAIL_ENV" <<EOFENV
PRIVORA_WEBMAIL_CLIENT=Roundcube
PRIVORA_WEBMAIL_URL=/webmail/
PRIVORA_WEBMAIL_ROOT=$WEBMAIL_ROOT
PRIVORA_WEBMAIL_FPM_SOCKET=$WEBMAIL_SOCKET
EOFENV
  chown root:privora-panel "$WEBMAIL_ENV" 2>/dev/null || chown root:root "$WEBMAIL_ENV"
  chmod 0640 "$WEBMAIL_ENV"
}

render_nginx(){
  [[ -x "$ROOT/scripts/render-panel-nginx.py" ]] || die 'Privora panel Nginx renderer missing'
  local server_name=_
  if [[ -r "$NGINX_CONF" ]]; then
    server_name="$(awk '$1=="server_name"{gsub(/;/,"",$2); print $2; exit}' "$NGINX_CONF" || true)"
    [[ -n "$server_name" ]] || server_name=_
    local found_socket
    found_socket="$(sed -n 's/^[[:space:]]*fastcgi_pass[[:space:]]\+unix:\([^;]*\);.*/\1/p' "$NGINX_CONF" | head -1)"
    [[ -n "$found_socket" ]] && PANEL_SOCKET="$found_socket"
  fi
  local tmp
  tmp="$(mktemp "${NGINX_CONF}.privora-webmail.XXXXXX")"
  python3 "$ROOT/scripts/render-panel-nginx.py" \
    --admin-port "$ADMIN_PORT" --hosting-port "$HOSTING_PORT" \
    --server-name "$server_name" --fpm-socket "$PANEL_SOCKET" \
    --phpmyadmin-fpm-socket "$PMA_SOCKET" \
    --webmail-fpm-socket "$WEBMAIL_SOCKET" --panel-root "$ROOT" >"$tmp"
  install -o root -g root -m0644 "$tmp" "$NGINX_CONF"
  rm -f "$tmp"
  [[ "$NGINX_CONF" == /etc/nginx/sites-available/* ]] && ln -sfn "$NGINX_CONF" /etc/nginx/sites-enabled/privora-panel.conf
}

verify(){
  [[ -f "$WEBMAIL_ROOT/index.php" ]] || die 'Roundcube index missing'
  [[ -f "$FPM_POOL" ]] || die 'dedicated Roundcube FPM pool missing'
  [[ -f "$WEBMAIL_CONF" ]] || die 'Privora Roundcube policy missing'
  [[ -f "$WEBMAIL_ENV" ]] || die 'Privora webmail launch metadata missing'
  [[ -r "$NGINX_CONF" ]] || die 'Privora Nginx config missing'
  grep -Fq 'location /webmail/' "$NGINX_CONF" || die 'Roundcube Nginx route missing'
  grep -Fq 'auth_request /_privora_webmail_auth;' "$NGINX_CONF" || die 'Roundcube panel-session gate missing'
  grep -Fq '[privora-webmail]' "$FPM_POOL" || die 'Roundcube FPM pool marker missing'
  grep -Fq "listen = $WEBMAIL_SOCKET" "$FPM_POOL" || die 'Roundcube FPM socket mismatch'
  grep -Fq "PRIVORA_WEBMAIL_URL=/webmail/" "$WEBMAIL_ENV" || die 'Roundcube launch URL mismatch'
  "$FPM_BIN" -t >/dev/null
  php8.4 -l "$WEBMAIL_ROOT/index.php" >/dev/null
  php8.4 -r 'foreach(["pdo_sqlite","mbstring","openssl","session","ctype","json"] as $e){if(!extension_loaded($e)){fwrite(STDERR,"missing PHP extension: $e\\n");exit(2);}}'
  nginx -t >/dev/null
  systemctl is-active --quiet "$FPM_SERVICE" || die "$FPM_SERVICE is not active"
  systemctl is-active --quiet postfix || die 'postfix is not active'
  systemctl is-active --quiet dovecot || die 'dovecot is not active'
  [[ -S "$WEBMAIL_SOCKET" ]] || die "Roundcube FPM socket missing: $WEBMAIL_SOCKET"
  local code
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "https://127.0.0.1:${HOSTING_PORT}/webmail/" || true)"
  [[ "$code" =~ ^(401|403)$ ]] || die "unauthenticated webmail route is not fail-closed (HTTP ${code:-000})"
  log "PASS client=Roundcube route=/webmail/ auth=Privora-session+mailbox fpm=$WEBMAIL_SOCKET unauthenticated_http=$code"
}

if ((VERIFY_ONLY)); then verify; exit 0; fi
backup_one "$NGINX_CONF" nginx
backup_one "$FPM_POOL" fpm-pool
backup_one "$WEBMAIL_CONF" roundcube-config
backup_one "$WEBMAIL_ENV" webmail-env
trap 'rc=$?; rollback "$rc"' ERR
if ((!CONFIG_ONLY)); then install_packages; fi
configure_files
render_nginx
nginx -t
systemctl restart "$FPM_SERVICE"
for _ in $(seq 1 40); do [[ -S "$WEBMAIL_SOCKET" ]] && break; sleep .25; done
systemctl reload nginx
verify
trap - ERR
log "Roundcube webmail configured successfully. Backup: $BACKUP"
