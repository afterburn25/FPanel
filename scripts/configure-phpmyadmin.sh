#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
ROOT="${PRIVORA_PANEL_ROOT:-/opt/privora-panel}"
VERIFY_ONLY=0
[[ "${1:-}" == "--verify-only" ]] && VERIFY_ONLY=1
log(){ printf '[phpmyadmin] %s\n' "$*"; }
die(){ echo "phpMyAdmin: $*" >&2; exit 1; }
((EUID==0)) || die 'root required'
[[ -r /etc/os-release ]] || die '/etc/os-release missing'
. /etc/os-release
[[ "${ID:-}" =~ ^(ubuntu|debian)$ ]] || die "automatic phpMyAdmin provisioning is currently certified for Debian/Ubuntu only (found ${ID:-unknown})"

PHPV=8.4
FPM_BIN="/usr/sbin/php-fpm${PHPV}"
FPM_SERVICE="php${PHPV}-fpm.service"
FPM_POOL="/etc/php/${PHPV}/fpm/pool.d/privora-phpmyadmin.conf"
PMA_SOCKET="/run/php/php${PHPV}-fpm-privora-phpmyadmin.sock"
PMA_ROOT="/usr/share/phpmyadmin"
PMA_CONF="/etc/phpmyadmin/conf.d/99-privora.php"
PMA_TMP="/var/lib/phpmyadmin/privora-tmp"
NGINX_CONF="/etc/nginx/sites-available/privora-panel.conf"
[[ -d /etc/nginx/sites-available ]] || NGINX_CONF="/etc/nginx/conf.d/privora-panel.conf"
PANEL_SOCKET="/run/php/privora-panel.sock"
PORTS=/etc/privora-panel/panel-ports.env
ADMIN_PORT=8443
HOSTING_PORT=2443
if [[ -r "$PORTS" ]]; then
  # shellcheck disable=SC1090
  . "$PORTS"
  ADMIN_PORT="${PRIVORA_ADMIN_PANEL_PORT:-$ADMIN_PORT}"
  HOSTING_PORT="${PRIVORA_HOSTING_PANEL_PORT:-$HOSTING_PORT}"
fi

install_packages(){
  command -v apt-get >/dev/null || die 'apt-get is required on this host'
  command -v debconf-set-selections >/dev/null || die 'debconf-set-selections is required'
  printf '%s\n' 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect' | debconf-set-selections
  printf '%s\n' 'phpmyadmin phpmyadmin/dbconfig-install boolean false' | debconf-set-selections
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  pkgs=(phpmyadmin)
  for pkg in php8.4-mysql php8.4-mbstring php8.4-xml php8.4-curl php8.4-zip php8.4-gd; do
    if apt-cache show "$pkg" >/dev/null 2>&1; then pkgs+=("$pkg"); fi
  done
  apt-get install -y --no-install-recommends "${pkgs[@]}"
}

configure_files(){
  [[ -x "$FPM_BIN" ]] || die "$FPM_BIN not found"
  [[ -f "$PMA_ROOT/index.php" ]] || die "$PMA_ROOT/index.php missing after package installation"
  install -d -o www-data -g www-data -m0700 "$PMA_TMP"
  install -d -o root -g root -m0755 "$(dirname "$FPM_POOL")" /etc/phpmyadmin/conf.d
  cat >"$FPM_POOL" <<POOL
[privora-phpmyadmin]
user = www-data
group = www-data
listen = $PMA_SOCKET
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 20s
clear_env = yes
php_admin_value[session.save_path] = /var/lib/php/sessions
php_admin_value[upload_tmp_dir] = $PMA_TMP
php_admin_value[open_basedir] = /usr/share/phpmyadmin:/usr/share/php:/etc/phpmyadmin:/var/lib/phpmyadmin:/var/lib/php/sessions:/tmp
php_admin_flag[display_errors] = off
php_admin_value[max_execution_time] = 300
php_admin_value[memory_limit] = 256M
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 132M
POOL
  chmod 0644 "$FPM_POOL"
  cat >"$PMA_CONF" <<'PHP'
<?php
/* Privora-managed phpMyAdmin policy. Keep this file separate from package-owned config.inc.php. */
if (!isset($i) || !is_int($i) || $i < 1) { $i = 1; }
if (!isset($cfg['Servers'][$i]) || !is_array($cfg['Servers'][$i])) { $cfg['Servers'][$i] = []; }
$cfg['Servers'][$i]['auth_type'] = 'cookie';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['AllowRoot'] = false;
$cfg['Servers'][$i]['hide_connection_errors'] = true;
$cfg['AllowArbitraryServer'] = false;
$cfg['LoginCookieRecall'] = false;
$cfg['LoginCookieStore'] = 0;
$cfg['LoginCookieValidity'] = 1800;
$cfg['CookieSameSite'] = 'Strict';
$cfg['TempDir'] = '/var/lib/phpmyadmin/privora-tmp';
PHP
  chmod 0644 "$PMA_CONF"
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
  tmp="$(mktemp "${NGINX_CONF}.privora-pma.XXXXXX")"
  python3 "$ROOT/scripts/render-panel-nginx.py" \
    --admin-port "$ADMIN_PORT" --hosting-port "$HOSTING_PORT" \
    --server-name "$server_name" --fpm-socket "$PANEL_SOCKET" \
    --phpmyadmin-fpm-socket "$PMA_SOCKET" --panel-root "$ROOT" >"$tmp"
  install -o root -g root -m0644 "$tmp" "$NGINX_CONF"
  rm -f "$tmp"
  [[ "$NGINX_CONF" == /etc/nginx/sites-available/* ]] && ln -sfn "$NGINX_CONF" /etc/nginx/sites-enabled/privora-panel.conf
}

verify(){
  [[ -f "$PMA_ROOT/index.php" ]] || die 'phpMyAdmin index missing'
  [[ -f "$FPM_POOL" ]] || die 'dedicated phpMyAdmin FPM pool missing'
  [[ -f "$PMA_CONF" ]] || die 'Privora phpMyAdmin policy missing'
  [[ -r "$NGINX_CONF" ]] || die 'Privora Nginx config missing'
  grep -Fq 'location /phpmyadmin/' "$NGINX_CONF" || die 'phpMyAdmin Nginx route missing'
  grep -Fq 'auth_request /_privora_phpmyadmin_auth;' "$NGINX_CONF" || die 'phpMyAdmin panel-session gate missing'
  grep -Fq '[privora-phpmyadmin]' "$FPM_POOL" || die 'phpMyAdmin FPM pool marker missing'
  grep -Fq "listen = $PMA_SOCKET" "$FPM_POOL" || die 'phpMyAdmin FPM socket mismatch'
  "$FPM_BIN" -t >/dev/null
  php8.4 -l "$PMA_ROOT/index.php" >/dev/null
  php8.4 -r 'foreach(["mysqli","mbstring","openssl","session","ctype"] as $e){if(!extension_loaded($e)){fwrite(STDERR,"missing PHP extension: $e\n");exit(2);}}'
  nginx -t >/dev/null
  systemctl is-active --quiet "$FPM_SERVICE" || die "$FPM_SERVICE is not active"
  [[ -S "$PMA_SOCKET" ]] || die "phpMyAdmin FPM socket missing: $PMA_SOCKET"
  local code
  code="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "https://127.0.0.1:${ADMIN_PORT}/phpmyadmin/" || true)"
  [[ "$code" =~ ^(401|403)$ ]] || die "unauthenticated phpMyAdmin route is not fail-closed (HTTP ${code:-000})"
  log "PASS package=$PMA_ROOT route=/phpmyadmin/ auth=Privora-session fpm=$PMA_SOCKET unauthenticated_http=$code"
}

if ((VERIFY_ONLY)); then verify; exit 0; fi
install_packages
configure_files
render_nginx
nginx -t
systemctl restart "$FPM_SERVICE"
for _ in $(seq 1 40); do [[ -S "$PMA_SOCKET" ]] && break; sleep .25; done
systemctl reload nginx
verify
