#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
MODE="${1:-}"
[[ "$MODE" == "--preflight" || "$MODE" == "--apply" ]] || { echo 'Usage: migrate.sh --preflight|--apply' >&2; exit 2; }

preflight(){
  command -v systemctl >/dev/null
  command -v python3 >/dev/null
  command -v nginx >/dev/null
  [[ -d /etc/privora-panel ]]
  [[ -d /var/lib/privora-panel/web ]]
  if [[ -d /etc/bind ]]; then command -v named-checkconf >/dev/null; fi
  if command -v php-fpm8.4 >/dev/null 2>&1; then php-fpm8.4 -t >/dev/null 2>&1 || true; fi
}

apply_bind(){
  [[ -d /etc/bind && -f /etc/bind/named.conf.local ]] || return 0
  install -d -m0755 /etc/bind/privora-zones
  touch /etc/bind/privora-zones.conf
  chmod 0644 /etc/bind/privora-zones.conf
  local backup="/etc/bind/named.conf.local.privora-update-6.28-$(date -u +%Y%m%dT%H%M%SZ).bak"
  cp -a /etc/bind/named.conf.local "$backup"
  python3 - <<'PY'
from pathlib import Path
import re
p=Path('/etc/bind/named.conf.local')
text=p.read_text()
pat=re.compile(r'^\s*include\s+["\x27]?/etc/bind/privora-zones\.conf["\x27]?;\s*$', re.M)
text=pat.sub('', text)
text=text.rstrip()+'\n\n// Privora-managed authoritative zones\ninclude "/etc/bind/privora-zones.conf";\n'
p.write_text(text)
PY
  if ! named-checkconf; then
    cp -a "$backup" /etc/bind/named.conf.local
    echo "BIND migration validation failed; restored $backup" >&2
    return 1
  fi
  systemctl reload bind9.service 2>/dev/null || systemctl reload named.service 2>/dev/null || true
}

apply_registrar_env(){
  local env=/etc/privora-panel/agent.env
  [[ -f "$env" ]] || return 0
  grep -q '^PRIVORA_REGISTRAR_PROVIDER=' "$env" || printf '%s\n' 'PRIVORA_REGISTRAR_PROVIDER=' >> "$env"
  grep -q '^PRIVORA_REGISTRAR_ADAPTER_URL=' "$env" || printf '%s\n' 'PRIVORA_REGISTRAR_ADAPTER_URL=' >> "$env"
  grep -q '^PRIVORA_REGISTRAR_TOKEN=' "$env" || printf '%s\n' 'PRIVORA_REGISTRAR_TOKEN=' >> "$env"
  chmod 0600 "$env"
}

apply_dedicated_fpm(){
  command -v php-fpm8.4 >/dev/null 2>&1 || return 0
  install -d -m0750 /etc/privora-panel/fpm /var/log/privora-panel
  if [[ ! -f /etc/privora-panel/fpm/privora-panel.conf ]]; then
    if [[ -f /etc/php/8.4/fpm/pool.d/privora-panel.conf ]]; then
      cp -a /etc/php/8.4/fpm/pool.d/privora-panel.conf /etc/privora-panel/fpm/privora-panel.conf
    else
      cat > /etc/privora-panel/fpm/privora-panel.conf <<'POOL'
[privora-panel]
user = privora-panel
group = privora-panel
listen = /run/php/privora-panel.sock
listen.owner = privora-panel
listen.group = www-data
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
POOL
    fi
  fi
  chmod 0640 /etc/privora-panel/fpm/privora-panel.conf
  cat > /etc/privora-panel/fpm/php-fpm.conf <<'FPM'
[global]
pid = /run/php/privora-panel-fpm.pid
error_log = /var/log/privora-panel/php-fpm.log
daemonize = no
include=/etc/privora-panel/fpm/privora-panel.conf
FPM
  php-fpm8.4 -t -y /etc/privora-panel/fpm/php-fpm.conf >/dev/null
  cat > /etc/systemd/system/privora-panel-fpm.service <<'UNIT'
[Unit]
Description=Privora Panel Dedicated PHP 8.4 FPM
After=network.target

[Service]
Type=simple
EnvironmentFile=-/etc/privora-panel/panel.env
ExecStart=/usr/sbin/php-fpm8.4 -F -y /etc/privora-panel/fpm/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
KillSignal=SIGQUIT
TimeoutStopSec=30
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  shared_changed=0
  if [[ -f /etc/php/8.4/fpm/pool.d/privora-panel.conf ]]; then
    mv /etc/php/8.4/fpm/pool.d/privora-panel.conf /etc/privora-panel/fpm/privora-panel.shared-master.backup
    shared_changed=1
  fi
  if [[ -f /etc/systemd/system/php8.4-fpm.service.d/privora-panel.conf ]]; then
    rm -f /etc/systemd/system/php8.4-fpm.service.d/privora-panel.conf
    shared_changed=1
  fi
  php-fpm8.4 -t >/dev/null
  systemctl daemon-reload
  if (( shared_changed )); then
    systemctl reset-failed php8.4-fpm.service >/dev/null 2>&1 || true
    systemctl restart php8.4-fpm.service
  fi
  systemctl enable privora-panel-fpm.service >/dev/null
  if ! systemctl is-active --quiet privora-panel-fpm.service; then
    systemctl reset-failed privora-panel-fpm.service >/dev/null 2>&1 || true
    systemctl start privora-panel-fpm.service
  fi
  for _ in $(seq 1 40); do [[ -S /run/php/privora-panel.sock ]] && break; sleep .25; done
  [[ -S /run/php/privora-panel.sock ]]
}

install_recovery_page(){
  install -d -m0755 /usr/share/privora-panel/recovery
  cat >/usr/share/privora-panel/recovery/_privora_recovery.html <<'RECOVERYHTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Privora Recovery Mode</title><style>body{font-family:system-ui,sans-serif;background:#111827;color:#f9fafb;display:grid;place-items:center;min-height:100vh;margin:0}.c{max-width:680px;padding:32px;border:1px solid #374151;border-radius:16px;background:#1f2937}h1{margin-top:0}code{color:#93c5fd}</style></head><body><main class="c"><h1>Privora Recovery Mode</h1><p>The control-panel application is temporarily unavailable, but the web server is still running.</p><p>Use server recovery tools or SSH to inspect <code>/opt/privora-panel</code> and the latest update transaction.</p></main></body></html>
RECOVERYHTML
  chmod 0644 /usr/share/privora-panel/recovery/_privora_recovery.html
}

preflight
[[ "$MODE" == "--preflight" ]] && exit 0
apply_bind
apply_registrar_env
apply_dedicated_fpm
install_recovery_page
nginx -t
exit 0
