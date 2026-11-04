#!/usr/bin/env bash
set -Eeuo pipefail

NGINX_CONF="${PRIVORA_PANEL_NGINX_CONF:-/etc/nginx/sites-available/privora-panel.conf}"
FPM_POOL="${PRIVORA_PANEL_FPM_POOL:-/etc/privora-panel/fpm/privora-panel.conf}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo 'This configurator must run as root.' >&2
  exit 1
fi

changed_nginx=0
changed_fpm=0

if [[ -f "$NGINX_CONF" ]] && ! grep -q 'fastcgi_read_timeout 600s;' "$NGINX_CONF"; then
  python3 - "$NGINX_CONF" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
# Apply to all Privora FastCGI routes. This file is the dedicated control-plane
# vhost, so extending the read/send timeout does not affect hosted websites.
s=s.replace('  fastcgi_pass unix:', '  fastcgi_read_timeout 600s;\n  fastcgi_send_timeout 600s;\n  fastcgi_pass unix:')
p.write_text(s)
PY
  changed_nginx=1
fi

if [[ -f "$FPM_POOL" ]] && ! grep -q '^php_admin_value\[max_execution_time\] = 600$' "$FPM_POOL"; then
  printf '\n; Privora curated component operations may legitimately run for several minutes.\nphp_admin_value[max_execution_time] = 600\n' >> "$FPM_POOL"
  changed_fpm=1
fi

if (( changed_fpm )); then
  if command -v php-fpm8.4 >/dev/null 2>&1; then
    php-fpm8.4 -t -y /etc/privora-panel/fpm/php-fpm.conf >/dev/null
  fi
  systemctl reload privora-panel-fpm.service
fi

if (( changed_nginx )); then
  nginx -t
  systemctl reload nginx
fi

echo "COMPONENT_RUNTIME_NGINX_TIMEOUT=$([[ -f "$NGINX_CONF" ]] && grep -q 'fastcgi_read_timeout 600s;' "$NGINX_CONF" && echo 600 || echo unchanged)"
echo "COMPONENT_RUNTIME_PHP_MAX_EXECUTION=$([[ -f "$FPM_POOL" ]] && grep -q '^php_admin_value\[max_execution_time\] = 600$' "$FPM_POOL" && echo 600 || echo unchanged)"
