#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
ROOT="${PRIVORA_PANEL_ROOT:-/opt/privora-panel}"
PORT_ENV=/etc/privora-panel/panel-ports.env
admin_port="${PRIVORA_ADMIN_PANEL_PORT:-8443}"
hosting_port="${PRIVORA_HOSTING_PANEL_PORT:-2443}"
if [[ -r "$PORT_ENV" ]]; then
  # shellcheck disable=SC1090
  . "$PORT_ENV"
  admin_port="${PRIVORA_ADMIN_PANEL_PORT:-$admin_port}"
  hosting_port="${PRIVORA_HOSTING_PANEL_PORT:-$hosting_port}"
fi
[[ "$admin_port" =~ ^[0-9]+$ && "$hosting_port" =~ ^[0-9]+$ ]] || { echo 'Invalid panel ports.' >&2; exit 1; }
((admin_port>=1 && admin_port<=65535 && hosting_port>=1 && hosting_port<=65535 && admin_port!=hosting_port)) || { echo 'Invalid panel port range.' >&2; exit 1; }
mapfile -t files < <(
  {
    find /etc/nginx/sites-available /etc/nginx/conf.d -maxdepth 1 -type f 2>/dev/null || true
    if [[ -d /etc/nginx/sites-enabled ]]; then
      for entry in /etc/nginx/sites-enabled/*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        target="$(readlink -f -- "$entry" 2>/dev/null || true)"
        [[ -n "$target" && -f "$target" ]] && printf '%s\n' "$target"
      done
    fi
  } | sort -u
)
((${#files[@]})) || exit 0
backup="$(mktemp -d /var/tmp/privora-panel-shortcuts.XXXXXX)"
cleanup(){ rm -rf "$backup"; }
trap cleanup EXIT
for f in "${files[@]}"; do
  safe="$(printf '%s' "$f" | sed 's#/#__#g')"
  cp -a "$f" "$backup/$safe"
done
set +e
output="$(python3 "$ROOT/scripts/reconcile-site-panel-shortcuts.py" --admin-port "$admin_port" --hosting-port "$hosting_port" "${files[@]}" 2>&1)"
rc=$?
set -e
printf '%s\n' "$output"
if ((rc!=0)) || ! nginx -t; then
  for f in "${files[@]}"; do
    safe="$(printf '%s' "$f" | sed 's#/#__#g')"
    [[ -f "$backup/$safe" ]] && cp -a "$backup/$safe" "$f"
  done
  nginx -t >/dev/null 2>&1 || true
  echo 'Privora site shortcut reconciliation failed; restored all Nginx files.' >&2
  exit 1
fi
systemctl reload nginx
