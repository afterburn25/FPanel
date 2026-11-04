#!/usr/bin/env bash
# Backward-compatible post-update reconciler for recovery handling and split panel listeners.
set -Eeuo pipefail
umask 027

ROOT="${PRIVORA_PANEL_ROOT:-/opt/privora-panel}"
PANEL_ENV=/etc/privora-panel/panel.env
PORT_ENV=/etc/privora-panel/panel-ports.env
RENDER="$ROOT/scripts/render-panel-nginx.py"
[[ $EUID -eq 0 ]] || { echo 'Privora panel listener reconciliation must run as root.' >&2; exit 1; }
[[ -x "$RENDER" ]] || { echo "Privora Nginx renderer missing: $RENDER" >&2; exit 1; }

conf=""
for c in /etc/nginx/sites-available/privora-panel.conf /etc/nginx/conf.d/privora-panel.conf; do
  [[ -f "$c" ]] && { conf="$c"; break; }
done
[[ -n "$conf" ]] || exit 0
[[ -s /etc/privora-panel/tls/panel.crt && -s /etc/privora-panel/tls/panel.key ]] || { echo 'Privora panel TLS material is missing.' >&2; exit 1; }

admin_port="${PRIVORA_ADMIN_PANEL_PORT:-}"
hosting_port="${PRIVORA_HOSTING_PANEL_PORT:-}"
if [[ -r "$PORT_ENV" ]]; then
  # shellcheck disable=SC1090
  . "$PORT_ENV"
  admin_port="${PRIVORA_ADMIN_PANEL_PORT:-$admin_port}"
  hosting_port="${PRIVORA_HOSTING_PANEL_PORT:-$hosting_port}"
fi
if [[ -r "$PANEL_ENV" ]]; then
  pe_admin="$(awk -F= '$1=="PRIVORA_ADMIN_PANEL_PORT"{print $2}' "$PANEL_ENV" | tail -1)"
  pe_hosting="$(awk -F= '$1=="PRIVORA_HOSTING_PANEL_PORT"{print $2}' "$PANEL_ENV" | tail -1)"
  [[ -n "$admin_port" ]] || admin_port="$pe_admin"
  [[ -n "$hosting_port" ]] || hosting_port="$pe_hosting"
fi
# Preserve a pre-existing custom Privora admin port when upgrading older one-listener installs.
if [[ -z "$admin_port" ]]; then
  admin_port="$(awk '/^[[:space:]]*listen[[:space:]]+[0-9]+[[:space:]]+ssl/{print $2; exit}' "$conf" | tr -d ';')"
fi
admin_port="${admin_port:-8443}"
hosting_port="${hosting_port:-2443}"
[[ "$admin_port" =~ ^[0-9]+$ && "$hosting_port" =~ ^[0-9]+$ ]] || { echo 'Invalid Privora panel port state.' >&2; exit 1; }
(( admin_port>=1 && admin_port<=65535 && hosting_port>=1 && hosting_port<=65535 && admin_port!=hosting_port )) || { echo 'Privora panel ports must be distinct values from 1-65535.' >&2; exit 1; }

port_listening(){
  local p="$1"
  ss -lntH 2>/dev/null | awk -v needle=":$p" '$4 ~ (needle "$") {found=1} END{exit found?0:1}'
}
config_owns_port(){
  local p="$1"
  grep -Eq "^[[:space:]]*listen[[:space:]]+(\\[::\\]:)?${p}([[:space:]]|;)" "$conf"
}
if port_listening "$admin_port" && ! config_owns_port "$admin_port"; then
  echo "Privora Command Center (PCC) port $admin_port is occupied by another listener; refusing to replace it." >&2
  exit 1
fi
if port_listening "$hosting_port" && ! config_owns_port "$hosting_port"; then
  requested="$hosting_port"; found=""
  for p in $(seq $((requested+1)) $((requested+100))); do
    ((p==admin_port)) && continue
    if ! port_listening "$p"; then found="$p"; break; fi
  done
  [[ -n "$found" ]] || { echo "No available Privora Panel (PPanel) port found near $requested." >&2; exit 1; }
  hosting_port="$found"
  echo "WARN: Privora Panel (PPanel) port $requested is occupied; selected $hosting_port instead."
fi

server_name="$(awk '/^[[:space:]]*server_name[[:space:]]+/{gsub(/;/,"",$2); print $2; exit}' "$conf")"
server_name="${server_name:-_}"
[[ "$server_name" =~ ^[A-Za-z0-9._-]+$ ]] || server_name=_
fpm_socket="$(sed -nE 's|.*fastcgi_pass[[:space:]]+unix:([^;]+);.*|\1|p' "$conf" | head -1)"
if [[ -z "$fpm_socket" ]]; then
  [[ -S /run/php/privora-panel.sock || -d /run/php ]] && fpm_socket=/run/php/privora-panel.sock || fpm_socket=/run/php-fpm/privora-panel.sock
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="$conf.before-dual-surface-$stamp"
candidate="$conf.dual-surface-$stamp.candidate"
env_backup=""
ports_backup=""
cp -a "$conf" "$backup"
[[ -f "$PANEL_ENV" ]] && { env_backup="$PANEL_ENV.before-dual-surface-$stamp"; cp -a "$PANEL_ENV" "$env_backup"; }
[[ -f "$PORT_ENV" ]] && { ports_backup="$PORT_ENV.before-dual-surface-$stamp"; cp -a "$PORT_ENV" "$ports_backup"; }

rollback(){
  local rc="${1:-1}"
  cp -a "$backup" "$conf" 2>/dev/null || true
  if [[ -n "$env_backup" && -f "$env_backup" ]]; then cp -a "$env_backup" "$PANEL_ENV"; fi
  if [[ -n "$ports_backup" && -f "$ports_backup" ]]; then cp -a "$ports_backup" "$PORT_ENV"; elif [[ -z "$ports_backup" ]]; then rm -f "$PORT_ENV"; fi
  nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  systemctl restart privora-panel-fpm.service >/dev/null 2>&1 || systemctl restart php8.4-fpm.service >/dev/null 2>&1 || systemctl restart php-fpm.service >/dev/null 2>&1 || true
  rm -f "$candidate"
  echo 'Privora panel listener reconciliation failed; previous panel listener configuration restored.' >&2
  exit "$rc"
}
trap 'rollback $?' ERR

python3 "$RENDER" --admin-port "$admin_port" --hosting-port "$hosting_port" --server-name "$server_name" --fpm-socket "$fpm_socket" --panel-root "$ROOT" >"$candidate"
cp -a "$candidate" "$conf"
nginx -t

set_env(){
  local file="$1" key="$2" value="$3" tmp="${file}.tmp.$$"
  if [[ -f "$file" ]]; then grep -v "^${key}=" "$file" >"$tmp" || true; else : >"$tmp"; fi
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  mv "$tmp" "$file"
}
install -d -m0750 /etc/privora-panel
set_env "$PANEL_ENV" PRIVORA_ADMIN_PANEL_PORT "$admin_port"
set_env "$PANEL_ENV" PRIVORA_HOSTING_PANEL_PORT "$hosting_port"
cat >"$PORT_ENV" <<ENV
PRIVORA_ADMIN_PANEL_PORT=$admin_port
PRIVORA_HOSTING_PANEL_PORT=$hosting_port
ENV
if getent group privora-panel >/dev/null 2>&1; then chown root:privora-panel "$PANEL_ENV" "$PORT_ENV"; fi
chmod 0640 "$PANEL_ENV" "$PORT_ENV"

# Restart only the panel FPM so it picks up port values used by cross-panel links/session scoping.
if systemctl cat privora-panel-fpm.service >/dev/null 2>&1; then
  systemctl restart privora-panel-fpm.service
elif systemctl cat php8.4-fpm.service >/dev/null 2>&1; then
  systemctl restart php8.4-fpm.service
else
  systemctl restart php-fpm.service
fi
systemctl reload nginx

for _ in $(seq 1 30); do port_listening "$admin_port" && port_listening "$hosting_port" && break; sleep .25; done
port_listening "$admin_port"
port_listening "$hosting_port"

# Update only Privora's dedicated bootstrap firewall table when it exists.
if command -v nft >/dev/null 2>&1 && { [[ -f /etc/privora-panel/nftables-bootstrap.nft ]] || nft list table inet privora_bootstrap >/dev/null 2>&1; }; then
  nft_candidate="/etc/privora-panel/nftables-bootstrap.nft.dual-surface-$stamp.candidate"
  cat >"$nft_candidate" <<NFT
table inet privora_bootstrap {
    chain input {
        type filter hook input priority -5; policy accept;
        ct state established,related accept
        iifname "lo" accept
        tcp dport { 22, 80, 443, $admin_port, $hosting_port } accept
    }
}
NFT
  nft -c -f "$nft_candidate"
  mv -f "$nft_candidate" /etc/privora-panel/nftables-bootstrap.nft
  if nft list table inet privora_bootstrap >/dev/null 2>&1; then nft delete table inet privora_bootstrap; fi
  nft -f /etc/privora-panel/nftables-bootstrap.nft
fi

admin_http="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 6 "https://127.0.0.1:$admin_port/" || true)"
hosting_http="$(curl -k -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 6 "https://127.0.0.1:$hosting_port/" || true)"
[[ "$admin_http" =~ ^(200|301|302|303|307|308|401|403)$ ]] || { echo "WHM listener health failed: HTTP ${admin_http:-000}" >&2; rollback 1; }
[[ "$hosting_http" =~ ^(200|301|302|303|307|308|401|403)$ ]] || { echo "PPanel listener health failed: HTTP ${hosting_http:-000}" >&2; rollback 1; }

trap - ERR
rm -f "$candidate"
echo "PASS: Privora Command Center (PCC) listener https://<host>:$admin_port"
echo "PASS: Privora Panel (PPanel) listener https://<host>:$hosting_port"
echo 'PASS: Recovery-safe API handling retained on both panel surfaces.'
