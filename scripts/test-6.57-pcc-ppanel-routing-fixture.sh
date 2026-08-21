#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(tr -d '\r\n' < "$ROOT/VERSION")" == '5.0.0-dev.6.57' ]]

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/enabled" "$tmp/available" "$tmp/conf.d" "$tmp/snippets" "$tmp/backups"
cat > "$tmp/available/legacy-site.conf" <<'NGINX'
server {
    listen 80;
    server_name privoralabs.com www.privoralabs.com;
    root /home/legacy/public;
    location / { try_files $uri $uri/ /index.php?$query_string; }
}
server {
    listen 443 ssl;
    server_name privoralabs.com www.privoralabs.com;
    root /home/legacy/public;
    location / { try_files $uri $uri/ /index.php?$query_string; }
}
NGINX
ln -s "$tmp/available/legacy-site.conf" "$tmp/enabled/legacy-site.conf"

python3 "$ROOT/scripts/reconcile-panel-path-aliases.py" \
  --pcc-port 8443 --ppanel-port 2443 \
  --snippet "$tmp/snippets/privora-panel-path-aliases.conf" \
  --sites-enabled "$tmp/enabled" --conf-d "$tmp/conf.d" \
  --backup-root "$tmp/backups" --no-nginx-test

grep -Fq 'location = /pcc { return 302 https://$host:8443/; }' "$tmp/snippets/privora-panel-path-aliases.conf"
grep -Fq 'location = /ppanel { return 302 https://$host:2443/; }' "$tmp/snippets/privora-panel-path-aliases.conf"
[[ "$(grep -Fc 'Privora PCC/PPanel access' "$tmp/available/legacy-site.conf")" -eq 2 ]]

# A second reconciliation must not duplicate either server-block include.
python3 "$ROOT/scripts/reconcile-panel-path-aliases.py" \
  --pcc-port 8443 --ppanel-port 2443 \
  --snippet "$tmp/snippets/privora-panel-path-aliases.conf" \
  --sites-enabled "$tmp/enabled" --conf-d "$tmp/conf.d" \
  --backup-root "$tmp/backups" --no-nginx-test >/dev/null
[[ "$(grep -Fc 'Privora PCC/PPanel access' "$tmp/available/legacy-site.conf")" -eq 2 ]]

# Listener ports must stay distinct and valid.
if python3 "$ROOT/scripts/reconcile-panel-path-aliases.py" --pcc-port 8443 --ppanel-port 8443 --no-nginx-test >/dev/null 2>&1; then
  echo 'reconciler accepted identical PCC/PPanel ports' >&2
  exit 1
fi

echo 'PASS: PCC/PPanel 8443/2443 convenience routing fixture'
