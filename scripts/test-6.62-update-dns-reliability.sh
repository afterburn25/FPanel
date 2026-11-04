#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="$ROOT/panel/public/api.php"
UPD="$ROOT/scripts/privora-update.sh"
AGENT="$ROOT/agent/internal/api/server.go"
DNS="$ROOT/agent/internal/hostadapter/nameserver_status.go"
INV="$ROOT/agent/internal/hostadapter/inventory.go"

# Update Center status must fail soft locally and always emit HTTP 200 after auth.
grep -Fq 'function degradedUpdateCenter(string $reason, bool $mfaRequired=false)' "$API"
grep -Fq "if((\$r['_status']??500)>=300){out(degradedUpdateCenter" "$API"
grep -Fq 'out(degradedUpdateCenter($e->getMessage(),$mfaRequired),200)' "$API"
grep -Fq "if(is_array(\$local))out(['transaction'=>\$local,'degraded'=>true,'source'=>'local-journal'],200)" "$API"
! grep -Fq 'degradedUpdateCenter(string $reason, Auth $auth)' "$API"

# Migrations are bounded and routine updates gracefully reload PCC PHP-FPM so
# promoted PHP/opcache workers are refreshed without destroying file sessions.
grep -Fq 'run_timed 90s "$stage/scripts/migrate.sh" --preflight' "$UPD"
grep -Fq 'run_timed 180s "$stage/scripts/migrate.sh" --apply' "$UPD"
grep -Fq 'gracefully reloading PCC PHP-FPM code workers' "$UPD"
grep -Fq 'run_timed 45s systemctl reload "$panel_fpm"' "$UPD"
if grep -Fq 'systemctl restart "$panel_fpm"' "$UPD"; then
  echo 'routine updater still restarts active PCC PHP-FPM' >&2; exit 1
fi

# Known domains remain visible in DNS manager even if authoritative discovery fails.
grep -Fq '"status": "not-configured"' "$AGENT"
grep -Fq '"source": "known-hosted-domain"' "$AGENT"
grep -Fq 'dns_known_without_local_zone' "$AGENT"

# Local authoritative discovery must not assume 127.0.0.1 only.
grep -Fq 'rndcZoneStatus' "$DNS"
grep -Fq 'localDNSProbeServers()' "$DNS"
grep -Fq '"local-authoritative-server:" + server' "$DNS"

# Legacy website fallback uses the recorded document root against active nginx -T blocks.
grep -Fq 'InspectKnownSite(domain, expectedRoot string)' "$INV"
grep -Fq 'domain-vhost-root-reconciled' "$INV"

php -l "$API" >/dev/null
bash -n "$UPD"
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter ./internal/api -count=1
)
echo 'PASS: 6.62 updater reliability and live-domain reconciliation gate'

# 6.62: DNS Zone Manager is independent from unrelated host probes and PCC never
# masks DNS backend errors as an empty zone list.
grep -Fq 'DiscoverDNSInventory(ctx context.Context)' "$INV"
grep -Fq 'dns_inventory_scope' "$INV"
grep -Fq 's.host.DiscoverDNSInventory(r.Context())' "$AGENT"
grep -Fq "'resource_errors'=>[]" "$API"
grep -Fq "'pcc-hosted-domain-fallback'" "$API"
grep -Fq 'DNS inventory error:' "$API"
grep -Fq "renderDNSZones(d.zones||[],d.resource_errors?.zones||'')" "$ROOT/panel/public/assets/app.js"

# Website creation must classify child hostnames against an existing parent
# zone/site instead of silently creating a separately delegated child zone.
grep -Fq 'bestHostedParentDomain(ctx context.Context, domain string)' "$AGENT"
grep -Fq 'autoProvisionHostedDNS(ctx context.Context, domain string)' "$AGENT"
grep -Fq 'POST /v1/dns/repair-hosted' "$AGENT"
grep -Fq 'dns.hosted.repair' "$AGENT"
grep -Fq 'Repair hosted DNS' "$ROOT/panel/public/admin.php"
grep -Fq "api('dns-repair-hosted'" "$ROOT/panel/public/assets/app.js"
grep -Fq 'privora-dns-reconcile-postupdate.php' "$UPD"
grep -Fq 'record dns_reconcile scheduled-after-pass' "$UPD"
php -l "$ROOT/scripts/privora-dns-reconcile-postupdate.php" >/dev/null

# PPanel access uses the primary domain instead of exposing a Linux username.
grep -Fq 'setHostingAccess(string $account,string $primaryDomain,string $password,string $panelUsername=' "$ROOT/panel/src/Store.php"
grep -Fq 'PPanel access ready · login ${r.login}' "$ROOT/panel/public/assets/app.js"
grep -Fq "route==='ppanel-access-set'" "$API"
grep -Fq "PPanel username or primary domain" "$ROOT/panel/public/index.php"

php -d variables_order=EGPCS -r '
require $argv[1];
$f=tempnam(sys_get_temp_dir(),"ppanel-"); @unlink($f); $s=new Store($f);
$u=$s->setHostingAccess("acmeweb","example.com","Correct-Horse-Battery-123");
if(($u["username"]??"")!=="example.com") exit(2);
$hit=$s->findUser("EXAMPLE.COM"); if(!$hit||($hit["account"]??"")!=="acmeweb") exit(3);
@unlink($f);
' "$ROOT/panel/src/Store.php"
