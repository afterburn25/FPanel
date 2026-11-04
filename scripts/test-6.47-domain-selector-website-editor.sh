#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
admin="$ROOT/panel/public/admin.php"
customer="$ROOT/panel/public/customer.php"
app="$ROOT/panel/public/assets/app.js"
cpjs="$ROOT/panel/public/assets/customer.js"
server="$ROOT/agent/internal/api/server.go"
inv="$ROOT/agent/internal/hostadapter/inventory.go"

grep -Fq 'id="adminDNSDomain" data-domain-source="zone-available"' "$admin"
grep -Fq 'data-domain-source="existing-active"' "$admin"
grep -Fq 'data-domain-source="existing-root"' "$admin"
grep -Fq 'id="siteEditModal"' "$admin"
grep -Fq 'data-site-edit=' "$app"
grep -Fq "startsWith('live-host')" "$app"
grep -Fq 'function fillWebsiteDomainSelectors' "$app"
grep -Fq 'id="cpSiteEditModal"' "$customer"
grep -Fq 'data-domain-source="zone-available"' "$customer"
grep -Fq 'function fillDomainInputs' "$cpjs"
grep -Fq 'data-cp-site-edit=' "$cpjs"
grep -Fq 'InspectManagedSite' "$inv"
grep -Fq 'privora_vhosts_reconciled' "$server"
# New-domain creation must remain a textbox: it is the intentional exception.
grep -Fq 'name="domain" id="siteDomain"' "$admin"
grep -Fq 'name="domain" id="cpSiteDomain"' "$customer"
# Existing-domain DNS creation must no longer be a free-text domain input.
! grep -Fq 'data-create="dns-create"><h3>Create zone</h3><label>Domain<input name="domain"' "$admin"
! grep -Fq 'data-customer-create="customer-dns-create"><h3>Create zone</h3><label>Domain<input name="domain"' "$customer"
echo 'dev.6.48 standard domain selectors / website editor invariants PASS'
