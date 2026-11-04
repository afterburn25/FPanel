#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
die(){ echo "FAIL: $*" >&2; exit 1; }
need(){ grep -Fq "$2" "$ROOT/$1" || die "$1 missing contract: $2"; }
for f in VERSION panel/public/admin.php panel/public/customer.php panel/public/api.php panel/public/assets/app.js panel/public/assets/customer.js agent/internal/api/server.go agent/internal/hostadapter/provision.go agent/internal/hosting/hosting.go; do [[ -f "$ROOT/$f" ]] || die "missing $f"; done
[[ "$(tr -d '\r\n' < "$ROOT/VERSION")" =~ ^5\.0\.0-dev\.6\.(8[6-9]|90)$ || "$(tr -d '\r\n' < "$ROOT/VERSION")" == "5.0.0-dev.7.0" ]] || die "VERSION is not a supported 6.86+ cumulative core"
need panel/public/admin.php 'id="subdomainDocumentRoot"'
need panel/public/admin.php 'id="subdomainUseDefaultRoot"'
need panel/public/admin.php 'id="subdomainUseParentRoot"'
need panel/public/customer.php 'id="cpSubdomainDocumentRoot"'
need panel/public/customer.php 'id="cpSubdomainUseParentRoot"'
need panel/public/assets/app.js 'parentRoot:String(site?.document_root||' 
need panel/public/assets/app.js 'Shared with the parent website. Deleting this subdomain removes only its vhost/DNS; the parent domain files are preserved.'
need panel/public/assets/app.js 'siteHasDedicatedDeletableRoot'
need panel/public/assets/customer.js 'customerSubdomainRootValues'
need panel/public/assets/customer.js "input.dataset.mode='parent'"
need panel/public/api.php "'document_root'=>trim"
need panel/public/api.php '$safeSubdomainFiles=$insideOwnTree&&!$sharedRoot;'
if grep -Fq '$deleteFiles=$isSubdomain ? true' "$ROOT/panel/public/api.php"; then die 'legacy blanket subdomain file deletion remains'; fi
need agent/internal/api/server.go 'DocumentRoot string `json:"document_root"`'
need agent/internal/api/server.go 'ProvisionSiteWithDocumentRoot'
need agent/internal/api/server.go 'managedSubdomainDeleteFilesAllowed'
need agent/internal/api/server.go 'DeleteSiteWithDocumentRoot'
need agent/internal/api/server.go 'files_preserved_reason'
need agent/internal/hostadapter/provision.go 'resolveSiteDocumentRoot'
need agent/internal/hostadapter/provision.go 'document root resolves outside the hosting account domains directory'
need agent/internal/hostadapter/provision.go 'deleteFiles = false'
need agent/internal/hosting/hosting.go 'requestedRoot := strings.TrimSpace(s.DocumentRoot)'
need agent/internal/hosting/hosting.go 'rootExisted := statErr == nil'
echo 'PASS: 6.86 editable subdomain document root and shared-root delete safety contract'
