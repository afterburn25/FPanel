#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail(){ echo "FAIL: $*" >&2; exit 1; }
pass(){ echo "PASS: Privora 6.72 PPanel workspace + full File Manager + account analytics contract."; }

ver="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[2-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || fail "VERSION is not a supported 6.72+ cumulative core"

CUSTOMER="$ROOT/panel/public/customer.php"
JS="$ROOT/panel/public/assets/customer.js"
CSS="$ROOT/panel/public/assets/app.css"
ICONS="$ROOT/panel/public/assets/ppanel-icons.svg"
API="$ROOT/panel/public/api.php"
CLIENT="$ROOT/panel/src/AgentClient.php"
SERVER="$ROOT/agent/internal/api/server.go"
FM="$ROOT/agent/internal/hostadapter/filemanager.go"
AN="$ROOT/agent/internal/hostadapter/account_analytics.go"

# Home structure: left rail, no temporary status strip, distinct Metrics/Security groups.
grep -F 'class="cp-rail cp-rail-left"' "$CUSTOMER" >/dev/null || fail "left PPanel information rail missing"
! grep -F 'pp-home-runtime-strip' "$CUSTOMER" >/dev/null || fail "temporary top runtime strip still present in PPanel HTML"
! grep -F 'class="cp-welcome"' "$CUSTOMER" >/dev/null || fail "top welcome/status banner still present on PPanel home"
for marker in 'GENERAL INFORMATION' 'SERVER INFORMATION' 'RESOURCE USAGE' 'data-group="metrics"' 'data-group="security"'; do
  grep -F "$marker" "$CUSTOMER" >/dev/null || fail "PPanel home marker missing: $marker"
done
for label in 'Resource Usage' 'Visitors' 'Analytics' 'Bandwidth' 'Raw Access' 'Errors'; do
  grep -F ">$label<" "$CUSTOMER" >/dev/null || fail "Metrics tool missing: $label"
done
for tone in tone-blue tone-cyan tone-green tone-purple tone-red tone-orange tone-yellow tone-pink tone-indigo tone-slate; do
  grep -F "$tone" "$CUSTOMER" >/dev/null || fail "colorful tool icon tone missing: $tone"
done
ICON_SPRITE="$ROOT/panel/public/assets/ppanel-icons.svg"
[[ -f "$ICON_SPRITE" ]] || fail "PPanel SVG icon sprite missing"
grep -F '/assets/ppanel-icons.svg?v=6.73#folder' "$CUSTOMER" >/dev/null || fail "recognizable SVG dashboard icons not wired"
for emoji in '📁' '🌐' '📧' '📊' '🛡️' '🐘' '⚙️'; do ! grep -F "$emoji" "$CUSTOMER" >/dev/null || fail "emoji dashboard icon still present: $emoji"; done

# Every home tool uses the bundled PPanel SVG sprite so icons are consistent across browsers.
[[ -s "$ICONS" ]] || fail "PPanel SVG icon sprite missing"
grep -F 'ppanel-icons.svg?v=6.73#' "$CUSTOMER" >/dev/null || fail "PPanel is not using bundled SVG icons"
while IFS= read -r symbol; do
  grep -F "symbol id=\"$symbol\"" "$ICONS" >/dev/null || fail "referenced icon symbol is undefined: $symbol"
done < <(grep -o 'ppanel-icons.svg?v=6.73#[A-Za-z0-9_-]*' "$CUSTOMER" | sed 's/.*#//' | sort -u)

# File Manager UI and server-authoritative operations.
for id in fmNewFile fmNewFolder fmUpload fmSearchToggle fmDeleteSelected fmRefresh fmBreadcrumbs fmFilesTable fmEditorModal; do
  grep -F "id=\"$id\"" "$CUSTOMER" >/dev/null || fail "File Manager UI control missing: $id"
done
for route in '/read' '/mkdir' '/upload' '/rename' '/copy' '/path' '/chmod' '/search' '/archive' '/extract'; do
  grep -F "/v1/files/{user}$route" "$SERVER" >/dev/null || fail "agent File Manager route missing: $route"
done
for method in ReadAccountFile WriteAccountBytes CreateAccountDirectory RenameAccountPath CopyAccountPath DeleteAccountPath ChmodAccountPath SearchAccountFiles CreateAccountZip ExtractAccountZip; do
  grep -F "func (a *Adapter) $method" "$FM" >/dev/null || fail "hostadapter file operation missing: $method"
done
for token in 'O_NOFOLLOW' 'requireCertified("linux-users")' 'archive entry exceeds 64 MiB control-panel limit' 'cannot copy a directory into itself' 'archive destination cannot be inside the source directory' 'archive exceeds 5000 entry control-panel limit' 'archive exceeds 512 MiB extracted-size control-panel limit'; do
  grep -F "$token" "$FM" >/dev/null || fail "File Manager safety marker missing: $token"
done
for action in customer-file-read customer-file-search customer-file-mkdir customer-file-upload customer-file-rename customer-file-copy customer-file-delete customer-file-chmod customer-file-archive customer-file-extract; do
  grep -F "$action" "$API" >/dev/null || fail "PPanel file API route missing: $action"
done
grep -F 'function fmTextEditable' "$JS" >/dev/null || fail "binary-safe editor gate missing"
grep -F 'function fmDeleteSelected' "$JS" >/dev/null || fail "multi-select delete missing"
grep -F 'data-fm-select-all' "$JS" >/dev/null || fail "select-all behavior missing"

# Account/server analytics and long-read transport.
grep -F 'GET /v1/hosting/accounts/{user}/usage' "$SERVER" >/dev/null || fail "account analytics route missing"
grep -F 'func (a *Adapter) AccountAnalytics' "$AN" >/dev/null || fail "account analytics adapter missing"
for field in 'UniqueVisitors' 'BandwidthBytes' 'HTTP4xx' 'HTTP5xx' 'TopPaths' 'TopReferrers' 'RecentVisitors' 'RecentErrors'; do
  grep -F "$field" "$AN" >/dev/null || fail "analytics field missing: $field"
done
grep -F 'tailTextFile(access, 16<<20)' "$AN" >/dev/null || fail "bounded access-log tail limit missing"
grep -F 'domain+".error.log"), 2<<20)' "$AN" >/dev/null || fail "bounded error-log tail limit missing"
grep -F 'public function getLong' "$CLIENT" >/dev/null || fail "long AgentClient GET transport missing"
grep -F "getLong('/v1/hosting/accounts/'" "$API" >/dev/null || fail "PPanel analytics does not use long GET transport"
for view in 'data-cp-view="metrics"' 'data-cp-view="visitors"' 'data-cp-view="analytics"' 'data-cp-view="bandwidth"' 'data-cp-view="access-logs"' 'data-cp-view="errors"'; do
  grep -F "$view" "$CUSTOMER" >/dev/null || fail "analytics view missing: $view"
done

# Security is independent from the optional metrics feature flag.
! grep -F "security:'metrics'" "$JS" >/dev/null || fail "Security Center incorrectly hidden behind metrics feature flag"

php -l "$CUSTOMER" >/dev/null
php -l "$API" >/dev/null
php -l "$CLIENT" >/dev/null
node --check "$JS" >/dev/null

pass
