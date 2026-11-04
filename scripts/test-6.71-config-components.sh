#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
need(){ grep -Fq -- "$2" "$ROOT/$1" || { echo "FAIL: $1 missing: $2" >&2; exit 1; }; }
need_re(){ grep -Eq -- "$2" "$ROOT/$1" || { echo "FAIL: $1 missing regex: $2" >&2; exit 1; }; }
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[1-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo 'FAIL: VERSION is not a supported 6.71+ cumulative core' >&2; exit 1; }

# Config Editor organization / common-first behavior.
need panel/public/admin.php 'COMMON EDITS'
need panel/public/admin.php 'data-config-category="Web Server"'
need panel/public/admin.php 'data-config-category="PHP"'
need panel/public/admin.php 'data-config-category="DNS"'
need panel/public/admin.php 'id="configFileSearch"'
need panel/public/admin.php 'id="configFilePath">No file selected</code>'
need panel/public/assets/app.js 'renderConfigFiles'
need agent/internal/hostadapter/configfiles.go 'Category    string `json:"category"`'
need agent/internal/hostadapter/configfiles.go 'Common      bool'
need agent/internal/hostadapter/configfiles.go 'Priority    int'

# Curated Extensions & Components page and search.
need panel/public/admin.php 'Extensions &amp; Components'
need panel/public/admin.php 'id="componentSearch"'
need panel/public/admin.php 'PDO SQLite'
need panel/public/assets/app.js 'componentMatches'
need panel/public/assets/app.js 'data-component-install'
need panel/public/api.php "route==='component-install'"
need panel/public/api.php "route==='component-remove'"
need agent/internal/api/server.go 'GET /v1/components'
need agent/internal/api/server.go 'POST /v1/components/{id}/install'
need agent/internal/api/server.go 'DELETE /v1/components/{id}'
need agent/internal/hostadapter/components.go 'component is not in the Privora allow-list'

# Requested catalog entries.
need agent/internal/hostadapter/components.go 'ID: "ffmpeg"'
need agent/internal/hostadapter/components.go 'phpComponent("php-pdo-sqlite", "PDO SQLite / SQLite3"'
need agent/internal/hostadapter/components.go '"php8.4-sqlite3"'
need agent/internal/hostadapter/components.go 'ID: "laravel-stack"'
need agent/internal/hostadapter/components.go 'Name: "Laravel Development Stack"'
need agent/internal/hostadapter/components.go '"global", "require", "laravel/installer"'
need agent/internal/hostadapter/components.go 'laravel/installer'

# No route accepts a caller supplied package token/command; mutations are by static component id.
! grep -Eq "component-(install|remove).*(package|command)" "$ROOT/panel/public/api.php" || { echo 'FAIL: component mutation route appears to accept a package/command field' >&2; exit 1; }

# Runtime FPM pool fragments must use INI-safe ';' comments, never shell-style '#'.
need scripts/configure-component-manager-runtime.sh '; Privora curated component operations may legitimately run for several minutes.'
need scripts/configure-component-manager-runtime.sh 'php_admin_value[max_execution_time] = 600'
! grep -Fq '# Privora curated component operations may legitimately run for several minutes.' "$ROOT/scripts/configure-component-manager-runtime.sh" || { echo 'FAIL: invalid # comment would be appended to PHP-FPM pool config' >&2; exit 1; }

echo 'PASS: Privora 6.71 Config Editor + curated Extensions & Components contract.'
