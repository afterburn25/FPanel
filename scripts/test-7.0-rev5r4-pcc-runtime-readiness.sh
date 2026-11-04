#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-/opt/privora-panel}"
INDEX="$ROOT/panel/public/index.php"
UPDATER="$ROOT/scripts/privora-update.sh"
[[ -f "$INDEX" && -f "$UPDATER" ]] || { echo "FAIL: required source files missing" >&2; exit 1; }
grep -Fq "header('X-Privora-Build: '.\$privoraBuild);" "$INDEX"
grep -Fq 'systemctl is-active --quiet "$panel_fpm"' "$UPDATER"
grep -Fq '[[ -S /run/php/privora-panel.sock ]]' "$UPDATER"
grep -Fq 'Health: probing panel HTTPS endpoint' "$UPDATER"
echo "PASS: 7.0 Rev5 Rev4 PCC runtime-readiness source invariants"
