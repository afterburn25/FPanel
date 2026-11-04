#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JS="$ROOT/panel/public/assets/app.js"
grep -Fq "Promise.allSettled([api('updates'),api('update-center')])" "$JS"
! grep -Fq "Promise.all([api('updates'),api('update-center')])" "$JS"
grep -Fq "System package inventory unavailable:" "$JS"
grep -Fq "Core updater status unavailable:" "$JS"
grep -Fq "CORE STATUS UNAVAILABLE" "$JS"
echo "dev.6.59 Update Center partial-failure resilience PASS"
