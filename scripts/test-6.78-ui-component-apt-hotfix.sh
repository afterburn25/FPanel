#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
v="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$v" =~ ^5\.0\.0-dev\.6\.(7[8-9]|8[0-9]|90)$ || "$v" == "5.0.0-dev.7.0" ]]
js="$ROOT/panel/public/assets/app.js"
admin="$ROOT/panel/public/admin.php"
css="$ROOT/panel/public/assets/app.css"
comp="$ROOT/agent/internal/hostadapter/components.go"
iso="$ROOT/agent/internal/hostadapter/isolated_exec.go"
svc="$ROOT/agent/privora-panel-agent.service"
grep -Fq 'function renderSites(rows)' "$js"
if [[ "$v" =~ ^5\.0\.0-dev\.6\.(8[0-9]|90)$ || "$v" == "5.0.0-dev.7.0" ]]; then
  grep -Fq "const componentTab=e.target.closest('#componentCategoryTabs [data-component-category]')" "$js"
else
  grep -Fq "\$('componentCategoryTabs')?.addEventListener('click'" "$js"
fi
! grep -Fq "const mt=e.target.closest('[data-component-category]')" "$js"
grep -Fq 'id="pageTitle" class="sr-only"' "$admin"
grep -Fq '.sr-only{' "$css"
! grep -Fq '<span class="eyebrow">${esc(g.name).toUpperCase()}</span><h3>${esc(g.name)}</h3>' "$js"
grep -Fq 'return runAPTTransaction(ctx, args, extraEnv...)' "$comp"
grep -Fq 'runIsolatedRootCommand(ctx, "privora-apt"' "$comp"
grep -Fq 'exec.LookPath("systemd-run")' "$iso"
grep -Fq '"--property=NoNewPrivileges=no"' "$iso"
grep -Fq 'NoNewPrivileges=true' "$svc"
node --check "$js" >/dev/null
php -l "$admin" >/dev/null
printf 'PASS: 6.78 UI/component/APT hotfix contract\n'
