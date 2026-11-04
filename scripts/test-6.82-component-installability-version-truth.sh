#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[2-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo "FAIL: expected supported 6.82+ cumulative lineage through 7.0, got $ver" >&2; exit 1; }
ISO="$ROOT/agent/internal/hostadapter/isolated_exec.go"; COMP="$ROOT/agent/internal/hostadapter/components.go"; WEBMAIL="$ROOT/agent/internal/hostadapter/webmail.go"; API_VER="$ROOT/agent/internal/api/version.go"; SERVER="$ROOT/agent/internal/api/server.go"; PLATFORM="$ROOT/agent/internal/api/server_platform.go"; ADMIN="$ROOT/panel/public/admin.php"; INDEX="$ROOT/panel/public/index.php"; CUSTOMER="$ROOT/panel/public/customer.php"; APP="$ROOT/panel/public/assets/app.js"; CTRL="$ROOT/panel/public/assets/components.js"; CUSTJS="$ROOT/panel/public/assets/customer.js"
grep -Fq "const currentVersion = \"$ver\"" "$API_VER"
grep -Fq '"version": currentVersion' "$SERVER"
grep -Fq '"version": currentVersion' "$PLATFORM"
! grep -Fq '<b>6.80 DEV</b>' "$ADMIN"
grep -Fq '$privoraBuildLabel' "$ADMIN"
grep -Fq "file_get_contents(dirname(__DIR__,2).'/VERSION')" "$INDEX"
grep -Fq 'app.js?v=<?=$privoraAssetVersion?>' "$ADMIN"
grep -Fq 'components.js?v=<?=$privoraAssetVersion?>' "$ADMIN"
grep -Fq 'customer.js?v=<?=$privoraAssetVersion?>' "$CUSTOMER"
grep -Fq "document.body?.dataset?.privoraBuild||'unknown'" "$APP"
grep -Fq "document.body?.dataset?.privoraBuild||'unknown'" "$CTRL"
grep -Fq "document.body?.dataset?.privoraBuild||'unknown'" "$CUSTJS"
grep -Fq '"--property=NoNewPrivileges=no"' "$ISO"
grep -Fq '"--property=MemoryDenyWriteExecute=no"' "$ISO"
grep -Fq 'runIsolatedRootCommand(ctx, "privora-apt"' "$COMP"
grep -Fq '"pcre.jit=0"' "$COMP"
grep -Fq 'runIsolatedRootCommand(ctx, "privora-composer"' "$COMP"
grep -Fq 'runIsolatedRootCommand(ctx, "privora-webmail"' "$WEBMAIL"
grep -Fq 'case "", "laravel-installer", "roundcube-webmail":' "$COMP"
grep -Fq 'data-component-install="${esc(e.id)}"' "$APP"
grep -Fq 'data-component-remove="${esc(e.id)}"' "$APP"
grep -Fq "document.addEventListener('click',event=>{const installButton" "$CTRL"
php -l "$INDEX" >/dev/null; php -l "$ADMIN" >/dev/null; php -l "$CUSTOMER" >/dev/null
node --check "$APP" >/dev/null; node --check "$CTRL" >/dev/null; node --check "$CUSTJS" >/dev/null
(cd "$ROOT/agent" && go test ./internal/hostadapter -run 'Test(AllCuratedComponentsHaveCertifiedInstallStrategy|LaravelComposerProvisionUsesIsolatedCLIAndDisablesPCREJIT|APTTransactionEscapesAgentCredentialSandboxThroughTransientUnit)' >/dev/null)
printf 'PASS: 6.82 version truth + isolated package/component/Laravel/webmail installability contract\n'
