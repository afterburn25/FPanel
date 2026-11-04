#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$ver" =~ ^5\.0\.0-dev\.6\.(8[3-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo "FAIL: expected supported 6.83-6.86 lineage, got $ver" >&2; exit 1; }
SERVER="$ROOT/agent/internal/api/server.go"
JOBS="$ROOT/agent/internal/api/software_jobs.go"
COMP="$ROOT/agent/internal/hostadapter/components.go"
SOFT="$ROOT/agent/internal/hostadapter/software_center.go"
API="$ROOT/panel/public/api.php"
JS="$ROOT/panel/public/assets/components.js"
APP="$ROOT/panel/public/assets/app.js"
CSS="$ROOT/panel/public/assets/app.css"
for f in "$SERVER" "$JOBS" "$COMP" "$SOFT" "$API" "$JS" "$APP" "$CSS"; do [[ -f "$f" ]] || { echo "FAIL: missing $f" >&2; exit 1; }; done

grep -Fq 'POST /v1/software/jobs' "$SERVER"
grep -Fq 'GET /v1/software/jobs/{id}' "$SERVER"
grep -Fq 'context.WithTimeout(context.Background(), 20*time.Minute)' "$JOBS"
grep -Fq 'InstallServerComponentWithProgress' "$JOBS"
grep -Fq 'ApplyComponentPresetWithProgress' "$JOBS"
grep -Fq 'runMu sync.Mutex' "$JOBS"
grep -Fq '"queued"' "$JOBS"
grep -Fq '"running"' "$JOBS"
grep -Fq '"complete"' "$JOBS"
grep -Fq '"failed"' "$JOBS"
grep -Fq 'reportComponentProgress(progress, 76, "composer"' "$COMP"
grep -Fq 'InstallServerComponentWithProgress(ctx, id' "$SOFT"
grep -Fq "if(\$route==='software-job-start')" "$API"
grep -Fq "if(\$route==='software-job-status')" "$API"
grep -Fq "request('software-job-start'" "$JS"
grep -Fq "request('software-job-status&id='" "$JS"
grep -Fq '<progress class="component-progress-track"' "$JS"
grep -Fq "startPanelSoftwareJob('preset','apply'" "$APP"
grep -Fq '<progress class="component-progress-track"' "$APP"
grep -Fq '.component-job-progress' "$CSS"
grep -Fq '.component-progress-track::-webkit-progress-value' "$CSS"
if grep -Eq 'style="width:\$\{value\}%' "$JS" "$APP"; then echo 'FAIL: inline progress styles would violate CSP' >&2; exit 1; fi
printf 'PASS: 6.83 asynchronous software jobs + card progress contract\n'

# 6.83 Rev3 UI helper-completeness and subdomain regression guard.
APP="$ROOT/panel/public/assets/app.js"
grep -Fq 'function populateSiteAccounts(rows)' "$APP" || { echo 'FAIL: populateSiteAccounts helper missing' >&2; exit 1; }
grep -Fq 'function populateSubdomainParents(rows)' "$APP" || { echo 'FAIL: populateSubdomainParents helper missing' >&2; exit 1; }
grep -Fq 'function updateSubdomainPreview()' "$APP" || { echo 'FAIL: updateSubdomainPreview helper missing' >&2; exit 1; }
grep -Fq 'function closeModal(target)' "$APP" || { echo 'FAIL: closeModal helper missing' >&2; exit 1; }
grep -Fq 'populateSiteAccounts(d.accounts||[])' "$APP" || { echo 'FAIL: site account population call missing' >&2; exit 1; }
grep -Fq 'populateSubdomainParents(d.sites||[])' "$APP" || { echo 'FAIL: subdomain parent population call missing' >&2; exit 1; }
grep -Fq "\$('subdomainParent')?.addEventListener('change',updateSubdomainPreview)" "$APP" || { echo 'FAIL: subdomain parent preview binding missing' >&2; exit 1; }
grep -Fq "\$('subdomainLabel')?.addEventListener('input',updateSubdomainPreview)" "$APP" || { echo 'FAIL: subdomain label preview binding missing' >&2; exit 1; }
python3 - "$APP" <<'PY_AUDIT'
import re,sys
s=open(sys.argv[1],encoding='utf-8').read()
defs=set(re.findall(r'\bfunction\s+([A-Za-z_$][\w$]*)\s*\(',s))
defs.update(re.findall(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>',s))
callbacks=set(re.findall(r'addEventListener\([^,]+,\s*([A-Za-z_$][\w$]*)\s*\)',s))
missing=sorted(callbacks-defs)
if missing: raise SystemExit('unresolved direct event callbacks: '+', '.join(missing))
summary=re.search(r'function renderSummary\(d\)\{([^\n]*)\}',s)
if not summary: raise SystemExit('renderSummary missing')
calls=set(re.findall(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(',summary.group(1)))
ignore={'Object','Number','String','$'}
missing=sorted(calls-defs-ignore)
if missing: raise SystemExit('renderSummary unresolved helpers: '+', '.join(missing))
required={'populateSiteAccounts','populateSubdomainParents','updateSubdomainPreview','closeModal'}
missing=sorted(required-defs)
if missing: raise SystemExit('required UI helper definitions missing: '+', '.join(missing))
print('UI_HELPER_COMPLETENESS_OK callbacks=%d required=%d'%(len(callbacks),len(required)))
PY_AUDIT
printf 'PASS: 6.83 Rev3 subdomain helper completeness contract\n'


# 6.83 Rev4 managed-subdomain lifecycle cleanup guard.
ADMIN="$ROOT/panel/public/admin.php"
grep -Fq 'id="siteDeleteDescription"' "$ADMIN" || { echo 'FAIL: delete modal lifecycle description hook missing' >&2; exit 1; }
grep -Fq 'id="siteDeleteFilesLabel"' "$ADMIN" || { echo 'FAIL: delete modal file label hook missing' >&2; exit 1; }
grep -Fq "f.dataset.siteKind=isSubdomain?'subdomain':'website'" "$APP" || { echo 'FAIL: delete modal does not classify subdomains' >&2; exit 1; }
grep -Fq "safeSubdomainFiles=isSubdomain&&siteHasDedicatedDeletableRoot(site)" "$APP" || { echo 'FAIL: subdomain delete does not distinguish dedicated vs shared document roots in PCC' >&2; exit 1; }
grep -Fq '$isSubdomain=is_array($managedSite)' "$API" || { echo 'FAIL: API bridge does not independently classify managed subdomains' >&2; exit 1; }
grep -Fq '$deleteFiles=$isSubdomain ? $safeSubdomainFiles :' "$API" || { echo 'FAIL: API bridge does not limit managed-subdomain cleanup to safe dedicated roots' >&2; exit 1; }
printf 'PASS: managed subdomain document-root cleanup contract (dedicated roots only; shared roots preserved)\n'
