#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ACME="$ROOT/agent/internal/hostadapter/acme.go"
TEST="$ROOT/agent/internal/hostadapter/acme_test.go"
MAIL="$ROOT/agent/internal/hostadapter/mail_secure.go"
[[ -f "$ACME" && -f "$TEST" && -f "$MAIL" ]] || { echo 'missing AutoSSL source files' >&2; exit 1; }
grep -Fq 'func acmeTraversalACLTargets(root string) []string' "$ACME"
grep -Fq 'strings.HasPrefix(clean, "/home/")' "$ACME"
grep -Fq 'strings.HasPrefix(clean, "/etc/privora-mail/acme/")' "$ACME"
grep -Fq 'commandExists("setfacl")' "$ACME"
grep -Fq '"u:www-data:--x"' "$ACME"
grep -Fq 'a.ensureACMEWebrootTraversal(ctx, root)' "$ACME"
grep -Fq 'cannot grant Nginx traversal to ACME webroot' "$ACME"
grep -Fq 'func TestACMETraversalACLTargetsAreLeastPrivilegeAndScoped' "$TEST"
grep -Fq 'acmeRoot := filepath.Join(state, "acme", result.Domain)' "$MAIL"
! grep -Eq 'chmod[^\n]*(o\+x|0777|0757|0775)' "$ACME"
[[ -x "$ROOT/dist/privora-hostadapter-cert.test" ]]
(cd "$ROOT/dist" && sha256sum -c privora-hostadapter-cert.test.sha256 >/dev/null)
out="$("$ROOT/dist/privora-hostadapter-cert.test" -test.v -test.run '^TestACMETraversalACLTargetsAreLeastPrivilegeAndScoped$' -test.count=1 2>&1)"
printf '%s\n' "$out" | grep -Fq -- '--- PASS: TestACMETraversalACLTargetsAreLeastPrivilegeAndScoped' || { printf '%s\n' "$out" >&2; echo 'precompiled AutoSSL traversal certification test did not run/pass' >&2; exit 1; }
echo 'PASS: 7.0 Rev5 Rev5 AutoSSL protected-webroot traversal contract'
