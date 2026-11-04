#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ACME="$ROOT/agent/internal/hostadapter/acme.go"
MAIL="$ROOT/agent/internal/hostadapter/mail_secure.go"
API="$ROOT/agent/internal/api/server.go"
TEST="$ROOT/agent/internal/hostadapter/acme_test.go"
MAILTEST="$ROOT/agent/internal/hostadapter/mail_secure_test.go"
for f in "$ACME" "$MAIL" "$API" "$TEST" "$MAILTEST"; do [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }; done

grep -Fq '"--cert-name", domain' "$ACME"
grep -Fq 'func (a *Adapter) resolveLetsEncryptLineage' "$ACME"
grep -Fq 'strings.HasPrefix(name, prefix)' "$ACME"
grep -Fq '"-checkhost", domain' "$ACME"
grep -Fq 'func TestACMEWebrootResolvesSuffixedCertbotLineage' "$TEST"

grep -Fq 'func (a *Adapter) IsManagedMailChallengeHost' "$MAIL"
grep -Fq 'privora-mail-"+domain+".conf' "$MAIL"
grep -Fq 'func (a *Adapter) InstallLetsEncryptMailTLS' "$MAIL"
grep -Fq 'a.renderMailServices(ctx, uid, gid, state, root, dovecotCfg, rspamdCfg, dkimDir, tlsDir)' "$MAIL"
grep -Fq 'func TestManagedMailChallengeHostDetection' "$MAILTEST"
grep -Fq 'func (a *Adapter) writeMailTLSSourcePaths' "$MAIL"
grep -Fq 'func (a *Adapter) mailTLSSourcePaths' "$MAIL"
grep -Fq 'func TestMailTLSSourcePathsPreserveResolvedLineage' "$MAILTEST"

grep -Fq 'if s.host.IsManagedMailChallengeHost(site.Domain)' "$API"
grep -Fq 's.host.InstallLetsEncryptMailTLS(r.Context(), site.Domain, acme)' "$API"
grep -Fq 's.host.InstallLetsEncryptNginxTLS(r.Context(), site.Domain, site.Username, site.PHPVersion, site.DocumentRoot, acme)' "$API"

[[ -x "$ROOT/dist/privora-hostadapter-cert.test" ]]
(cd "$ROOT/dist" && sha256sum -c privora-hostadapter-cert.test.sha256 >/dev/null)
out="$($ROOT/dist/privora-hostadapter-cert.test -test.v -test.run 'TestACMEWebrootResolvesSuffixedCertbotLineage|TestManagedMailChallengeHostDetection|TestMailTLSSourcePathsPreserveResolvedLineage' -test.count=1 2>&1)"
printf '%s\n' "$out" | grep -Fq -- '--- PASS: TestACMEWebrootResolvesSuffixedCertbotLineage' || { printf '%s\n' "$out" >&2; exit 1; }
printf '%s\n' "$out" | grep -Fq -- '--- PASS: TestManagedMailChallengeHostDetection' || { printf '%s\n' "$out" >&2; exit 1; }
printf '%s\n' "$out" | grep -Fq -- '--- PASS: TestMailTLSSourcePathsPreserveResolvedLineage' || { printf '%s\n' "$out" >&2; exit 1; }

echo 'PASS: 7.0 Rev5 Rev6 AutoSSL mail TLS routing + Certbot lineage contract'
