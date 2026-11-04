#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
fail(){ echo "FAIL: $*" >&2; exit 1; }

v="$(tr -d '[:space:]' < "$ROOT/VERSION")"
[[ "$v" == "5.0.0-dev.6.89" || "$v" == "5.0.0-dev.6.90" || "$v" == "5.0.0-dev.7.0" ]] || fail "VERSION is not supported 6.89+ cumulative lineage through 7.0"
authgo="$ROOT/agent/internal/hostadapter/mail_auth.go"
mailgo="$ROOT/agent/internal/hostadapter/mail.go"
secure="$ROOT/agent/internal/hostadapter/mail_secure.go"
installer="$ROOT/install/privora-install.sh"
reconciler="$ROOT/scripts/reconcile-mail-auth.sh"

for f in "$authgo" "$mailgo" "$secure" "$installer" "$reconciler"; do [[ -s "$f" ]] || fail "missing $f"; done

grep -Fq 'driver = passwd-file' "$authgo" || fail 'passwd-file auth backend missing'
grep -Fq 'username_format=%%u' "$authgo" || fail 'full-address Dovecot lookup missing'
grep -Fq 'auth-system.conf.ext' "$authgo" || fail 'system-auth disable logic missing'
grep -Fq 'service auth-worker' "$authgo" || fail 'auth-worker access configuration missing'
grep -Fq 'group = %s' "$authgo" || fail 'auth-worker Privora group wiring missing'
grep -Fq '0640' "$authgo" || fail 'protected auth-file mode missing'
grep -Fq 'ReconcileMailAuthentication(ctx)' "$mailgo" || fail 'mailbox mutation reconciliation missing'
grep -Fq 'certifyMailboxPassword(ctx, address, password)' "$mailgo" || fail 'mailbox password certification missing'
grep -Fq 'doveadm", "auth", "test", "-x", "service=imap", address' "$authgo" || fail 'safe Dovecot auth test path missing'
! grep -Eq 'doveadm.*auth.*test.*password' "$authgo" || fail 'plaintext password appears in doveadm argv construction'
grep -Fq 'smtpd_sasl_type' "$authgo" || fail 'Postfix Dovecot SASL wiring missing'
grep -Fq 'submission/inet/smtpd_sasl_auth_enable=yes' "$authgo" || fail 'SMTP submission AUTH missing'
grep -Fq 'submissions/inet/smtpd_sasl_auth_enable=yes' "$authgo" || fail 'SMTPS AUTH missing'
grep -Fq 'mail_auth_foundation' "$installer" || fail 'fresh-install mail-auth phase missing'
grep -Fq 'reconcile-mail-auth.sh' "$installer" || fail 'installer does not invoke mail-auth reconciler'

bash -n "$installer"
bash -n "$reconciler"
if [[ "${PRIVORA_SKIP_GO_TESTS:-0}" != "1" ]]; then
  (
    cd "$ROOT/agent"
    go test ./internal/hostadapter ./internal/api
  )
fi

echo 'PASS: 6.89 virtual-mail passwd-file authentication / auth-worker access / SMTP AUTH regression gate'
