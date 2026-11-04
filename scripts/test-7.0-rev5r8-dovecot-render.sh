#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-/opt/privora-panel}"
F="$ROOT/agent/internal/hostadapter/mail_secure.go"
[[ -f "$F" ]] || { echo "FAIL: missing $F"; exit 1; }
# Canonical renderer must exist.
grep -Fq 'func renderPrivoraDovecotMailConfig' "$F"
# Reject the unsupported inline nested blocks that caused Dovecot 2.3.21 to report Garbage after '{'.
! grep -Fq 'service lmtp { unix_listener' "$F"
! grep -Fq 'protocol lmtp { mail_plugins' "$F"
! grep -Fq 'plugin { sieve' "$F"
! grep -Fq 'service imap-login { inet_listener' "$F"
! grep -Fq 'service pop3-login { inet_listener' "$F"
! grep -Fq 'local_name %s { ssl_cert' "$F"
# Required canonical multiline constructs.
grep -Fq 'service lmtp {' "$F"
grep -Fq '  unix_listener /var/spool/postfix/private/dovecot-lmtp {' "$F"
grep -Fq 'service imap-login {' "$F"
grep -Fq '  inet_listener imaps {' "$F"
grep -Fq 'service pop3-login {' "$F"
grep -Fq 'fmt.Fprintf(&localNames, "local_name %s {\n' "$F"
# Regression unit test must remain present.
grep -Fq 'TestRenderPrivoraDovecotMailConfigUsesCanonicalMultilineBlocks' "$ROOT/agent/internal/hostadapter/mail_secure_test.go"
echo 'PASS: Rev5 Rev8 Dovecot renderer uses canonical multiline blocks.'
