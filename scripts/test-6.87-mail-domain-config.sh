#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
fail(){ echo "FAIL: $*" >&2; exit 1; }
v="$(tr -d '[:space:]' < "$ROOT/VERSION")"; [[ "$v" == "5.0.0-dev.6.87" || "$v" == "5.0.0-dev.6.88" || "$v" == "5.0.0-dev.6.89" || "$v" == "5.0.0-dev.6.90" || "$v" == "5.0.0-dev.7.0" ]] || fail "VERSION is not supported 6.87+ cumulative lineage through 7.0"
grep -q 'GET /v1/mail/domains/{domain}/configuration' "$ROOT/agent/internal/api/server.go" || fail "mail configuration route missing"
grep -q 'InspectMailClientConfiguration' "$ROOT/agent/internal/hostadapter/mail_secure.go" || fail "live mail inspector missing"
grep -q 'renderBINDTXTValue' "$ROOT/agent/internal/hostadapter/resources.go" || fail "TXT chunk renderer missing"
grep -q 'parseBINDTXTValue' "$ROOT/agent/internal/hostadapter/dns.go" || fail "TXT chunk parser missing"
grep -q "mail-domain-config" "$ROOT/panel/public/api.php" || fail "PCC mail-domain configuration bridge missing"
grep -q "customer-mail-domain-config" "$ROOT/panel/public/api.php" || fail "PPanel mail-domain configuration bridge missing"
grep -q 'data-mail-domain-manage' "$ROOT/panel/public/assets/app.js" || fail "PCC Manage / Setup hook missing"
grep -q 'data-cp-mail-domain-manage' "$ROOT/panel/public/assets/customer.js" || fail "PPanel Manage / Setup hook missing"
grep -q 'mailDomainManageModal' "$ROOT/panel/public/admin.php" || fail "PCC mail-domain modal missing"
grep -q 'cpMailDomainManageModal' "$ROOT/panel/public/customer.php" || fail "PPanel mail-domain modal missing"
grep -q 'SMTP server delivery (not normal client submission)' "$ROOT/panel/public/assets/app.js" || fail "SMTP 25 guidance missing"
grep -q 'DKIM selector:' "$ROOT/panel/public/assets/app.js" || fail "DKIM selector output missing"
! grep -q 'mailbox plaintext' "$ROOT/panel/public/assets/app.js" || fail "unexpected plaintext-password behavior marker"
echo "PASS: 6.87 live mail-domain configuration + DKIM TXT reliability contract"
