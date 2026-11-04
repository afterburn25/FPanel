#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
grep -Fq 'InspectMailDomainReadiness' "$ROOT/agent/internal/hostadapter/mail_secure.go"
grep -Fq 'certificateCoversHost' "$ROOT/agent/internal/hostadapter/mail_secure.go"
grep -Fq 'RemoveMailDomainAuthentication' "$ROOT/agent/internal/hostadapter/mail_secure.go"
grep -Fq 'DELETE /v1/mail/domains/{domain}/authentication' "$ROOT/agent/internal/api/server.go"
grep -Fq 'mail.domain.authentication.delete' "$ROOT/agent/internal/api/server_platform.go"
grep -Fq "mail-domain-auth-delete" "$ROOT/panel/public/api.php"
grep -Fq "customer-mail-domain-auth-delete" "$ROOT/panel/public/api.php"
grep -Fq 'data-mail-domain-auth-delete' "$ROOT/panel/public/assets/app.js"
grep -Fq 'data-cp-mail-domain-auth-delete' "$ROOT/panel/public/assets/customer.js"
grep -Fq 'website_preserved' "$ROOT/agent/internal/api/server_platform.go"
grep -Fq 'mailboxes_preserved' "$ROOT/agent/internal/api/server_platform.go"
grep -Fq 'mx_preserved' "$ROOT/agent/internal/api/server_platform.go"
echo 'PASS: 6.88 live mail-domain readiness + safe authentication delete contract'
