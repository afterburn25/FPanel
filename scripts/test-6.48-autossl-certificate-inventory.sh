#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
grep -Fq 'id="autoSSLDomain"' "$ROOT/panel/public/admin.php"
grep -Fq 'id="autoSSLResults"' "$ROOT/panel/public/admin.php"
grep -Fq 'Active certificates' "$ROOT/panel/public/admin.php"
grep -Fq 'id="cpAutoSSLDomain"' "$ROOT/panel/public/customer.php"
grep -Fq 'id="cpAutoSSLResults"' "$ROOT/panel/public/customer.php"
grep -Fq "customer-ssl-autossl" "$ROOT/panel/public/api.php"
grep -Fq "'domain'=>strtolower(trim((string)(\$d['domain']??'')))" "$ROOT/panel/public/api.php"
grep -Eq 'Domain[[:space:]]+string `json:"domain,omitempty"`' "$ROOT/agent/internal/api/server.go"
grep -Fq '"pending": pending' "$ROOT/agent/internal/api/server.go"
grep -Fq '"days_remaining": days' "$ROOT/agent/internal/api/server.go"
grep -Fq 'refreshAutoSSLDomainSelector' "$ROOT/panel/public/assets/app.js"
grep -Fq 'renderAutoSSLResults' "$ROOT/panel/public/assets/app.js"
grep -Fq 'refreshCustomerAutoSSLDomainSelector' "$ROOT/panel/public/assets/customer.js"
grep -Fq 'renderCustomerAutoSSLResults' "$ROOT/panel/public/assets/customer.js"
if grep -Fq 'Hosting account (optional)<input name="owner"' "$ROOT/panel/public/admin.php"; then
  echo 'raw account AutoSSL target still exposed in UI' >&2; exit 1
fi
echo 'PASS: 6.48 AutoSSL feedback and active certificate inventory invariants'
