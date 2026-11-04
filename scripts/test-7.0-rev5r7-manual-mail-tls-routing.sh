#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
API="$ROOT/agent/internal/api/server.go"
PANEL="$ROOT/panel/public/api.php"
grep -Fq 'if s.host.IsManagedMailChallengeHost(in.Domain) {' "$API"
grep -Fq 'installErr = s.host.InstallLetsEncryptMailTLS(r.Context(), in.Domain, result)' "$API"
grep -Fq 'installErr = s.host.InstallLetsEncryptNginxTLS(r.Context(), in.Domain, site.Username, site.PHPVersion, site.DocumentRoot, result)' "$API"
grep -Fq "postLong('/v1/ssl/issue',['domain'=>\$domain],180)" "$PANEL"
grep -Fq "postLong('/v1/ssl/issue',['domain'=>(string)(\$d['domain']??'')],180)" "$PANEL"
echo 'PASS: Rev5 Rev7 manual mail TLS routing + long certificate mutation transport'
