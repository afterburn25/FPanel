#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
server="$ROOT/agent/internal/api/server.go"
grep -Fq 'func (s *Server) nameserversForDomain(domain string) resources.NameserverConfig' "$server"
grep -Fq 'func (s *Server) nameserversForDomain(domain string) resources.NameserverConfig' "$server"
grep -Fq 'ns := s.nameserversForDomain(domain)' "$server"
grep -Fq 'ns := s.nameserversForDomain(in.Domain)' "$server"
grep -Eq 'context\.WithTimeout\(r\.Context\(\), (8|12)\*time\.Second\)' "$server"
grep -Fq 'APT inventory timed out; package status will retry on refresh.' "$server"
grep -Fq '"degraded": degraded, "status_reason": statusReason' "$server"
echo 'PASS: 6.65 per-domain nameserver selection and package inventory resilience gate'
