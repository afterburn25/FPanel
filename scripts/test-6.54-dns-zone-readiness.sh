#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
grep -Fq 'isDNSZoneApexOwner' "$ROOT/agent/internal/hostadapter/nameserver_status.go"
grep -Fq 'local-authoritative-server' "$ROOT/agent/internal/hostadapter/nameserver_status.go"
grep -Fq 'authoritativeNSFromDig' "$ROOT/agent/internal/hostadapter/nameserver_status.go"
grep -Fq 'TestInspectNameserverSetupAcceptsFQDNApexAndInheritedOwner' "$ROOT/agent/internal/hostadapter/nameserver_status_test.go"
grep -Fq 'TestInspectNameserverSetupAcceptsLoadedLegacyZoneOutsidePrivoraDirectory' "$ROOT/agent/internal/hostadapter/nameserver_status_test.go"
(
  cd "$ROOT/agent"
  go test ./internal/hostadapter -run 'TestInspectNameserverSetup|TestReadUpdateDeleteManagedBINDRecords' -count=1
)
echo 'dev.6.54 DNS zone readiness reconciliation PASS'
