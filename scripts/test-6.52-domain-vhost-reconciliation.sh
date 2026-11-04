#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inv="$ROOT/agent/internal/hostadapter/inventory.go"
grep -Fq 'domain-vhost-reconciled' "$inv"
grep -Fq 'nginx", "-T"' "$inv"
grep -Fq 'scanDir(a.cfg.NginxSitesEnabled, true)' "$inv"
grep -Fq 'server_name' "$inv"
cd "$ROOT/agent"
go test ./internal/hostadapter -run 'TestInspectManagedSiteReconcilesCustomFilenameAndInlineDirectives|TestDiscoverNginxSitesUsesEffectiveConfigFromNginxT|TestSiteFromBlockCollapsesWWWAliasAndMarksPrivoraVhostManaged' -count=1
echo 'dev.6.52 domain/vhost reconciliation invariants PASS'
