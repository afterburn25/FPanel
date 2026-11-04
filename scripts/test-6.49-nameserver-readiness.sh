#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
grep -Fq 'setup_status' agent/internal/api/server.go
grep -Fq 'InspectNameserverSetup' agent/internal/api/server.go
grep -Fq 'DNSZoneConfigured' agent/internal/hostadapter/nameserver_status.go
grep -Fq 'NameserverServiceRunning' agent/internal/hostadapter/nameserver_status.go
grep -Fq 'GlueRegistered' agent/internal/hostadapter/nameserver_status.go
grep -Fq 'DelegationActive' agent/internal/hostadapter/nameserver_status.go
grep -Fq 'POST /v1/dns/registrar' agent/internal/api/server.go
grep -Fq 'ConfigureRegistrarConnection' agent/internal/hostadapter/registrar_config.go
grep -Fq 'registrar-connect' panel/public/api.php
grep -Fq 'data-registrar-connect' panel/public/assets/app.js
grep -Fq 'data-nameserver-manual' panel/public/assets/app.js
grep -Fq 'DNS zone:' panel/public/assets/app.js
grep -Fq 'Nameserver service:' panel/public/assets/app.js
grep -Fq 'Glue records:' panel/public/assets/app.js
grep -Fq 'Delegation:' panel/public/assets/app.js
grep -Fq 'Connect Registrar' panel/public/admin.php
grep -Fq 'Show Manual Instructions' panel/public/assets/app.js
echo 'PASS: 6.49 nameserver readiness / registrar workflow invariants'
