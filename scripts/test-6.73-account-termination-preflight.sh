#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

grep -Fq 'GET /v1/hosting/accounts/{user}/termination-plan' agent/internal/api/server.go
grep -Fq 'PlanFingerprint string' agent/internal/api/server.go
grep -Fq 'termination plan changed or was not confirmed' agent/internal/api/server.go
grep -Fq 'UnmanagedDatabases' agent/internal/api/account_termination.go
grep -Fq 'externally managed website configuration must be removed or adopted before termination' agent/internal/api/account_termination.go
grep -Fq 'externally managed website configuration must be removed or adopted before termination' agent/internal/api/account_termination.go
grep -Fq "account-termination-plan" panel/public/api.php
grep -Fq 'accountTerminationPlan' panel/public/admin.php
grep -Fq 'renderTerminationPlan' panel/public/assets/app.js

gofmt -w agent/internal/api/account_termination.go agent/internal/api/account_termination_test.go agent/internal/api/server.go
(cd agent && go test ./internal/api -run 'TestAccountTermination' -count=1)
php -l panel/public/api.php >/dev/null
php -l panel/public/admin.php >/dev/null
node --check panel/public/assets/app.js

echo 'PASS: 6.73 account termination preflight / stale-plan guard contract retained'
