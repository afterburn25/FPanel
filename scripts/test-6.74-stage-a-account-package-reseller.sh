#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ver="$(tr -d '\r\n' < VERSION)"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[4-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]]
grep -Fq 'Owner         string' agent/internal/hosting/hosting.go
grep -Fq 'Reseller      string' agent/internal/hosting/hosting.go
grep -Fq 'SetLinuxUserPassword' agent/internal/hostadapter/adapter.go
grep -Fq 'SetLinuxUserShellPolicy' agent/internal/hostadapter/adapter.go
grep -Fq 'DeleteMailbox' agent/internal/hostadapter/mail.go
grep -Fq 'ManagedDatabases' agent/internal/api/account_termination.go
grep -Fq 'UnmanagedDatabases' agent/internal/api/account_termination.go
grep -Fq 'ManagedMailboxes' agent/internal/api/account_termination.go
grep -Fq 'ApplyCgroupV2Limits' agent/internal/api/server_platform.go
grep -Fq 'POST /v1/hosting/accounts/bulk' agent/internal/api/server.go
grep -Fq 'PATCH /v1/hosting/accounts/{user}' agent/internal/api/server.go
grep -Fq 'PATCH /v1/resellers/{name}' agent/internal/api/server.go
grep -Fq 'resellerScope' panel/src/Auth.php
grep -Fq 'setResellerAccess' panel/src/Store.php
grep -Fq 'requireAdminAccountScope' panel/public/api.php
grep -Fq 'requireAccountCapacity' panel/public/api.php
grep -Fq 'enforceResellerAllocation' panel/public/api.php
grep -Fq "customer-sftp-create'=>'sftp'" panel/public/api.php
grep -Fq "customer-deployment-create'=>'git'" panel/public/api.php
grep -Fq 'reseller-access-set' panel/public/api.php
grep -Fq 'resellerAccessModal' panel/public/admin.php
grep -Fq 'accountBulkRun' panel/public/assets/app.js
grep -Fq 'data-reseller-access' panel/public/assets/app.js

gofmt -w agent/internal/hosting/hosting.go agent/internal/hostadapter/adapter.go agent/internal/hostadapter/mail.go agent/internal/resources/resources.go agent/internal/platform/platform.go agent/internal/api/account_termination.go agent/internal/api/server.go agent/internal/api/server_platform.go
(cd agent && go test ./internal/hosting ./internal/resources ./internal/hostadapter ./internal/api -count=1)
php -l panel/src/Auth.php >/dev/null
php -l panel/src/Store.php >/dev/null
php -l panel/src/AgentClient.php >/dev/null
php -l panel/public/api.php >/dev/null
php -l panel/public/admin.php >/dev/null
node --check panel/public/assets/app.js

echo 'PASS: 6.74 Stage A account lifecycle / package enforcement / feature policy / reseller scope'
