#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
need(){ grep -Fq -- "$2" "$ROOT/$1" || { echo "FAIL: $1 missing: $2" >&2; exit 1; }; }
need_re(){ grep -Eq -- "$2" "$ROOT/$1" || { echo "FAIL: $1 missing regex: $2" >&2; exit 1; }; }
ver="$(tr -d '\r\n' < "$ROOT/VERSION")"; [[ "$ver" =~ ^5\.0\.0-dev\.6\.(7[0-9]|8[0-9]|90)$ || "$ver" == "5.0.0-dev.7.0" ]] || { echo "FAIL: 6.70 lifecycle contract tested on unsupported version $ver" >&2; exit 1; }

need agent/internal/api/server.go 'POST /v1/databases/{name}/user'
need agent/internal/api/server.go 'Password string `json:"password,omitempty"`'
need agent/internal/api/server.go 'credentials'
need agent/internal/api/server.go 'secret_once'
need agent/internal/hostadapter/database.go 'resolveDatabasePassword'
need agent/internal/hostadapter/database.go 'RenameDatabaseUser'
need agent/internal/hostadapter/database.go 'database password must be 12-128 characters'
need agent/internal/resources/resources.go 'UpdateDatabaseUser'

need panel/public/api.php "customer-database-password"
need panel/public/api.php "customer-database-user"
need panel/public/api.php "customer-database-delete"
need panel/public/api.php "confirm_name"
need panel/public/admin.php 'Database user<input name="user"'
need panel/public/admin.php 'id="databaseCredentials"'
need panel/public/admin.php 'id="databaseEditModal"'
need panel/public/customer.php 'Database user<input name="user"'
need panel/public/customer.php 'id="cpDatabaseCredentials"'
need panel/public/customer.php 'id="cpDatabaseEditModal"'
need panel/public/assets/app.js 'data-db-password'
need panel/public/assets/app.js 'data-db-delete'
need panel/public/assets/app.js 'showDatabaseCredentials'
need panel/public/assets/customer.js 'data-customer-db-password'
need panel/public/assets/customer.js 'data-customer-db-delete'
need panel/public/assets/customer.js 'showCustomerDatabaseCredentials'

# No UI may claim that a stored plaintext password can be recovered.
! grep -Eqi 'show (current|existing) database password|recover database password' "$ROOT/panel/public/admin.php" "$ROOT/panel/public/customer.php" || { echo 'FAIL: UI implies plaintext password recovery' >&2; exit 1; }

echo 'PASS: Privora 6.70 database credential/lifecycle contract.'
