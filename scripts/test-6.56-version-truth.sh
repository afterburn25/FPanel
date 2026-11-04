#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V="$(tr -d '\r\n' < "$ROOT/VERSION")"
[[ "$V" =~ ^5\.0\.0-dev\.6\.[0-9]+$ || "$V" == "5.0.0-dev.7.0" ]] || { echo "unexpected VERSION: $V" >&2; exit 1; }
grep -Fq "PRIVORA_VERSION=\"$V\"" "$ROOT/install/privora-install.sh"
grep -Fq "'privora_version'=>'$V'" "$ROOT/install/privora-install.sh"
grep -Fq 'app.css?v=<?=$privoraAssetVersion?>' "$ROOT/panel/public/admin.php"
grep -Fq 'app.js?v=<?=$privoraAssetVersion?>' "$ROOT/panel/public/admin.php"
grep -Fq 'app.css?v=<?=$privoraAssetVersion?>' "$ROOT/panel/public/customer.php"
grep -Fq 'customer.js?v=<?=$privoraAssetVersion?>' "$ROOT/panel/public/customer.php"
grep -Fq "const currentVersion = \"$V\"" "$ROOT/agent/internal/api/version.go"
grep -Fq "Version: \"$V\"" "$ROOT/agent/internal/api/server_platform.go"
grep -Fq "Privora Agent $V listening" "$ROOT/agent/cmd/privora-agent/main.go"
# Runtime-facing source must not retain older 6.50 identity.
if grep -RIn --exclude='*.md' --exclude='CHECKPOINT.md' --exclude='ROADMAP.md' --exclude='FULL-CORE-MANIFEST.json' --exclude='UPDATE-MANIFEST.json' --exclude-dir='__pycache__' '5\.0\.0-dev\.6\.50' \
  "$ROOT/install" "$ROOT/panel/public" "$ROOT/agent"; then
  echo 'stale 6.50 runtime version identity found' >&2
  exit 1
fi
echo 'dev.6.56 runtime version truth PASS'
