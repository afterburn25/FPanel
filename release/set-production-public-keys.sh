#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; CORE="${1:?core release public key required}"; APP="${2:?app catalog public key required}"
for k in "$CORE" "$APP"; do openssl pkey -pubin -in "$k" -noout >/dev/null; done
install -m0644 "$CORE" "$ROOT/install/release-public-key.pem"
install -m0644 "$APP" "$ROOT/install/app-release-public-key.pem"
python3 - "$ROOT/install/privora-install.sh" "$CORE" <<'PY'
from pathlib import Path
import sys
script=Path(sys.argv[1]); key=Path(sys.argv[2]).read_text().strip(); s=script.read_text()
start=s.index("-----BEGIN PUBLIC KEY-----", s.index("write_embedded_release_key"))
end=s.index("-----END PUBLIC KEY-----",start)+len("-----END PUBLIC KEY-----")
s=s[:start]+key+s[end:];script.write_text(s)
PY
for pair in "core-release:$CORE" "app-catalog:$APP"; do name=${pair%%:*}; path=${pair#*:}; fp=$(openssl pkey -pubin -in "$path" -outform DER|sha256sum|awk '{print $1}'); echo "$name public-key sha256=$fp"; done
echo 'Production public keys installed into source/bootstrap. Commit only the public keys and obtain dual review before release.'
