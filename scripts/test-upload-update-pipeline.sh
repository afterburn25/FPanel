#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/key.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/key.pem" -pubout -out "$TMP/pub.pem" >/dev/null 2>&1
if PRIVORA_RELEASE_PRIVATE_KEY="$TMP/key.pem" PRIVORA_RELEASE_CHANNEL=developer "$ROOT/scripts/build-upload-update-zip.sh" "$TMP/should-fail.zip" >/dev/null 2>&1; then
  echo 'builder accepted a signing key that does not match embedded stable trust' >&2; exit 1
fi
# Exercise the stable-trust invariant without depending on a real release private key:
# use an isolated source copy whose embedded public key matches this test key.
cp -a "$ROOT" "$TMP/src"
install -m0644 "$TMP/pub.pem" "$TMP/src/install/release-public-key.pem"
PRIVORA_RELEASE_PRIVATE_KEY="$TMP/key.pem" PRIVORA_RELEASE_CHANNEL=developer "$TMP/src/scripts/build-upload-update-zip.sh" "$TMP/update.zip" >/dev/null
"$TMP/src/scripts/verify-upload-update.py" "$TMP/update.zip" --public-key "$TMP/pub.pem" --inspect-only >"$TMP/inspect.json"
python3 - "$TMP/inspect.json" "$(cat "$ROOT/VERSION")" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); assert p['ok'] is True and p['version']==sys.argv[2]; assert len(p['payload_sha256'])==64 and len(p['zip_sha256'])==64
PY
cp "$TMP/update.zip" "$TMP/tampered.zip"
python3 - "$TMP/tampered.zip" "$(cat "$ROOT/VERSION")" <<'PY'
import sys,zipfile
p,v=sys.argv[1:]
with zipfile.ZipFile(p,'a') as z:z.writestr(f'privora-panel-{v}/TAMPERED.txt',b'tamper')
PY
if "$TMP/src/scripts/verify-upload-update.py" "$TMP/tampered.zip" --public-key "$TMP/pub.pem" --inspect-only >/dev/null 2>&1; then
  echo 'tampered uploaded update package was accepted' >&2; exit 1
fi
echo 'Privora uploaded update package pipeline PASS'
