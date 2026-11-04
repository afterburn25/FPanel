#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/key.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/key.pem" -pubout -out "$TMP/pub.pem" >/dev/null 2>&1
PRIVORA_RELEASE_SIGNING_KEY="$TMP/key.pem" PRIVORA_RELEASE_CHANNEL=developer SOURCE_DATE_EPOCH=1787097600 "$ROOT/scripts/build-signed-release.sh" "$ROOT" "$TMP/out" >/dev/null
artifact="$TMP/out/developer/$(cat "$ROOT/VERSION")/privora-panel-$(cat "$ROOT/VERSION").tar.zst"
"$ROOT/scripts/verify-signed-release.sh" "$artifact" "$TMP/pub.pem" >/dev/null
cp "$artifact" "$TMP/tampered.tar.zst"; printf X >> "$TMP/tampered.tar.zst"
cp "$artifact.sha256" "$TMP/tampered.tar.zst.sha256"; cp "$artifact.sig" "$TMP/tampered.tar.zst.sig"; cp "$artifact.json" "$TMP/tampered.tar.zst.json"; cp "$artifact.json.sig" "$TMP/tampered.tar.zst.json.sig"
if "$ROOT/scripts/verify-signed-release.sh" "$TMP/tampered.tar.zst" "$TMP/pub.pem" >/dev/null 2>&1; then echo 'tampered release was accepted' >&2; exit 1; fi
[[ -s "$TMP/out/developer/current.json" && -s "$TMP/out/developer/current.json.sig" ]]
openssl dgst -sha256 -verify "$TMP/pub.pem" -signature "$TMP/out/developer/current.json.sig" "$TMP/out/developer/current.json" >/dev/null
"$ROOT/release/prepare-delivery-root.sh" "$TMP/out" "$TMP/delivery" >/dev/null
[[ -s "$TMP/delivery/install/index" && -s "$TMP/delivery/downloads/releases/developer/current.json" ]]
echo 'signed release pipeline PASS'
