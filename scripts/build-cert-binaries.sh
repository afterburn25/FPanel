#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/dist"
cd "$ROOT/agent"
CGO_ENABLED=0 go test -c -trimpath -o "$ROOT/dist/privora-hostadapter-cert.test" ./internal/hostadapter
CGO_ENABLED=0 go test -c -trimpath -o "$ROOT/dist/privora-api-cert.test" ./internal/api
chmod 0755 "$ROOT/dist/privora-hostadapter-cert.test" "$ROOT/dist/privora-api-cert.test"
for f in privora-hostadapter-cert.test privora-api-cert.test; do
  sha256sum "$ROOT/dist/$f" | sed "s#  $ROOT/dist/#  #" > "$ROOT/dist/$f.sha256"
done
echo 'Privora precompiled certification executables built.'
