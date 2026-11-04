#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
SRC="${1:-.}"; OUT="${2:-./release-out}"; CHANNEL="${PRIVORA_RELEASE_CHANNEL:-developer}"; KEY="${PRIVORA_RELEASE_SIGNING_KEY:-}"
[[ -n "$KEY" && -r "$KEY" ]] || { echo 'Set PRIVORA_RELEASE_SIGNING_KEY to an RSA private key outside the source tree.' >&2; exit 2; }
[[ -f "$SRC/VERSION" && -d "$SRC/agent" && -d "$SRC/panel" ]] || { echo 'invalid Privora source tree' >&2; exit 2; }
[[ "$CHANNEL" =~ ^(stable|early-access|developer)$ ]] || { echo 'invalid release channel' >&2; exit 2; }
command -v zstd >/dev/null; command -v openssl >/dev/null; command -v sha256sum >/dev/null
if find "$SRC" -type l -print -quit | grep -q .; then echo 'release source must not contain symlinks' >&2; exit 2; fi
python3 - "$SRC" <<'PYFILES'
import os,sys
root=sys.argv[1]
for dp,dn,fn in os.walk(root):
  for n in dn+fn:
    if any(ord(c)<32 or ord(c)==127 for c in n): raise SystemExit('release source contains control-character filename')
print('release source filename policy PASS')
PYFILES
version="$(tr -d '\r\n' < "$SRC/VERSION")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.]+)?$ ]] || { echo "invalid VERSION: $version" >&2; exit 2; }
mkdir -p "$OUT/$CHANNEL/$version" "$OUT/$CHANNEL"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
stage="$work/privora-panel-$version"; mkdir -p "$stage"
rsync -a --delete \
  --exclude '.git' --exclude 'panel/storage' --exclude 'runtime' \
  --exclude 'evidence/sandbox-host-adapter-certification.json' \
  --exclude '*.key' --exclude '*.pem~' --exclude '*.cookie' --exclude '*.session' \
  "$SRC/" "$stage/"
# Never ship a pre-existing binary from a different source tree.
rm -f "$stage/dist/privora-agent" "$stage/dist/privora-hostadapter-cert.test" "$stage/dist/privora-api-cert.test"; mkdir -p "$stage/dist"
( cd "$stage/agent" && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$stage/dist/privora-agent" ./cmd/privora-agent && CGO_ENABLED=0 go test -c -trimpath -o "$stage/dist/privora-hostadapter-cert.test" ./internal/hostadapter && CGO_ENABLED=0 go test -c -trimpath -o "$stage/dist/privora-api-cert.test" ./internal/api )
for f in privora-agent privora-hostadapter-cert.test privora-api-cert.test; do sha256sum "$stage/dist/$f" | sed "s#  $stage/dist/#  #" > "$stage/dist/$f.sha256"; done
# Reproducible archive metadata: stable ordering, uid/gid, and timestamp.
created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; epoch="${SOURCE_DATE_EPOCH:-$(date -u +%s)}"
artifact="$OUT/$CHANNEL/$version/privora-panel-$version.tar.zst"
TZ=UTC tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$work" -cf - "privora-panel-$version" | zstd -19 -T0 -q -o "$artifact"
sha="$(sha256sum "$artifact" | awk '{print $1}')"; size="$(stat -c %s "$artifact")"
printf '%s  %s\n' "$sha" "$(basename "$artifact")" > "$artifact.sha256"
openssl dgst -sha256 -sign "$KEY" -out "$artifact.sig" "$artifact"
cat > "$artifact.json" <<JSON
{
  "schema": "privora-release-v1",
  "version": "$version",
  "channel": "$CHANNEL",
  "artifact": "$(basename "$artifact")",
  "sha256": "$sha",
  "size_bytes": $size,
  "created_at": "$created",
  "minimum_bootstrap": "5.0.0-dev.6"
}
JSON
openssl dgst -sha256 -sign "$KEY" -out "$artifact.json.sig" "$artifact.json"
# The channel pointer is small, signed, and contains only immutable version/artifact identity.
cat > "$OUT/$CHANNEL/current.json" <<JSON
{
  "schema": "privora-channel-pointer-v1",
  "channel": "$CHANNEL",
  "version": "$version",
  "artifact_path": "$version/$(basename "$artifact")",
  "sha256": "$sha",
  "created_at": "$created"
}
JSON
openssl dgst -sha256 -sign "$KEY" -out "$OUT/$CHANNEL/current.json.sig" "$OUT/$CHANNEL/current.json"
# Compatibility aliases used by the zero-argument bootstrap/update path.
cp "$artifact" "$OUT/$CHANNEL/privora-panel-current.tar.zst"
cp "$artifact.sha256" "$OUT/$CHANNEL/privora-panel-current.tar.zst.sha256"
# Rewrite filename in compatibility checksum so sha256sum -c succeeds after download as release.tar.zst.
printf '%s  release.tar.zst\n' "$sha" > "$OUT/$CHANNEL/privora-panel-current.tar.zst.sha256"
cp "$artifact.sig" "$OUT/$CHANNEL/privora-panel-current.tar.zst.sig"
cp "$artifact.json" "$OUT/$CHANNEL/privora-panel-current.tar.zst.json"
cp "$artifact.json.sig" "$OUT/$CHANNEL/privora-panel-current.tar.zst.json.sig"
printf 'release=%s\nsha256=%s\nsize=%s\nchannel=%s\n' "$artifact" "$sha" "$size" "$CHANNEL"
