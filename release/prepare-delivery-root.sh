#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; SIGNED="${1:?signed release repository root required}"; OUT="${2:-./delivery-root}"; APP_MANIFEST="${3:-}"
[[ -d "$SIGNED/stable" || -d "$SIGNED/developer" || -d "$SIGNED/early-access" ]] || { echo 'signed release root has no channels' >&2; exit 2; }
rm -rf "$OUT"; mkdir -p "$OUT/install" "$OUT/downloads/releases" "$OUT/downloads/apps"
install -m0644 "$ROOT/install/privora-install.sh" "$OUT/install/index"
cp -a "$SIGNED"/. "$OUT/downloads/releases/"
if [[ -n "$APP_MANIFEST" ]]; then [[ -r "$APP_MANIFEST" && -r "$APP_MANIFEST.sig" ]] || { echo 'app manifest/signature missing' >&2; exit 2; }; install -m0644 "$APP_MANIFEST" "$OUT/downloads/apps/releases.json"; install -m0644 "$APP_MANIFEST.sig" "$OUT/downloads/apps/releases.json.sig"; fi
find "$OUT" -type f -exec chmod 0644 {} +
echo "delivery_root=$OUT"
