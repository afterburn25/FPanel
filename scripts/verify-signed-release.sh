#!/usr/bin/env bash
set -Eeuo pipefail
ART="${1:?release artifact required}"; PUB="${2:?public key required}"
[[ -r "$ART" && -r "$ART.sha256" && -r "$ART.sig" && -r "$ART.json" && -r "$ART.json.sig" && -r "$PUB" ]] || { echo 'release sidecar missing' >&2; exit 2; }
base="$(basename "$ART")"; dir="$(dirname "$ART")"
expected="$(awk 'NR==1{print $1}' "$ART.sha256")"; actual="$(sha256sum "$ART"|awk '{print $1}')"; [[ "$expected" == "$actual" ]] || { echo 'artifact sha256 mismatch' >&2; exit 1; }
openssl dgst -sha256 -verify "$PUB" -signature "$ART.sig" "$ART" >/dev/null
openssl dgst -sha256 -verify "$PUB" -signature "$ART.json.sig" "$ART.json" >/dev/null
python3 - "$ART.json" "$base" "$actual" <<'PY'
import json,sys
p,name,sha=sys.argv[1:]
d=json.load(open(p,encoding='utf-8'))
assert d.get('schema')=='privora-release-v1'
assert d.get('artifact')==name
assert d.get('sha256')==sha
assert isinstance(d.get('size_bytes'),int) and d['size_bytes']>0
assert d.get('channel') in {'stable','early-access','developer'}
print('release metadata PASS', d['version'], d['channel'], sha)
PY
