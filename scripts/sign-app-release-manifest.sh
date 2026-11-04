#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
IN="${1:?unsigned app manifest JSON required}"; OUT="${2:-$IN}"; KEY="${PRIVORA_APP_RELEASE_SIGNING_KEY:-}"
[[ -n "$KEY" && -r "$KEY" ]] || { echo 'Set PRIVORA_APP_RELEASE_SIGNING_KEY to the separate app-catalog RSA private key.' >&2; exit 2; }
python3 - "$IN" <<'PY'
import json,re,sys,urllib.parse
p=sys.argv[1]; d=json.load(open(p,encoding='utf-8'))
assert d.get('schema')=='privora-app-release-manifest-v1'
rels=d.get('releases'); assert isinstance(rels,list) and 0 < len(rels) <= 512
current={}; templates=set()
for r in rels:
    assert re.fullmatch(r'[a-z0-9][a-z0-9-]{1,47}',r['template']); templates.add(r['template'])
    u=urllib.parse.urlparse(r['url']); assert u.scheme=='https' and u.netloc and not u.username
    assert re.fullmatch(r'[0-9a-f]{64}',r['sha256'])
    assert r['archive'] in ('zip','tar.gz')
    assert 1024 <= int(r['max_bytes']) <= 1073741824
    assert r['bootstrap'] in ('wordpress','joomla','guided-web','none')
    if r.get('current') is True: current[r['template']]=current.get(r['template'],0)+1
assert all(current.get(t)==1 for t in templates)
print('app manifest schema PASS')
PY
if [[ "$IN" != "$OUT" ]]; then cp "$IN" "$OUT"; fi
openssl dgst -sha256 -sign "$KEY" -out "$OUT.sig" "$OUT"
echo "signed=$OUT signature=$OUT.sig"
