#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-/tmp/privora-upload-update.zip}"
KEY="${PRIVORA_RELEASE_PRIVATE_KEY:-}"
CHANNEL="${PRIVORA_RELEASE_CHANNEL:-developer}"
MIN_VERSION="${PRIVORA_MIN_VERSION:-}"
[[ "$CHANNEL" =~ ^(stable|early-access|developer)$ ]] || { echo 'invalid channel' >&2; exit 2; }
[[ -n "$KEY" && -r "$KEY" ]] || { echo 'PRIVORA_RELEASE_PRIVATE_KEY must point to the offline RSA signing key' >&2; exit 2; }
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
SELF_VERIFY_KEY="$ROOT/install/release-public-key.pem"
[[ -r "$SELF_VERIFY_KEY" ]] || { echo "embedded release public key missing" >&2; exit 2; }
# The private key used to sign a routine release MUST match the public key embedded in the core.
TMPPUB="$(mktemp)"; trap 'rm -f "$TMPPUB"' EXIT
openssl pkey -in "$KEY" -pubout -out "$TMPPUB" >/dev/null 2>&1
cmp -s <(openssl pkey -pubin -in "$SELF_VERIFY_KEY" -outform DER 2>/dev/null) <(openssl pkey -pubin -in "$TMPPUB" -outform DER 2>/dev/null) || { echo "signing key does not match embedded stable release trust key" >&2; exit 2; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; rm -f "$TMPPUB"' EXIT
NAME="privora-panel-$VERSION"; STAGE="$TMP/$NAME"
mkdir -p "$STAGE"
rsync -a --delete --exclude 'UPDATE-MANIFEST.json' --exclude 'UPDATE-MANIFEST.sig' --exclude '__pycache__' --exclude '*.pyc' "$ROOT/" "$STAGE/"
PAYLOAD="$(python3 - "$STAGE" <<'PY'
import hashlib,os,sys
root=os.path.realpath(sys.argv[1]); rows=[]
for base,dirs,files in os.walk(root):
 dirs.sort(); files.sort()
 for f in files:
  p=os.path.join(base,f); rel=os.path.relpath(p,root).replace(os.sep,'/')
  if rel in ('UPDATE-MANIFEST.json','UPDATE-MANIFEST.sig'): continue
  h=hashlib.sha256(); size=os.path.getsize(p)
  with open(p,'rb') as fh:
   for b in iter(lambda:fh.read(1024*1024),b''): h.update(b)
  rows.append(f'{rel}\0{size}\0{h.hexdigest()}\n'.encode())
out=hashlib.sha256()
for r in sorted(rows): out.update(r)
print(out.hexdigest())
PY
)"
python3 - "$STAGE/UPDATE-MANIFEST.json" "$VERSION" "$CHANNEL" "$MIN_VERSION" "$PAYLOAD" <<'PY'
import datetime,json,sys
p,v,c,m,h=sys.argv[1:]
d={'schema':'privora-upload-update-v1','version':v,'channel':c,'created_at':datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'),'payload_sha256':h,'services':['privora-panel-agent.service','privora-panel-fpm.service','php8.4-fpm.service','nginx.service','bind9.service'],'migrations':['scripts/migrate.sh']}
if m:d['min_version']=m
open(p,'w',encoding='utf-8').write(json.dumps(d,sort_keys=True,separators=(',',':'))+'\n')
PY
openssl dgst -sha256 -sign "$KEY" -out "$STAGE/UPDATE-MANIFEST.sig" "$STAGE/UPDATE-MANIFEST.json"
rm -f "$OUT"; (cd "$TMP" && zip -q -r "$OUT" "$NAME")
python3 "$ROOT/scripts/verify-upload-update.py" "$OUT" --public-key "$SELF_VERIFY_KEY" --inspect-only >/dev/null
echo "PASS: generated upload ZIP verifies with embedded stable release trust key" >&2
sha256sum "$OUT"
