#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
OUT="${1:-./privora-production-keys}"
[[ "${PRIVORA_OFFLINE_KEYGEN:-}" == "YES_I_AM_OFFLINE" ]] || { echo 'Refusing key generation. Run only on an offline/isolated signing workstation with PRIVORA_OFFLINE_KEYGEN=YES_I_AM_OFFLINE.' >&2; exit 2; }
command -v openssl >/dev/null
mkdir -p "$OUT"; chmod 0700 "$OUT"
for purpose in core-release app-catalog; do
  priv="$OUT/$purpose-private.pem"; pub="$OUT/$purpose-public.pem"
  [[ ! -e "$priv" && ! -e "$pub" ]] || { echo "$purpose key already exists" >&2; exit 1; }
  echo "Generating encrypted RSA-4096 $purpose key. OpenSSL will request a strong passphrase."
  openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096 -out "$priv"
  openssl pkey -in "$priv" -pubout -out "$pub"
  chmod 0600 "$priv"; chmod 0644 "$pub"
  fp="$(openssl pkey -pubin -in "$pub" -outform DER | sha256sum | awk '{print $1}')"
  printf '%s  %s\n' "$fp" "$purpose-public-key-sha256" | tee "$OUT/$purpose-fingerprint.txt"
done
cat > "$OUT/README.txt" <<'TXT'
These are production signing keys. NEVER copy *-private.pem to a Privora VPS, web server, source repository, CI artifact, support ticket, or release package.
Keep at least two encrypted offline backups under separate custody. Publish/record public-key fingerprints out-of-band before first release. Rotation requires dual review and an overlap/revocation plan.
TXT
chmod 0600 "$OUT/README.txt"
echo "Key ceremony complete in $OUT"
