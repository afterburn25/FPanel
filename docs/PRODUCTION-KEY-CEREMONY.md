# Production Signing-Key Ceremony

Privora has two independent signing authorities: **core release** and **curated application catalog**. The private keys must never exist on a managed VPS or public download server.

`release/key-ceremony-offline.sh` is provided for an isolated workstation. It generates encrypted RSA-4096 keys and public-key SHA-256 fingerprints. An HSM-backed equivalent is preferred for commercial production.

After dual-reviewing the public fingerprints, use `release/set-production-public-keys.sh CORE_PUBLIC APP_PUBLIC` on the release-engineering source tree. This updates the core public key file, the bootstrap's embedded core key, and the app-catalog public key. Only public keys are committed/shipped.

Before first public release, test recovery, key rotation, emergency revocation, and a second-person release approval process.
