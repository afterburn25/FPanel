# Privora Panel 5.0.0-dev.6.44 — Reliable Signed Updates + Automatic Let's Encrypt

- Routine release signing uses one stable release trust key; the package builder refuses a private key that does not match the public key embedded in the core.
- Every generated Update Center ZIP is self-verified with the embedded public key before delivery.
- New websites and subdomains automatically attempt Let's Encrypt issuance after provisioning.
- DNS not yet propagated does not roll back site creation; SSL remains Pending and AutoSSL can retry later.
- Successful issuance rewrites the Privora-managed Nginx vhost for HTTPS and HTTP→HTTPS redirect, validates Nginx, reloads it, and rolls back the vhost if validation/reload fails.
- Certbot is installed for full and web roles; renewal timer is enabled when provided by the platform package.

- Pending certificates are retried automatically by `privora-autossl.timer` approximately every 30 minutes, with jitter.
