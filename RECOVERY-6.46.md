# Privora Panel 5.0.0-dev.6.46 — Recovery API Mutation Repair

- Supersedes quarantined 6.45.
- Fixes malformed embedded-Python quoting in `scripts/apply-recovery-vhost.sh`.
- Adds executable mutation-path verification so recovery-vhost repair must successfully generate and validate the dedicated JSON `/api.php` fallback from an older Nginx configuration.
- Retains stable release trust, automatic Let’s Encrypt/AutoSSL retry, friendly hosting identities, durable website visibility, and the subdomain builder.
