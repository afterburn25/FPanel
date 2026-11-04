# Privora Panel 5.0.0-dev.6.68 — DNS Transaction, Site Reconciliation & AutoSSL Truth

- AutoSSL proves the local Host-header/webroot path and treats its own public hairpin request as advisory; Certbot/Let’s Encrypt performs authoritative external validation. Production self-probes bypass environment proxies.
- DNS record edits are true replace transactions preserving original identity; changing name/type cannot leave stale records. SOA/apex NS remain protected.
- Recorded DNS zones are checked against the running authoritative nameserver before they can be marked missing.
- Changing the default nameserver set persists established root-domain selections before the switch and explicitly assigns the new base domain to its own set.
- Public glue is considered usable when either configured IP family is confirmed, with IPv4/IPv6 readiness exposed separately.
- Missing Nginx website mappings can be reconstructed from durable hosting identity, existing document root and existing PHP-FPM pool without recreating files/accounts.
- ACME probe clients clone production HTTP transports with proxy routing disabled even when an HTTP client is injected; controlled non-HTTP test transports remain preserved.
- Direct-upgrade acceptance validates the exact `/v1/health` version and running agent executable hash rather than depending on a short journal tail that can rotate past the startup line during multi-site preflight.
- AutoSSL normalizes only the public challenge path after creation: `.well-known` and `acme-challenge` are forced to 0755 and the temporary token to 0644. This explicitly defeats the privileged agent service's `UMask=0007`, which otherwise turned 0755/0644 requests into 0750/0640 and caused Nginx to return HTTP 403 for every challenge.
