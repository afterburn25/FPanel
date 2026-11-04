# Privora Panel 5.0.0-dev.6.43 Recovery Notes

## Friendly identity
The underlying Linux username remains unchanged. Normal website/account views show the primary domain; use technical account details or logs when the raw system identifier is actually needed.

## Website missing status
`Needs attention` means Privora has durable metadata for the domain but the current live-host Nginx inventory did not return it. The domain is intentionally kept visible.

Recovery procedure:
1. Inspect Live Host Discovery diagnostics.
2. Validate `nginx -t` and inspect the effective `nginx -T` server block for the domain.
3. Confirm the vhost has a valid `server_name` and document root.
4. Restore/enable the vhost if necessary and reload Nginx.
5. Refresh Privora; the website returns to Active automatically when discovery sees it.

Do not delete and recreate a website merely because it is marked Needs attention.

## Subdomain creation
The Subdomain Name field accepts one label only. Choose the parent from the adjacent existing-domain dropdown. A domain marked Needs attention is shown for visibility but cannot be selected until its live vhost is healthy.
