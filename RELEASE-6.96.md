# Privora Panel 5.0.0-dev.6.96 — Advanced Website & Domain Policies

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds Force HTTPS, HSTS, HTTPS redirect, directory-index and hotlink-protection policy management.
- Reconciles policy into certified Nginx configuration with syntax validation and rollback.
- PPanel changes are restricted to domains owned by the authenticated hosting account.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
