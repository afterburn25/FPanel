# Privora Panel 5.0.0-dev.6.91 — Mail Operations & Delivery Diagnostics

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds live Postfix queue inspection with safe retry/delete operations on PCC.
- Adds delivery-history search and mailbox-level Sieve filters; PPanel is restricted to its own mailbox addresses.
- Keeps Postfix/Dovecot virtual-user authentication from 6.89 as the single mail identity source.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
