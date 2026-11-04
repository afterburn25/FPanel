# Privora Panel 5.0.0-dev.6.93 — Scoped API Tokens & Automation Security

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Exposes issue/rotate/revoke token lifecycle with explicit scopes, expiry, owner binding and optional CIDR restrictions.
- Adds account-scoped PPanel tokens while preserving root/server-only APIs on PCC.
- Token secrets remain one-time values and all use remains audit-compatible.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
