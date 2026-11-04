# Privora Panel 5.0.0-dev.6.99 — DNSSEC, Templates & Dynamic DNS

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds BIND DNSSEC status/enable/disable with DS output for registrar publication.
- Adds PCC DNS templates with safe save/apply/delete and PPanel Dynamic DNS guidance through scoped dns.write API tokens.
- Preserves authoritative-zone ownership boundaries and existing nameserver/delegation workflows.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
