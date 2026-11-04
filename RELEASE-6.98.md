# Privora Panel 5.0.0-dev.6.98 — Application Lifecycle Center

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds live WordPress/Laravel/Node/Python discovery and allow-listed lifecycle actions.
- Mutating application actions take a local pre-change backup and execute as the hosting account rather than root.
- Replaces the old deployment-simulation presentation with a live lifecycle workspace; Platform Labs remains explicitly simulation-gated.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
