# Privora Panel 5.0.0-dev.6.94 — Monitoring & Resource Analytics 2.0

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds live CPU, memory, disk, load, service and mail-queue telemetry plus persisted five-minute historical samples.
- Adds alert rules and incident lifecycle with automatic open/resolve evaluation in the Agent background worker.
- Keeps customer analytics account-scoped while server-wide health remains PCC-only.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
