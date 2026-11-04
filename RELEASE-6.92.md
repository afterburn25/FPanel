# Privora Panel 5.0.0-dev.6.92 — Backup Center 2.0 & Verified Restore

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds scheduled local site/account backup policies, retention pruning, run-now, archive verification and durable status.
- Adds an Agent background scheduler so policies execute while PCC/PPanel is closed and verifies backups when requested.
- Keeps live restore limited to the already-certified site restore path; unsupported remote destinations/scopes fail closed.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
