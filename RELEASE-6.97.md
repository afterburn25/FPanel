# Privora Panel 5.0.0-dev.6.97 — Database Activity & Session Controls

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds MySQL/MariaDB/PostgreSQL activity inspection and allow-listed session termination.
- PPanel only sees sessions whose database belongs to its hosting account and revalidates ownership before termination.
- Preserves existing database/user lifecycle, phpMyAdmin and credential handling.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
