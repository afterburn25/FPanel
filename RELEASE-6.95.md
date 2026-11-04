# Privora Panel 5.0.0-dev.6.95 — Security Advisor & Hardening Center

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds live security findings for firewall, fail2ban, mail-auth drift, SSH policy and Privora runtime permissions.
- Adds allow-listed repair actions with validation/rollback where applicable.
- Withholds SSH lockout-risk hardening unless a usable administrative authorized_keys entry exists.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.
