# Privora Panel 5.0.0-dev.6.51 — Direct Upgrade Readiness Repair

This checkpoint supersedes the failed 6.50 direct-upgrade delivery path while retaining all 6.50 core/UI features.

## Direct-upgrade repair

- Direct development upgrades now wait for the panel PHP-FPM service and dedicated socket before HTTP validation.
- Panel and API probes use bounded retry loops rather than a single immediate request after restart.
- Failed health probes persist root/API response bodies, headers, service status, Nginx errors, and PHP-FPM errors into the direct-upgrade transaction directory before rollback.
- The Privora agent is not synchronously restarted inside the upgrade transaction. Agent refresh is scheduled only after the panel passes health checks.
- A failed promotion still atomically restores the previous certified core.

The 6.50 direct-upgrade package must not be retried. Use the 6.51 direct-upgrade bundle.
