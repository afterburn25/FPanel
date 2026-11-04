# Privora Panel 5.0.0-dev.6.24 — PHP-FPM Restart Rate-Limit Recovery

Source baseline: exact 5.0.0-dev.6.23 fresh-installer runtime-hardening candidate.

## Fixes

- Controlled installer/runtime PHP-FPM restarts now clear systemd service start-rate counters before restarting the dedicated PHP 8.4 FPM service. This prevents sequential recovery/reconciliation phases from failing with `start-limit-hit` even when each individual PHP-FPM configuration is valid.
- Retains dev.6.23 ZIP permission normalization for bundled runtime executables.
- Retains non-blocking behavior for the non-live `downloads.privora.example` development app catalog unless `--require-app-catalog` is explicitly selected.
- Retains complete-package probing before attempting optional PHP-version installation.

## Promotion boundary

This remains a fresh-install candidate until verified end-to-end on the target VPS.
