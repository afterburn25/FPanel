# Privora Panel 5.0.0-dev.7.0 Rev5 Rev4 — PCC Runtime Readiness Acceptance Repair

Release date: 2026-09-07 UTC

- Retains Rev5 database-owner dropdown and Rev5 Rev2 package-capacity repair.
- Retains Rev5 Rev3 canonical PCC hostname build-truth verification and rollback hardening.
- Repairs the live acceptance race by waiting for privora-panel-fpm.service, /run/php/privora-panel.sock, and a healthy canonical PCC HTTPS response before requiring X-Privora-Build.
- The build-truth gate remains fail-closed and still requires exactly X-Privora-Build: 5.0.0-dev.7.0.
- On failure, diagnostics include HTTP status, response headers, FPM service state, socket state, and recent Nginx/Privora FPM logs before rollback.
- Underlying VERSION remains 5.0.0-dev.7.0.
