# Privora Panel 5.0.0-dev.6.30 — Update Health Observability & Readiness Recovery

- Update Center now journals and displays Health/Restart sub-operations instead of a single opaque stage label.
- Dedicated `privora-panel-fpm.service` is restarted instead of double-restarting shared website PHP-FPM.
- Health waits for the panel FPM service and `/run/php/privora-panel.sock` before HTTPS probing.
- HTTPS health accepts normal panel/login responses (2xx, redirects, 401, 403) and records the last HTTP code on failure.
- Curated app-catalog refresh skips non-live `.example` development targets and uses strict connect/overall timeouts for real endpoints.
- Update failure journals now record the failing phase, line, command, and operation.
- Migration avoids restarting shared PHP-FPM when the panel is already isolated.
