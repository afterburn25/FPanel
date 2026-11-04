# Privora Panel 5.0.0-dev.6.8 — PHP-FPM Socket Permission Recovery

This recovery addresses the first clean Ubuntu 24.04 VPS health-check failure where the Privora HTTPS listener was present but Nginx returned HTTP 502.

## Root cause
The dedicated PHP-FPM pool created `/run/php/privora-panel.sock` as `privora-panel:privora-panel` mode `0660`, while Ubuntu Nginx workers run as `www-data`. Nginx therefore could not connect to the FastCGI socket.

## Fix
- Ubuntu/Debian installs now set the Privora FPM socket group to the Nginx worker group (`www-data` by default).
- RHEL-like installs use the `nginx` worker identity.
- Runtime reconciliation repairs the socket group in an already-written pool file before restarting PHP-FPM/Nginx.
- Final health now invokes runtime reconciliation again, making the fix resume-safe when earlier phases/certification are already journaled complete.
- Health still fails closed unless the FPM socket exists and Nginx is actually listening on the Privora port.

The existing dev.6.x installer journal is compatible. If `health` is unfinished, rerunning dev.6.8 skips completed phases and repairs the runtime before retrying health.
