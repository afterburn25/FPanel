# Privora Panel 5.0.0-dev.6.11 — PHP Bootstrap Probe Recovery

Recovery for the first clean Ubuntu 24.04 VPS after dev.6.10 reached the final health phase and the service-identity PHP bootstrap probe failed with `PHP Parse error: syntax error, unexpected end of file in Command line code on line 1`.

The failure was in the health probe itself: a malformed inline `php -r` command contained broken shell/PHP quoting. dev.6.11 replaces that inline command with a root-created temporary PHP file, runs it under the real `privora-panel` service identity with the protected environment loaded, validates the exact success marker, emits probe stderr/stdout on failure, and removes the temporary files. The existing dev.6.x phase journal remains compatible, so an unfinished health phase resumes without replaying completed certification.
