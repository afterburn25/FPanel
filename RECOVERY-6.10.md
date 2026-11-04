# Privora Panel 5.0.0-dev.6.10 — Runtime State Recovery

Recovery for a clean Ubuntu 24.04 installation that reaches the final health phase but returns HTTP 500.

The production PHP worker runs as `privora-panel`. Earlier recovery builds corrected code-tree and FastCGI-socket permissions, but the parent `/var/lib/privora-panel` directory could remain `root:root 0750` from the initial `umask 027` creation. That prevents the worker from traversing to `/var/lib/privora-panel/web`, causing session/state access to fail.

This recovery reconciles the parent runtime directory to `root:privora-panel 0750`, keeps the writable web state/session/tmp subtree private to `privora-panel` (`0700`), preserves the state file at `0600`, proves traversal/write access as the service identity, and executes the real PHP bootstrap as `privora-panel` before the HTTP health check.
