# Privora Panel 5.0.0-dev.6.9 — Panel Runtime Permission Recovery

This recovery addresses the first clean Ubuntu 24.04 full-stack install reaching the final health phase and returning HTTP 500 after the prior FastCGI socket-group recovery. The production release tree under `/opt/privora-panel` can inherit a root-only `0750` top-level directory from the installer umask, preventing the dedicated PHP-FPM identity and Nginx worker from traversing/reading the panel code even though the FastCGI socket itself is reachable.

The recovery reconciles only the panel code tree: `/opt/privora-panel` and `panel/` become root-owned `0755`; `panel/public` is root-owned/readable for Nginx static/front-controller access; `panel/src` is root:`privora-panel` with `0750/0640`. Secrets remain under `/etc/privora-panel` and runtime state under `/var/lib/privora-panel`; they are not made public.

The unfinished `health` phase re-applies this permission reconciliation, validates/restarts PHP-FPM and Nginx, and emits Nginx/PHP-FPM diagnostic tails if the HTTP health endpoint is still not successful. Existing dev.6.x phase journals remain compatible.
