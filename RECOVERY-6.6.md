# Privora Panel 5.0.0-dev.6.6 Runtime Reconcile Recovery

This recovery addresses a clean Ubuntu install where the phase journal marked `services=done` but Nginx never began listening on 8443 and the Privora PHP-FPM pool may not have been loaded. Package installation can start Nginx/PHP-FPM before Privora writes its configs; `systemctl enable --now` does not reload already-running services.

Before machine certification, dev.6.6 now validates the Privora Nginx/PHP-FPM configuration, explicitly restarts PHP-FPM, reloads/restarts Nginx, confirms the dedicated FPM socket exists, and confirms the configured Privora port is listening. The normal services phase also uses explicit runtime activation going forward.
