# Privora 6.60 Recovery Notes

If the update health gate fails, the normal atomic updater must restore 6.59 automatically. The post-pass Nginx reconciler backs up all touched site files, runs `nginx -t`, restores them on validation failure, and reloads Nginx only after a clean validation. AutoSSL preflight challenge files are temporary and removed after each probe.
