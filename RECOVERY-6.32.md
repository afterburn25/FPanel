# Privora Panel 5.0.0-dev.6.33 — Deferred Agent Refresh

Fixes Update Center stalls at `Restart: restarting Privora agent`.

The privileged update worker no longer synchronously restarts the API agent while
an update transaction is active. It validates the promoted agent binary, keeps the
currently running agent alive for progress/rollback reporting, completes FPM/Nginx
health checks, marks the transaction PASS, and only then schedules a detached agent
refresh. Rollback uses the same terminal-journal-first model.

Also corrects the packaged agent systemd unit to the canonical
`/usr/local/libexec/privora-agent` path and aligns active version surfaces to 6.32.
