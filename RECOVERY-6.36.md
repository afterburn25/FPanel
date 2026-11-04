# Privora Panel 5.0.0-dev.6.36 — Validation Isolation & Exact Failure Reporting

Repairs the uploaded-update Validation gate after dev.6.35. Live Nginx recovery-mode edits are no longer performed inside pre-promotion migrations. The migration installs only the static recovery page. Recovery-vhost configuration is deferred until after the update transaction reaches PASS and is applied by a rollback-safe helper that validates Nginx before reload.

Validation now journals explicit Nginx and per-file PHP validation operations, captures Nginx/PHP diagnostic output, and reports the exact relative PHP file on failure. The live panel root remains untouched until validation succeeds and atomic promotion begins.
