# Privora Panel 5.0.0-dev.6.20 — Core Baseline Reconciliation

This recovery repairs hybrid dev.6.x installations whose original `source`/`privora_files` phases were journaled complete before later recovery builds were applied.

Key guarantees:
- stages the complete current Privora core rather than refreshing selected files only;
- preserves protected `/etc/privora-panel` secrets and `/var/lib/privora-panel` runtime/user state;
- validates staged PHP/JS/shell/Python and prebuilt agent/certification checksums before promotion;
- atomically swaps `/opt/privora-panel` with a rollback copy;
- validates the real PHP→agent bridge, authoritative live inventory and HTTPS panel after promotion;
- commits `/opt/privora-panel/VERSION` only after those production checks pass;
- restores the previous core automatically if post-promotion validation fails;
- updater EXIT guard converts any premature termination with `status=running` into an authoritative failed transaction.
