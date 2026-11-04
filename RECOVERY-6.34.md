# Privora Panel 5.0.0-dev.6.35 — Atomic Panel Core Promotion

- Live `/opt/privora-panel` and the staged release are switched with Linux `renameat2(RENAME_EXCHANGE)`, so the panel root is never absent during promotion.
- Rollback uses the same atomic exchange.
- Update snapshots are mandatory, checksum-verified, and verified to contain the panel public entry points before promotion.
- Pre-promotion recovery restores mutable config/state only and never overwrites the live panel core.
- Post-promotion rollback atomically restores the previous core and restores config/state while excluding `/opt/privora-panel` from archive extraction.
- Staged releases must contain all critical web/updater/agent files before migrations or promotion.
- Privora agent refresh remains deferred until the transaction is terminal.
