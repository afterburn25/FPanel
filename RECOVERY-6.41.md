# Privora Panel 5.0.0-dev.6.41 Recovery Notes

6.41 is built forward from the verified 6.40 core and retains the atomic Update Center recovery model.

## Update transaction recovery
- Failure before promotion leaves the live core in place and restores only transaction-managed mutable state when required.
- Failure after promotion uses the atomic exchange rollback path; do not manually delete `/opt/privora-panel` or `/opt/privora-panel.releases`.
- The update status API remains alive through terminal PASS/rollback and the Privora agent refresh is deferred until after terminal state.

## State compatibility
- Package and Feature Manager additions are JSON-backed and additive.
- Update snapshots protect `/var/lib/privora-panel` state. A transaction rollback restores the captured state together with the prior core where appropriate.
- Do not hand-edit package/feature/account JSON during an update transaction.

## Backup restore recovery
- Certified real restore in 6.41 is limited to site backups with a recorded SHA-256.
- Before publication, the current site directory is renamed to `<site>.privora-before-restore-<timestamp>`.
- If publication fails, Privora attempts to restore that rollback directory automatically.
- Do not remove the rollback sibling until the restored site has been verified.
- Account/server restore is not exposed as a live destructive operation in this release.

## Database recovery
- Password rotation and destructive deletion are available only for Privora-managed databases/users.
- Discovered external databases are inventory-only for destructive lifecycle actions.
- A rotated password is shown once; it is not retained in plaintext Privora state.

## Capability-gated modules
Mail daemons, phpMyAdmin, Fail2Ban, ModSecurity, ClamAV, remote migration execution and live DNS-cluster replication depend on detected/certified host adapters. A missing dependency should be shown as unavailable/gated rather than emulated.

## Permission invariants
- `/opt/privora-panel.releases` must be 0755.
- Staged/live code directories must be 0755.
- Non-executable release files must be 0644.
- Required scripts and `dist/privora-agent` must be executable.
- `privora-panel` must be able to traverse the release path and read `panel/public/index.php` and `panel/public/api.php`.

## Panel-side webmail integration
- Hosting panel Email group includes a first-class Webmail tool.
- Host capability detection recognizes Roundcube, SnappyMail, and RainLoop.
- Launch is fail-closed: Privora exposes an Open Webmail action only when `/etc/privora-panel/webmail.env` supplies a relative or HTTPS `PRIVORA_WEBMAIL_URL` and a supported client is detected.
- Feature Manager includes a `webmail` entitlement; customer passwords are never stored by Privora.
- Mail Server Suite shows webmail readiness alongside Postfix/Dovecot/Rspamd.
