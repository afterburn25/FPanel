# Privora Panel 5.0.0-dev.6.89 — Virtual Mail Authentication Core Repair

**Status:** prepared candidate. Do not treat as accepted/live until installed and verified on the target VPS.

## What this repairs

- Makes Privora-managed virtual mailboxes authenticate through Dovecot `passwd-file` using `/etc/privora-mail/dovecot_users` for both `passdb` and `userdb`.
- Disables the active `auth-system.conf.ext` path when Privora virtual mail is enabled so managed email addresses do not fall back to PAM or Linux `/etc/passwd`.
- Preserves full-address login (`user@domain`), `{SHA512-CRYPT}` password hashes, per-user UID/GID, home, Maildir and quota fields.
- Reasserts `/etc/privora-mail` as protected group-readable state and `dovecot_users` as `root:privora-panel 0640` after every atomic mailbox-map replacement.
- Gives Dovecot `auth` and `auth-worker` processes an explicit `privora-panel` primary group so the protected password database remains readable without making it world-readable.
- Configures Postfix SMTP submission (587/465) to authenticate through the same Dovecot socket at `private/auth`; no second password database is introduced.

## Durable reconciliation

- Adds an idempotent core `ReconcileMailAuthentication` path used by mailbox create, password/quota update and delete.
- Adds `scripts/reconcile-mail-auth.sh` to the fresh-install/mail-service reconciliation path.
- Validates effective Dovecot `passdb`/`userdb`, rejects PAM/system-passwd fallback, runs `doveconf -n`, validates Postfix SASL settings and `postfix check`, restarts services, checks active state, and resolves a known Privora mailbox with `doveadm user`.
- Generated Dovecot/Postfix configuration is snapshotted and restored if validation or post-restart certification fails.
- Mailbox create/password-reset certification runs `doveadm auth test` with the plaintext password on stdin, not in process arguments or surfaced error text.

## Regression coverage

- Dovecot auth selector rewrite is idempotent and removes active system authentication.
- Effective auth validation requires both `passdb` and `userdb` to be `passwd-file`.
- Password reset changes the stored hash while preserving Maildir/quota metadata and `0640` protection.
- Full-address mailbox lookup and real Dovecot auth certification paths are exercised.
- SMTP AUTH is pinned to the Dovecot `private/auth` socket for both submission services.
- Fresh-install reconciliation is shell-syntax checked and exercised in a hermetic command simulation before packaging.

## Preserved state

This migration does not intentionally change existing mailbox contents, mailbox passwords (unless explicitly reset), domains, aliases, DKIM/SPF/DMARC, TLS certificates, Postfix queues, Maildir ownership, quotas or Privora state records.
