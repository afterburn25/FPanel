# Privora Panel 5.0.0-dev.6.85 — Professional Mail Center & Mailbox Lifecycle

Prepared from the exact certified 5.0.0-dev.6.84 source tree. This is a candidate release and does not change the accepted live baseline until its live upgrade gate is completed and explicitly accepted.

## Mail Center UX

- Reworks PCC and PPanel mail management into a dedicated, organized Mail Center.
- Mailbox creation uses a local-part field plus a domain dropdown populated from created/owned hosted domains.
- Alias / forwarder creation uses the same created-domain dropdown model.
- Mailbox creation requires an operator-entered password and confirmation (12–128 characters), with a browser-local strong-password generator.
- Privora does not persist plaintext mailbox passwords and does not echo operator-entered passwords back from the Agent.
- Adds mailbox, domain, and forwarder summary counts plus clearer live-inventory tables and client configuration panels.
- Removes the old browser alert that displayed a one-time generated mailbox password.

## Mailbox lifecycle

- Adds `PATCH /v1/mailboxes/{address}` for quota changes and optional password reset.
- Adds `DELETE /v1/mailboxes/{address}` for real transactional mailbox deletion.
- Mailbox edits deliberately do not rename the address or touch the existing Maildir.
- Mailbox deletion uses the existing transactional mail-map/Maildir rollback path.
- PCC and PPanel expose Edit and Delete actions with exact-address destructive confirmation.

## Forwarder lifecycle

- Adds `PATCH /v1/mail/aliases/{address}` to change a forwarder's destination.
- Adds `DELETE /v1/mail/aliases/{address}` to remove a real Postfix forwarder.
- Real Postfix alias-map changes are atomic and rollback if postmap or Postfix reload fails.
- PCC and PPanel independently enforce domain/account ownership before forwarding mutations.

## Security and source discipline

- Retains the typed privileged Agent architecture and existing Postfix/Dovecot/Rspamd security posture.
- Domain ownership is derived from live hosted-site inventory; UI selections are not trusted as authorization.
- Mailbox passwords are hashed with SHA512-CRYPT for Dovecot and never persisted to Privora state in plaintext.
- Exact-source direct-upgrade packaging refuses to patch an unknown 6.84 tree.
