# Privora Panel 5.0.0-dev.6.88 — Live Mail Readiness & Authentication Lifecycle

- Mail-domain badges refresh from live DNS and server TLS state instead of stale creation-time metadata.
- TLS readiness accepts the certificate actually configured in Postfix/Dovecot, including wildcard SAN certificates such as `*.example.com`.
- Adds **Remove authentication** for domain authentication rows in PCC and PPanel.
- Removal deletes Privora-managed SPF, `mail._domainkey` DKIM and DMARC authentication records plus the Privora DKIM private key.
- Website, DNS zone, mail A/AAAA, MX, mail host, TLS, mailboxes, aliases and Maildir data are preserved.
- Exact-domain confirmation is required and ownership/scope is revalidated server-side.
