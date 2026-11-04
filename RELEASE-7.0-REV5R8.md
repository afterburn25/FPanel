# Privora Panel 5.0.0-dev.7.0 Rev5 Rev8

## Dovecot canonical block rendering repair

Rev5 Rev8 fixes a mail-service reconciliation failure on Dovecot 2.3.x where Privora emitted nested Dovecot blocks on a single line. Dovecot rejected the generated `/etc/dovecot/conf.d/99-privora-mail.conf` with `Garbage after '{'`.

The generator now renders LMTP listeners, IMAP/POP3 listeners, plugin/protocol blocks, and per-host `local_name` TLS SNI blocks using canonical multiline Dovecot syntax. Virtual passwd-file authentication, mail TLS routing, and existing mail data remain unchanged.

This candidate is not accepted/live until installed and verified on the target server.
