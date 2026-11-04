# Privora Panel 5.0.0-dev.6.87 — Mail Domain Live Configuration & DKIM DNS Reliability

- Fixes BIND rendering of long TXT records such as 2048-bit DKIM keys by emitting legal adjacent <=240-byte character strings and parsing them back as one logical TXT value.
- Adds a read-only live mail-domain configuration endpoint backed by actual Dovecot/Postfix configuration, service state, TLS material and live TCP listener checks.
- PCC and PPanel Mail Domain tables now include Manage / Setup.
- Per-domain setup displays IMAP, POP3 and SMTP servers, actual enabled ports, TLS mode, authentication requirement, username format, listener state, DKIM selector and a copyable mail-client configuration block.
- SMTP port 25 is identified as server-to-server delivery rather than normal authenticated client submission.
- No plaintext mailbox password is read or displayed.
