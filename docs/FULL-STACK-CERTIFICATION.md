# Clean-VPS Full-Stack Certification

Privora does not infer that an adapter works merely because its package was requested by the installer. A managed VPS receives a machine-bound certification artifact after destructive-safe probes run on that exact machine.

For a full hosting node the bootstrap invokes:

```bash
PRIVORA_CERT_ROLE=full PRIVORA_CERT_REQUIRE_FULL=1 ./scripts/vps-host-certify.sh
```

A full installation is promotable only when the evidence status is `PASS` and all required adapters are present. A `PARTIAL` or `FAIL` artifact is not accepted by the privileged agent as portable proof and must never be copied to another machine.

The current development sandbox intentionally demonstrates the negative path: because its package repositories cannot currently resolve, missing hosting services remain uninstalled and full certification returns `FAIL` with an exact adapter list. This is preferable to a control panel that completes setup while major hosting services are absent.

On the intended fresh VPS, the certification sequence should follow installation of the complete role package set and should test at minimum Linux-user lifecycle, account containment, Nginx/PHP-FPM config validation/rollback, databases, DNS, ACME, nftables, Postfix/Dovecot/Rspamd, SFTP jail, quotas, cgroup-v2 and verified backup/restore primitives.
