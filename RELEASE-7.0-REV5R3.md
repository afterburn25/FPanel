# Privora Panel 5.0.0-dev.7.0 Rev5 Rev3

Canonical PCC Build Truth & Rollback Reliability Repair

- Retains the Rev5 database-owner dropdown and Rev5 Rev2 PPanel database package-capacity repair.
- Corrects the live installer acceptance probe to request the canonical PCC hostname from `/etc/privora-panel/tls/panel-certificate-source.env` with local DNS resolution to `127.0.0.1:8443`.
- Uses a normal HTTPS GET and still requires the exact `X-Privora-Build: 5.0.0-dev.7.0` response header.
- Strengthens post-promotion rollback so any failed live acceptance path restores the predecessor tree before the installer exits.
- Does not change the underlying VERSION, database schema, hosted-site data, mail, DNS, or TLS configuration.
