# Privora Control Suite

Development and certification repository for the Privora hosting control platform.

## Official control surfaces

- **Privora Command Center (PCC)** — server/root/reseller administration. Default direct access: `https://host:8443`. Convenience access: `https://domain/pcc`.
- **Privora Panel (PPanel)** — hosting-user control panel. Default direct access: `https://host:2443` unless that port is occupied. Convenience access: `https://domain/ppanel`.

The `/pcc` and `/ppanel` paths are convenience redirects into the isolated listeners; PCC and PPanel retain separate session/authentication scopes.

## Release discipline

GitHub tests must pass before a build is allowed onto the live VPS. Routine upgrades are delivered through Privora Update Center. Direct SSH/PowerShell upgrades are emergency-only.

Current development checkpoint: **5.0.0-dev.6.57 — PCC/PPanel Identity & Dual Access Routing**.

This checkpoint also carries forward the DNS Zone Manager reconciliation, DNS readiness, website status/editing, AutoSSL/certificate inventory, nameserver/registrar workflow, recovery-safe API, package-type guards, and version-consistency repairs from the preceding development train.
