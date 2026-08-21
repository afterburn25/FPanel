# Privora Control Suite

Development and certification repository for the Privora hosting control platform.

## Official control surfaces

- **Privora Command Center (PCC)** — server/root/reseller administration. Default direct access: `https://host:8443`. Convenience access: `https://domain/pcc`.
- **Privora Panel (PPanel)** — hosting-user control panel. Default direct access: `https://host:2443` unless that port is occupied. Convenience access: `https://domain/ppanel`.

The `/pcc` and `/ppanel` paths are convenience redirects into the isolated listeners; PCC and PPanel retain separate session/authentication scopes.

## Release discipline

GitHub tests must pass before a build is allowed onto the live VPS. Routine upgrades are delivered through Privora Update Center. Direct SSH/PowerShell upgrades are emergency-only.

Current development checkpoint: **5.0.0-dev.6.61 — Update Reliability & Live Domain Reconciliation Repair**.

6.61 carries forward the PCC/PPanel identity and routing work plus DNS Zone Manager reconciliation, website status/editing, AutoSSL/certificate inventory, nameserver/registrar workflow, recovery-safe API, package-type guards, version-consistency repairs, and the 6.60 HTTP-01 work. It adds fail-soft Update Center status, bounded migration execution, PCC session-preserving routine updates, known-domain DNS visibility, local authoritative DNS listener discovery, and legacy-vhost document-root reconciliation.
