# Production gates

## Gate A — single-host mutation safety (1.0)

Every enabled adapter must have typed inputs, no shell-string execution, strict validation, dependency probes, machine-bound certification, preflight validation where applicable, rollback/compensation, timeout/cancellation, audit evidence and supported-host integration tests.

Already live-certified in the current disposable host: Linux account create/suspend/unsuspend, account file containment, local backup and real Nginx parser validation.

Still required for 1.0: live quota/cgroup, PHP-FPM, DB, authoritative DNS, ACME, mail, SFTP and nftables certification plus restore, migration, load and destructive failure testing.

## Gate B — remote node trust (2.0)

Implemented core: TLS1.3 mTLS, persistent replay defense and durable enrollment/rotation/revocation registry.

Production still requires protected CA custody, approved bootstrap, revocation distribution, remote convergence and partition/fleet-update certification.

## Gate C — cloud provisioning (3.0)

Implemented core: durable lifecycle intents/results, idempotency, exact destructive confirmation and encrypted secret vault.

Production still requires provider-specific adapters, operational credential rotation, signed node bootstrap, teardown reconciliation and cost/resource tagging.

## Gate D — commercial automation (4.0)

Implemented core: restart-durable compensating orders and a tamper-detectable double-entry ledger.

Production still requires verified provider webhooks, payment reconciliation, subscriptions/refunds, billing-driven suspend safeguards and end-to-end commercial retry tests.

## Gate E — distributed fabric (5.0)

Implemented core: persistent placement, health-aware replanning, majority-observation fence intent and healthy-backend route plans.

Production still requires explicit data consistency semantics, real replication, deployed consensus/fencing authority, traffic routing, regional failure drills and chaos certification. A local quorum algorithm is not itself distributed consensus.

## One-command VPS bootstrap / updater gate (dev.5)

Implemented: supported-OS detection, resumable installer phases, apt/dnf package/library maintenance, hosting-stack install plans, dedicated PHP-FPM panel identity, protected root-agent socket, Nginx frontend, generated secrets, automatic maintenance timer, machine certification hook, signed safe updater, atomic promotion and rollback helper.

Still required before calling the hosted installer production-ready:

- publish real Privora install/update endpoints;
- replace the development release public key with the production offline/HSM-controlled signing public key;
- destructive clean-VPS certification on each supported Ubuntu/Debian/AlmaLinux/Rocky release;
- installer failure-injection across package-manager/network/reboot interruptions;
- real database/mail/DNS/PHP/ACME/nftables integration certification on those targets;
- release rollback testing across database migrations and supported package transitions;
- recovery procedure for interrupted package-manager/kernel updates.
