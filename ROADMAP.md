# Privora Panel Roadmap — 5.0.0-dev.6 One-Command Bootstrap + Safe Updater

Version numbers describe capability gates. A development contract is not a production backend, and simulations are never promoted solely because the UI exists.

## 0.1–0.18 — secure hosting foundation — VERIFIED DEV

- [x] Privileged Go agent, Unix socket transport, service allow-list and audit trail.
- [x] Authentication, Argon2id, sessions, CSRF and RBAC.
- [x] Privora Panel (PPanel) customer shell + Privora Command Center (PCC) administrator shell.
- [x] Backend-enforced hosting-user account scope and cross-account denial.
- [x] Hosting accounts/sites, PHP 8.2–8.5 routing, safe mock files, SFTP models, databases, DNS, SSL state, backups, mailboxes, reseller and firewall/application models.
- [x] Expanded PPanel account controls: redirects, custom error pages, MIME types, directory privacy, hotlink policy, autoresponders, spam policy, PHP options/extensions, IP blocking, SSH public keys and restore requests.
- [x] Curated app-installer catalog and account-scoped install plans for WordPress, Joomla, Drupal, Grav, phpBB, PrestaShop, Nextcloud, Moodle, Matomo and Laravel.

## 0.19–0.29 — tasks, deployments and mail — IMPLEMENTED DEV

- [x] Cron/task records and safe mock execution state.
- [x] Git/Laravel/WordPress/Node/Python deployment plans and step evidence.
- [x] Mail-domain policy, DKIM/SPF/DMARC intent, aliases and outbound limits.
- [x] Mail reputation-check records.
- [x] Certified curated app signed-download/safe-extract/private-stage/atomic-publish adapter with WordPress and Joomla headless bootstrap.
- [ ] Real cron installation, additional app-specific headless bootstraps beyond WordPress/Joomla, package/runtime installers and Postfix/Dovecot/Rspamd/webmail adapters.

## 0.30–0.39 — security, audit and monitoring — IMPLEMENTED DEV

- [x] Firewall-rule contract; host mutation gated.
- [x] Brute-force ban records, malware scan records and integrity checks.
- [x] SSH hardening policy model.
- [x] Security posture scoring.
- [x] HMAC-SHA256 panel→agent authentication with timestamp/nonce/replay rejection.
- [x] Cryptographically hash-chained privileged audit log and verifier.
- [x] Metrics, alert rules and incident models.
- [ ] Production nftables/firewalld backend, malware scanner adapter, off-host audit export and monitoring daemon.

## 0.40–0.49 — operating controls and resellers — IMPLEMENTED DEV

- [x] Update policy and resource-limit/cgroup intent.
- [x] One-command root VPS bootstrap with resumable phases, automatic packages/libraries, stack install, service setup, admin bootstrap, certification and health checks.
- [x] Safe updater with snapshots, signed release verification, dependency updates, migration hooks, atomic promotion, health checks and rollback.
- [x] Nightly systemd maintenance timer; security + normal package/library patches automatic by default, major-version upgrades approval-gated.
- [x] PCC Update Center host-policy sync and typed update-job launch.
- [x] Process/storage/network inventory contracts.
- [x] Reseller branding model.
- [x] PCC Ctrl+K command palette navigation.
- [x] Offline key-ceremony, signed release builder/verifier, signed channel metadata and static delivery-root tooling implemented.
- [ ] Production release-signing key custody/HSM ceremony, live delivery endpoints, multi-distribution destructive installer certification, cgroup/quota certification, storage/network mutators and privileged terminal isolation.

## 0.50–0.59 — delegation, migration and clusters — IMPLEMENTED DEV

- [x] Delegated user/permission records.
- [x] cPanel/DirectAdmin/Plesk/generic migration plans with staged/delta-sync evidence.
- [x] Server cluster and load-balancer contracts.
- [ ] Real cPanel import parser/certification, mTLS remote-agent transport, PKI lifecycle, DNS/backup/database/mail cluster adapters.

## 0.60–0.69 — provisioning, API and CLI — IMPLEMENTED DEV

- [x] Provisioning profiles.
- [x] Scoped API key issuance; raw secret returned once, hash stored at rest.
- [x] External REST surface with hardcoded resource/scope map.
- [x] `privora` CLI for health/accounts/sites/horizons/account/site/backup/DNS/SSL operations.
- [x] Webhook registration contract.
- [ ] Real cloud-provider adapters, webhook delivery/signature engine and secret-vault integration.

## 0.70–0.79 — extensions and business automation — IMPLEMENTED DEV CONTRACTS

- [x] Plugin installation records.
- [x] Invoice and notification contracts.
- [x] Existing account→site→DNS→certificate automation simulation.
- [ ] Payment gateway adapters, subscription lifecycle, verified payment webhooks, real marketplace and support desk.

## 0.80–0.89 — diagnostics, recovery and update trust — IMPLEMENTED DEV

- [x] Diagnostic/repair records and before-state intent.
- [x] Configuration revision records.
- [x] Secret-reference model that stores references instead of secret material.
- [x] Signed-release metadata contract.
- [x] TOTP MFA with encrypted-at-rest enrollment secret.
- [x] Typed host-operation planner with explicit validation/rollback and `executable:false` gate.
- [x] Cryptographic release manifest/signature/checksum verifier and rollback-aware update transaction implementation.
- [ ] Hardware-backed/external vault, passkeys/recovery codes, production signing-key custody and destructive rollback certification on supported VPS distributions.

## 0.90–0.99 — portability, staging, isolation and certification — IMPLEMENTED DEV

- [x] Portable account-export manifest contract.
- [x] Performance recommendations.
- [x] Staging environment records.
- [x] Site-isolation policy intent.
- [x] Certification/evidence gate records.
- [ ] Real encrypted archive/restore, production staging sync, namespace/cgroup enforcement and destructive failure-injection certification.

## 1.0 — Privora Panel/PCC-class single-server release — PARTIAL REAL / PRODUCTION BLOCKED

- [x] 6.70 database lifecycle: one-time create/reset credentials, database-user edit, account-scoped delete, and phpMyAdmin-ready access without plaintext password persistence.
- [x] Machine-bound host certification gate; `--host-mutations` alone cannot enable adapters.
- [x] Live Linux account create plus reversible suspend/unsuspend.
- [x] Root-owned SFTP-chroot account root with customer-owned writable subdirectories.
- [x] Real account file list/write with `openat`/`O_NOFOLLOW` and symlink escape rejection.
- [x] Verified local `.tar.zst` backup with SHA-256.
- [x] Generated Nginx vhost accepted by real Nginx parser.
- [x] Controlled transactional adapters for PHP-FPM, DB, DNS, ACME, nftables, quota, cgroup v2, mail, SFTP and cPanel staging.
- [ ] Live-certify those service adapters on supported hosts where dependencies are installed/writable.
- [x] Full-role bootstrap/certification is fail-closed and refuses partial hosts.
- [ ] Complete restore, deletion/rollback, full cPanel import, live full-stack VPS certification, load/failure/security certification.
## 2.0 — Multi-server platform — DURABLE CORE / PRODUCTION BLOCKED

- [x] TLS 1.3 mutual-TLS channel and typed command executor.
- [x] Durable replay guard survives restart.
- [x] Persistent node certificate registry.
- [x] Enrollment, certificate rotation, old-fingerprint revocation and explicit revoke.
- [ ] Production CA custody/bootstrap/revocation distribution.
- [ ] Real remote convergence and network-partition/fleet-update certification.
## 3.0 — Hosting cloud — DURABLE CORE / PRODUCTION BLOCKED

- [x] Provider lifecycle interface and safe destructive-delete confirmation.
- [x] Durable create/delete intent and idempotency state; ambiguous restart state fails closed.
- [x] AES-256-GCM secret vault with authenticated encryption and versioned rotation.
- [ ] Real cloud provider API adapters and operational credential injection.
- [ ] Signed node bootstrap, reconciliation, teardown/cost/failure certification.
## 4.0 — Hosting automation platform — DURABLE CORE / PRODUCTION BLOCKED

- [x] Restart-durable order journal and completed-step persistence.
- [x] Reverse compensation and fail-closed incomplete recovery.
- [x] Append-only, hash-chained double-entry billing ledger.
- [ ] Payment gateway adapters and verified signed webhooks.
- [ ] Subscription/refund/reconciliation and billing-driven suspend/unsuspend certification.
## 5.0 — Distributed hosting fabric — DURABLE SAFETY CORE / PRODUCTION BLOCKED

- [x] Persistent node/workload/placement controller.
- [x] Multi-region capacity-aware placement and unhealthy-node replanning.
- [x] Fresh-majority observation requirement before fence-and-replace intent.
- [x] Route plan excludes unhealthy placement backends.
- [ ] Real replication engine and deployed distributed consensus/fencing authority.
- [ ] Live DNS/LB traffic steering, cross-region secret/state distribution and chaos/DR certification.