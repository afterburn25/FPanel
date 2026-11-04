# Privora Panel — 5.0.0-dev.7.0 Server Readiness, Automated Repair & Ten-Release Control-Panel Expansion

## 5.0.0-dev.7.0

- Cumulative release train from 6.91 through 7.0 covering mail operations, scheduled/verified backups, scoped API tokens, monitoring/alerts, Security Advisor, advanced site policies, database activity, application lifecycle, DNSSEC/templates/dynamic DNS and server readiness/repair.
- Adds real Agent background work for scheduled local backups and historical metric capture.
- Adds PCC Repair All safe items with per-action results and fail-closed SSH hardening.
- Runs three global PCC/PPanel polish passes for functional completeness, workflow efficiency, visual consistency, accessibility and truthful capability presentation.
- Preserves virtual-mail passwd-file authentication and the Nginx/PHP VERSION permission hardening from 6.89/6.90.
- Prepared candidate: not accepted/live until installed and confirmed on the VPS.

# Privora Panel — 5.0.0-dev.6.90 Control Panel Coverage, Efficiency & Three-Pass UX Polish

## 5.0.0-dev.6.90

- Completes a full PCC/PPanel functional coverage audit and repairs dead/blank navigation destinations.
- Adds functional PCC Firewall Manager and Reseller Center workspaces and consolidates experimental Fleet/Cloud/Automation/Fabric controls under Platform Labs.
- Exposes secure authenticator-app 2FA management in both PCC and PPanel using Privora's existing TOTP backend.
- Adds account-scoped PPanel Disk Usage with a dedicated Files-authorized live-usage route.
- Adds PCC Needs Attention guidance, direct dashboard task shortcuts, expanded command search, PPanel Quick Start and keyboard tool search.
- Removes duplicate DOM IDs and verifies frontend navigation/API route coverage.
- Hardens Nginx traversal and VERSION-file ownership/mode to prevent recurrence of the 6.89 Recovery Mode/stale-version incident.
- Preserves the confirmed 6.89 virtual-mail authentication core and all earlier production safety boundaries.

## 5.0.0-dev.6.89

- Permanently wires Privora virtual mailboxes to Dovecot `passwd-file` authentication instead of PAM/system accounts.
- Protects `/etc/privora-mail/dovecot_users` as `root:privora-panel 0640` while explicitly granting Dovecot auth/auth-worker the required group access.
- Reconciles and certifies virtual-mail authentication after mailbox lifecycle changes and during fresh install/mail-service reconciliation.
- Routes Postfix submission AUTH through the same Dovecot authentication socket and validates configuration before service restart.
- Adds rollback and regression gates for password reset, full-address lookup, Maildir/quota preservation, file replacement/permissions, Dovecot lookup/auth and SMTP AUTH configuration.

# Privora Panel — 5.0.0-dev.6.83 Asynchronous Software Jobs & Card Progress

## 5.0.0-dev.6.83

- Moves long component, Smart Preset, and PHP-runtime installs/removals into typed asynchronous Agent jobs so browser/PHP-FPM request lifetimes cannot abort provisioning.
- Adds queued/running/complete/failed job state with phase, percentage, message, error, and result reporting.
- Adds live progress bars directly on Extensions & Components and Smart Preset cards, with polling/reconnection after temporary API bridge interruptions.
- Serializes software mutations to prevent overlapping APT/Composer transactions.
- Preserves isolated APT execution, isolated Laravel Composer with `pcre.jit=0`, Roundcube isolation, and the hardened long-running Agent.

# Privora Panel — 5.0.0-dev.6.72 PPanel Workspace, Full File Manager & Account Analytics


## 5.0.0-dev.6.72

- Reorganizes PPanel into a left information rail plus grouped tool workspace; removes the extra top status strip and the remaining welcome/status banner.
- Adds live server/account information and quota/resource usage to the left rail.
- Uses a consistent same-origin SVG icon system with recognizable colorful tools across the Files, Domains, Email, Databases, Software, Metrics and Security containers.
- Adds a full account-scoped File Manager with navigation, upload, create/edit/download, copy/move/rename, permissions, search, ZIP create/extract, delete and multi-select delete, plus recursion and archive-expansion safety limits.
- Adds live Resource Usage, Visitors, Analytics, Bandwidth, Raw Access and Errors using account ownership plus Nginx access/error logs.
- Retains the PCC-only privilege boundary for OS package changes and all prior database, phpMyAdmin, Roundcube, AutoSSL and component-manager safety contracts.

## 5.0.0-dev.6.71

- Cleaner PCC Config Editor with common edits first, categories, search, and a full-width selected-file workspace.
- Searchable, allow-listed Extensions & Components manager for PHP/PDO modules, FFmpeg/media tools, database clients, server utilities and developer tooling.
- Laravel Development Stack with Composer, Laravel installer, Git, Node/NPM and PHP 8.4 framework dependencies.
- First-class Roundcube provisioning behind the PCC/PPanel session gate with a dedicated PHP-FPM pool.
- Repairs the PPanel database post-create `applyDatabaseCapabilities` JavaScript error while preserving one-time credential handling.

Privora Panel is a self-hosted hosting/server control plane targeting cPanel + WHM-class control without putting an unrestricted root shell behind the browser.

**This repository is a verified development checkpoint, not a production 5.0 release.** It now combines real, machine-certified single-host adapters with durable 2.0–5.0 control-plane primitives. Features that require services or infrastructure not present on the certification host remain fail-closed rather than being reported as complete.

## 5.0.0-dev.6.62 update reliability and live-domain reconciliation

- Fixes the creation-path DNS regression: child hostnames entered through Create Website now use an existing parent zone instead of becoming independent child zones.
- Adds **Repair hosted DNS** to repair previously created root/child websites in place, including missing root zones and parent-zone A/AAAA records.
- Adds PPanel primary-domain login provisioning/reset from PCC; customers no longer need to know the Linux account username.
- Gracefully reloads active PCC PHP-FPM after promotion so new code/opcache is loaded without hard-resetting file-backed login sessions.
- Fixes real `dig` argument order for local-authoritative, delegation, and glue checks.
- Adds exact local-authoritative SOA fallback so hosted zones such as `privoralabs.com` remain visible in DNS Zone Manager even when BIND hides the backing zone file.
- Adds effective `nginx -T` server-name fallback so active legacy/imported vhosts do not remain falsely marked **Needs attention**.
- Ensures every Privora HTTP vhost exposes `/.well-known/acme-challenge/` ahead of hidden-file deny rules and reconciles that exception into existing managed vhosts after update.
- AutoSSL now performs a public HTTP-01 webroot probe before Certbot and distinguishes DNS pending, HTTP challenge blocking, and true ACME issuance failures.
- Certbot failures surface useful validation detail extracted from the ACME log.
- PCC branding keeps **Privora Command Center** on one line above the logo/status row.



## 5.0.0-dev.6.46 recovery-safe Update Center API

- `/api.php` remains JSON during recovery; HTML Recovery Mode is reserved for browser UI pages.
- FastCGI transport errors on the API return a compact JSON 503 fallback.
- Recovery-vhost reconciliation repairs older Nginx configs with the API exception.
- Retains 6.44 stable signed-update trust, AutoSSL, and automatic Let’s Encrypt retries.

## 5.0.0-dev.6.43 friendly hosting identity and domain workflow

This cumulative checkpoint reorganizes the PCC and PPanel shells around faster everyday operation while retaining the 6.40/6.41 hosting and WHM expansion work.

- Admin navigation uses collapsible functional groups and automatically opens the active group.
- Both shells include Panel Preferences with dropdown controls for theme, density, navigation behavior, table spacing and motion.
- Create Website is a guided, professional multi-section workflow with owner/runtime selectors and a provisioning summary.
- Known account domains are presented as selectors throughout customer settings where the domain already exists.
- PHP Options uses setting-aware value selectors for common bounded directives instead of generic free text.
- Website inventories remain compact vertical lists for fast scanning, while destructive actions and capability-gated features remain explicit.
- All 6.40/6.41 functionality is cumulative, including nameserver sets, subdomains, suspended-account deletion, Packages/Feature Manager/Resellers, MultiPHP, database controls, mail/Webmail, AutoSSL, verified restore, security/monitoring/API/plugin/DNS-cluster surfaces.

## Permanent dual-shell UX

- **Privora Panel (PPanel):** normal `hosting-user` accounts receive the grouped-icon hosting workspace. Customer routes derive scope from the authenticated account.
- **Privora Command Center (PCC):** root/server/reseller/support roles receive persistent left navigation for server, accounts, hosting, security, operations and platform engineering.



## 5.0.0-dev.6 one-command VPS bootstrap

This checkpoint adds the intended fresh-VPS operating model: SSH in as root once, run one bootstrap command, then perform normal administration from Privora.

- `install/privora-install.sh` is a resumable, idempotent root bootstrap with `--dry-run`, `--source-dir`, `--release-url`, `--hostname`, `--mode`, `--channel` and unattended administrator options.
- Supported OS detection covers Ubuntu, Debian, AlmaLinux and Rocky Linux; unsupported distributions fail closed.
- The bootstrap updates package indexes/system libraries, installs the selected hosting stack, configures multi-PHP on Debian/Ubuntu, installs Go/Composer/Node/Python tooling, builds Privora, generates secrets, installs Nginx + dedicated PHP-FPM, creates the protected agent socket boundary, configures firewall bootstrap, initializes the first administrator, runs machine-bound host certification and health checks.
- Normal web control runs as a dedicated `privora-panel` identity; the privileged agent remains root with a group-protected Unix socket. No PHP development server is used by the production bootstrap.
- Installation phases are journaled under `/var/lib/privora-installer`; rerunning the command resumes completed phases instead of blindly repeating them.

## Safe Update Center

- `scripts/privora-update.sh` performs pre-update snapshot, OS/package/library maintenance, signed Privora release verification, dependency resolution, staging, migrations, config validation, atomic promotion, service restart and health checks.
- `scripts/privora-update-rollback.sh` verifies the pre-update snapshot, restores the previous promoted release **and** the captured Privora/Nginx configuration/state, then revalidates/restarts services.
- A nightly `privora-maintenance.timer` performs policy-controlled automatic maintenance. Defaults: security updates ON, normal package/library patch updates ON, major-version upgrades approval-gated, automatic reboot OFF.
- PCC Update Center can save the real host maintenance policy and launch typed `security` or `full` update jobs through the certified privileged agent. Kernel/system updates may mark a reboot pending; reboot occurs automatically only when the administrator explicitly enables Auto Reboot and the configured maintenance day/hour is active.
- PCC Update Center also accepts signed Privora ZIP uploads. Packages are staged into a root-owned area, signature/version/payload verified, then require fresh server-root PAM reauthorization before installation. If the WHM account has TOTP MFA enabled, a current authenticator code is also required. The root password is never stored or placed on a command line.
- Uploaded core updates are serialized with a transaction lock, snapshot before change, stage/migrate/validate before atomic promotion, stream progress from a durable journal, and automatically restore/roll back on failure.
- Release verification requires HTTPS, SHA-256 and an RSA signature. The included public key is a development placeholder and **must be replaced by the production offline release-signing public key before hosted releases are published**.
- Go tests independently verify signed-manifest/checksum rejection and durable update-journal semantics.

One-command delivery target once Privora release hosting is published. The bootstrap automatically selects the signed release for its update channel; no release URL is required:

```bash
curl -fsSL --proto '=https' --tlsv1.2 https://install.privora.example | bash
```

For source-tree testing now:

```bash
sudo ./install/privora-install.sh --source-dir "$(pwd)" --hostname panel.example.com --admin-email admin@example.com
```


## 5.0.0-dev.6 signed delivery and fail-closed full bootstrap

- `scripts/build-signed-release.sh` produces signed, checksum-pinned core release archives and channel metadata from a private key that must live outside the source tree.
- Core release and curated application signatures use separate trust roots. Offline key-ceremony and delivery-webroot tooling live under `release/`.
- The installer/updater validate signed metadata and archive containment before extraction.
- Full/web bootstrap requires the signed application catalog by default.
- The resumable installer aborts any unfinished phase that fails; only journaled completed phases are skipped.
- `--mode full` requires machine-bound full-role certification before reporting installation success.
- This sandbox proves the fail-closed path because its package repositories cannot currently resolve: available real slices certify, while the missing PHP/DB/DNS/mail/firewall/quota/cgroup adapters prevent a false full-stack PASS. See `CHECKPOINT.md` and `docs/FULL-STACK-CERTIFICATION.md`.

## 5.0.0-dev.6 PPanel-side expansion

The regular hosting-user shell now exposes a broader Privora Panel (PPanel) tool set while preserving backend account scope:

- Redirects, custom HTTP error pages, MIME mappings, directory privacy and hotlink protection.
- Autoresponders, spam policy controls and existing mailbox/routing/forwarder tools.
- PHP options and per-site extension policy in addition to PHP version selection.
- IP blocker, SSH public-key policy and scoped backup-restore requests.
- Curated Application Installer with WordPress, Joomla, Drupal, Grav, phpBB, PrestaShop, Nextcloud, Moodle, Matomo and Laravel recipes.
- Installer recipes declare runtime/database requirements and rollback-aware steps. Customer install requests are limited to domains owned by the authenticated hosting account.
- The curated installer now has an executable signed-source host adapter: separate app-catalog RSA trust, HTTPS + pinned SHA-256/size policy, safe archive extraction, private same-filesystem staging, database provisioning hooks, atomic publish and rollback. WordPress and Joomla have noninteractive bootstrap paths; Joomla secrets are fed to its CLI installer through stdin. Other recipes remain guided until their application-specific bootstrap is separately certified.

## What is real in the 1.0 host gate

On the disposable Debian certification host, Privora has live-tested the signed panel/agent path for:

- Linux hosting-user creation with `/usr/sbin/nologin`;
- chroot-safe account layout: `/home/<user>` root-owned, writable `domains`, `tmp` and `logs` customer-owned;
- suspend/unsuspend via reversible Linux account expiry;
- account-rooted file list/write using `openat` + `O_NOFOLLOW` with symlink/traversal escape rejection;
- verified local `.tar.zst` backups with SHA-256 evidence;
- generated Nginx configuration accepted by the real Nginx parser.

Additional real adapters exist and have controlled tests for PHP-FPM transactions, MariaDB/PostgreSQL provisioning, BIND-style DNS, ACME/certbot, nftables, filesystem quota, cgroup v2 limits, Postfix/Dovecot mailbox provisioning, OpenSSH internal-SFTP, and cPanel backup staging. They remain unavailable on a machine unless the dependency exists **and** a machine-bound certification artifact authorizes that adapter.

## Security/control-plane foundation

- Go privileged agent over a protected Unix socket; no arbitrary shell endpoint.
- HMAC-SHA256 panel→agent signing over method, URI, timestamp, nonce and body digest.
- request freshness + replay rejection; privileged actor/request IDs in audit events.
- Argon2id authentication, secure sessions, CSRF, RBAC and encrypted-at-rest TOTP MFA.
- hash-chained privileged JSONL audit records with verifier.
- typed host mutations; machine-bound host certification gates.
- scoped external API keys stored by digest and a fixed REST resource/scope map.
- PHP Unix-socket client correctly decodes HTTP/1.1 chunked agent responses.

## Durable 2.0–5.0 cores

These are real tested control-plane primitives, but **not claims of deployed production infrastructure**:

- **2.0 Fleet:** TLS 1.3 mutual TLS, typed command executor, durable replay guard, persistent node certificate registry, rotation and revocation.
- **3.0 Cloud:** provider lifecycle interface, restart-durable idempotency state, destructive-delete confirmation, AES-256-GCM credential vault.
- **4.0 Automation:** restart-durable order journal, fail-closed ambiguous recovery, reverse compensation, append-only hash-chained double-entry billing ledger.
- **5.0 Fabric:** persistent node/workload/placement controller, region/capacity placement, unhealthy-node replanning, majority-observation fence intent, route-plan filtering.

Real cloud-provider APIs, payment gateways, data replication, deployed consensus/fencing authority, and live multi-region traffic routing remain production blockers.

## Verification

```bash
./scripts/verify.sh
./scripts/integration-smoke.sh
```

On a disposable root-capable supported test host:

```bash
./scripts/live-host-cert.sh
```

The live certification output is machine-bound through SHA-256 of `/etc/machine-id`; copying it to another server does not certify that server.

## Development quick start

```bash
export PRIVORA_DEV_PASSWORD='choose-a-strong-dev-password'
./scripts/dev.sh
```

See `CHECKPOINT.md`, `ROADMAP.md`, `SECURITY.md`, `docs/MILESTONE-MATRIX.md`, `docs/PRODUCTION-GATES.md`, `docs/EXTERNAL-API.md`, and `docs/ARCHITECTURE-5.0.md`.
