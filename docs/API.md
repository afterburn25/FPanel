# Privora Agent API — development contract

All requests require `X-Privora-Agent-Token`. Mutations should also send `X-Privora-Actor` and `X-Privora-Request-ID`.

## Server

- `GET /v1/health`
- `GET /v1/system`
- `GET /v1/services`
- `GET /v1/services/{service}/logs`
- `POST /v1/services/{service}/{start|stop|restart|reload}`
- `GET /v1/packages/updates`

## Hosting

- `GET|POST /v1/hosting/accounts`
- `POST /v1/hosting/accounts/{user}/{suspend|unsuspend}`
- `GET|POST /v1/sites`
- `POST /v1/sites/{domain}/php`
- `GET /v1/files/{user}?path=...`
- `POST /v1/files/{user}/write`
- `GET|POST /v1/sftp`
- `GET|POST /v1/applications`

## Hosting services

- `GET|POST /v1/databases`
- `GET|POST /v1/dns/zones`
- `GET /v1/ssl`
- `POST /v1/ssl/issue`
- `GET|POST /v1/backups`
- `GET|POST /v1/mailboxes`
- `GET|POST /v1/resellers`
- `GET|POST /v1/firewall/rules`

## Future platform simulations

- `GET|POST /v1/fleet/nodes` — 2.0 simulation
- `GET|POST /v1/cloud/instances` — 3.0 mock provider
- `GET /v1/automation/runs`
- `POST /v1/automation/provision` — 4.0 simulation
- `GET|POST /v1/fabric/workloads` — 5.0 placement simulation

Future-platform mutation responses carry `simulation: true`. Non-mock implementations fail closed where the real backend does not yet exist.

## Control-plane customer API (0.18)

These routes are exposed by `panel/public/api.php`, not directly by the privileged agent. They require an authenticated `hosting-user` and derive the hosting-account scope from the authenticated user record rather than trusting a browser-supplied account name.

- `GET ?route=customer-summary`
- `GET ?route=customer-resources`
- `GET ?route=customer-files&path=...`
- `POST ?route=customer-file-write`
- `POST ?route=customer-site-create`
- `POST ?route=customer-site-php`
- `POST ?route=customer-sftp-create`
- `POST ?route=customer-application-create`
- `POST ?route=customer-database-create`
- `POST ?route=customer-dns-create`
- `POST ?route=customer-ssl-issue`
- `POST ?route=customer-backup-create`
- `POST ?route=customer-mailbox-create`

Customer DNS/SSL/mail/application/PHP mutations verify that the target domain belongs to the authenticated hosting account before forwarding a typed request to the agent.

## Customer-side expansion (5.0.0-dev.6)

Privileged agent endpoints used by the expanded Privora Panel (PPanel) shell:

- `GET /v1/account-controls` — list durable account-control policies.
- `POST /v1/account-controls` — create a validated account-control policy (`redirect`, `error_page`, `mime_type`, `directory_privacy`, `hotlink`, `ip_block`, `ssh_key`, `autoresponder`, `spam_policy`, `php_setting`, `php_extension`, `restore_request`).
- `GET /v1/apps/catalog` — curated application recipes.
- `GET /v1/apps/installer/installs` — list prepared application installs.
- `POST /v1/apps/installer/install` — prepare an account/domain-scoped install plan. This does not execute arbitrary third-party installer code.

The PHP customer control plane derives the owner from the authenticated `hosting-user`; callers cannot submit an alternate owner. Domain-scoped operations are rejected before reaching the agent when the domain is not owned by that account.

