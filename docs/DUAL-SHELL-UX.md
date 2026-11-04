# Privora Panel Dual-Shell UX

## Privora Panel (PPanel)

Audience: normal hosting customers.

Interaction model: Privora Panel (PPanel) grouped feature panels with clear icons, a global tool search, account information and quota/statistics rail. No server/root navigation is present.

Groups currently surfaced:

- Files: File Manager, SFTP, Backups, Disk Usage placeholder.
- Domains: Domains, DNS Zone Editor, SSL/TLS, Redirects placeholder.
- Email: Email Accounts plus forwarder/spam/routing placeholders.
- Databases: MariaDB/MySQL, PostgreSQL, phpMyAdmin placeholder.
- Software: MultiPHP, Applications, Git Deployment placeholder, Cron placeholder.
- Metrics & Security: Resource Usage, Security plus analytics/error placeholders.

Customer-facing routes use account-scoped API endpoints. The assigned hosting account is stored on the authenticated `hosting-user` record.

## Privora Command Center (PCC)

Audience: root administrator, server administrator, reseller, support/read-only administrative roles.

Interaction model: PCC persistent left-side navigation with hierarchical sections and denser pages. Navigation is generated according to permissions.

Primary sections:

- Server Configuration
- Account Functions
- Hosting Services
- Platform Labs (simulation-gated)

## Security rule

The UI split is not the security boundary. API permission checks and hosting-account scoping are mandatory even when a tool is absent from the customer interface.
