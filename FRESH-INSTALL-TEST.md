# Privora Panel 5.0.0-dev.7.0 — Fresh Install / Acceptance Test

1. Install on a supported fresh Ubuntu 24.04 host and confirm PCC :8443 and PPanel :2443 are healthy.
2. Confirm PCC displays `7.0 DEV`, all visible sidebar destinations open, and PPanel tool navigation has no blank/dead views.
3. Confirm `/opt/privora-panel` is Nginx-traversable while `VERSION` remains `root:privora-panel 0640` and readable by dedicated PHP-FPM.
4. Confirm Dovecot passdb/userdb remain passwd-file, Postfix AUTH uses Dovecot, existing full-address mailbox logins remain valid, and Mail Queue/Delivery/Filters load.
5. Create site/account backup policies, use Run now, verify the resulting archive, and confirm unsupported destinations/scopes fail closed.
6. Issue/rotate/revoke a PPanel API token and prove it cannot escape the authenticated hosting account.
7. Confirm monitoring samples persist, alert/incident evaluation operates, and server-wide monitoring/security remains PCC-only.
8. Review Security Advisor; verify SSH hardening is not offered/applied without an administrative key.
9. Apply and rollback/test an advanced website policy on a disposable domain.
10. Confirm PPanel database activity only exposes owned databases and session-kill revalidates ownership.
11. Discover an application and run only allow-listed lifecycle actions as the hosting account; mutating actions must take a pre-change backup.
12. Enable/inspect DNSSEC on a disposable managed zone, capture DS output, and exercise DNS-template application from PCC.
13. Run Server Readiness and Repair All on safe findings; inspect per-action results and confirm failed actions are reported rather than hidden.
14. Confirm scheduled backup/metric background work continues with the browser closed and survives Agent restart.
15. Validate Nginx, PHP-FPM, Postfix, Dovecot, BIND/database services present on the host and run the packaged post-install acceptance gate.

Only promote 7.0 to accepted/live after the user confirms the installed VPS passes acceptance.
