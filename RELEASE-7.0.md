# Privora Panel 5.0.0-dev.7.0 — Server Readiness, Automated Repair & Three-Pass Product Polish

This release is part of the cumulative 6.91 → 7.0 development train prepared from 5.0.0-dev.6.90.

## Changes

- Adds a server-readiness score covering services, websites, DNS, SSL, security and backup state with auditable history.
- Adds individual safe repairs plus Repair All for service restart, hosted-DNS repair, website repair, AutoSSL, panel permissions, mail auth and eligible security fixes.
- Runs three cross-panel polish passes for structural completeness, workflow consistency, visual/accessibility/copy cleanup and removal of misleading legacy placeholders.
- Preserves typed Agent boundaries, customer ownership checks, transactional validation/rollback, the 6.89 virtual-mail auth architecture and the 6.90 Nginx/VERSION permission hardening.

## Safety / acceptance

- No unrestricted browser root shell is introduced; privileged mutations remain typed and allow-listed through the Agent/HostAdapter.
- Customer operations remain account/feature scoped and server-wide controls remain PCC-only.
- This release train remains a prepared candidate until packaged, installed on the VPS and accepted by the user.

## Rev2 — Runtime UID-transition isolation hotfix

- Corrects the live 7.0 acceptance failure where commands launched from the hardened Agent attempted UID/GID transitions directly and were denied by `NoNewPrivileges=true` / `RestrictSUIDSGID=true`.
- PostgreSQL operations and account-owned application commands now run in short-lived, typed systemd transient units directly as the validated target user. No shell is introduced and `root` is rejected as a user-command target.
- Postfix queue read/retry/delete/flush operations now run through the existing short-lived isolated root-maintenance boundary so `postqueue`/`postsuper` can perform their required Postfix privilege transitions.
- WordPress/Joomla bootstrap and PostgreSQL logical import/export use the same bounded user-unit path, including stdin/stdout streaming, rather than direct `runuser` inside the Agent.
- The long-running `privora-panel-agent.service` remains hardened with `NoNewPrivileges=true` and `RestrictSUIDSGID=true`; the fix does not weaken that unit.
- Production upgrade and post-install acceptance paths explicitly skip retained Go certification tests; Go compilation remains a build-time activity only and is never required on the VPS.
- Live evidence used for this correction: root-shell `runuser -u postgres -- id`, `postfix check`, and `postqueue -p` all succeeded while earlier Agent-originated `runuser`/`postsuper` operations were denied, isolating the fault to the Agent sandbox boundary.
