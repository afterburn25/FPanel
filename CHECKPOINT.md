# Current Development Checkpoint

**5.0.0-dev.7.0 — Server Readiness, Automated Repair & Ten-Release Control-Panel Expansion**

Prepared cumulatively from the frozen 5.0.0-dev.6.90 candidate source. The 6.91–7.0 train adds live mail operations, Backup Center 2.0, scoped API-token lifecycle, historical monitoring/alerts, Security Advisor, advanced website/domain controls, database activity/session controls, application lifecycle, DNSSEC/templates/dynamic DNS and server-readiness/repair.

## Three polish passes

1. **Functional completeness:** no dead navigation, no duplicate IDs, no unsupported backup scopes, no misleading legacy restore/deployment placeholder, customer ownership checks for new PPanel mutations, and real background execution for scheduled work.
2. **Workflow/organization:** goal-oriented PCC/PPanel placement, run-now/verify/repair actions beside the resources they affect, consolidated readiness guidance, and server-only operations kept out of customer workflows.
3. **Visual/accessibility/truthfulness:** consistent workbenches/actions/status copy, responsive existing design system, no fake production claims, and explicit capability gates where infrastructure is not certified.

## Acceptance boundary

5.0.0-dev.7.0 is a prepared candidate only. Do not promote it to the accepted/live baseline until the cumulative package is installed on the VPS and PCC/PPanel, mail authentication, background jobs, backups, monitoring, DNS, applications, database activity, readiness repairs, services and rollback are accepted by the user.
