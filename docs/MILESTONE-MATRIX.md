# Privora Panel milestone matrix — 5.0.0-dev.6

| Train | Implemented/tested now | Production status |
|---|---|---|
| 0.1–0.18 | secure agent, auth, dual PCC/PPanel shells, account scoping | development baseline |
| 0.19–0.39 | tasks/deploy/mail/security/monitoring contracts + HMAC/replay/audit chain | some service adapters still gated |
| 0.40–0.69 | update/resource/migration/cluster/API/CLI contracts | host/provider integrations gated |
| 0.70–0.99 | plugins/billing/diagnostics/revisions/exports/staging/isolation/certification | production integrations gated |
| 1.0 | live Linux account create/suspend/unsuspend, safe account files, local backup, real Nginx parser; controlled DB/DNS/ACME/firewall/mail/SFTP/quota/cgroup adapters | **BLOCKED** until all required adapters + restore/failure/security cert pass |
| 2.0 | TLS1.3 mTLS, typed executor, persistent replay, durable enrollment/rotation/revocation | **BLOCKED** on real remote convergence/PKI operations/partition cert |
| 3.0 | durable provider lifecycle + encrypted vault | **BLOCKED** on real provider adapters/bootstrap/teardown cert |
| 4.0 | durable compensating orders + hash-chained double-entry ledger | **BLOCKED** on payments/webhooks/subscription reconciliation |
| 5.0 | persistent placement controller + majority-observation fencing intent + route planner | **BLOCKED** on replication/real consensus/fencing/routing/chaos cert |

`5.0.0-dev.6` means the implementation train reaches the 5.0 architecture horizon. It does not mean production 5.0 infrastructure is deployed or certified.
