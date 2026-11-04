# Privora 5.0.0-dev.6.64 — Agent Handoff & Root DNS Truth

This checkpoint addresses the live 6.63 behavior where child hostnames were classified correctly but `privoralabs.com` remained `NOT CONFIGURED`, while the update also exposed a brief `Agent unavailable` error during the deferred agent refresh.

- PCC retries Unix-socket connection establishment during the bounded agent-refresh handoff.
- Post-update hosted-DNS reconciliation waits for a healthy `/v1/health` response rather than merely checking that the socket pathname exists.
- DNS reconciliation retries transient post-restart failures and always persists the last result/error to `dns-reconcile-last.json`.
- DNS Zone Manager displays the exact per-domain hosted-DNS repair result and reason.
- DNS-only inventory falls back to `rndc zonestatus` for hosted root domains when effective BIND config parsing is degraded, preventing a loaded legacy zone from being mislabeled `NOT CONFIGURED`.
