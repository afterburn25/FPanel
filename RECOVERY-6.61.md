# Privora 5.0.0-dev.6.62 — Update Reliability & Live Domain Reconciliation Repair

This development checkpoint addresses live defects observed after the 6.60 Update Center installation.

## Update Center reliability
- `GET api.php?route=update-center` is fail-soft for authorized PCC users.
- `GET api.php?route=update-status&id=...` also falls back to the local transaction journal if the agent is briefly unavailable during its deferred post-pass refresh, so the browser can still observe the terminal PASS/rollback state.
- Agent errors, non-2xx agent responses, malformed/missing transaction state, and MFA metadata errors are converted to HTTP 200 JSON with `degraded=true` and `status_error`.
- The fallback reads only the local installed VERSION and latest readable transaction journal; it does not recursively call the agent.
- Routine updates no longer restart an already-active PCC PHP-FPM service merely because core files changed, preserving authenticated PCC sessions.
- Migration preflight/apply commands are bounded by explicit timeouts and expose named progress operations.

## DNS / website reconciliation
- Local DNS discovery uses `rndc zonestatus` when available and probes loopback plus local interface addresses rather than assuming BIND listens on 127.0.0.1.
- Known hosted/root domains are never omitted from DNS Zone Manager. If no authoritative local zone can be confirmed, the domain is shown explicitly as `not-configured` with a Create Zone action.
- Website reconciliation can use the recorded document root against active `nginx -T` blocks when legacy formatting prevents exact server_name parsing.

## Delivery
- This release is intended as a signed Update Center upgrade from 5.0.0-dev.6.60 or newer.
