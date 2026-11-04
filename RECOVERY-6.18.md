# Privora Panel 5.0.0-dev.6.18 — Update Launch & Truthful Preflight Recovery

This recovery fixes WHM uploaded updates that could appear stuck on **Preflight** even when the privileged updater worker never reached preflight.

## Root cause addressed

The browser optimistically painted `preflight` immediately after the agent accepted an update request. The real updater created its transaction journal only after the transient systemd worker started and after acquiring the global update lock. If the worker exited before journaling (for example because another update held the lock), the browser had no authoritative transaction state and could remain visually stuck on Preflight.

## Changes

- Agent creates a root-owned transaction journal in phase `launch` before invoking `systemd-run`.
- Launch failures are written into that journal and become visible to WHM.
- Global update-lock contention records a failed transaction with the explicit error `another Privora update transaction is already running` rather than exiting before status exists.
- Uploaded authorization/hash validation in preflight is bounded to 20 seconds.
- WHM now starts at **Launch worker (2%)**, not Preflight, until the updater itself proves it entered preflight.
- Launch-worker stall warning threshold is 30 seconds; Preflight alert threshold is reduced to 45 seconds.
- Recovery installer phase `update_launch_recovery` refreshes the updater, agent, and WHM monitor without replaying completed bootstrap phases.

## Verification

- Full Go suite PASS.
- `scripts/verify.sh` PASS.
- `scripts/integration-smoke.sh` PASS.
- `scripts/test-upload-update-pipeline.sh` PASS.
- Direct lock-contention journal regression PASS (exit 75 is surfaced as a failed launch transaction).
