# Privora Panel 5.0.0-dev.6.17 — Update Progress & Stall Observability

This release upgrades the WHM Update Center transaction display from a phase-only bar into a live progress monitor.

## Added

- Numeric update percentage and named transaction stages.
- Total transaction elapsed time.
- Current-stage elapsed time.
- Last recorded updater activity age.
- Current operation text from the root updater journal.
- Phase-specific `POTENTIAL STALL` warnings when a stage runs substantially longer than its expected threshold.
- Automatic recovery of an in-progress transaction monitor after a browser refresh/reopen.
- A ten-stage visual pipeline: Preflight, Snapshot, Verify Package, Dependencies, Stage Release, Migrations, Validate, Promote, Restart Services, Health Checks.
- Server-side journal timestamps (`started_at`, `phase_started_at`, `activity_at`) and operation labels.
- Resume-safe installer phase `update_progress_observability` for existing dev.6.x servers.

The warning is intentionally advisory: Privora does not kill a long-running update merely because it crossed an expected-duration threshold. The updater continues to be polled and the operator can see the exact stage and operation before deciding whether intervention is appropriate.
