# Privora Panel 5.0.0-dev.6.31 — Update Failure Visibility & Bootstrap Recovery

- Update Center renders successful states green and failed/rollback states red.
- Failure provenance survives rollback: failed phase, operation, command, return code and error remain visible.
- Restart operations are bounded with timeouts and report the exact service operation.
- Health checks retain per-substep progress and diagnostics.
- A one-time bootstrap installs the current updater engine before the next uploaded ZIP transaction so an older updater cannot fail before the new release takes over.
