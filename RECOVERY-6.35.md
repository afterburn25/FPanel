# Privora Panel 5.0.0-dev.6.35 — Snapshot Verification Pipeline Repair

- Fixes a real VPS failure in the Snapshot phase where a valid compressed snapshot was streamed directly into `grep -q` under `pipefail`.
- Snapshot verification now persists the complete tar listing, normalizes leading `./` and `/`, and verifies the required panel web-root files from that saved list.
- Snapshot tar stderr is retained alongside the transaction backup for diagnostics.
- Update remains fail-closed before staging/promotion if the snapshot itself is invalid or incomplete.
