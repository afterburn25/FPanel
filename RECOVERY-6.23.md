# Privora Panel 5.0.0-dev.6.23 — Fresh Installer Runtime Hardening

Source baseline: exact 5.0.0-dev.6.22 fresh-core candidate.

## Fixes

- Fresh installation no longer fails when a ZIP extractor drops Unix execute bits from bundled runtime binaries. The installer normalizes the permissions after copying the source and before cryptographic verification.
- The non-live `downloads.privora.example` development app-catalog endpoint is no longer mandatory by default. Core installation continues safely with one-click curated-app execution disabled until a real signed catalog is configured. `--require-app-catalog` retains fail-closed behavior for production deployments that explicitly require the catalog.
- PHP version installation now probes the complete required package set before invoking apt, avoiding noisy partial-package failures when a configured PHP version is not available from the repository.

## Promotion boundary

This is a fresh-install candidate until verified on the target VPS.
