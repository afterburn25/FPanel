# Privora Panel 5.0.0-dev.6.21 — Transaction-Bound Update Authorization Recovery

Repairs the WHM uploaded-update preflight handoff by removing the root reauthorization bearer token from the transient systemd command line. Authorization is stored in a root-only transaction-bound record, validated against transaction id, expiry and exact staged ZIP SHA-256, and consumed once. The recovery performs a full atomic core-baseline reconciliation so dev.6.20 website-account onboarding is included coherently.
