# Privora Panel 5.0.0-dev.6.29 — Update Dependency & Channel Gate Recovery

- Fix uploaded-update Dependencies failures caused by `dist/privora-agent.sha256` embedding an absolute build-machine path.
- Agent checksum generation now emits a portable basename-only sidecar and verification rejects absolute-path sidecars.
- Development fresh installs default to the `developer` update channel unless explicitly overridden.
- The updater falls back to the developer channel for installed `-dev.` versions when no policy environment exists.
- Upload inspection rejects channel mismatches immediately with an actionable Maintenance Policy message rather than failing later in the transaction.
