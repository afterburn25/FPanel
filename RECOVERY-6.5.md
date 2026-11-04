# Privora Panel 5.0.0-dev.6.5 — Certification Toolchain Recovery

## Trigger
The first clean Ubuntu 24.04 install reached the machine-bound `certification` phase and failed with:

```text
go: download go1.23 for linux/amd64: toolchain not available
ERROR phase=certification line=337 rc=1
```

## Root cause
`vps-host-certify.sh` still invoked `go test` on the managed VPS. Production installation/certification must not depend on installing or downloading a Go compiler.

## Fix
- Ship precompiled Linux/amd64 host-adapter and API certification test executables in `dist/`.
- Ship SHA-256 sidecars for both.
- Verify their digests before execution.
- Machine certification executes these test binaries directly with `PRIVORA_LIVE_HOST_TEST=1`.
- The signed release builder rebuilds all three binaries (agent + two certification executables) from the same source before signing.
- The production updater verifies shipped prebuilt binaries instead of rebuilding Go code on the VPS.

Existing dev.6.x journals remain compatible; because `certification` was not marked complete, dev.6.5 resumes at that phase.

## Resume-safe refresh
Because a real dev.6.4 install may already have `privora_files=done`, the dev.6.5 `certification` phase refreshes only `scripts/vps-host-certify.sh` plus the two precompiled certification executables/checksums from the currently supplied recovery source before certification. Earlier phases remain skipped.
