# Privora Panel 5.0.0-dev.6.1 Installer Recovery

This recovery checkpoint fixes a clean Ubuntu 24.04 installation failure in the `privora_files` phase.

The dev.6 source package already shipped a verified, statically linked x86-64 Privora agent, but the installer rebuilt the agent unconditionally on the target VPS. That made installation depend unnecessarily on the VPS Go toolchain version. Dev.6.1 now verifies the bundled agent against `dist/privora-agent.sha256` and installs it directly on x86-64 hosts. Source compilation is retained only as a fallback for architectures without a bundled binary.

The installer remains resumable: a VPS that already completed `preflight` through `source` can rerun dev.6.1 and continue at `privora_files` using the existing `/var/lib/privora-installer/state.env` journal.
