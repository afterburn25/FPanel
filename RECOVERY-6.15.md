# Privora Panel 5.0.0-dev.6.17 — API Bridge & Live Inventory Recovery

This recovery addresses the first real VPS report where the WHM/cPanel shells loaded but live controls returned `Failed to fetch` and existing websites were not visible.

## Core changes

- The privileged agent now supports explicit Unix-socket group ownership via `--socket-group` and the production systemd unit pins the agent socket to the `privora-panel` group at mode `0660`.
- The installer includes a production-identity bridge test: PHP runs as `privora-panel`, loads the protected panel environment, opens the Unix socket through `AgentClient`, and must receive `/v1/health` before the phase passes.
- PHP-to-agent GET requests allow up to 20 seconds so live-host inventory commands are not truncated by the older five-second client deadline.
- WHM and customer JavaScript build the API URL from `document.baseURI`, send same-origin credentials explicitly, disable cache, and surface a Privora-specific API bridge error instead of the browser's opaque `Failed to fetch` message.
- Nginx website discovery no longer requires a `.conf` suffix. It scans `sites-available/*`, `sites-enabled/*`, and `conf.d/*.conf`, deduplicates symlink targets, treats `conf.d` as active, and discovers all valid `server_name` entries found in a candidate file.
- A new resume-safe installer phase `agent_bridge_live_inventory` upgrades the agent/API client/frontend assets, hardens the installed systemd socket contract, restarts the affected services, and proves the production service identity can communicate with the privileged agent.

## Verification

- Go test suite: PASS
- PHP syntax: PASS
- JavaScript syntax: PASS
- Installer/shell syntax: PASS
- Privora full verify suite: PASS
- Integration smoke: PASS
- Production-identity Unix socket bridge test (unprivileged `nobody` identity): PASS
- Extensionless + `conf.d` Nginx inventory regression test: PASS
