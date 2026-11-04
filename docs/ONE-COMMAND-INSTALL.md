# Privora One-Command VPS Installation

Target operating model: provision a clean VPS, SSH in as `root`, run one Privora bootstrap command, then perform routine hosting/server administration in the Privora Command Center (PCC).

## Delivery command (after release hosting is published)

```bash
curl -fsSL --proto '=https' --tlsv1.2 https://install.privora.example | bash
```

The hosted bootstrap embeds/pins the release-verification public key and automatically selects the signed release endpoint for the selected channel (`stable` by default). No `--release-url`, administrator password, or hostname argument is required for the normal one-command path. The release bundle is not extracted until its SHA-256 and RSA signature verify. The checked-in key in this development checkpoint is **development-only** and must be replaced before public release hosting.

## Current source-tree test

```bash
sudo ./install/privora-install.sh \
  --source-dir "$(pwd)" \
  --hostname panel.example.com \
  --admin-email admin@example.com \
  --mode full \
  --channel stable
```

Use `--dry-run` to print the entire mutation plan without changing the machine.

## Automatic work performed

OS/capacity preflight; package index and library updates; required hosting stack packages; PHP/runtime tooling; source verification/acquisition; agent build; generated secrets; dedicated panel identity; PHP-FPM/Nginx; systemd; firewall bootstrap; initial administrator; machine-bound host-adapter certification; health checks; and installation of the nightly Privora safe-maintenance timer.

The phase journal at `/var/lib/privora-installer/state.env` makes the installer resumable. Rerunning it after an interruption skips phases already recorded as complete.

## Ongoing automatic maintenance

After installation, `privora-maintenance.timer` runs the same safe updater under the PCC Update Center policy. Security patches and ordinary package/library patches default to automatic. Major PHP/database/runtime upgrades remain approval-gated. Automatic reboot defaults to **off**; when explicitly enabled, Privora reboots only if the OS reports a reboot is required and the configured maintenance day/hour is active.

Every update transaction snapshots Privora source, panel state and Nginx configuration first. A failed post-promotion update invokes the rollback helper, which verifies the snapshot, restores the previous release/configuration/state, validates Nginx, and restarts the Privora agent.

The `install.privora.example` and `downloads.privora.example` hostnames in this development checkpoint are delivery targets, not live public release infrastructure yet.
