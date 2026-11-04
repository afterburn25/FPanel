# Privora Panel 5.0.0-dev.6.42 — Release Staging Parent Traversal Repair

- Fixes Stage release failures when `/opt/privora-panel.releases` was created under a restrictive umask as `0750 root:root`.
- The updater now creates/repairs the release-staging parent with `install -d -m0755` before rsync staging.
- Stage verification explicitly proves the `privora-panel` runtime user can traverse the staging parent before checking staged PHP readability.
- The failure remains pre-promotion and therefore cannot replace the live panel core.
