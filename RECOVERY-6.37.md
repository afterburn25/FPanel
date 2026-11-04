# Privora Panel 5.0.0-dev.6.37 — Update Permission & Version Truth Recovery

- Signed update extraction normalizes release directories to 0755, ordinary files to 0644, executable files to 0755.
- Staged and promoted panel files are verified readable by the `privora-panel` runtime user.
- Promotion and final health require `/opt/privora-panel/VERSION` to match the signed target version before PASS can be recorded.
- PHP-FPM unit discovery uses bounded `systemctl show` checks instead of pipefail-sensitive `list-unit-files | grep -q` pipelines.
