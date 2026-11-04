# Privora Panel 5.0.0-dev.6.3 — systemd Alias Recovery

Ubuntu 24.04 may expose `bind9.service` as an alias of the canonical BIND unit `named.service`. `systemctl enable` refuses alias names even though starting/reloading the alias can work. The installer now resolves every requested role service through `systemctl show <unit> -p Id --value` and enables/starts the canonical unit.

This build is journal-compatible with dev.6.x. If `role_services` failed, completed phases remain skipped and the installer resumes at the unfinished phase.
