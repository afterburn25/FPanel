# Privora Panel 5.0.0-dev.6.64 — DNS Creation Contract Repair

- Fixes new root-zone provisioning after branded nameservers are already configured.
- Adds required in-bailiwick A/AAAA records for configured authoritative nameservers before `named-checkzone`.
- Prevents child hostnames from being misreported as independent unconfigured authoritative zones.
- DNS Zone Manager shows child sites as `Configured via parent` or `Parent record missing`.
- Hosted-DNS repair reuses the corrected provisioning contract for existing affected sites.
- Carries all 6.62 updater, PPanel access, AutoSSL, PCC/PPanel routing, DNS inventory, and recovery fixes.
