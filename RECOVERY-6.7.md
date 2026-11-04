# Privora Panel 5.0.0-dev.6.7 — nftables Certification Probe Recovery

The first clean Ubuntu 24.04 VPS reached full machine certification and reported only `nftables` missing, even though the Privora bootstrap firewall had already successfully passed `nft -c` validation and applied its dedicated table.

Root cause: `scripts/vps-host-certify.sh` still rendered its disposable nftables certification candidate as a fragile one-line nested table/chain expression. Ubuntu's nft parser rejected that probe, creating a false-negative certification result.

Dev.6.7 changes the nftables certification candidate to canonical multiline syntax, validates it with `nft -c -f`, and records a useful diagnostic if the candidate check fails. The probe is check-only and does not modify the live firewall.

The existing dev.6.x installer journal remains compatible. Because `certification` is unfinished, rerunning dev.6.7 refreshes the certification script/binaries and resumes at certification without repeating completed host phases.
