# Privora Panel 5.0.0-dev.6.4 — nftables Bootstrap Recovery

This recovery fixes the first clean Ubuntu 24.04 VPS firewall-phase failure.

## Failure observed

The installer reached `firewall` and nftables rejected the generated one-line ruleset with:

```text
/etc/privora-panel/nftables-bootstrap.nft:3:1-1: Error: syntax error, unexpected end of file
```

## Fix

- Generate a canonical multiline nftables ruleset.
- Use `iifname "lo"` for loopback interface matching.
- Validate the candidate with `nft -c -f` before changing live Privora firewall state.
- Replace only Privora's own `inet privora_bootstrap` table.
- Never flush the global host ruleset or unrelated tables.
- Verify the installed Privora table can be listed after apply.
- Preserve the existing phase journal so a failed clean-VPS install resumes at `firewall`.

The bootstrap chain deliberately retains `policy accept` at this stage. Production hardening is applied only after the panel is healthy and machine certification has completed, preventing installer firewall changes from locking out SSH during bootstrap.
