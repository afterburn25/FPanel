# Privora 5.0.0-dev.6.62 — Creation-Path DNS Repair, PPanel Access & Update Consistency

This checkpoint follows live 6.60/6.61 evidence showing that newer websites could be created successfully while DNS provisioning remained incomplete, and that generic Create Website and Add Subdomain did not share the same DNS-parent semantics.

## DNS creation contract
- Generic Create Website now detects the longest existing hosted/DNS parent. A child hostname such as `demo.privategather.com` is classified as a subdomain and updates the existing `privategather.com` authoritative zone instead of creating a separately delegated child zone.
- Add Subdomain and Create Website now converge on the same parent-zone DNS behavior.
- Root websites still provision their own authoritative BIND zone.
- The DNS result is written back to hosted-site state so incomplete DNS is visible rather than silently discarded.
- `POST /v1/dns/repair-hosted` replays the certified DNS provisioning contract for existing sites, repairs legacy child classification, creates missing root zones when possible, and updates existing parent-zone A/AAAA records without recreating websites.
- PCC DNS Zone Manager exposes **Repair hosted DNS** so existing affected domains can be repaired in place.
- DNS Zone Manager remains fail-soft and keeps every known hosted domain visible even when BIND inventory is degraded.

## PPanel access
- PPanel customer login uses the account primary domain as the normal login identity rather than the underlying Linux username.
- PCC Hosting Accounts shows PPanel readiness and provides Set/Reset PPanel Access.
- Existing/imported accounts can receive PPanel credentials without renaming the Linux account.
- PCC and PPanel retain independent session cookies and surface authorization.

## Update consistency
- Migration preflight/apply remain explicitly timeout-bounded.
- Active PCC PHP-FPM is gracefully reloaded after atomic promotion so new PHP/opcache workers read the promoted code while file-backed PCC/PPanel sessions survive.
- Hard PHP-FPM restart remains avoided for routine updates.
- Update Center and transaction status retain local fail-soft fallbacks during agent refresh.

## Delivery
- Intended as a signed Update Center upgrade from 5.0.0-dev.6.60 or newer.
