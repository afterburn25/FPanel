# Privora 5.0.0-dev.6.65 — Per-Domain Nameserver Selection & Package Inventory Resilience

Live comparison showed an older/default domain (`privategather.com`) with its own branded nameservers configured correctly while a later domain (`privoralabs.com`) with its own nameserver set remained NOT CONFIGURED.

Root cause repaired:
- root-zone provisioning and hosted-DNS repair used the global/default nameserver set even when the target domain had its own exact nameserver set;
- later-added branded nameserver domains could therefore be provisioned with the wrong NS pair;
- package inventory allowed the server-side apt/dnf probe to consume the same 20-second deadline as PCC, risking a truncated response and `Invalid response from agent`.

6.65 behavior:
- exact matching nameserver set wins for root-zone create/repair;
- default nameserver set is only a fallback for domains without their own set;
- package inventory has a 12-second server deadline and returns valid degraded JSON instead of a partial response.

PPanel access improvement:
- PCC can assign a custom customer-facing PPanel username independent from the Linux hosting username;
- usernames are 3-64 characters using letters, numbers, dot, underscore or hyphen and are collision-checked case-insensitively;
- the hosting account primary domain remains a durable alternate login alias;
- renaming a PPanel username removes the previous custom username so stale login names do not remain valid;
- PPanel sign-in explicitly accepts either the custom PPanel username or the primary domain.
