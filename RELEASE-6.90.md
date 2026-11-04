# Privora Panel 5.0.0-dev.6.90 — Control Panel Coverage, Efficiency & Three-Pass UX Polish

**Status:** prepared candidate. Built from the confirmed live 5.0.0-dev.6.89 Virtual Mail Authentication Core. Do not promote to accepted/live until installed and verified on the target VPS.

## Pass 1 — functional coverage and missing controls

- Repairs the PCC navigation contract so every exposed destination has a matching workspace; no blank/dead PCC destinations remain.
- Adds a real PCC Firewall Manager backed by the existing typed firewall API instead of a placeholder page.
- Adds a real PCC Reseller Center for reseller policy, package/feature permissions, account limits and PCC-access management.
- Consolidates Fleet, Cloud, Automation and Fabric simulation controls into Platform Labs & Engineering so experimental contracts do not clutter the production navigation.
- Exposes the existing secure TOTP/MFA backend in both PCC and PPanel, including enrollment, confirmation and credential-protected disable flows.
- Adds PPanel Disk Usage backed by the live account usage adapter with account-scoped Files authorization; it no longer depends on the broader Metrics feature.
- Preserves the 6.89 virtual-mail passwd-file authentication core and all existing mailbox/Maildir/TLS/DKIM/SPF/DMARC behavior.

## Pass 2 — organization and operator efficiency

- Reorganizes everyday PCC labels around direct hosting/server tasks and adds dashboard shortcuts for accounts, websites, mail, SSL/AutoSSL, backups and security.
- Adds an actionable PCC Needs Attention workspace sourced from live service, website, discovery, update and security state.
- Expands PCC Ctrl/Cmd+K command search with hosting/WHM terminology and operational synonyms.
- Reorganizes PPanel around goal-based Websites & Domains, Email, Files, Databases, Security, Performance & Metrics, and Software groups.
- Adds a PPanel Quick Start strip for the most common customer workflows.
- Adds Ctrl/Cmd+K and `/` shortcuts to focus PPanel tool search when the user is not typing in a form control.

## Pass 3 — visual/navigation polish

- Normalizes the new pages against the existing Privora design system for responsive layout, density settings, light/dark themes, focus-visible keyboard states and reduced-motion preferences.
- Removes duplicate DOM IDs that could cause JavaScript to update one summary while a second copy remained stale or blank.
- Keeps destructive controls visually separated and keeps simulated/platform-lab functions explicitly labeled as gated.
- Keeps production-safe browser boundaries: no unrestricted browser terminal/root shell is introduced.

## Runtime-permission hardening

6.90 permanently closes the permission class that caused the confirmed 6.89 PCC incident:

- `/opt/privora-panel` and `/opt/privora-panel/panel` are normalized to root-owned `0755` traversal for Nginx.
- `/opt/privora-panel/VERSION` is normalized to `root:privora-panel 0640` so dedicated PHP-FPM can render the true build while the file is not world-readable.
- Installer certification explicitly proves the `privora-panel` identity can read VERSION and the Nginx worker can read the public entrypoint.
- Atomic VERSION commit preserves `root:privora-panel 0640` ownership/mode.

## Regression coverage

- PCC: 30 navigation destinations, 30 matching views, zero duplicate HTML IDs.
- PPanel: 40 navigation destinations, 40 matching views, zero duplicate HTML IDs.
- All statically referenced PCC/PPanel frontend API route names are represented by `api.php`.
- MFA, Firewall Manager, Reseller Center, Platform Labs consolidation, Needs Attention, Quick Start and Disk Usage have dedicated 6.90 regression assertions.
- The complete Go, PHP, JavaScript, shell, prior release regression and 6.89 mail-auth gates remain required before packaging.

## Intentionally gated future expansion

Features requiring server-side adapters are not presented as falsely complete. Examples include a production mail queue manager/Track Delivery workflow, full mailbox filtering engine, Dynamic DNS and broader WHM-style server tuning controls. These remain roadmap items until their HostAdapter paths can be implemented and certified fail-closed.
