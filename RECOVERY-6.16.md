# Privora Panel 5.0.0-dev.6.17 — Authoritative Inventory Recovery

This recovery fixes live-host inventory that could remain empty after the PHP-to-agent bridge itself was repaired.

## Changes
- Nginx website discovery now treats `nginx -T` as the authoritative active configuration and therefore sees arbitrary include paths, not just Debian `sites-available`/`sites-enabled` conventions.
- Conventional Nginx files are still scanned so disabled vhosts remain visible and discovery works if `nginx -T` is temporarily unavailable.
- Host inventory runs slow Nginx/PHP/SQL probes concurrently and shares an 8-second authoritative snapshot across rapid WHM API requests so a slow SQL probe cannot blank Accounts/Websites.
- Website ownership can be inferred from real passwd home directories or the document-root UID; externally configured normal users can be surfaced as discovered hosting accounts without being falsely marked Privora-managed.
- WHM Websites includes Live Host Discovery diagnostics: detected sites/accounts, effective Nginx server-block count, scan paths, and warnings.
- Installer/updater production checks now query `/v1/host/inventory` as the real `privora-panel` PHP identity.
- Browser ZIP updates restart PHP-FPM in addition to the Privora agent and Nginx so API/frontend PHP changes take effect immediately.
