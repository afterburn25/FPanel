# Privora Panel 5.0.0-dev.6.26 — Website Transaction & Operator UI Repair

- Isolates the Privora control panel on `privora-panel-fpm.service` so customer PHP-FPM reloads cannot reset active panel/API requests.
- Invalidates live-host discovery immediately after website provisioning so the Websites page sees the new vhost without waiting for the discovery cache.
- Automatically attempts local authoritative DNS provisioning for a newly created website when Privora has certified BIND control and a public server address.
- Creates default A/AAAA records for the zone and ns1/ns2 plus a `www` CNAME, and returns a truthful managed/action-required DNS result.
- Makes Privora BIND zone include configuration part of full/dns installation.
- Filters Service Manager to installed systemd units and rejects actions against absent services instead of showing phantom apache2/httpd controls.
- Removes Build Train, Build Status, Build horizon and the roadmap page from the production panel UI.
- Improves non-JSON API error reporting so upstream failures expose HTTP context instead of only `Invalid server response`.
