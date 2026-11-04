# Privora Panel 5.0.0-dev.6.26 — Website Lifecycle & WHM Core Controls

Prepared from 5.0.0-dev.6.25 after live VPS testing exposed duplicate website mutation and incomplete DNS lifecycle behavior.

## Website lifecycle
- Duplicate-domain preflight now runs before owner allocation, filesystem changes, Nginx writes, PHP-FPM changes, or DNS changes.
- Host adapter refuses to overwrite an existing Privora vhost/document tree as a second defense.
- Website inventory de-duplicates normalized domains.
- Delete Website removes the managed vhost and registration; website files are preserved by default and deleted only with explicit opt-in.
- Privora-managed DNS can be deleted with the website; externally managed zones are not removed.

## DNS / nameservers
- BIND foundation is verified/repaired from the live transaction, including the Privora zone include.
- Full BIND configuration is validated before reload and rolled back on failure.
- Nameserver Manager configures a global primary/secondary pair and authoritative A/AAAA records.
- New hosted zones use configured global Privora nameservers when present.
- Registrar glue/child-host registration is explicitly reported as external unless a registrar API integration exists.

## Server configuration editor
- Approved Nginx, Apache/httpd, PHP-FPM and BIND files are discoverable in the panel.
- Supported Nginx/Apache vhost files are also listed dynamically.
- Saves require optimistic SHA matching, create root-only backups, validate the corresponding server configuration, reload the service, and roll back on validation/reload failure.
- Arbitrary root filesystem paths are not accepted.

## Verification
- Go tests PASS.
- PHP syntax PASS.
- JavaScript syntax PASS.
- Shell/bootstrap syntax PASS.
- Project verification PASS.
- Live integration smoke PASS.
