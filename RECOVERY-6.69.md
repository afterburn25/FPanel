# Privora 5.0.0-dev.6.69 — First-Class phpMyAdmin Integration

- Installs phpMyAdmin through the operating-system package manager on supported Debian/Ubuntu hosts.
- Routes phpMyAdmin only through Privora PCC/PPanel listeners; hosted websites do not receive a public /phpmyadmin alias.
- Requires an authenticated Privora session with database-management permission before Nginx serves phpMyAdmin.
- PPanel Feature Manager can disable phpMyAdmin per hosting package.
- Uses a dedicated PHP-FPM pool for phpMyAdmin instead of executing third-party code in the Privora panel pool.
- Uses phpMyAdmin cookie authentication against the local MySQL/MariaDB server; Privora never stores database passwords for browser SSO.
- Disables no-password login, arbitrary-server login, credential recall, and root login in the Privora phpMyAdmin configuration.
- Adds live package/path/route/pool capability detection and PCC/PPanel launch controls.
