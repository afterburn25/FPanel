# Privora Panel 5.0.0-dev.6.71 — Config Workspace, Curated Components & Webmail Provisioning

Built from the exact 5.0.0-dev.6.70 database-lifecycle source after live use exposed the PPanel post-create JavaScript typo and after the operator requested a cleaner server Config Editor, searchable package/extension installation, Laravel tooling, and first-class webmail provisioning.

## Database UI recovery

- Replaces the stale `applyDatabaseCapabilities()` post-create call with the real `renderDatabaseEngines()` function.
- Database provisioning remains server-authoritative; the UI no longer throws after a successful create.
- PPanel JavaScript is cache-busted at the 6.71 asset version.

## Config Editor redesign

- Common edits appear first instead of an undifferentiated vertical file form.
- Approved configuration files are categorized as Web Server, PHP, DNS, or Advanced.
- Search matches title, description, service and path.
- The selected file uses a horizontal header with title, category, service, path and safety state on one line/area, followed by a full-width editor.
- Saves retain Privora's backup, syntax-validation and rollback contract.

## Extensions & Components

- Adds a PCC **Extensions & Components** workspace under Server Configuration.
- Search matches friendly component names, package names and tags.
- Components are curated/allow-listed; the browser cannot submit arbitrary package names or shell commands.
- Inventory reports Installed, Partial, Available or Not supported from the live APT catalog.
- Includes PHP/PDO drivers and extensions, FFmpeg/media tools, database clients, server utilities and developer tools.
- Laravel Development Stack installs Composer, Git, Node/NPM, PHP 8.4 framework modules and the Laravel installer. Laravel 13 is compatible with the server's PHP 8.4 runtime.

## Roundcube webmail

- Adds a first-class **Roundcube Webmail** component and a direct **Install / Repair Roundcube** action in PCC Mail.
- Debian/Ubuntu provisioning pre-seeds Roundcube's dbconfig-common SQLite metadata database before Privora configuration.
- Uses a dedicated PHP 8.4 FPM pool/socket.
- `/webmail/` is exposed only on the Privora control-plane listeners.
- A PCC/PPanel session gate is required before the Roundcube mailbox login is served.
- Roundcube authenticates mailbox credentials against local Dovecot/Postfix; Privora does not store mailbox passwords.
- The Roundcube installer path is denied from the web route.

## Safety

- Component install/remove operations are serialized and allow-listed by static component ID.
- Shared/core components that Privora cannot safely remove are marked non-removable.
- Component operations receive bounded 600-second control-plane timeouts.
- Webmail configuration backs up managed Nginx/FPM/Roundcube files and restores them if validation fails.
- Existing phpMyAdmin, panel TLS anchors, DNS, AutoSSL, PCC/PPanel split ports and database lifecycle semantics are retained.
- 5.0.0-dev.6.45 remains permanently quarantined and was not used.
