# Privora Panel 5.0.0-dev.6.70 — Database Credential & Lifecycle Recovery

Built from the exact live-certified 5.0.0-dev.6.69 tree after phpMyAdmin became available but database creation exposed no usable password to the operator.

## Live defect recovered

- The agent already returned one-time database credentials on create, but PCC/PPanel generic create handlers discarded them and only displayed `Resource created`.
- PPanel did not expose a database username/password form and had no database edit, password-reset, or delete controls.
- Existing database passwords cannot be recovered because Privora intentionally does not persist plaintext database secrets.

## 6.70 contract

- Create Database accepts database name, database user, certified engine, owner/scope, and an optional operator-selected password.
- Blank password generates a cryptographically random server-side password; manual passwords must be 12–128 characters and contain no line breaks/NUL.
- Successful create/reset/edit returns credentials once and both PCC/PPanel display them in a persistent `SAVE NOW / SHOWN ONCE` card.
- Plaintext database passwords are never written into Privora resource state or inventory.
- Existing Privora-managed database users can be renamed and/or assigned a new password.
- Existing passwords are reset, never retrieved.
- Database deletion drops the database and its paired Privora-managed database user and requires exact database-name confirmation.
- PPanel database mutations enforce account ownership and the `databases` feature gate.
- Database names are intentionally not renamed by the editor. MySQL/MariaDB do not provide a safe native atomic database rename; 6.70 edits database access identity instead of performing risky table-copy migration under a rename button.
- phpMyAdmin remains panel-session gated and uses the resulting database username/password.

## Safety

- Database identifiers remain validated by the host adapter.
- Credential validation occurs before host-client/tool discovery so invalid secrets fail consistently.
- MySQL/MariaDB user rename attempts a best-effort rename rollback if the password update fails.
- PostgreSQL role rename/password update is transactional.
- Delete acts only on Privora-managed database metadata and paired users.
- 5.0.0-dev.6.45 remains permanently quarantined and is not used.
