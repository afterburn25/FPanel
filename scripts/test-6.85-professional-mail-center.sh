#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
[[ "$(tr -d '\r\n' < "$ROOT/VERSION")" =~ ^5\.0\.0-dev\.6\.(8[5-9]|90)$ || "$(tr -d '\r\n' < "$ROOT/VERSION")" == "5.0.0-dev.7.0" ]]
API="$ROOT/panel/public/api.php"; ADMIN="$ROOT/panel/public/admin.php"; CUSTOMER="$ROOT/panel/public/customer.php"; JS="$ROOT/panel/public/assets/app.js"; CJS="$ROOT/panel/public/assets/customer.js"; CSS="$ROOT/panel/public/assets/app.css"; SERVER="$ROOT/agent/internal/api/server.go"; PSERVER="$ROOT/agent/internal/api/server_platform.go"; MAIL="$ROOT/agent/internal/hostadapter/mail.go"; SECURE="$ROOT/agent/internal/hostadapter/mail_secure.go"
# Both surfaces build mailbox/forwarder addresses from a local-part + live domain selector.
grep -Fq 'id="mailboxCreateForm"' "$ADMIN"
grep -Fq 'data-domain-source="existing"' "$ADMIN"
grep -Fq 'id="mailAliasCreateForm"' "$ADMIN"
grep -Fq 'id="cpMailboxCreateForm"' "$CUSTOMER"
grep -Fq 'data-domain-source="existing-active"' "$CUSTOMER"
grep -Fq 'id="cpAliasCreateForm"' "$CUSTOMER"
grep -Fq 'name="password_confirm"' "$ADMIN"
grep -Fq 'name="password_confirm"' "$CUSTOMER"
# Professional management inventory and edit/delete surfaces are present.
grep -Fq 'id="mailboxEditModal"' "$ADMIN"
grep -Fq 'id="mailAliasEditModal"' "$ADMIN"
grep -Fq 'id="cpMailboxEditModal"' "$CUSTOMER"
grep -Fq 'id="cpAliasEditModal"' "$CUSTOMER"
grep -Fq 'data-mailbox-edit=' "$JS"
grep -Fq 'data-mailbox-delete=' "$JS"
grep -Fq 'data-mail-alias-edit=' "$JS"
grep -Fq 'data-mail-alias-delete=' "$JS"
grep -Fq 'data-customer-mailbox-edit=' "$CJS"
grep -Fq 'data-customer-mailbox-delete=' "$CJS"
grep -Fq 'data-customer-alias-edit=' "$CJS"
grep -Fq 'data-customer-alias-delete=' "$CJS"
grep -Fq '.mail-address-builder' "$CSS"
# Rev2 declutters the Mail Center into a compact overview + dedicated workspaces.
grep -Fq 'class="mail-overview"' "$ADMIN"
grep -Fq 'class="mail-tabs"' "$ADMIN"
grep -Fq 'data-mail-tab="mailboxes"' "$ADMIN"
grep -Fq 'data-mail-panel="forwarders"' "$ADMIN"
grep -Fq 'data-mail-panel="domains"' "$ADMIN"
grep -Fq 'data-mail-panel="webmail"' "$ADMIN"
grep -Fq 'class="panel-card mail-compose' "$ADMIN"
grep -Fq 'customer-mail-overview' "$CUSTOMER"
grep -Fq 'customer-mail-compose' "$CUSTOMER"
grep -Fq 'function setMailWorkspaceTab' "$JS"
grep -Fq '.mail-tabs' "$CSS"
grep -Fq '.mail-compose' "$CSS"
! grep -Fq '<div class="mail-center-grid"' "$ADMIN"
! grep -Fq '<div class="mail-center-grid"' "$CUSTOMER"
grep -Fq -- "-mail-r2" "$ADMIN"
grep -Fq -- "-mail-r2" "$CUSTOMER"
# Old browser-alert credential flow must be gone.
! grep -Fq 'SAVE THIS PASSWORD NOW' "$CJS"
! grep -Fq 'save the one-time password' "$JS"
# API bridge requires operator password and exposes scoped lifecycle routes.
grep -Fq "customer-mailbox-update" "$API"
grep -Fq "customer-mailbox-delete" "$API"
grep -Fq "customer-mail-alias-update" "$API"
grep -Fq "customer-mail-alias-delete" "$API"
grep -Fq "mailbox-update" "$API"
grep -Fq "mailbox-delete" "$API"
grep -Fq "mail-alias-update" "$API"
grep -Fq "mail-alias-delete" "$API"
grep -Fq "Mailbox password must be at least 12 characters" "$API"
grep -Fq "Type the exact mailbox address to confirm deletion" "$API"
grep -Fq "Type the exact forwarder address to confirm deletion" "$API"
# Agent routes and transactional host mutation methods exist.
grep -Fq 'PATCH /v1/mailboxes/{address}' "$SERVER"
grep -Fq 'DELETE /v1/mailboxes/{address}' "$SERVER"
grep -Fq 'ProvisionMailboxWithPassword' "$MAIL"
grep -Fq 'func (a *Adapter) UpdateMailbox' "$MAIL"
grep -Fq 'func (a *Adapter) UpdateMailAlias' "$SECURE"
grep -Fq 'func (a *Adapter) DeleteMailAlias' "$SECURE"
grep -Fq 'mailbox.update' "$SERVER"
grep -Fq 'mailbox.delete' "$SERVER"
grep -Fq 'mail.alias.update' "$PSERVER"
grep -Fq 'mail.alias.delete' "$PSERVER"
# Mailbox editing must preserve address/Maildir: update method only rewrites auth/quota map.
python3 - "$MAIL" <<'PY'
import sys
s=open(sys.argv[1],encoding='utf-8').read()
a=s.index('func (a *Adapter) UpdateMailbox')
b=s.find('\nfunc ',a+10)
body=s[a:b if b!=-1 else None]
assert 'dovecot_users' in body
assert 'userdb_quota_rule' in body
assert 'os.Rename(' not in body
assert 'mailDirForAddress' not in body
PY
echo 'PASS: 6.85 Rev2 professional Mail Center / decluttered workspace / domain dropdown / password / edit-delete lifecycle contract'
