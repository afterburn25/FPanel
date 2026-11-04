#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

STATE_DIR="${PRIVORA_MAIL_STATE_DIR:-/etc/privora-mail}"
DOVECOT_DIR="${PRIVORA_DOVECOT_CONF_DIR:-/etc/dovecot/conf.d}"
AUTH_MAIN="$DOVECOT_DIR/10-auth.conf"
AUTH_PRIVORA="$DOVECOT_DIR/auth-privora.conf.ext"
AUTH_ACCESS="$DOVECOT_DIR/99-privora-mail-auth-access.conf"
AUTH_GROUP="${PRIVORA_MAIL_AUTH_GROUP:-privora-panel}"
BACKUP_ROOT="${PRIVORA_MAIL_AUTH_BACKUP_ROOT:-/var/lib/privora-panel/mail-auth-backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP="$BACKUP_ROOT/$STAMP"
committed=0

log(){ printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root."
for cmd in getent install python3 doveconf doveadm postconf postfix systemctl; do command -v "$cmd" >/dev/null || die "$cmd is required"; done
getent group "$AUTH_GROUP" >/dev/null || die "required mail-auth group is missing: $AUTH_GROUP"
[[ -f "$AUTH_MAIN" ]] || die "Dovecot auth selector is missing: $AUTH_MAIN"

POSTFIX_DIR="$(postconf -h config_directory 2>/dev/null || true)"
POSTFIX_DIR="${POSTFIX_DIR:-/etc/postfix}"
MAIN_CF="$POSTFIX_DIR/main.cf"
MASTER_CF="$POSTFIX_DIR/master.cf"

paths=(
  "$AUTH_MAIN" "$AUTH_PRIVORA" "$AUTH_ACCESS"
  "$MAIN_CF" "$MASTER_CF"
  "$STATE_DIR/dovecot_users" "$STATE_DIR/virtual_mailboxes"
  "$STATE_DIR/virtual_domains" "$STATE_DIR/virtual_aliases"
)

backup_path(){
  local p="$1" rel="${p#/}"
  mkdir -p "$BACKUP/files/$(dirname "$rel")" "$BACKUP/presence/$(dirname "$rel")"
  if [[ -e "$p" || -L "$p" ]]; then
    cp -a "$p" "$BACKUP/files/$rel"
    : > "$BACKUP/presence/$rel"
  fi
}
restore_path(){
  local p="$1" rel="${p#/}"
  if [[ -e "$BACKUP/presence/$rel" ]]; then
    mkdir -p "$(dirname "$p")"
    rm -rf "$p"
    cp -a "$BACKUP/files/$rel" "$p"
  else
    rm -f "$p"
  fi
}
rollback(){
  [[ "$committed" -eq 0 ]] || return 0
  log "Mail-auth reconcile failed; restoring previous Dovecot/Postfix/auth-state files."
  for p in "${paths[@]}"; do restore_path "$p" || true; done
  doveconf -n >/dev/null 2>&1 && systemctl restart dovecot >/dev/null 2>&1 || true
  postfix check >/dev/null 2>&1 && systemctl restart postfix >/dev/null 2>&1 || true
}
trap rollback ERR

mkdir -p "$BACKUP"
for p in "${paths[@]}"; do backup_path "$p"; done

log "Securing Privora virtual-mail state"
install -d -o root -g "$AUTH_GROUP" -m0750 "$STATE_DIR"
for f in dovecot_users virtual_mailboxes virtual_domains virtual_aliases; do
  [[ -e "$STATE_DIR/$f" ]] || : > "$STATE_DIR/$f"
  chown root:"$AUTH_GROUP" "$STATE_DIR/$f"
  chmod 0640 "$STATE_DIR/$f"
done

log "Installing Privora passwd-file authentication backend"
cat >"$AUTH_PRIVORA" <<EOF_AUTH
# Privora-managed virtual mailbox authentication.
# Full-address logins are mandatory; do not replace with PAM/system passwd.
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u $STATE_DIR/dovecot_users
}
userdb {
  driver = passwd-file
  args = username_format=%u $STATE_DIR/dovecot_users
}
EOF_AUTH
chmod 0644 "$AUTH_PRIVORA"

cat >"$AUTH_ACCESS" <<EOF_ACCESS
# Privora-managed Dovecot authentication worker access.
# The password database remains root:$AUTH_GROUP 0640 and is never world-readable.
service auth {
  user = \$default_internal_user
  group = $AUTH_GROUP
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
service auth-worker {
  user = \$default_internal_user
  group = $AUTH_GROUP
}
EOF_ACCESS
chmod 0644 "$AUTH_ACCESS"

python3 - "$AUTH_MAIN" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
out=[]; seen=False
for line in s.splitlines():
    t=line.strip()
    if t and not t.startswith('#'):
        f=t.split()
        if len(f)>=2 and f[0] in ('!include','!include_try'):
            base=Path(f[1]).name
            if base=='auth-system.conf.ext':
                out.append('# Privora disabled system authentication: '+t)
                continue
            if base=='auth-privora.conf.ext':
                if not seen:
                    out.append('!include auth-privora.conf.ext'); seen=True
                continue
    out.append(line)
if not seen:
    out += ['', '# Privora virtual mailbox authentication', '!include auth-privora.conf.ext']
p.write_text('\n'.join(out).rstrip()+'\n')
PY
chmod 0644 "$AUTH_MAIN"

log "Configuring Postfix SMTP AUTH through Dovecot"
postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_security_options = noanonymous'
postconf -e 'smtpd_tls_auth_only = yes'
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
postconf -M 'submission/inet=submission inet n - y - - smtpd'
postconf -P 'submission/inet/syslog_name=postfix/submission'
postconf -P 'submission/inet/smtpd_tls_security_level=encrypt'
postconf -P 'submission/inet/smtpd_sasl_auth_enable=yes'
postconf -P 'submission/inet/smtpd_sasl_type=dovecot'
postconf -P 'submission/inet/smtpd_sasl_path=private/auth'
postconf -P 'submission/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject'
postconf -P 'submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'
postconf -M 'submissions/inet=submissions inet n - y - - smtpd'
postconf -P 'submissions/inet/syslog_name=postfix/submissions'
postconf -P 'submissions/inet/smtpd_tls_wrappermode=yes'
postconf -P 'submissions/inet/smtpd_tls_security_level=encrypt'
postconf -P 'submissions/inet/smtpd_sasl_auth_enable=yes'
postconf -P 'submissions/inet/smtpd_sasl_type=dovecot'
postconf -P 'submissions/inet/smtpd_sasl_path=private/auth'
postconf -P 'submissions/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject'
postconf -P 'submissions/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'

log "Validating effective Dovecot and Postfix configuration"
summary="$(doveconf -n passdb userdb)"
printf '%s\n' "$summary" | grep -q 'driver = passwd-file' || die "Dovecot passwd-file passdb/userdb not effective"
[[ "$(printf '%s\n' "$summary" | grep -c 'driver = passwd-file' || true)" -ge 2 ]] || die "Dovecot does not expose both passwd-file passdb and userdb"
! printf '%s\n' "$summary" | grep -q 'driver = pam' || die "PAM passdb is still active"
! printf '%s\n' "$summary" | grep -Eq '^[[:space:]]*driver = passwd[[:space:]]*$' || die "system passwd userdb is still active"
doveconf -n >/dev/null
[[ "$(postconf -h smtpd_sasl_type)" == "dovecot" ]] || die "Postfix SASL type is not Dovecot"
[[ "$(postconf -h smtpd_sasl_path)" == "private/auth" ]] || die "Postfix SASL path is not private/auth"
[[ "$(postconf -h smtpd_sasl_auth_enable)" == "yes" ]] || die "Postfix SMTP AUTH is not enabled"
postfix check

log "Restarting and certifying mail authentication services"
systemctl restart dovecot
systemctl restart postfix
systemctl is-active --quiet dovecot
systemctl is-active --quiet postfix

known="$(awk -F: 'NF>1 && $1 ~ /@/ {print $1; exit}' "$STATE_DIR/dovecot_users")"
if [[ -n "$known" ]]; then
  doveadm user "$known" >/dev/null
  log "Dovecot virtual-user lookup passed for $known"
fi

committed=1
trap - ERR
log "PASS: Privora virtual-mail authentication reconciled safely."
echo "Backup: $BACKUP"
