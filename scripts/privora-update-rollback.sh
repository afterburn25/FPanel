#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
atomic_exchange_dirs(){
  local left="$1" right="$2"
  python3 - "$left" "$right" <<'PYEXCHANGE'
import ctypes,os,sys
left,right=sys.argv[1:]
libc=ctypes.CDLL(None,use_errno=True); fn=getattr(libc,'renameat2',None)
if fn is None: raise SystemExit('renameat2 unavailable; refusing non-atomic rollback')
AT_FDCWD=-100; RENAME_EXCHANGE=2
fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]; fn.restype=ctypes.c_int
if fn(AT_FDCWD,os.fsencode(left),AT_FDCWD,os.fsencode(right),RENAME_EXCHANGE)!=0:
    e=ctypes.get_errno(); raise OSError(e,os.strerror(e),f'{left} <-> {right}')
PYEXCHANGE
}
((EUID==0))||{ echo root required >&2;exit 1;}
id="${1:-}";[[ "$id" =~ ^[0-9]{8}T[0-9]{6}Z-([0-9]+|[0-9a-f]{16})$ ]]||exit 2
state="/var/lib/privora-panel/update-transactions/$id/journal.env";[[ -r "$state" ]]||exit 1
# journal.env is generated only by Privora's updater with shell-escaped values.
# shellcheck disable=SC1090
. "$state"
[[ -n "${previous:-}"&&-d "$previous" ]]||{ echo 'previous release missing' >&2;exit 1; }
backup_dir="${backup:-}"
if [[ -n "$backup_dir" && -f "$backup_dir/privora-files.tar.zst" && -f "$backup_dir/privora-files.tar.zst.sha256" ]]; then
  (cd "$backup_dir" && sha256sum -c privora-files.tar.zst.sha256)
fi
failed="/opt/privora-panel.failed-$id"
[[ ! -e "$failed" ]]||{ echo "rollback target already exists: $failed" >&2;exit 1; }
# Atomic exchange means the live panel path always exists. After the exchange,
# $previous contains the failed release and /opt/privora-panel is restored.
atomic_exchange_dirs /opt/privora-panel "$previous"
mv "$previous" "$failed"
[[ -f /opt/privora-panel/panel/public/index.php && -f /opt/privora-panel/panel/public/admin.php ]] || { echo 'restored panel web root is incomplete' >&2; exit 1; }
# Restore only mutable config/state. Never extract the archived panel core over
# the atomically restored working release.
if [[ -n "$backup_dir" && -f "$backup_dir/privora-files.tar.zst" ]]; then
  tar --zstd -xpf "$backup_dir/privora-files.tar.zst" -C / --exclude='opt/privora-panel' --exclude='opt/privora-panel/**'
fi
install -d -m0755 /usr/local/libexec /usr/local/bin /usr/local/sbin
install -m0750 /opt/privora-panel/dist/privora-agent /usr/local/libexec/privora-agent
install -m0750 /opt/privora-panel/scripts/privora-update.sh /usr/local/sbin/privora-update
install -m0750 /opt/privora-panel/scripts/privora-update-rollback.sh /usr/local/sbin/privora-update-rollback
systemctl daemon-reload
nginx -t
systemctl reload nginx
printf 'status=%q\nphase=%q\noperation=%q\nresult=%q\n' rolled-back rollback "Rollback complete after ${failed_phase:-unknown} failure" rolled-back >>"$state"
# Keep the status API alive through rollback. Refresh the restored agent only after
# the rollback journal is terminal so Update Center can show the original failure.
systemd-run --unit="privora-agent-rollback-refresh-$id" --collect --on-active=2s --property=TimeoutStartSec=45s -- /bin/systemctl restart privora-panel-agent.service >/dev/null 2>&1 || true
echo "Rollback $id PASS"
