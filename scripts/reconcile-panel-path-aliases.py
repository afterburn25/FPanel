#!/usr/bin/env python3
"""Safely add Privora PCC/PPanel path-access aliases to active website vhosts.

The aliases are implemented as redirects to the isolated control-panel listeners:
  /pcc    -> https://$host:<PCC_PORT>/
  /ppanel -> https://$host:<PPANEL_PORT>/

Existing site content never shares a PHP/session runtime with the control panels.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

MARKER = "include ../snippets/privora-panel-path-aliases.conf; # Privora PCC/PPanel access"


def validate_port(value: str) -> int:
    p = int(value)
    if not 1 <= p <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return p


def render_snippet(pcc: int, ppanel: int) -> str:
    if pcc == ppanel:
        raise ValueError("PCC and PPanel ports must differ")
    return f'''# Managed by Privora. Do not edit manually.\n# Convenience paths preserve separate PCC/PPanel listener and session boundaries.\nlocation = /pcc {{ return 302 https://$host:{pcc}/; }}\nlocation = /pcc/ {{ return 302 https://$host:{pcc}/; }}\nlocation = /ppanel {{ return 302 https://$host:{ppanel}/; }}\nlocation = /ppanel/ {{ return 302 https://$host:{ppanel}/; }}\n'''


def server_blocks(text: str):
    # Conservative brace scanner. We only mutate blocks explicitly beginning with
    # the nginx `server {` directive and containing listen 80/443 + server_name.
    for m in re.finditer(r'(?m)^([ \t]*)server\s*\{', text):
        depth = 0
        i = m.end() - 1
        quote = None
        esc = False
        comment = False
        while i < len(text):
            ch = text[i]
            if comment:
                if ch == '\n': comment = False
                i += 1; continue
            if quote:
                if esc: esc = False
                elif ch == '\\': esc = True
                elif ch == quote: quote = None
                i += 1; continue
            if ch == '#': comment = True; i += 1; continue
            if ch in ('"', "'"): quote = ch; i += 1; continue
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    yield m.start(), i + 1, m.group(1), text[m.start():i+1]
                    break
            i += 1


def eligible(block: str) -> bool:
    if not re.search(r'(?m)^\s*server_name\s+[^;]+;', block):
        return False
    listens = re.findall(r'(?m)^\s*listen\s+([^;]+);', block)
    if not any(re.search(r'(?<!\d)(80|443)(?!\d)', x) for x in listens):
        return False
    if re.search(r'(?m)^\s*listen\s+(?:\[::\]:)?(?:8443|2443)\b', block):
        return False
    return True


def inject(text: str) -> tuple[str, int, int]:
    blocks = list(server_blocks(text))
    edits = []
    changed = 0
    skipped_conflict = 0
    for start, end, indent, block in blocks:
        if not eligible(block) or MARKER in block:
            continue
        if re.search(r'(?m)^\s*location\s*=\s*/(?:pcc|ppanel)/?\s*\{', block):
            skipped_conflict += 1
            continue
        open_brace = text.find('{', start, end)
        edits.append((open_brace + 1, f"\n{indent}    {MARKER}"))
        changed += 1
    for pos, addition in reversed(edits):
        text = text[:pos] + addition + text[pos:]
    return text, changed, skipped_conflict


def candidates(enabled: Path, confd: Path) -> list[Path]:
    out = []
    seen = set()
    for base in (enabled, confd):
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            if entry.name == 'privora-panel.conf' or (base == confd and entry.suffix != '.conf'):
                continue
            try:
                target = entry.resolve(strict=True)
            except (FileNotFoundError, RuntimeError):
                continue
            if not target.is_file() or target in seen:
                continue
            seen.add(target); out.append(target)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcc-port', type=validate_port, default=int(os.getenv('PRIVORA_ADMIN_PANEL_PORT', '8443')))
    ap.add_argument('--ppanel-port', type=validate_port, default=int(os.getenv('PRIVORA_HOSTING_PANEL_PORT', '2443')))
    ap.add_argument('--snippet', default='/etc/nginx/snippets/privora-panel-path-aliases.conf')
    ap.add_argument('--sites-enabled', default='/etc/nginx/sites-enabled')
    ap.add_argument('--conf-d', default='/etc/nginx/conf.d')
    ap.add_argument('--backup-root', default='/var/lib/privora-panel/nginx-path-alias-backups')
    ap.add_argument('--no-nginx-test', action='store_true')
    a = ap.parse_args()
    if a.pcc_port == a.ppanel_port:
        raise SystemExit('PCC and PPanel ports must differ')

    snippet = Path(a.snippet)
    enabled = Path(a.sites_enabled)
    confd = Path(a.conf_d)
    backup_root = Path(a.backup_root)
    files = candidates(enabled, confd)
    planned = []
    conflicts = 0
    for path in files:
        try: original = path.read_text()
        except (UnicodeDecodeError, OSError): continue
        revised, count, skipped = inject(original)
        conflicts += skipped
        if count:
            planned.append((path, original, revised, count))

    snippet.parent.mkdir(parents=True, exist_ok=True)
    rendered_snippet = render_snippet(a.pcc_port, a.ppanel_port).encode()
    old_snippet = snippet.read_bytes() if snippet.exists() else None
    snippet_changed = old_snippet != rendered_snippet
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup_dir = backup_root / stamp
    if planned or snippet_changed:
        backup_dir.mkdir(parents=True, exist_ok=True)
    if snippet_changed and old_snippet is not None:
        (backup_dir / 'snippet.before').write_bytes(old_snippet)
    if snippet_changed:
        snippet.write_bytes(rendered_snippet)
        os.chmod(snippet, 0o644)

    backups = []
    for idx, (path, original, revised, count) in enumerate(planned):
        bp = backup_dir / f'vhost-{idx}.conf'
        bp.write_text(original)
        backups.append((path, original))
        tmp = path.with_name(path.name + f'.privora.{os.getpid()}.tmp')
        tmp.write_text(revised)
        os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
        print(f'patched={path} server_blocks={count}')

    if not a.no_nginx_test:
        r = subprocess.run(['nginx', '-t'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0:
            for path, original in backups:
                path.write_text(original)
            if old_snippet is None:
                try: snippet.unlink()
                except FileNotFoundError: pass
            else:
                snippet.write_bytes(old_snippet)
            print(r.stdout, file=sys.stderr)
            print('Privora PCC/PPanel alias reconciliation failed nginx validation; all changes restored.', file=sys.stderr)
            return 1
    print(f'PCC/PPanel path aliases ready: /pcc -> :{a.pcc_port}, /ppanel -> :{a.ppanel_port}; patched_files={len(planned)} conflicts_skipped={conflicts}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
