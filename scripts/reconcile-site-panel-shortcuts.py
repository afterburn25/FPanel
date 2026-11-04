#!/usr/bin/env python3
"""Reconcile Privora reserved routes in managed hosting vhosts.

Adds PCC/PPanel shortcut redirects and the ACME HTTP-01 exception required for
Let's Encrypt webroot validation. Only server blocks with a /home/... document
root or an explicit Privora-managed marker are eligible. Existing explicit PCC
or PPanel locations are preserved and reported as conflicts rather than overwritten.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import re

p=argparse.ArgumentParser()
p.add_argument('--admin-port', type=int, required=True)
p.add_argument('--hosting-port', type=int, required=True)
p.add_argument('files', nargs='+')
a=p.parse_args()
for name,port in [('PCC',a.admin_port),('PPanel',a.hosting_port)]:
    if port < 1 or port > 65535:
        raise SystemExit(f'invalid {name} port: {port}')
if a.admin_port == a.hosting_port:
    raise SystemExit('PCC and PPanel ports must differ')

SERVER_RE=re.compile(r'\bserver\s*\{')
ROOT_RE=re.compile(r'(?m)^\s*root\s+(/home/[^;\s]+)\s*;')
NAME_RE=re.compile(r'(?m)^\s*server_name\s+([^;]+);')

def blocks(text:str):
    out=[]
    for m in SERVER_RE.finditer(text):
        start=m.start(); brace=text.find('{',m.start()); depth=0; quote=None; esc=False; comment=False
        i=brace
        while i < len(text):
            c=text[i]
            if comment:
                if c=='\n': comment=False
                i+=1; continue
            if quote:
                if esc: esc=False
                elif c=='\\': esc=True
                elif c==quote: quote=None
                i+=1; continue
            if c=='#': comment=True; i+=1; continue
            if c in ('"',"'"): quote=c; i+=1; continue
            if c=='{': depth+=1
            elif c=='}':
                depth-=1
                if depth==0:
                    out.append((start,i+1)); break
            i+=1
    return out

def shortcut_lines(indent='    '):
    return (
      f"{indent}# Privora Panel reserved shortcuts\n"
      f"{indent}location = /pcc {{ return 302 https://$host:{a.admin_port}/; }}\n"
      f"{indent}location = /pcc/ {{ return 302 https://$host:{a.admin_port}/; }}\n"
      f"{indent}location = /ppanel {{ return 302 https://$host:{a.hosting_port}/; }}\n"
      f"{indent}location = /ppanel/ {{ return 302 https://$host:{a.hosting_port}/; }}\n"
    )

def acme_lines(indent='    '):
    return (
      f"{indent}# Privora AutoSSL HTTP-01 challenge exception\n"
      f"{indent}location ^~ /.well-known/acme-challenge/ {{ try_files $uri =404; }}\n"
    )

changed=[]; conflicts=[]
for raw in a.files:
    path=Path(raw)
    if not path.is_file() or path.name == 'privora-panel.conf':
        continue
    try: text=path.read_text()
    except UnicodeDecodeError: continue
    edits=[]
    for start,end in blocks(text):
        block=text[start:end]
        if not ROOT_RE.search(block) and 'Managed by Privora Panel' not in block:
            continue
        if not NAME_RE.search(block):
            continue
        has_pcc=re.search(r'(?m)^\s*location\s+(?:=\s*)?/pcc(?:/)?\s*\{',block)
        has_ppanel=re.search(r'(?m)^\s*location\s+(?:=\s*)?/ppanel(?:/)?\s*\{',block)
        has_acme=re.search(r'(?m)^\s*location\s+\^~\s+/\.well-known/acme-challenge/\s*\{',block)
        additions=[]
        if not has_acme:
            additions.append(acme_lines('    '))
        if has_pcc or has_ppanel:
            if not (has_pcc and has_ppanel): conflicts.append(str(path))
        else:
            additions.append(shortcut_lines('    '))
        if additions:
            close=end-1
            edits.append((close, '\n'+''.join(additions)))
    if edits:
        new=text
        for pos,addition in sorted(edits, reverse=True):
            new=new[:pos]+addition+new[pos:]
        path.write_text(new)
        changed.append(str(path))

for x in changed: print('CHANGED '+x)
for x in sorted(set(conflicts)): print('CONFLICT '+x)
print(f'SUMMARY changed={len(changed)} conflicts={len(set(conflicts))}')
