#!/usr/bin/env python3
import os,re,sys,tempfile,shutil
p='/etc/dovecot/conf.d/99-privora-mail.conf'
if not os.path.exists(p):
    print('DOVECOT_PRIVORA_CONFIG=ABSENT')
    raise SystemExit(0)
s=open(p,encoding='utf-8').read()
original=s
repls=[
(r'^service lmtp \{ unix_listener ([^ ]+) \{ mode = ([^;]+); user = ([^;]+); group = ([^;]+); \} \}$',
 lambda m: f"service lmtp {{\n  unix_listener {m.group(1)} {{\n    mode = {m.group(2).strip()}\n    user = {m.group(3).strip()}\n    group = {m.group(4).strip()}\n  }}\n}}"),
(r'^protocol lmtp \{ mail_plugins = (.*?) \}$',
 lambda m: f"protocol lmtp {{\n  mail_plugins = {m.group(1).strip()}\n}}"),
(r'^plugin \{ sieve = (.*?) \}$',
 lambda m: f"plugin {{\n  sieve = {m.group(1).strip()}\n}}"),
(r'^service imap-login \{ inet_listener imap \{ port = 0 \} inet_listener imaps \{ port = 993; ssl = yes \} \}$',
 lambda m: "service imap-login {\n  inet_listener imap {\n    port = 0\n  }\n  inet_listener imaps {\n    port = 993\n    ssl = yes\n  }\n}"),
(r'^service pop3-login \{ inet_listener pop3 \{ port = 0 \} inet_listener pop3s \{ port = 995; ssl = yes \} \}$',
 lambda m: "service pop3-login {\n  inet_listener pop3 {\n    port = 0\n  }\n  inet_listener pop3s {\n    port = 995\n    ssl = yes\n  }\n}"),
(r'^local_name ([^ ]+) \{ ssl_cert = <([^;]+); ssl_key = <([^;]+); \}$',
 lambda m: f"local_name {m.group(1)} {{\n  ssl_cert = <{m.group(2).strip()}\n  ssl_key = <{m.group(3).strip()}\n}}"),
]
for pattern, repl in repls:
    s=re.sub(pattern,repl,s,flags=re.M)
if s==original:
    if re.search(r'\{[^\n{}]+\{', s) or re.search(r'^local_name .*\{ .*;$', s, re.M):
        print('ERROR: unsupported inline Privora Dovecot syntax remains',file=sys.stderr)
        raise SystemExit(2)
    print('DOVECOT_PRIVORA_CONFIG=UNCHANGED')
    raise SystemExit(0)
backup=p+'.pre-rev5r8'
if not os.path.exists(backup): shutil.copy2(p,backup)
fd,tmp=tempfile.mkstemp(prefix='.99-privora-mail.',dir=os.path.dirname(p))
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(s)
    os.chmod(tmp,0o644)
    os.replace(tmp,p)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
print('DOVECOT_PRIVORA_CONFIG=REPAIRED')
