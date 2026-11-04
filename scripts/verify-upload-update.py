#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, re, stat, subprocess, sys, tempfile, zipfile

MAX_FILES=100000
MAX_TOTAL=1024*1024*1024
MAX_MANIFEST=65536
REQ={"VERSION","panel/public/index.php","scripts/privora-update.sh","scripts/privora-update-rollback.sh","dist/privora-agent","dist/privora-agent.sha256"}
VER_RE=re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9][A-Za-z0-9.-]*)?$")
SHA_RE=re.compile(r"^[0-9a-f]{64}$")

def fail(msg):
    raise ValueError(msg)

def clean_name(name):
    if not name or name.startswith('/') or '\\' in name or '\x00' in name:
        fail('unsafe archive path')
    p=pathlib.PurePosixPath(name)
    if '..' in p.parts or not p.parts:
        fail('unsafe archive path')
    return p

def canonical_digest(zf, payload_members, prefix):
    rows=[]
    total=0
    for zi in sorted(payload_members, key=lambda z:z.filename):
        p=clean_name(zi.filename)
        rel='/'.join(p.parts[len(prefix):])
        if not rel or rel in ('UPDATE-MANIFEST.json','UPDATE-MANIFEST.sig') or zi.is_dir():
            continue
        mode=(zi.external_attr >> 16) & 0xffff
        if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
            fail('special files are not allowed')
        total += zi.file_size
        if total > MAX_TOTAL:
            fail('archive payload too large')
        h=hashlib.sha256()
        with zf.open(zi,'r') as f:
            for chunk in iter(lambda:f.read(1024*1024), b''):
                h.update(chunk)
        rows.append(f"{rel}\0{zi.file_size}\0{h.hexdigest()}\n".encode())
    out=hashlib.sha256()
    for row in rows: out.update(row)
    return out.hexdigest(), total

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('zip_path')
    ap.add_argument('--public-key',required=True)
    ap.add_argument('--extract-to')
    ap.add_argument('--inspect-only',action='store_true')
    args=ap.parse_args()
    zp=os.path.realpath(args.zip_path)
    st=os.stat(zp)
    if not stat.S_ISREG(st.st_mode): fail('update package must be a regular file')
    if st.st_size < 1024 or st.st_size > 536870912: fail('update package size is outside allowed range')
    zip_sha=hashlib.sha256(open(zp,'rb').read()).hexdigest()
    with zipfile.ZipFile(zp,'r') as zf:
        infos=zf.infolist()
        if not infos or len(infos)>MAX_FILES: fail('invalid update archive member count')
        names=[clean_name(i.filename) for i in infos]
        candidates=[]
        for p in names:
            if p.name=='UPDATE-MANIFEST.json': candidates.append(p)
        if len(candidates)!=1: fail('update archive must contain exactly one UPDATE-MANIFEST.json')
        mp=candidates[0]
        prefix=mp.parts[:-1]
        sigp=pathlib.PurePosixPath(*prefix,'UPDATE-MANIFEST.sig') if prefix else pathlib.PurePosixPath('UPDATE-MANIFEST.sig')
        byname={str(p):zi for p,zi in zip(names,infos)}
        if str(sigp) not in byname: fail('update archive signature is missing')
        for p in names:
            if tuple(p.parts[:len(prefix)]) != tuple(prefix): fail('update archive contains files outside its release root')
        raw=zf.read(byname[str(mp)])
        if len(raw)>MAX_MANIFEST: fail('update manifest is too large')
        sig=zf.read(byname[str(sigp)])
        with tempfile.TemporaryDirectory(prefix='privora-update-verify-') as td:
            mf=os.path.join(td,'manifest.json'); sf=os.path.join(td,'manifest.sig')
            open(mf,'wb').write(raw); open(sf,'wb').write(sig)
            cp=subprocess.run(['openssl','dgst','-sha256','-verify',args.public_key,'-signature',sf,mf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if cp.returncode!=0: fail('update manifest signature verification failed')
        try: m=json.loads(raw)
        except Exception: fail('update manifest is invalid JSON')
        if m.get('schema')!='privora-upload-update-v1': fail('unsupported update manifest schema')
        version=str(m.get('version','')); channel=str(m.get('channel',''))
        if not VER_RE.fullmatch(version): fail('invalid update version')
        if channel not in ('stable','early-access','developer'): fail('invalid update channel')
        payload=str(m.get('payload_sha256','')).lower()
        if not SHA_RE.fullmatch(payload): fail('invalid payload SHA-256')
        min_version=str(m.get('min_version',''))
        if min_version and not VER_RE.fullmatch(min_version): fail('invalid minimum version')
        if not str(m.get('created_at','')).strip(): fail('missing update creation time')
        services=m.get('services',[]); migrations=m.get('migrations',[])
        if not isinstance(services,list) or not all(isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_.@-]{1,80}',x) for x in services): fail('invalid service list')
        if not isinstance(migrations,list) or not all(isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_./-]{1,120}',x) for x in migrations): fail('invalid migration list')
        got,total=canonical_digest(zf,infos,prefix)
        if got != payload: fail('update payload digest mismatch')
        relnames={'/'.join(p.parts[len(prefix):]) for p in names if len(p.parts)>=len(prefix)}
        missing=sorted(REQ-relnames)
        if missing: fail('update package missing required files: '+', '.join(missing))
        vpath=str(pathlib.PurePosixPath(*prefix,'VERSION')) if prefix else 'VERSION'
        if zf.read(byname[vpath]).decode('utf-8','strict').strip()!=version: fail('VERSION does not match update manifest')
        if args.extract_to and not args.inspect_only:
            # The extracted tree becomes the candidate live /opt/privora-panel tree.
            # It must remain traversable/readable by Nginx and the dedicated panel
            # PHP-FPM user. Do not inherit the updater process umask (027) into the
            # release root, and never normalize ordinary source files to 0640.
            dest=os.path.realpath(args.extract_to); os.makedirs(dest,mode=0o755,exist_ok=True); os.chmod(dest,0o755)
            for p,zi in zip(names,infos):
                rel=pathlib.PurePosixPath(*p.parts[len(prefix):]) if len(p.parts)>len(prefix) else pathlib.PurePosixPath('.')
                if str(rel) in ('.','UPDATE-MANIFEST.json','UPDATE-MANIFEST.sig'): continue
                target=os.path.realpath(os.path.join(dest,*rel.parts))
                if os.path.commonpath([dest,target]) != dest: fail('archive extraction escaped destination')
                if zi.is_dir():
                    os.makedirs(target,mode=0o755,exist_ok=True); os.chmod(target,0o755); continue
                os.makedirs(os.path.dirname(target),mode=0o755,exist_ok=True)
                with zf.open(zi,'r') as src, open(target,'wb') as dst:
                    while True:
                        b=src.read(1024*1024)
                        if not b: break
                        dst.write(b)
                mode=(zi.external_attr>>16)&0o777
                os.chmod(target, 0o755 if mode & 0o111 else 0o644)
            for walk_root,dirs,_files in os.walk(dest):
                os.chmod(walk_root,0o755)
                for d in dirs:
                    os.chmod(os.path.join(walk_root,d),0o755)
        print(json.dumps({'ok':True,'version':version,'channel':channel,'min_version':min_version,'created_at':m['created_at'],'services':services,'migrations':migrations,'payload_sha256':payload,'zip_sha256':zip_sha,'size_bytes':st.st_size,'payload_bytes':total},separators=(',',':')))

if __name__=='__main__':
    try: main()
    except Exception as e:
        print(str(e),file=sys.stderr); sys.exit(1)
