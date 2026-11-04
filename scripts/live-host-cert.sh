#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ "$(id -u)" -ne 0 ]; then echo "live host certification requires a disposable root-capable test host" >&2; exit 2; fi
mkdir -p evidence
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'Running destructive sandbox adapter certification...\n'
(
 cd agent
 PRIVORA_LIVE_HOST_TEST=1 go test ./internal/hostadapter -run 'TestLiveLinuxUserLifecycle|TestNginxRealParserWhenAvailable|TestLocalBackup|TestInspectCPanelBackup|TestDNSAndDatabaseRenderers' -v
) | tee "$TMP/test-output.txt"
printf 'Running live API-to-host account provisioning certification...\n' | tee -a "$TMP/test-output.txt"
( cd agent; PRIVORA_LIVE_HOST_TEST=1 go test ./internal/api -run 'TestLiveProductionAccountProvision|TestLiveProductionAccountBackup|TestLiveProductionAccountFiles' -v ) | tee -a "$TMP/test-output.txt"
(
 cd agent
 go run ./cmd/privora-host-probe
) > "$TMP/availability.json"
python3 - "$TMP" "$ROOT/evidence/host-adapter-certification.json" <<'PY'
import json, os, platform, sys, datetime, hashlib
src,out=sys.argv[1:]
availability=json.load(open(os.path.join(src,'availability.json')))
test=open(os.path.join(src,'test-output.txt')).read()
try: mid=open('/etc/machine-id','rb').read().strip()
except OSError: mid=os.environ.get('HOSTNAME','unknown').encode()
obj={
  'profile':'privora-panel-host-adapter-certification-v1',
  'status':'PASS',
  'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'machine_id_sha256':hashlib.sha256(mid).hexdigest(),
  'certified_adapters':['linux-users','nginx','local-backup','account-files','cpanel-inspector','cpanel-stager','dns-renderer','database-renderer'],
  'host':{'platform':platform.platform(),'machine':platform.machine(),'python':platform.python_version()},
  'tests':{'status':'PASS','sha256':hashlib.sha256(test.encode()).hexdigest(),'output':test},
  'availability_before_certification':availability.get('capabilities',[]),
}
open(out,'w').write(json.dumps(obj,indent=2)+'\n')
PY
(
 cd agent
 go run ./cmd/privora-host-probe --cert ../evidence/host-adapter-certification.json
) > "$TMP/after.json"
python3 - "$TMP/after.json" "$ROOT/evidence/host-adapter-certification.json" <<'PY'
import json,sys
ap,evidence=sys.argv[1:]
e=json.load(open(evidence)); e['capabilities_after_certification']=json.load(open(ap)).get('capabilities',[])
open(evidence,'w').write(json.dumps(e,indent=2)+'\n')
PY
sha256sum evidence/host-adapter-certification.json
printf 'PASS: evidence/host-adapter-certification.json\n'
