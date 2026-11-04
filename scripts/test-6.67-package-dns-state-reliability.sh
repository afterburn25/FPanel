#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
server="$ROOT/agent/internal/api/server.go"
client="$ROOT/panel/src/AgentClient.php"
store="$ROOT/panel/src/Store.php"
js="$ROOT/panel/public/assets/app.js"
grep -Fq 'context.WithTimeout(r.Context(), 8*time.Second)' "$server"
grep -Fq 'Setpgid: true' "$server"
grep -Fq 'syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)' "$server"
grep -Fq "Agent response timed out before completion." "$client"
grep -Fq 'tempnam($dir, basename($this->path).' "$store"
grep -Fq 'if ($changed) { $this->save(); }' "$store"
grep -Fq "await api('dns-create',{method:'POST',data:{domain,dnssec:false}})" "$js"
! grep -Fq 'Use Create zone to bring it under Privora DNS management.' "$js"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
state="$tmp/panel-state.json"
for _ in $(seq 1 32); do
  php -r 'require $argv[1]; $s=new Store($argv[2]); $s->ensurePackageDefaults();' "$store" "$state" &
done
wait
php -r '$d=json_decode(file_get_contents($argv[1]),true,512,JSON_THROW_ON_ERROR); if(count($d["packages"]??[])<3 || count($d["feature_lists"]??[])<2) exit(2);' "$state"
if find "$tmp" -maxdepth 1 -type f -name 'panel-state.json.tmp.*' -print -quit | grep -q .; then
  echo 'orphan panel-state temporary file remained' >&2; exit 1
fi
echo 'PASS: 6.67 package hard-deadline / state-write / direct-DNS reliability gate'
