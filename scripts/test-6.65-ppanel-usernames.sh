#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
php -d display_errors=1 -r '
require $argv[1]."/panel/src/Store.php";
$dir=sys_get_temp_dir()."/privora-ppanel-user-".bin2hex(random_bytes(6));
mkdir($dir,0750,true);
$store=new Store($dir."/state.json");
$u=$store->setHostingAccess("acctone","example.com","correct-horse-battery-staple","customerone");
if(($u["username"]??"")!=="customerone") throw new RuntimeException("custom username not stored");
if(($store->findUser("customerone")["account"]??"")!=="acctone") throw new RuntimeException("custom username login failed");
if(($store->findUser("example.com")["account"]??"")!=="acctone") throw new RuntimeException("primary domain alias login failed");
$u=$store->setHostingAccess("acctone","example.com","another-long-password","newcustomer");
if(($u["username"]??"")!=="newcustomer") throw new RuntimeException("username rename failed");
if($store->findUser("customerone")!==null) throw new RuntimeException("stale custom username remained active");
if(($store->findUser("example.com")["username"]??"")!=="newcustomer") throw new RuntimeException("domain alias not preserved after rename");
$store->setHostingAccess("accttwo","other.test","password-for-other-account","othuser");
$duplicate=false;
try{$store->setHostingAccess("acctthree","third.test","password-for-third-account","othuser");}catch(InvalidArgumentException $e){$duplicate=str_contains($e->getMessage(),"already in use");}
if(!$duplicate) throw new RuntimeException("duplicate PPanel username was not rejected");
$invalid=false;
try{$store->setHostingAccess("acctthree","third.test","password-for-third-account","bad user");}catch(InvalidArgumentException $e){$invalid=true;}
if(!$invalid) throw new RuntimeException("invalid PPanel username was not rejected");
echo "PASS: PPanel custom username storage, aliases, rename and collision checks\n";
' "$ROOT"
grep -Fq "name=\"panel_username\"" "$ROOT/panel/public/admin.php"
grep -Fq "Primary-domain login alias" "$ROOT/panel/public/admin.php"
grep -Fq "panel_username" "$ROOT/panel/public/api.php"
grep -Fq "ppanelAccessAlias" "$ROOT/panel/public/assets/app.js"
grep -Fq "PPanel username or primary domain" "$ROOT/panel/public/index.php"
echo 'PASS: 6.65 PPanel custom username UX/API gate'
