<?php

declare(strict_types=1);
require __DIR__.'/../src/bootstrap.php';
header('Content-Type: application/json'); header('Cache-Control: no-store');

function out(array $body, int $status=200): never { http_response_code($status); echo json_encode($body, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); exit; }
function bodyJson(): array { $raw=file_get_contents('php://input'); if($raw===false||$raw==='') return []; $d=json_decode($raw,true); if(!is_array($d)) out(['error'=>'Invalid JSON'],400); return $d; }
function agent(Auth $auth): AgentClient { $u=$auth->requireUser(); return new AgentClient(getenv('PRIVORA_AGENT_SOCKET') ?: '/run/privora-panel/agent.sock', getenv('PRIVORA_AGENT_TOKEN') ?: '', ($u['role'] ?? 'user').':'.($u['username'] ?? 'unknown')); }
function mutationGuard(Auth $auth,string $perm): void { if($_SERVER['REQUEST_METHOD']!=='POST') out(['error'=>'POST required'],405); Auth::verifyCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null); $auth->requirePermission($perm); }
function localUpdateVersion(): string {
    $path='/opt/privora-panel/VERSION';
    $v=@file_get_contents($path);
    if($v===false){$fallback=dirname(__DIR__,2).'/VERSION';$v=@file_get_contents($fallback);}
    $v=trim((string)$v);
    return preg_match('/^5\.0\.0-dev\.\d+\.\d+$/',$v)?$v:'unknown';
}
function localUpdateTransaction(string $id): ?array {
    if(!preg_match('/^[0-9]{8}T[0-9]{6}Z-(?:[0-9]+|[0-9a-f]{16})$/',$id))return null;
    $dir='/var/lib/privora-panel/update-transactions/'.$id;
    if(!is_dir($dir))return null;
    $json=@file_get_contents($dir.'/journal.json');
    if($json!==false){$d=json_decode($json,true);if(is_array($d)){if(empty($d['id']))$d['id']=$id;return $d;}}
    $env=@file($dir.'/journal.env',FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES); if(!is_array($env))return null;
    $d=['id'=>$id];
    foreach($env as $line){if($line===''||$line[0]==='#'||!str_contains($line,'='))continue;[$k,$v]=explode('=',$line,2);$k=trim($k);$v=str_replace('\\ ',' ',trim($v));if(in_array($k,['status','phase','old_version','new_version','backup','error','operation','failed_phase','failed_operation','failed_command','failed_rc','failed_error','started_at','phase_started_at','activity_at'],true))$d[$k==='backup'?'backup_path':$k]=$v;}
    return $d;
}
function localLatestUpdateTransaction(): ?array {
    $root='/var/lib/privora-panel/update-transactions';
    $dirs=@glob($root.'/*',GLOB_ONLYDIR); if(!is_array($dirs)||!$dirs)return null;
    rsort($dirs,SORT_STRING);
    foreach($dirs as $dir){$d=localUpdateTransaction(basename($dir));if(is_array($d))return $d;}
    return null;
}
function degradedUpdateCenter(string $reason, bool $mfaRequired=false): array {
    // Status refresh must remain available even if the privileged agent,
    // transaction parser, or MFA metadata path is temporarily unavailable.
    // Keep this fallback dependency-light: local VERSION + journal only.
    $transaction=null;
    try{$transaction=localLatestUpdateTransaction();}catch(Throwable){}
    return [
        'version'=>localUpdateVersion(),
        'policy'=>['channel'=>'developer','security_auto'=>false,'package_auto'=>false,'major_versions_manual'=>true,'auto_reboot'=>false,'reboot_window'=>'Sun 03:00'],
        'last_transaction'=>$transaction,
        'signed_release_required'=>true,'upload_update_supported'=>true,'upload_max_bytes'=>536870912,
        'root_reauth_required'=>true,'root_reauth_available'=>false,
        'mfa_required'=>$mfaRequired,
        'degraded'=>true,'status_error'=>substr(trim($reason),0,500),
        'automatic_timer'=>'privora-maintenance.timer','rollback_helper'=>'/usr/local/sbin/privora-update-rollback'
    ];
}
function customerFeatures(Store $store, AgentClient $client, string $scope): array {
    $accounts=$client->get('/v1/hosting/accounts'); $packageName='';
    foreach(($accounts['accounts']??[]) as $a){if(($a['username']??'')===$scope){$packageName=(string)($a['package']??'');break;}}
    $featureName='Default'; foreach($store->packages() as $p){if(strcasecmp((string)($p['name']??''),$packageName)===0){$featureName=(string)($p['feature_list']??'Default');break;}}
    foreach($store->featureLists() as $f){if(strcasecmp((string)($f['name']??''),$featureName)===0)return array_values((array)($f['features']??[]));}
    return [];
}
function requireCustomerFeature(Store $store, AgentClient $client, string $scope, string $feature): void {
    if(!in_array($feature,customerFeatures($store,$client,$scope),true)) out(['error'=>'This feature is disabled by the hosting package.','feature'=>$feature],403);
}
function ppanelAccounts(Store $store,array $rows): array {
    foreach($rows as $i=>$a){
        $account=strtolower(trim((string)($a['username']??''))); $domain=strtolower(trim((string)($a['primary_domain']??'')));
        $access=$account!==''?$store->hostingAccessForAccount($account):null;
        $rows[$i]['ppanel_configured']=is_array($access);
        $rows[$i]['ppanel_login']=is_array($access)?(string)($access['username']??$domain):$domain;
    }
    return $rows;
}

function adminResellerScope(array $user): ?string { return Auth::resellerScope($user); }
function filterAdminAccounts(array $user,array $rows): array {
    $scope=adminResellerScope($user); if($scope===null)return array_values($rows);
    return array_values(array_filter($rows,fn($a)=>strtolower(trim((string)($a['reseller']??'')))===$scope));
}
function requireAdminAccountScope(array $user,AgentClient $client,string $username): array {
    $username=strtolower(trim($username));
    if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username)) out(['error'=>'Invalid hosting account'],400);
    $r=$client->get('/v1/hosting/accounts');
    foreach(($r['accounts']??[]) as $a){
        if(strtolower((string)($a['username']??''))!==$username)continue;
        $scope=adminResellerScope($user);
        if($scope!==null && strtolower(trim((string)($a['reseller']??'')))!==$scope) out(['error'=>'Hosting account is outside this reseller scope'],403);
        return $a;
    }
    out(['error'=>'Hosting account not found'],404);
}
function currentResellerPolicy(array $user,AgentClient $client): ?array {
    $scope=adminResellerScope($user); if($scope===null)return null;
    $r=$client->get('/v1/resellers');
    foreach(($r['resellers']??[]) as $rr){if(strtolower(trim((string)($rr['name']??'')))===$scope)return $rr;}
    out(['error'=>'Reseller policy is not configured for this login'],403);
}
function requireRootAdministrator(array $user): void {
    if(($user['role']??'')==='reseller') out(['error'=>'This operation is reserved for server administrators.'],403);
}
function resellerAllowsPackage(array $user,AgentClient $client,string $package): void {
    $policy=currentResellerPolicy($user,$client); if($policy===null)return;
    if(($policy['status']??'active')!=='active') out(['error'=>'Reseller is suspended'],403);
    $allowed=array_map('strtolower',array_map('strval',(array)($policy['allowed_packages']??[])));
    if($allowed && !in_array(strtolower($package),$allowed,true)) out(['error'=>'Package is outside this reseller policy'],403);
}
function packageByName(Store $store,string $name): ?array {
    $name=trim($name);
    foreach($store->packages() as $p){if(strcasecmp((string)($p['name']??''),$name)===0)return $p;}
    // Legacy live-host discovery used synthetic labels before Package Manager became authoritative.
    // Reconcile only those known labels to the conservative Starter policy; unknown custom names still fail closed.
    if(in_array(strtolower($name),['automatic','detected','discovered'],true)){
        foreach($store->packages() as $p){if(strcasecmp((string)($p['name']??''),'Starter')===0)return $p;}
    }
    return null;
}
function hostingOwnerForDomain(AgentClient $client,string $domain): string {
    $domain=strtolower(trim($domain));
    foreach(($client->get('/v1/sites')['sites']??[]) as $site){
        if(strtolower((string)($site['domain']??''))===$domain)return (string)($site['username']??'');
    }
    return '';
}
function accountAndPackage(Store $store,AgentClient $client,string $scope): array {
    $account=null;$accounts=$client->get('/v1/hosting/accounts');
    foreach(($accounts['accounts']??[]) as $a){if(strtolower((string)($a['username']??''))===strtolower($scope)){$account=$a;break;}}
    if(!$account)out(['error'=>'Hosting account not found'],404);
    $package=packageByName($store,(string)($account['package']??''));
    if(!$package)out(['error'=>'Hosting package policy is unavailable for this account'],409);
    return [$account,$package];
}
function requireAccountCapacity(Store $store,AgentClient $client,string $scope,string $kind): void {
    [$account, $pkg]=accountAndPackage($store,$client,$scope);
    // Existing/imported accounts are adopted as Detected/Discovered until an administrator
    // deliberately assigns a package. Do not invent Starter quotas for those legacy accounts.
    $rawPackage=strtolower(trim((string)($account['package']??'')));
    if(in_array($rawPackage,['automatic','detected','discovered'],true))return;
    $sites=$client->get('/v1/sites')['sites']??[];
    $ownedSites=array_values(array_filter($sites,fn($x)=>strtolower((string)($x['username']??''))===strtolower($scope)));
    $ownedDomains=array_values(array_map(fn($x)=>strtolower((string)($x['domain']??'')),$ownedSites));
    $count=0;$key='';
    if($kind==='site'){ $key='sites';$count=count($ownedSites); }
    elseif($kind==='domain'){ $key='domains';$count=count(array_filter($ownedSites,fn($x)=>(string)($x['kind']??'website')!=='subdomain')); }
    elseif($kind==='subdomain'){ $key='subdomains';$count=count(array_filter($ownedSites,fn($x)=>(string)($x['kind']??'')==='subdomain')); }
    elseif($kind==='database'){ $key='databases';$count=count(array_filter($client->get('/v1/databases')['databases']??[],fn($x)=>strtolower((string)($x['owner']??''))===strtolower($scope))); }
    elseif($kind==='database_user'){ $key='database_users';$count=count(array_filter($client->get('/v1/databases')['databases']??[],fn($x)=>strtolower((string)($x['owner']??''))===strtolower($scope) && trim((string)($x['user']??''))!=='')); }
    elseif($kind==='mailbox'){ $key='mailboxes';$count=count(array_filter($client->get('/v1/mailboxes')['mailboxes']??[],fn($x)=>in_array(strtolower((string)($x['domain']??'')),$ownedDomains,true))); }
    elseif($kind==='sftp'){ $key='ftp_accounts';$count=count(array_filter($client->get('/v1/sftp')['sftp_accounts']??[],fn($x)=>strtolower((string)($x['owner']??''))===strtolower($scope))); }
    elseif($kind==='cron'){ $key='cron_jobs';$count=count(array_filter($client->get('/v1/tasks/cron')['cron_jobs']??[],fn($x)=>strtolower((string)($x['owner']??''))===strtolower($scope))); }
    else return;
    $limit=(int)($pkg[$key]??0);
    $label=['databases'=>'Database','database_users'=>'Database user','sites'=>'Website','domains'=>'Domain','subdomains'=>'Subdomain','mailboxes'=>'Mailbox','ftp_accounts'=>'FTP/SFTP account','cron_jobs'=>'Cron job'][$key]??ucwords(str_replace('_',' ',$key));
    $packageName=(string)($pkg['name']??'');
    if($limit<=0) out(['error'=>$label.' creation is disabled by hosting package '.$packageName,'resource'=>$key,'used'=>$count,'limit'=>$limit,'package'=>$packageName],409);
    if($count >= $limit) out(['error'=>$label.' limit reached ('.$count.'/'.$limit.') on hosting package '.$packageName,'resource'=>$key,'used'=>$count,'limit'=>$limit,'package'=>$packageName],409);
}
function ownedCustomerDomains(AgentClient $client,string $scope): array {
    $out=[]; foreach(($client->get('/v1/sites')['sites']??[]) as $s){if(strtolower((string)($s['username']??''))===strtolower($scope)){ $d=strtolower(trim((string)($s['domain']??''))); if($d!=='')$out[]=$d; }}
    return array_values(array_unique($out));
}
function requireCustomerDomain(AgentClient $client,string $scope,string $domain): string {
    $domain=strtolower(trim($domain)); if($domain===''||!in_array($domain,ownedCustomerDomains($client,$scope),true))out(['error'=>'Domain is outside this hosting account'],403); return $domain;
}
function customerMailboxOwned(AgentClient $client,string $scope,string $address): bool {
    $address=strtolower(trim($address)); if(!str_contains($address,'@'))return false; $domain=substr(strrchr($address,'@'),1); return in_array($domain,ownedCustomerDomains($client,$scope),true);
}
function customerDatabaseNames(AgentClient $client,string $scope): array {
    $out=[]; foreach(($client->get('/v1/databases')['databases']??[]) as $db){if(strtolower((string)($db['owner']??''))===strtolower($scope)){ $n=(string)($db['name']??''); if($n!=='')$out[]=$n; }} return $out;
}
function requireCustomerBackup(AgentClient $client,string $scope,string $id): array {
    foreach(($client->get('/v1/backups')['backups']??[]) as $b){if((string)($b['id']??'')!==$id)continue; $res=strtolower((string)($b['resource']??'')); if($res===strtolower($scope)||in_array($res,ownedCustomerDomains($client,$scope),true)||in_array((string)($b['resource']??''),customerDatabaseNames($client,$scope),true))return $b; out(['error'=>'Backup is outside this hosting account'],403); } out(['error'=>'Backup not found'],404);
}
function enforceResellerAllocation(array $user,Store $store,AgentClient $client,string $packageName,string $replaceAccount=''): void {
    $policy=currentResellerPolicy($user,$client); if($policy===null)return;
    $scope=adminResellerScope($user); if($scope===null)return;
    $candidate=packageByName($store,$packageName); if(!$candidate)out(['error'=>'Package not found'],404);
    $disk=0;$bandwidth=0;$count=0;
    $accounts=$client->get('/v1/hosting/accounts')['accounts']??[];
    foreach($accounts as $a){
        if(strtolower((string)($a['reseller']??''))!==$scope)continue;
        if($replaceAccount!=='' && strtolower((string)($a['username']??''))===strtolower($replaceAccount))continue;
        $pkg=packageByName($store,(string)($a['package']??'')); if(!$pkg)continue;
        $count++;$disk+=(int)($pkg['disk_gb']??0);$bandwidth+=(int)($pkg['bandwidth_gb']??0);
    }
    $count++;$disk+=(int)($candidate['disk_gb']??0);$bandwidth+=(int)($candidate['bandwidth_gb']??0);
    if((int)($policy['max_accounts']??0)>0 && $count>(int)$policy['max_accounts'])out(['error'=>'Reseller account limit would be exceeded','used'=>$count-1,'limit'=>(int)$policy['max_accounts']],409);
    if((int)($policy['disk_gb']??0)>0 && $disk>(int)$policy['disk_gb'])out(['error'=>'Reseller disk allocation would be exceeded','requested_total_gb'=>$disk,'limit_gb'=>(int)$policy['disk_gb']],409);
    if((int)($policy['bandwidth_gb']??0)>0 && $bandwidth>(int)$policy['bandwidth_gb'])out(['error'=>'Reseller bandwidth allocation would be exceeded','requested_total_gb'=>$bandwidth,'limit_gb'=>(int)$policy['bandwidth_gb']],409);
}

try {
    $user=$auth->requireUser(); $route=(string)($_GET['route'] ?? 'summary'); $client=agent($auth);
    $customerScope = Auth::accountScope($user);
    $isCustomer = $customerScope !== null;

    if($route==='mfa-status') { out($auth->mfaStatus()); }
    if($route==='mfa-begin') { mutationGuard($auth, Auth::shellFor($user)==='customer'?'resources.self.write':'server.read'); out($auth->beginMfa(),201); }
    if($route==='mfa-confirm') { mutationGuard($auth, Auth::shellFor($user)==='customer'?'resources.self.write':'server.read'); $d=bodyJson(); if(!$auth->confirmMfa((string)($d['code']??''))) out(['error'=>'Invalid authentication code'],400); out(['ok'=>true,'enabled'=>true]); }
    if($route==='mfa-disable') { mutationGuard($auth, Auth::shellFor($user)==='customer'?'resources.self.write':'server.read'); $d=bodyJson(); if(!$auth->disableMfa((string)($d['password']??''),(string)($d['code']??''))) out(['error'=>'Password or authentication code is invalid'],403); out(['ok'=>true,'enabled'=>false]); }

    if($route==='webmail-auth') {
        if($isCustomer){
            $auth->requirePermission('resources.self.write');
            if(!$customerScope) out(['error'=>'Hosting account scope missing'],403);
            requireCustomerFeature($store,$client,$customerScope,'webmail');
        } else {
            $auth->requirePermission('resources.write');
        }
        $caps=$client->get('/v1/host/capabilities'); $ready=false;
        foreach(($caps['capabilities']??[]) as $cap){if(($cap['name']??'')==='webmail' && !empty($cap['available']) && !empty($cap['certified'])){$ready=true;break;}}
        if(!$ready) out(['error'=>'Webmail is not installed and certified on this server.'],503);
        http_response_code(204); exit;
    }
    if($route==='phpmyadmin-auth') {
        if($isCustomer){
            $auth->requirePermission('resources.self.write');
            if(!$customerScope) out(['error'=>'Hosting account scope missing'],403);
            requireCustomerFeature($store,$client,$customerScope,'phpmyadmin');
        } else {
            $auth->requirePermission('resources.write');
        }
        $caps=$client->get('/v1/host/capabilities'); $ready=false;
        foreach(($caps['capabilities']??[]) as $cap){if(($cap['name']??'')==='phpmyadmin' && !empty($cap['available']) && !empty($cap['certified'])){$ready=true;break;}}
        if(!$ready) out(['error'=>'phpMyAdmin is not installed and certified on this server.'],503);
        http_response_code(204); exit;
    }

    if($route==='customer-summary') {
        $auth->requirePermission('hosting.self.read');
        if(!$customerScope) out(['error'=>'Hosting account scope missing'],403);
        $accounts=$client->get('/v1/hosting/accounts');
        $sites=$client->get('/v1/sites');
        $account=null; foreach(($accounts['accounts']??[]) as $a){if(($a['username']??'')===$customerScope){$account=$a;break;}}
        if(!$account) out(['error'=>'Assigned hosting account not found'],404);
        $ownedSites=array_values(array_filter($sites['sites']??[],fn($x)=>($x['username']??'')===$customerScope));
        $package=packageByName($store,(string)($account['package']??''));
        $sys=$client->get('/v1/system');
        $serverInfo=['hostname'=>$sys['hostname']??'', 'os'=>$sys['os']??'', 'architecture'=>$sys['architecture']??'', 'cpu_cores'=>$sys['cpu_cores']??0, 'memory_total_mb'=>$sys['memory_total_mb']??0, 'memory_free_mb'=>$sys['memory_free_mb']??0, 'load_1'=>$sys['load_1']??0, 'load_5'=>$sys['load_5']??0, 'load_15'=>$sys['load_15']??0, 'uptime_seconds'=>$sys['uptime_seconds']??0];
        out(['account'=>$account,'sites'=>$ownedSites,'package'=>$package,'features'=>customerFeatures($store,$client,$customerScope),'server'=>$serverInfo,'shell'=>'customer']);
    }
    if($route==='customer-components') {
        $auth->requirePermission('hosting.self.read');
        if(!$customerScope) out(['error'=>'Hosting account scope missing'],403);
        $componentResponse=$client->get('/v1/components');
        $components=array_values(array_map(static function($c){
            return [
                'id'=>(string)($c['id']??''),
                'name'=>(string)($c['name']??''),
                'category'=>(string)($c['category']??''),
                'description'=>(string)($c['description']??''),
                'tags'=>array_values(array_map('strval',(array)($c['tags']??[]))),
                'packages'=>array_values(array_map('strval',(array)($c['packages']??[]))),
                'installed'=>(bool)($c['installed']??false),
                'available'=>(bool)($c['available']??false),
                'partial'=>(bool)($c['partial']??false),
                'status'=>(string)($c['status']??'unknown'),
                'status_reason'=>(string)($c['status_reason']??''),
                'version'=>(string)($c['version']??''),
                'featured'=>(bool)($c['featured']??false),
            ];
        },(array)($componentResponse['components']??[])));
        out(['components'=>$components,'manager'=>(string)($componentResponse['manager']??'unknown')]);
    }
    if($route==='customer-mail-domain-config') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope) out(['error'=>'Hosting account scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'email');
        $domain=strtolower(trim((string)($_GET['domain']??''))); $sites=$client->get('/v1/sites'); $owned=false; foreach(($sites['sites']??[]) as $site){if(($site['username']??'')===$customerScope && strtolower((string)($site['domain']??''))===$domain){$owned=true;break;}}
        if(!$owned) out(['error'=>'Mail domain is outside this hosting account'],403); $r=$client->getLong('/v1/mail/domains/'.rawurlencode($domain).'/configuration',30); out($r,$r['_status']??200);
    }
    if($route==='customer-mail-domain-auth-delete') {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Hosting account scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'email');
        $d=bodyJson(); $domain=strtolower(trim((string)($d['domain']??''))); if($domain==='' || (string)($d['confirm_domain']??'')!==$domain) out(['error'=>'Type the exact domain to confirm authentication removal'],422);
        $sites=$client->get('/v1/sites'); $owned=false; foreach(($sites['sites']??[]) as $site){if(($site['username']??'')===$customerScope && strtolower((string)($site['domain']??''))===$domain){$owned=true;break;}} if(!$owned) out(['error'=>'Mail domain is outside this hosting account'],403);
        $r=$client->deleteLong('/v1/mail/domains/'.rawurlencode($domain).'/authentication',[],60); out($r,$r['_status']??200);
    }
    if($route==='customer-resources') {
        $auth->requirePermission('hosting.self.read');
        if(!$customerScope) out(['error'=>'Hosting account scope missing'],403);
        $sites=$client->get('/v1/sites');
        $ownedSites=array_values(array_filter($sites['sites']??[],fn($x)=>($x['username']??'')===$customerScope));
        $domains=array_values(array_map(fn($x)=>(string)($x['domain']??''),$ownedSites));
        $fetch=fn(string $path,string $key)=>($client->get($path)[$key]??[]);
        $out=[];
        $out['sftp_accounts']=array_values(array_filter($fetch('/v1/sftp','sftp_accounts'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['applications']=array_values(array_filter($fetch('/v1/applications','applications'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['databases']=array_values(array_filter($fetch('/v1/databases','databases'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['zones']=array_values(array_filter($fetch('/v1/dns/zones','zones'),fn($x)=>in_array((string)($x['domain']??''),$domains,true)));
        $out['certificates']=array_values(array_filter($fetch('/v1/ssl','certificates'),fn($x)=>in_array((string)($x['domain']??''),$domains,true)));
        $out['backups']=array_values(array_filter($fetch('/v1/backups','backups'),fn($x)=>($x['resource']??'')===$customerScope || in_array((string)($x['resource']??''),$domains,true)));
        $out['mailboxes']=array_values(array_filter($fetch('/v1/mailboxes','mailboxes'),fn($x)=>in_array((string)($x['domain']??''),$domains,true)));
        $out['cron_jobs']=array_values(array_filter($fetch('/v1/tasks/cron','cron_jobs'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['deployments']=array_values(array_filter($fetch('/v1/deployments','deployments'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['mail_domains']=array_values(array_filter($fetch('/v1/mail/domains','mail_domains'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['mail_aliases']=array_values(array_filter($fetch('/v1/mail/aliases','mail_aliases'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['staging']=array_values(array_filter($fetch('/v1/staging','staging'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['isolation']=array_values(array_filter($fetch('/v1/isolation','isolation'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['account_controls']=array_values(array_filter($fetch('/v1/account-controls','account_controls'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['host_capabilities']=$client->get('/v1/host/capabilities');
        $out['php_runtimes']=$client->get('/v1/php/runtimes')['runtimes']??[];
        $out['app_catalog']=$fetch('/v1/apps/catalog','catalog');
        $out['app_installs']=array_values(array_filter($fetch('/v1/apps/installer/installs','app_installs'),fn($x)=>($x['owner']??'')===$customerScope));
        $out['sites']=$ownedSites;
        $out['features']=customerFeatures($store,$client,$customerScope);
        out($out);
    }
    if($route==='customer-files') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'files');
        $path=(string)($_GET['path']??'.'); $r=$client->get('/v1/files/'.rawurlencode($customerScope).'?path='.rawurlencode($path)); out($r,$r['_status']??200);
    }
    if($route==='customer-file-write') {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'files'); $d=bodyJson();
        $r=$client->post('/v1/files/'.rawurlencode($customerScope).'/write',['path'=>(string)($d['path']??''),'content'=>(string)($d['content']??'')]);
        if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'file.write','Wrote '.($d['path']??'')); out($r,$r['_status']??200);
    }
    if($route==='customer-file-read') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'files');
        $path=(string)($_GET['path']??''); $download=(string)($_GET['download']??'')==='1'?'&download=1':''; $r=$client->get('/v1/files/'.rawurlencode($customerScope).'/read?path='.rawurlencode($path).$download); out($r,$r['_status']??200);
    }
    if($route==='customer-file-search') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'files');
        $q=(string)($_GET['q']??''); $r=$client->get('/v1/files/'.rawurlencode($customerScope).'/search?q='.rawurlencode($q)); out($r,$r['_status']??200);
    }
    if(in_array($route,['customer-file-mkdir','customer-file-upload','customer-file-rename','customer-file-copy','customer-file-delete','customer-file-chmod','customer-file-archive','customer-file-extract'],true)) {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'files'); $d=bodyJson(); $u=rawurlencode($customerScope);
        if($route==='customer-file-mkdir') $r=$client->post('/v1/files/'.$u.'/mkdir',['path'=>(string)($d['path']??'')]);
        elseif($route==='customer-file-upload') $r=$client->postLong('/v1/files/'.$u.'/upload',['path'=>(string)($d['path']??''),'content_base64'=>(string)($d['content_base64']??'')],60);
        elseif($route==='customer-file-rename') $r=$client->post('/v1/files/'.$u.'/rename',['from'=>(string)($d['from']??''),'to'=>(string)($d['to']??'')]);
        elseif($route==='customer-file-copy') $r=$client->postLong('/v1/files/'.$u.'/copy',['from'=>(string)($d['from']??''),'to'=>(string)($d['to']??'')],60);
        elseif($route==='customer-file-delete') $r=$client->delete('/v1/files/'.$u.'/path',['path'=>(string)($d['path']??'')]);
        elseif($route==='customer-file-chmod') $r=$client->post('/v1/files/'.$u.'/chmod',['path'=>(string)($d['path']??''),'mode'=>(string)($d['mode']??'')]);
        elseif($route==='customer-file-archive') $r=$client->postLong('/v1/files/'.$u.'/archive',['source'=>(string)($d['source']??''),'destination'=>(string)($d['destination']??'')],60);
        else $r=$client->postLong('/v1/files/'.$u.'/extract',['archive'=>(string)($d['archive']??''),'destination'=>(string)($d['destination']??'.')],60);
        out($r,$r['_status']??200);
    }
    if($route==='customer-disk-usage') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'files');
        $r=$client->getLong('/v1/hosting/accounts/'.rawurlencode($customerScope).'/usage',60); out($r,$r['_status']??200);
    }
    if($route==='customer-analytics') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'metrics');
        $r=$client->getLong('/v1/hosting/accounts/'.rawurlencode($customerScope).'/usage',60); out($r,$r['_status']??200);
    }
    if($route==='customer-site-create') {
        mutationGuard($auth,'sites.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'domains'); requireAccountCapacity($store,$client,$customerScope,'site'); requireAccountCapacity($store,$client,$customerScope,'domain'); $d=bodyJson();
        $payload=['domain'=>(string)($d['domain']??''),'username'=>$customerScope,'php_version'=>(string)($d['php_version']??'8.4')];
        $r=$client->post('/v1/sites',$payload); if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'site.create','Created website '.$payload['domain']); out($r,$r['_status']??200);
    }
    if($route==='customer-subdomain-create') {
        mutationGuard($auth,'sites.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'subdomains'); requireAccountCapacity($store,$client,$customerScope,'site'); requireAccountCapacity($store,$client,$customerScope,'subdomain'); $d=bodyJson();
        $parent=strtolower(trim((string)($d['parent_domain']??'')));
        $sites=$client->get('/v1/sites'); $owned=false; foreach(($sites['sites']??[]) as $site){if(($site['username']??'')===$customerScope && strtolower((string)($site['domain']??''))===$parent){$owned=true;break;}}
        if(!$owned) out(['error'=>'Parent website is outside this account'],403);
        $payload=['parent_domain'=>$parent,'label'=>(string)($d['label']??''),'username'=>$customerScope,'php_version'=>(string)($d['php_version']??'8.4'),'document_root'=>trim((string)($d['document_root']??''))];
        $r=$client->post('/v1/subdomains',$payload); if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'subdomain.create','Created subdomain '.(($r['site']['domain']??'')?:($payload['label'].'.'.$parent))); out($r,$r['_status']??200);
    }
    if($route==='customer-ssl-autossl') {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'ssl'); $d=bodyJson();
        $domain=strtolower(trim((string)($d['domain']??''))); $sites=$client->get('/v1/sites'); $owned=[];
        foreach(($sites['sites']??[]) as $s){ if(($s['username']??'')===$customerScope && ($s['status']??'')==='active') $owned[]=strtolower((string)($s['domain']??'')); }
        if($domain!=='' && !in_array($domain,$owned,true)) out(['error'=>'Website is outside this account or is not active'],403);
        $r=$client->postLong('/v1/ssl/autossl',['owner'=>$customerScope,'domain'=>$domain],180); out($r,$r['_status']??200);
    }
    if($route==='customer-site-php') {
        mutationGuard($auth,'php.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'php'); $d=bodyJson(); $domain=(string)($d['domain']??''); $version=(string)($d['version']??'');
        $sites=$client->get('/v1/sites'); $ok=false; foreach(($sites['sites']??[]) as $s){if(($s['username']??'')===$customerScope && ($s['domain']??'')===strtolower($domain)){$ok=true;break;}}
        if(!$ok) out(['error'=>'Website is outside this account'],403); if(!in_array($version,['8.2','8.3','8.4','8.5'],true))out(['error'=>'Unsupported PHP version'],400);
        $r=$client->post('/v1/sites/'.rawurlencode(strtolower($domain)).'/php',['version'=>$version]); out($r,$r['_status']??200);
    }
    if($route==='customer-backup-restore') {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'backups');
        $d=bodyJson(); $id=(string)($d['id']??''); if(!preg_match('/^bkp_[a-z0-9]+$/',$id)) out(['error'=>'Invalid backup ID'],400);
        $all=$client->get('/v1/backups'); $backup=null; foreach(($all['backups']??[]) as $b){if(($b['id']??'')===$id){$backup=$b;break;}}
        if(!$backup) out(['error'=>'Backup not found'],404); $resource=(string)($backup['resource']??'');
        $sites=$client->get('/v1/sites'); $owned=array_values(array_filter($sites['sites']??[],fn($x)=>($x['username']??'')===$customerScope)); $domains=array_map(fn($x)=>(string)($x['domain']??''),$owned);
        if($resource!==$customerScope && !in_array($resource,$domains,true)) out(['error'=>'Backup is outside this hosting account'],403);
        $r=$client->post('/v1/backups/'.rawurlencode($id).'/restore',['confirm_resource'=>(string)($d['confirm_resource']??'')]); out($r,$r['_status']??200);
    }
    if(in_array($route,['customer-database-password','customer-database-user','customer-database-delete'],true)) {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'databases'); $d=bodyJson();
        $name=trim((string)($d['name']??'')); if($name==='') out(['error'=>'Database name is required'],400);
        $all=$client->get('/v1/databases'); $owned=null; foreach(($all['databases']??[]) as $row){ if(($row['name']??'')===$name && ($row['owner']??'')===$customerScope){$owned=$row;break;} }
        if(!$owned || empty($owned['managed'])) out(['error'=>'Database is outside this hosting account or is not Privora-managed'],403);
        if($route==='customer-database-password') {
            $password=(string)($d['password']??''); $confirm=(string)($d['password_confirm']??''); if($password!=='' && $password!==$confirm) out(['error'=>'Database password confirmation does not match'],400);
            $r=$client->post('/v1/databases/'.rawurlencode($name).'/password',['password'=>$password]); out($r,$r['_status']??200);
        }
        if($route==='customer-database-user') {
            $newUser=trim((string)($d['user']??'')); if($newUser==='') out(['error'=>'Database user is required'],400); $password=(string)($d['password']??''); $confirm=(string)($d['password_confirm']??''); if($password!=='' && $password!==$confirm) out(['error'=>'Database password confirmation does not match'],400);
            $r=$client->post('/v1/databases/'.rawurlencode($name).'/user',['user'=>$newUser,'password'=>$password]); out($r,$r['_status']??200);
        }
        if(($d['confirm_name']??'')!==$name) out(['error'=>'Type the exact database name to confirm deletion'],400);
        $r=$client->delete('/v1/databases/'.rawurlencode($name).'?confirm='.rawurlencode($name)); out($r,$r['_status']??200);
    }
    if(in_array($route,['customer-mailbox-update','customer-mailbox-delete','customer-mail-alias-update','customer-mail-alias-delete'],true)) {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'email'); $d=bodyJson();
        $address=strtolower(trim((string)($d['address']??''))); $domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):'';
        $sites=$client->get('/v1/sites'); $domains=[]; foreach(($sites['sites']??[]) as $site){if(($site['username']??'')===$customerScope)$domains[]=strtolower((string)($site['domain']??''));}
        if($address==='' || !in_array($domain,$domains,true)) out(['error'=>'Mail address is outside this hosting account'],403);
        if(str_starts_with($route,'customer-mailbox-')) {
            $all=$client->get('/v1/mailboxes'); $owned=null; foreach(($all['mailboxes']??[]) as $row){if(strtolower((string)($row['address']??''))===$address){$owned=$row;break;}}
            if(!$owned) out(['error'=>'Mailbox not found'],404);
            if($route==='customer-mailbox-update') {
                $password=(string)($d['password']??''); $confirm=(string)($d['password_confirm']??''); if($password!==$confirm) out(['error'=>'Mailbox password confirmation does not match'],400); if($password!=='' && strlen($password)<12) out(['error'=>'Mailbox password must be at least 12 characters'],400);
                $quota=(int)($d['quota_mb']??($owned['quota_mb']??1024)); if($quota<100 || $quota>102400) out(['error'=>'Mailbox quota must be between 100 and 102400 MB'],400);
                $r=$client->patch('/v1/mailboxes/'.rawurlencode($address),['quota_mb'=>$quota,'password'=>$password]); out($r,$r['_status']??200);
            }
            if(($d['confirm_address']??'')!==$address) out(['error'=>'Type the exact mailbox address to confirm deletion'],400);
            $r=$client->delete('/v1/mailboxes/'.rawurlencode($address)); out($r,$r['_status']??200);
        }
        $all=$client->get('/v1/mail/aliases'); $owned=null; foreach(($all['mail_aliases']??[]) as $row){if(strtolower((string)($row['address']??''))===$address && (($row['owner']??'')==='' || ($row['owner']??'')===$customerScope)){$owned=$row;break;}}
        if(!$owned) out(['error'=>'Forwarder not found'],404);
        if($route==='customer-mail-alias-update') { $destination=trim((string)($d['destination']??'')); if($destination==='') out(['error'=>'Forwarder destination is required'],400); $r=$client->patch('/v1/mail/aliases/'.rawurlencode($address),['destination'=>$destination]); out($r,$r['_status']??200); }
        if(($d['confirm_address']??'')!==$address) out(['error'=>'Type the exact forwarder address to confirm deletion'],400);
        $r=$client->delete('/v1/mail/aliases/'.rawurlencode($address)); out($r,$r['_status']??200);
    }
    if(str_starts_with($route,'customer-') && in_array($route,['customer-sftp-create','customer-application-create','customer-app-install','customer-control-create','customer-database-create','customer-dns-create','customer-ssl-issue','customer-backup-create','customer-mailbox-create','customer-cron-create','customer-deployment-create','customer-mail-domain-create','customer-mail-alias-create','customer-staging-create','customer-isolation-set'],true)) {
        mutationGuard($auth,'resources.self.write'); if(!$customerScope) out(['error'=>'Scope missing'],403); $featureMap=['customer-sftp-create'=>'sftp','customer-application-create'=>'applications','customer-app-install'=>'applications','customer-control-create'=>'domains','customer-database-create'=>'databases','customer-dns-create'=>'dns','customer-ssl-issue'=>'ssl','customer-backup-create'=>'backups','customer-mailbox-create'=>'email','customer-cron-create'=>'cron','customer-deployment-create'=>'git','customer-mail-domain-create'=>'email','customer-mail-alias-create'=>'email','customer-staging-create'=>'domains','customer-isolation-set'=>'metrics'];requireCustomerFeature($store,$client,$customerScope,$featureMap[$route]??'domains'); $d=bodyJson();
        $sites=$client->get('/v1/sites'); $domains=[]; foreach(($sites['sites']??[]) as $s){if(($s['username']??'')===$customerScope)$domains[]=(string)$s['domain'];}if($route==='customer-sftp-create')requireAccountCapacity($store,$client,$customerScope,'sftp');elseif($route==='customer-database-create'){requireAccountCapacity($store,$client,$customerScope,'database');requireAccountCapacity($store,$client,$customerScope,'database_user');}elseif($route==='customer-mailbox-create')requireAccountCapacity($store,$client,$customerScope,'mailbox');elseif($route==='customer-cron-create')requireAccountCapacity($store,$client,$customerScope,'cron');
        if($route==='customer-sftp-create') $r=$client->post('/v1/sftp',['username'=>(string)($d['username']??''),'owner'=>$customerScope,'root'=>'/home/'.$customerScope,'auth'=>(string)($d['auth']??'ssh-key')]);
        elseif($route==='customer-application-create'){ $domain=(string)($d['domain']??''); if(!in_array(strtolower($domain),$domains,true))out(['error'=>'Website is outside this account'],403); $r=$client->post('/v1/applications',['type'=>(string)($d['type']??'laravel'),'domain'=>$domain,'owner'=>$customerScope,'runtime'=>(string)($d['runtime']??'php8.4')]); }
        elseif($route==='customer-app-install'){ $domain=strtolower((string)($d['domain']??'')); if(!in_array($domain,$domains,true))out(['error'=>'Website is outside this account'],403); $r=$client->post('/v1/apps/installer/install',['template'=>(string)($d['template']??''),'version'=>(string)($d['version']??''),'domain'=>$domain,'owner'=>$customerScope,'path'=>(string)($d['path']??'.'),'database'=>(string)($d['database']??''),'runtime'=>(string)($d['runtime']??''),'admin_user'=>(string)($d['admin_user']??''),'admin_password'=>(string)($d['admin_password']??''),'admin_email'=>(string)($d['admin_email']??''),'site_title'=>(string)($d['site_title']??'')]); }
        elseif($route==='customer-control-create'){ $domain=strtolower((string)($d['domain']??'')); if($domain!=='' && !in_array($domain,$domains,true))out(['error'=>'Control domain is outside this account'],403); $r=$client->post('/v1/account-controls',['owner'=>$customerScope,'kind'=>(string)($d['kind']??''),'domain'=>$domain,'name'=>(string)($d['name']??''),'value'=>(string)($d['value']??'')]); }
        elseif($route==='customer-database-create'){ $password=(string)($d['password']??''); $confirm=(string)($d['password_confirm']??''); if($password!=='' && $password!==$confirm)out(['error'=>'Database password confirmation does not match'],400); $r=$client->post('/v1/databases',['name'=>(string)($d['name']??''),'user'=>(string)($d['user']??''),'password'=>$password,'engine'=>(string)($d['engine']??'mariadb'),'owner'=>$customerScope]); }
        elseif($route==='customer-dns-create'){ $domain=strtolower((string)($d['domain']??'')); if(!in_array($domain,$domains,true))out(['error'=>'Website is outside this account'],403); $r=$client->post('/v1/dns/zones',['domain'=>$domain,'dnssec'=>(bool)($d['dnssec']??false)]); }
        elseif($route==='customer-ssl-issue'){ $domain=strtolower((string)($d['domain']??'')); if(!in_array($domain,$domains,true))out(['error'=>'Website is outside this account'],403); $r=$client->postLong('/v1/ssl/issue',['domain'=>$domain],180); }
        elseif($route==='customer-backup-create'){ $resource=(string)($d['resource']??''); if($resource!==$customerScope && !in_array(strtolower($resource),$domains,true))out(['error'=>'Backup target is outside this account'],403); $r=$client->post('/v1/backups',['scope'=>(string)($d['scope']??'site'),'resource'=>$resource,'destination'=>(string)($d['destination']??'local')]); }
        elseif($route==='customer-mailbox-create'){ $address=strtolower(trim((string)($d['address']??''))); $domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):''; if(!in_array($domain,$domains,true))out(['error'=>'Mailbox domain is outside this account'],403); $password=(string)($d['password']??''); $confirm=(string)($d['password_confirm']??''); if(strlen($password)<12)out(['error'=>'Mailbox password must be at least 12 characters'],400); if($password!==$confirm)out(['error'=>'Mailbox password confirmation does not match'],400); $r=$client->post('/v1/mailboxes',['address'=>$address,'quota_mb'=>(int)($d['quota_mb']??1024),'password'=>$password]); }
        elseif($route==='customer-cron-create') $r=$client->post('/v1/tasks/cron',['owner'=>$customerScope,'schedule'=>(string)($d['schedule']??''),'command'=>(string)($d['command']??'')]);
        elseif($route==='customer-deployment-create'){ $domain=strtolower((string)($d['domain']??'')); if(!in_array($domain,$domains,true))out(['error'=>'Website is outside this account'],403); $r=$client->post('/v1/deployments',['kind'=>(string)($d['kind']??'git'),'domain'=>$domain,'owner'=>$customerScope,'repository'=>(string)($d['repository']??''),'branch'=>(string)($d['branch']??'main'),'runtime'=>(string)($d['runtime']??'php8.4')]); }
        elseif($route==='customer-mail-domain-create'){ $domain=strtolower((string)($d['domain']??'')); if(!in_array($domain,$domains,true))out(['error'=>'Mail domain is outside this account'],403); $r=$client->postLong('/v1/mail/domains',['domain'=>$domain,'owner'=>$customerScope,'dmarc'=>(string)($d['dmarc']??'quarantine')],180); }
        elseif($route==='customer-mail-alias-create'){ $address=strtolower((string)($d['address']??'')); $domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):''; if(!in_array($domain,$domains,true))out(['error'=>'Alias domain is outside this account'],403); $r=$client->post('/v1/mail/aliases',['address'=>$address,'destination'=>(string)($d['destination']??''),'owner'=>$customerScope]); }
        elseif($route==='customer-staging-create'){ $production=strtolower((string)($d['production_domain']??'')); $staging=strtolower((string)($d['staging_domain']??'')); if(!in_array($production,$domains,true))out(['error'=>'Production site is outside this account'],403); $r=$client->post('/v1/staging',['production_domain'=>$production,'staging_domain'=>$staging,'owner'=>$customerScope]); }
        else $r=$client->post('/v1/isolation',['owner'=>$customerScope,'namespaces'=>(bool)($d['namespaces']??true),'cgroups'=>(bool)($d['cgroups']??true),'private_tmp'=>(bool)($d['private_tmp']??true),'no_new_privileges'=>(bool)($d['no_new_privileges']??true)]);
        out($r,$r['_status']??200);
    }
    // 6.91-7.0 customer workflows: account-scoped and capability-gated.
    if($route==='customer-mail-delivery') {
        $auth->requirePermission('hosting.self.read'); if(!$customerScope)out(['error'=>'Scope missing'],403); requireCustomerFeature($store,$client,$customerScope,'email');
        $q=trim((string)($_GET['query']??'')); $r=$client->getLong('/v1/mail/delivery?query='.rawurlencode($q).'&limit=200',30); $domains=ownedCustomerDomains($client,$customerScope);
        if(($r['_status']??500)<300)$r['events']=array_values(array_filter((array)($r['events']??[]),static function($e)use($domains){$hay=strtolower(json_encode($e,JSON_UNESCAPED_SLASHES)?:'');foreach($domains as $d){if(str_contains($hay,'@'.$d)||str_contains($hay,$d))return true;}return false;})); out($r,$r['_status']??200);
    }
    if($route==='customer-mail-filters') {
        $auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'email');$r=$client->get('/v1/mail/filters?owner='.rawurlencode($customerScope));out($r,$r['_status']??200);
    }
    if($route==='customer-mail-filter-save') {
        mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'email');$d=bodyJson();$address=strtolower((string)($d['address']??''));if(!customerMailboxOwned($client,$customerScope,$address))out(['error'=>'Mailbox is outside this hosting account'],403);
        $r=$client->postLong('/v1/mail/filters',['id'=>(string)($d['id']??''),'owner'=>$customerScope,'address'=>$address,'name'=>(string)($d['name']??''),'field'=>(string)($d['field']??'from'),'operator'=>(string)($d['operator']??'contains'),'value'=>(string)($d['value']??''),'action'=>(string)($d['action']??'fileinto'),'destination'=>(string)($d['destination']??''),'enabled'=>true],30);out($r,$r['_status']??200);
    }
    if($route==='customer-mail-filter-delete') {
        mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'email');$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/mail/filters?owner='.rawurlencode($customerScope));$owned=false;foreach(($all['filters']??[]) as $f){if((string)($f['id']??'')===$id){$owned=true;break;}}if(!$owned)out(['error'=>'Filter not found'],404);$r=$client->delete('/v1/mail/filters/'.rawurlencode($id));out($r,$r['_status']??200);
    }
    if($route==='customer-backup-policies') {$auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'backups');$r=$client->get('/v1/backup/policies?owner='.rawurlencode($customerScope));out($r,$r['_status']??200);}
    if($route==='customer-backup-policy-save') {
        mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'backups');$d=bodyJson();$scope=(string)($d['scope']??'site');$resource=(string)($d['resource']??'');$allowed=$resource===$customerScope||in_array(strtolower($resource),ownedCustomerDomains($client,$customerScope),true)||in_array($resource,customerDatabaseNames($client,$customerScope),true);if(!$allowed)out(['error'=>'Backup policy target is outside this hosting account'],403);
        $r=$client->post('/v1/backup/policies',['id'=>(string)($d['id']??''),'owner'=>$customerScope,'scope'=>$scope,'resource'=>$resource,'destination'=>'local','schedule'=>(string)($d['schedule']??'daily'),'retention'=>(int)($d['retention']??14),'verify'=>(bool)($d['verify']??true),'enabled'=>true]);out($r,$r['_status']??200);
    }
    if($route==='customer-backup-policy-run') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'backups');$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/backup/policies?owner='.rawurlencode($customerScope));$owned=false;foreach(($all['policies']??[]) as $x){if((string)($x['id']??'')===$id){$owned=true;break;}}if(!$owned)out(['error'=>'Backup policy not found'],404);$r=$client->postLong('/v1/backup/policies/'.rawurlencode($id).'/run',[],180);out($r,$r['_status']??200);}
    if($route==='customer-backup-policy-delete') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'backups');$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/backup/policies?owner='.rawurlencode($customerScope));$owned=false;foreach(($all['policies']??[]) as $x){if((string)($x['id']??'')===$id){$owned=true;break;}}if(!$owned)out(['error'=>'Backup policy not found'],404);$r=$client->delete('/v1/backup/policies/'.rawurlencode($id));out($r,$r['_status']??200);}
    if($route==='customer-backup-verify') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'backups');$d=bodyJson();$id=(string)($d['id']??'');requireCustomerBackup($client,$customerScope,$id);$r=$client->postLong('/v1/backups/'.rawurlencode($id).'/verify',[],120);out($r,$r['_status']??200);}
    if($route==='customer-api-keys') {$auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);$r=$client->get('/v1/api-keys');$r['api_keys']=array_values(array_filter((array)($r['api_keys']??[]),fn($k)=>strtolower((string)($k['owner']??''))===strtolower($customerScope)));out($r,$r['_status']??200);}
    if($route==='customer-api-key-create') {
        mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);$d=bodyJson();$allowed=['health.read','sites.read','resources.read','backups.read','backups.write','dns.read','dns.write','ssl.read','ssl.write','mail.read','mail.write','monitoring.read','databases.read','databases.write'];$scopes=array_values(array_intersect($allowed,array_map('strval',(array)($d['scopes']??[]))));if(!$scopes)out(['error'=>'Select at least one allowed API scope'],400);$cidrs=$d['allowed_cidrs']??[];if(is_string($cidrs))$cidrs=preg_split('/\s*,\s*/',$cidrs,-1,PREG_SPLIT_NO_EMPTY);$payload=['name'=>(string)($d['name']??''),'owner'=>$customerScope,'scopes'=>$scopes,'allowed_cidrs'=>array_values(array_map('strval',(array)$cidrs))];$expires=trim((string)($d['expires_at']??''));if($expires!==''){try{$payload['expires_at']=(new DateTimeImmutable($expires))->format(DATE_RFC3339);}catch(Throwable $e){out(['error'=>'Invalid API token expiry'],400);}}$r=$client->post('/v1/api-keys',$payload);out($r,$r['_status']??200);
    }
    if(in_array($route,['customer-api-key-revoke','customer-api-key-rotate'],true)) {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/api-keys');$owned=false;foreach(($all['api_keys']??[]) as $k){if((string)($k['id']??'')===$id&&strtolower((string)($k['owner']??''))===strtolower($customerScope)){$owned=true;break;}}if(!$owned)out(['error'=>'API token not found'],404);$r=$route==='customer-api-key-revoke'?$client->delete('/v1/api-keys/'.rawurlencode($id)):$client->post('/v1/api-keys/'.rawurlencode($id).'/rotate',[]);out($r,$r['_status']??200);}
    if($route==='customer-site-policies') {$auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'domains');$r=$client->get('/v1/sites/policies');$domains=ownedCustomerDomains($client,$customerScope);$r['policies']=array_values(array_filter((array)($r['policies']??[]),fn($p)=>in_array(strtolower((string)($p['domain']??'')),$domains,true)));out($r,$r['_status']??200);}
    if($route==='customer-site-policy-save') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'domains');$d=bodyJson();$domain=requireCustomerDomain($client,$customerScope,(string)($d['domain']??''));$r=$client->postLong('/v1/sites/'.rawurlencode($domain).'/policy',['owner'=>$customerScope,'force_https'=>(bool)($d['force_https']??false),'hsts'=>(bool)($d['hsts']??false),'hsts_max_age'=>(int)($d['hsts_max_age']??15552000),'redirect_target'=>(string)($d['redirect_target']??''),'directory_index'=>(string)($d['directory_index']??'index.php index.html index.htm'),'hotlink_protection'=>(bool)($d['hotlink_protection']??false)],60);out($r,$r['_status']??200);}
    if($route==='customer-database-activity') {$auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'databases');$engine=(string)($_GET['engine']??'mariadb');$r=$client->get('/v1/databases/activity?engine='.rawurlencode($engine));$names=array_map('strtolower',customerDatabaseNames($client,$customerScope));$r['activity']=array_values(array_filter((array)($r['activity']??[]),fn($x)=>in_array(strtolower((string)($x['database']??'')),$names,true)));out($r,$r['_status']??200);}
    if($route==='customer-database-session-kill') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'databases');$d=bodyJson();$id=(string)($d['id']??'');$engine=(string)($d['engine']??'mariadb');$activity=$client->get('/v1/databases/activity?engine='.rawurlencode($engine));$names=array_map('strtolower',customerDatabaseNames($client,$customerScope));$owned=false;foreach(($activity['activity']??[]) as $x){if((string)($x['id']??'')===$id&&in_array(strtolower((string)($x['database']??'')),$names,true)){$owned=true;break;}}if(!$owned)out(['error'=>'Database session is outside this hosting account'],403);$r=$client->post('/v1/databases/activity/'.rawurlencode($id).'/kill',['engine'=>$engine]);out($r,$r['_status']??200);}
    if($route==='customer-apps-discover') {$auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'applications');$r=$client->getLong('/v1/apps/discover',30);$domains=ownedCustomerDomains($client,$customerScope);$r['applications']=array_values(array_filter((array)($r['applications']??[]),fn($a)=>in_array(strtolower((string)($a['domain']??'')),$domains,true)));out($r,$r['_status']??200);}
    if($route==='customer-app-action') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'applications');$d=bodyJson();$domain=requireCustomerDomain($client,$customerScope,(string)($d['domain']??''));$r=$client->postLong('/v1/apps/'.rawurlencode($domain).'/action',['action'=>(string)($d['action']??'status')],60);out($r,$r['_status']??200);}
    if($route==='customer-dnssec-status') {$auth->requirePermission('hosting.self.read');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'dns');$domain=requireCustomerDomain($client,$customerScope,(string)($_GET['domain']??''));$r=$client->get('/v1/dns/zones/'.rawurlencode($domain).'/dnssec');out($r,$r['_status']??200);}
    if($route==='customer-dnssec-set') {mutationGuard($auth,'resources.self.write');if(!$customerScope)out(['error'=>'Scope missing'],403);requireCustomerFeature($store,$client,$customerScope,'dns');$d=bodyJson();$domain=requireCustomerDomain($client,$customerScope,(string)($d['domain']??''));$r=$client->postLong('/v1/dns/zones/'.rawurlencode($domain).'/dnssec',['enabled'=>(bool)($d['enabled']??false)],60);out($r,$r['_status']??200);}
    if($route==='advanced-all') {
        $auth->requirePermission('server.read');
        $map=[
            'cron_jobs'=>['/v1/tasks/cron','cron_jobs'],'catalog'=>['/v1/apps/catalog','catalog'],'deployments'=>['/v1/deployments','deployments'],
            'mail_domains'=>['/v1/mail/domains','mail_domains'],'mail_aliases'=>['/v1/mail/aliases','mail_aliases'],'reputation'=>['/v1/mail/reputation','reputation'],
            'bans'=>['/v1/security/bans','bans'],'malware_scans'=>['/v1/security/malware','malware_scans'],'integrity_checks'=>['/v1/security/integrity','integrity_checks'],
            'metrics'=>['/v1/monitoring/metrics','metrics'],'alert_rules'=>['/v1/monitoring/alerts','alert_rules'],'incidents'=>['/v1/monitoring/incidents','incidents'],
            'resource_limits'=>['/v1/resources/limits','resource_limits'],'processes'=>['/v1/system/processes','processes'],'volumes'=>['/v1/system/storage','volumes'],'interfaces'=>['/v1/system/network','interfaces'],
            'brands'=>['/v1/reseller/brands','brands'],'delegates'=>['/v1/delegates','delegates'],'migrations'=>['/v1/migrations','migrations'],'clusters'=>['/v1/clusters','clusters'],
            'load_balancers'=>['/v1/load-balancers','load_balancers'],'profiles'=>['/v1/provision/profiles','profiles'],'api_keys'=>['/v1/api-keys','api_keys'],'webhooks'=>['/v1/webhooks','webhooks'],
            'plugins'=>['/v1/plugins','plugins'],'invoices'=>['/v1/billing/invoices','invoices'],'notifications'=>['/v1/notifications','notifications'],'diagnostics'=>['/v1/diagnostics','diagnostics'],
            'repairs'=>['/v1/repairs','repairs'],'revisions'=>['/v1/config/revisions','revisions'],'secrets'=>['/v1/secrets','secrets'],'releases'=>['/v1/releases','releases'],
            'exports'=>['/v1/exports','exports'],'recommendations'=>['/v1/performance/recommendations','recommendations'],'staging'=>['/v1/staging','staging'],'isolation'=>['/v1/isolation','isolation'],
            'certification'=>['/v1/certification','certification'],'horizons'=>['/v1/horizons','horizons']
        ];
        $out=[]; foreach($map as $key=>$spec){$r=$client->get($spec[0]);$out[$key]=$r[$spec[1]]??[];}
        $out['platform_summary']=$client->get('/v1/platform/summary');
        $out['security_posture']=$client->get('/v1/security/posture');
        $out['ssh_policy']=$client->get('/v1/security/ssh')['ssh_policy']??[];
        $out['update_policy']=$client->get('/v1/system/update-policy')['update_policy']??[];
        $out['audit_verify']=$client->get('/v1/audit/verify');
        $out['host_capabilities']=$client->get('/v1/host/capabilities');
        $out['host_inventory']=$client->get('/v1/host/inventory');
        out($out);
    }
    if($route==='summary') {
        $auth->requirePermission('server.read');
        $health=$client->get('/v1/health'); $system=$client->get('/v1/system'); $services=$client->get('/v1/services'); $accounts=$client->get('/v1/hosting/accounts'); $sites=$client->get('/v1/sites'); $suite=$client->get('/v1/control-suite');
        $warnings=array_values(array_unique(array_merge((array)($accounts['warnings']??[]),(array)($sites['warnings']??[]))));
        out(['health'=>$health,'system'=>$system,'services'=>$services['services']??[],'accounts'=>ppanelAccounts($store,$accounts['accounts']??[]),'sites'=>$sites['sites']??[],'events'=>$store->events(),'packages'=>$store->packages(),'control_suite'=>$suite,'inventory'=>['source'=>(string)($sites['source']??$accounts['source']??'unknown'),'collected_at'=>$sites['collected_at']??$accounts['collected_at']??null,'warnings'=>$warnings,'diagnostics'=>$sites['diagnostics']??$accounts['diagnostics']??[]]]);
    }
    if($route==='services') { $auth->requirePermission('server.read'); $r=$client->get('/v1/services'); out($r,$r['_status']??200); }
    if($route==='service') { mutationGuard($auth,'server.services'); $d=bodyJson(); $service=(string)($d['service']??'');$action=(string)($d['action']??''); if(!preg_match('/^[A-Za-z0-9_.@-]{1,80}$/',$service)||!in_array($action,['start','stop','restart','reload'],true)) out(['error'=>'Invalid service/action'],400); $r=$client->post('/v1/services/'.rawurlencode($service).'/'.$action); $store->addEvent((string)$user['username'],'service.'.$action,$action.' '.$service); out($r,$r['_status']??200); }
    if($route==='updates') { $auth->requirePermission('server.updates'); $r=$client->get('/v1/packages/updates'); out($r,$r['_status']??200); }
    if($route==='update-upload-prepare') {
        mutationGuard($auth,'server.updates');
        if(!isset($_FILES['package']) || !is_array($_FILES['package'])) out(['error'=>'Privora update ZIP is required'],400);
        $f=$_FILES['package']; $err=(int)($f['error']??UPLOAD_ERR_NO_FILE); if($err!==UPLOAD_ERR_OK) out(['error'=>'Update package upload failed (code '.$err.')'],400);
        $size=(int)($f['size']??0); if($size<1024 || $size>536870912) out(['error'=>'Update package must be between 1 KB and 512 MB'],413);
        $original=(string)($f['name']??'privora-update.zip'); if(!preg_match('/\.zip$/i',$original)) out(['error'=>'Only Privora ZIP update packages are accepted'],400);
        $tmp=(string)($f['tmp_name']??''); if($tmp==='' || !is_uploaded_file($tmp)) out(['error'=>'Invalid uploaded file'],400);
        $fh=@fopen($tmp,'rb'); $magic=$fh?fread($fh,4):false; if($fh)fclose($fh); if($magic===false || !in_array($magic,["PK\x03\x04","PK\x05\x06","PK\x07\x08"],true)) out(['error'=>'Uploaded file is not a ZIP archive'],400);
        $dir=getenv('PRIVORA_UPDATE_UPLOAD_INBOX') ?: '/var/lib/privora-panel/web/update-uploads'; if(!is_dir($dir) || !is_writable($dir)) out(['error'=>'Privora update inbox is unavailable'],503);
        $target=$dir.'/'.bin2hex(random_bytes(16)).'.zip'; if(!move_uploaded_file($tmp,$target)) out(['error'=>'Could not stage uploaded package'],500); @chmod($target,0600);
        try{$r=$client->postLong('/v1/system/update-upload/prepare',['upload_path'=>$target,'original_name'=>substr(basename($original),0,180)],60);}catch(Throwable $e){@unlink($target);throw $e;}
        if(($r['_status']??500)>=300)@unlink($target); out($r,$r['_status']??200);
    }
    if($route==='update-upload-start') {
        mutationGuard($auth,'server.updates'); $d=bodyJson(); $id=(string)($d['upload_id']??''); $rootPassword=(string)($d['root_password']??''); $mfaCode=(string)($d['mfa_code']??'');
        if(!preg_match('/^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/',$id)) out(['error'=>'Invalid update transaction'],400);
        if($rootPassword==='' || strlen($rootPassword)>1024) out(['error'=>'Root password is required'],400);
        $mfa=$auth->mfaStatus();
        if(($mfa['enabled']??false)===true && !$auth->verifyMfaCode($mfaCode)) { $rootPassword=''; $mfaCode=''; unset($d['root_password'],$d['mfa_code']); out(['error'=>'Authenticator code is invalid'],403); }
        $r=$client->postLong('/v1/system/update-upload/start',['upload_id'=>$id,'root_password'=>$rootPassword],30); $rootPassword=''; $mfaCode=''; unset($d['root_password'],$d['mfa_code']); out($r,$r['_status']??200);
    }
    if($route==='update-status') {
        $auth->requirePermission('server.updates'); $id=(string)($_GET['id']??''); if(!preg_match('/^[0-9]{8}T[0-9]{6}Z-([0-9]+|[0-9a-f]{16})$/',$id)) out(['error'=>'Invalid update transaction'],400);
        try{
            $r=$client->get('/v1/system/update-transactions/'.rawurlencode($id));
            if(($r['_status']??500)<300)out($r,200);
        }catch(Throwable){}
        $local=localUpdateTransaction($id);
        if(is_array($local))out(['transaction'=>$local,'degraded'=>true,'source'=>'local-journal'],200);
        out(['error'=>'Update transaction status is temporarily unavailable'],503);
    }
    if($route==='update-center') { $auth->requirePermission('server.updates'); $mfaRequired=false; try{$mfaRequired=(bool)($auth->mfaStatus()['enabled']??false);}catch(Throwable){} try{$r=$client->get('/v1/system/update-center'); if(($r['_status']??500)>=300){out(degradedUpdateCenter((string)($r['error']??('Agent update-center HTTP '.($r['_status']??500))),$mfaRequired),200);} $r['mfa_required']=$mfaRequired; out($r,200);}catch(Throwable $e){out(degradedUpdateCenter($e->getMessage(),$mfaRequired),200);} }
    if($route==='update-run') { mutationGuard($auth,'server.updates'); $d=bodyJson(); $r=$client->post('/v1/system/update-run',['mode'=>(string)($d['mode']??'security'),'channel'=>(string)($d['channel']??'stable'),'release_url'=>(string)($d['release_url']??'')]); out($r,$r['_status']??200); }
    if($route==='update-policy-set') { mutationGuard($auth,'server.updates'); $d=bodyJson(); $r=$client->post('/v1/system/update-policy',['channel'=>(string)($d['channel']??'stable'),'security_auto'=>(bool)($d['security_auto']??true),'package_auto'=>(bool)($d['package_auto']??true),'major_versions_manual'=>(bool)($d['major_versions_manual']??true),'auto_reboot'=>(bool)($d['auto_reboot']??false),'reboot_window'=>(string)($d['reboot_window']??'Sun 03:00')]); out($r,$r['_status']??200); }
    if($route==='host-inventory') { $auth->requirePermission('server.read'); $r=$client->get('/v1/host/inventory'); out($r,$r['_status']??200); }
    if($route==='accounts') { $auth->requirePermission('hosting.read'); $r=$client->get('/v1/hosting/accounts'); if(($r['_status']??500)<300)$r['accounts']=ppanelAccounts($store,filterAdminAccounts($user,$r['accounts']??[])); out($r,$r['_status']??200); }
    if($route==='account-create') { mutationGuard($auth,'hosting.write'); $d=bodyJson(); $packageName=(string)($d['package']??'Starter');resellerAllowsPackage($user,$client,$packageName);enforceResellerAllocation($user,$store,$client,$packageName);$package=null;foreach($store->packages() as $p){if(($p['name']??'')===$packageName){$package=$p;break;}}if(!$package)out(['error'=>'Selected hosting package does not exist'],400);$reseller=adminResellerScope($user);if($reseller===null)$reseller=strtolower(trim((string)($d['reseller']??'')));$owner=adminResellerScope($user)??trim((string)($d['owner']??''));$payload=['username'=>(string)($d['username']??''),'primary_domain'=>(string)($d['primary_domain']??''),'package'=>$packageName,'owner'=>$owner,'reseller'=>$reseller]; $r=$client->post('/v1/hosting/accounts',$payload); if(($r['_status']??500)<300){$limit=$client->post('/v1/resources/limits',['owner'=>$payload['username'],'cpu_percent'=>(int)($package['cpu_percent']??100),'memory_mb'=>(int)($package['ram_mb']??1024),'pids'=>(int)($package['pids']??128),'io_weight'=>(int)($package['io_weight']??100),'disk_gb'=>(int)($package['disk_gb']??10),'bandwidth_gb'=>(int)($package['bandwidth_gb']??100)]);$r['package_policy_applied']=(($limit['_status']??500)<300);$store->addEvent((string)$user['username'],'hosting.account.create','Created hosting account '.$payload['username'].' with package '.$packageName);} out($r,$r['_status']??200); }
    if($route==='account-termination-plan') { $auth->requirePermission('hosting.read');$username=strtolower(trim((string)($_GET['username']??'')));requireAdminAccountScope($user,$client,$username);if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username))out(['error'=>'Invalid hosting account'],400);$r=$client->get('/v1/hosting/accounts/'.rawurlencode($username).'/termination-plan');out($r,$r['_status']??200); }
    if($route==='account-action') { mutationGuard($auth,'hosting.write'); $d=bodyJson();$username=(string)($d['username']??'');requireAdminAccountScope($user,$client,$username);$action=(string)($d['action']??'');if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username)||!in_array($action,['suspend','unsuspend'],true))out(['error'=>'Invalid account action'],400);$r=$client->post('/v1/hosting/accounts/'.rawurlencode($username).'/'.$action);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'hosting.account.'.$action,ucfirst($action).' '.$username);out($r,$r['_status']??200); }
    if($route==='account-detail') { $auth->requirePermission('hosting.read');$username=strtolower(trim((string)($_GET['username']??'')));requireAdminAccountScope($user,$client,$username);if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username))out(['error'=>'Invalid account'],400);$r=$client->get('/v1/hosting/accounts/'.rawurlencode($username));$events=array_values(array_filter($store->events(),fn($e)=>str_contains(strtolower((string)($e['message']??'')),strtolower($username))));$r['history']=$events;out($r,$r['_status']??200); }
    if($route==='account-update') { mutationGuard($auth,'hosting.write');$d=bodyJson();$username=strtolower(trim((string)($d['username']??'')));requireAdminAccountScope($user,$client,$username);if(adminResellerScope($user)!==null){$d['reseller']=adminResellerScope($user);$d['owner']=adminResellerScope($user);}if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username))out(['error'=>'Invalid account'],400);$payload=[];foreach(['primary_domain','owner','reseller','notes','shell_policy'] as $k){if(array_key_exists($k,$d))$payload[$k]=(string)$d[$k];}$r=$client->patch('/v1/hosting/accounts/'.rawurlencode($username),$payload);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'hosting.account.update','Updated hosting account '.$username);out($r,$r['_status']??200); }
    if($route==='account-password') { mutationGuard($auth,'hosting.write');$d=bodyJson();$username=strtolower(trim((string)($d['username']??'')));requireAdminAccountScope($user,$client,$username);$password=(string)($d['password']??'');$confirm=(string)($d['password_confirm']??'');if($password!==$confirm)out(['error'=>'Passwords do not match'],400);$r=$client->post('/v1/hosting/accounts/'.rawurlencode($username).'/password',['password'=>$password]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'hosting.account.password','Reset hosting account password for '.$username);out($r,$r['_status']??200); }
    if($route==='account-bulk-action') { mutationGuard($auth,'hosting.write');$d=bodyJson();$users=array_values(array_unique(array_filter(array_map(fn($v)=>strtolower(trim((string)$v)),(array)($d['users']??[])),fn($v)=>preg_match('/^[a-z][a-z0-9_]{2,23}$/',$v))));$action=(string)($d['action']??'');if(!$users||!in_array($action,['suspend','unsuspend'],true))out(['error'=>'Select accounts and a supported action'],400);foreach($users as $scopedUser)requireAdminAccountScope($user,$client,$scopedUser);$r=$client->post('/v1/hosting/accounts/bulk',['users'=>$users,'action'=>$action]);$store->addEvent((string)$user['username'],'hosting.account.bulk','Bulk '.$action.' for '.count($users).' hosting accounts');out($r,$r['_status']??200); }
    if($route==='account-bulk-package') { mutationGuard($auth,'resources.write');$d=bodyJson();$users=array_values(array_unique((array)($d['users']??[])));$name=trim((string)($d['package']??''));resellerAllowsPackage($user,$client,$name);foreach($users as $scopedUser)requireAdminAccountScope($user,$client,(string)$scopedUser);$pkg=null;foreach($store->packages() as $p){if(strcasecmp((string)($p['name']??''),$name)===0){$pkg=$p;break;}}if(!$pkg)out(['error'=>'Package not found'],404);$results=[];$failed=0;foreach($users as $raw){$username=strtolower(trim((string)$raw));if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username))continue;enforceResellerAllocation($user,$store,$client,$name,$username);$limits=$client->post('/v1/resources/limits',['owner'=>$username,'cpu_percent'=>(int)($pkg['cpu_percent']??100),'memory_mb'=>(int)($pkg['ram_mb']??1024),'pids'=>(int)($pkg['pids']??128),'io_weight'=>(int)($pkg['io_weight']??100),'disk_gb'=>(int)($pkg['disk_gb']??10),'bandwidth_gb'=>(int)($pkg['bandwidth_gb']??100)]);if(($limits['_status']??500)>=300){$results[]=['username'=>$username,'ok'=>false,'error'=>$limits['error']??'limit enforcement failed'];$failed++;continue;}$r=$client->post('/v1/hosting/accounts/'.rawurlencode($username).'/package',['package'=>$pkg['name']]);$ok=(($r['_status']??500)<300);if(!$ok)$failed++;$results[]=['username'=>$username,'ok'=>$ok,'error'=>$r['error']??null];}$store->addEvent((string)$user['username'],'account.package.bulk','Assigned '.$pkg['name'].' to '.(count($results)-$failed).' accounts');out(['ok'=>$failed===0,'results'=>$results,'failed'=>$failed],$failed?207:200); }
    if($route==='ppanel-access-set') { mutationGuard($auth,'hosting.write');$d=bodyJson();$account=strtolower(trim((string)($d['account']??'')));requireAdminAccountScope($user,$client,$account);$domain=strtolower(trim((string)($d['primary_domain']??'')));$panelUsername=strtolower(trim((string)($d['panel_username']??'')));$password=(string)($d['password']??'');$accounts=$client->get('/v1/hosting/accounts');$found=null;foreach(($accounts['accounts']??[]) as $a){if(strtolower((string)($a['username']??''))===$account){$found=$a;break;}}if(!$found)out(['error'=>'Hosting account not found'],404);$actual=strtolower(trim((string)($found['primary_domain']??'')));if($actual==='')out(['error'=>'Hosting account does not have a primary domain yet'],409);if($domain!==''&&$domain!==$actual)out(['error'=>'Primary domain does not match the hosting account'],409);$access=$store->setHostingAccess($account,$actual,$password,$panelUsername);$store->addEvent((string)$user['username'],'ppanel.access.set','Set PPanel username '.$access['username'].' for '.$actual);out(['ok'=>true,'account'=>$account,'login'=>$access['username'],'login_aliases'=>$access['login_aliases']??[$actual],'ppanel_path'=>'/ppanel','ppanel_port'=>(int)(getenv('PRIVORA_HOSTING_PANEL_PORT')?:2443)]); }
    if($route==='account-delete') { mutationGuard($auth,'hosting.write');$d=bodyJson();$username=strtolower(trim((string)($d['username']??'')));requireAdminAccountScope($user,$client,$username);$confirm=(string)($d['confirm_username']??'');if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$username)||$confirm!==$username)out(['error'=>'Type the exact account username to confirm deletion'],400);$r=$client->delete('/v1/hosting/accounts/'.rawurlencode($username),['delete_dns'=>(bool)($d['delete_dns']??true),'plan_fingerprint'=>(string)($d['plan_fingerprint']??'')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'hosting.account.delete','Deleted suspended hosting account '.$username);out($r,$r['_status']??200); }
    if($route==='sites') { $auth->requirePermission('hosting.read'); $r=$client->get('/v1/sites'); out($r,$r['_status']??200); }
    if($route==='site-create') { mutationGuard($auth,'sites.write');$d=bodyJson();$target=(string)($d['username']??'');requireAdminAccountScope($user,$client,$target);requireAccountCapacity($store,$client,$target,'site');requireAccountCapacity($store,$client,$target,'domain');$payload=['domain'=>(string)($d['domain']??''),'username'=>(string)($d['username']??''),'php_version'=>(string)($d['php_version']??'8.4')];$r=$client->post('/v1/sites',$payload);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'site.create','Created website '.$payload['domain']);out($r,$r['_status']??200); }
    if($route==='subdomain-create') { mutationGuard($auth,'sites.write');$d=bodyJson();$payload=['parent_domain'=>(string)($d['parent_domain']??''),'label'=>(string)($d['label']??''),'username'=>(string)($d['username']??''),'php_version'=>(string)($d['php_version']??'8.4'),'document_root'=>trim((string)($d['document_root']??''))];$r=$client->post('/v1/subdomains',$payload);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'subdomain.create','Created subdomain '.(($r['site']['domain']??'')?:($payload['label'].'.'.$payload['parent_domain'])));out($r,$r['_status']??200); }
    if($route==='site-delete') {
        mutationGuard($auth,'sites.write');
        $d=bodyJson();
        $domain=strtolower(trim((string)($d['domain']??'')));
        if($domain==='')out(['error'=>'Domain required'],400);
        // A managed subdomain may use either its own dedicated document root or a
        // shared/custom root. Only a verified dedicated root is eligible for
        // recursive cleanup; shared parent-domain content is always preserved.
        $sitesResponse=$client->get('/v1/sites');
        if(($sitesResponse['_status']??200)>=300)out(['error'=>'Unable to verify website ownership/type before deletion'],503);
        $managedSite=null;
        foreach(($sitesResponse['sites']??[]) as $site){
            if(strtolower(trim((string)($site['domain']??'')))===$domain){$managedSite=$site;break;}
        }
        $isSubdomain=is_array($managedSite)&&(
            strtolower(trim((string)($managedSite['kind']??'')))==='subdomain' ||
            trim((string)($managedSite['parent_domain']??''))!==''
        );
        $safeSubdomainFiles=false;
        if($isSubdomain){
            $siteRoot=rtrim(trim((string)($managedSite['document_root']??'')),'/');
            $siteUser=strtolower(trim((string)($managedSite['username']??'')));
            $ownTree='/home/'.$siteUser.'/domains/'.$domain;
            $insideOwnTree=$siteRoot!=='' && str_starts_with($siteRoot.'/',rtrim($ownTree,'/').'/') && $siteRoot!==$ownTree;
            $sharedRoot=false;
            if($siteRoot!==''){
                foreach(($sitesResponse['sites']??[]) as $other){
                    if(strtolower(trim((string)($other['domain']??'')))===$domain)continue;
                    if(rtrim(trim((string)($other['document_root']??'')),'/')===$siteRoot){$sharedRoot=true;break;}
                }
            }
            $safeSubdomainFiles=$insideOwnTree&&!$sharedRoot;
        }
        $deleteFiles=$isSubdomain ? $safeSubdomainFiles : (bool)($d['delete_files']??false);
        $r=$client->delete('/v1/sites/'.rawurlencode($domain),['delete_files'=>$deleteFiles,'delete_dns'=>(bool)($d['delete_dns']??true)]);
        if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'site.delete','Deleted '.($isSubdomain?'subdomain ':'website ').$domain.($deleteFiles?' including files':''));
        out($r,$r['_status']??200);
    }
    if($route==='config-files') { $auth->requirePermission('server.services');$r=$client->get('/v1/config-files');out($r,$r['_status']??200); }
    if($route==='config-read') { $auth->requirePermission('server.services');$id=(string)($_GET['id']??'');$r=$client->get('/v1/config-files/'.rawurlencode($id));out($r,$r['_status']??200); }
    if($route==='config-write') { mutationGuard($auth,'server.services');$d=bodyJson();$id=(string)($d['id']??'');$r=$client->post('/v1/config-files/'.rawurlencode($id),['content'=>(string)($d['content']??''),'expected_sha'=>(string)($d['expected_sha']??'')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'config.write','Validated config update '.$id);out($r,$r['_status']??200); }
    if($route==='components') { $auth->requirePermission('server.services');$r=$client->get('/v1/components');out($r,$r['_status']??200); }
    if($route==='software-jobs') { $auth->requirePermission('server.services');$r=$client->get('/v1/software/jobs');out($r,$r['_status']??200); }
    if($route==='software-job-status') { $auth->requirePermission('server.services');$id=trim((string)($_GET['id']??''));if(!preg_match('/^sw-[a-f0-9]{16}$/',$id))out(['error'=>'Invalid software job ID'],400);$r=$client->get('/v1/software/jobs/'.rawurlencode($id));out($r,$r['_status']??200); }
    if($route==='software-job-start') { mutationGuard($auth,'server.services');$d=bodyJson();$kind=strtolower(trim((string)($d['kind']??'')));$action=strtolower(trim((string)($d['action']??'')));$target=strtolower(trim((string)($d['target']??'')));$v=(string)($d['php_version']??'');$allowed=(($kind==='component'&&in_array($action,['install','remove'],true)&&preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/',$target))||($kind==='preset'&&$action==='apply'&&preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/',$target)&&in_array($v,['8.2','8.3','8.4','8.5'],true))||($kind==='php-version'&&in_array($action,['install','remove'],true)&&in_array($target,['8.2','8.3','8.4','8.5'],true)));if(!$allowed)out(['error'=>'Invalid software job request'],400);$r=$client->postLong('/v1/software/jobs',['kind'=>$kind,'action'=>$action,'target'=>$target,'php_version'=>$v],20);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'server.software.job','Queued '.$kind.' '.$action.' '.$target);out($r,$r['_status']??200); }
    if($route==='component-presets') { $auth->requirePermission('server.services');$v=(string)($_GET['php_version']??'8.4');if(!in_array($v,['8.2','8.3','8.4','8.5'],true))$v='8.4';$r=$client->get('/v1/components/presets?php_version='.rawurlencode($v));out($r,$r['_status']??200); }
    if($route==='component-preset-apply') { mutationGuard($auth,'server.services');$d=bodyJson();$id=strtolower(trim((string)($d['id']??'')));$v=(string)($d['php_version']??'8.4');if(!preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/',$id)||!in_array($v,['8.2','8.3','8.4','8.5'],true))out(['error'=>'Invalid preset or PHP version'],400);$r=$client->postLong('/v1/components/presets/'.rawurlencode($id).'/apply',['php_version'=>$v],540);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'server.component.preset','Applied component preset '.$id.' for PHP '.$v);out($r,$r['_status']??200); }
    if($route==='php-versions') { $auth->requirePermission('php.write');$r=$client->get('/v1/php/versions');out($r,$r['_status']??200); }
    if($route==='php-extensions') { $auth->requirePermission('server.services');$r=$client->get('/v1/php/extensions');out($r,$r['_status']??200); }
    if($route==='php-version-install') { mutationGuard($auth,'server.services');$d=bodyJson();$v=(string)($d['version']??'');if(!in_array($v,['8.2','8.3','8.4','8.5'],true))out(['error'=>'Unsupported PHP version'],400);$r=$client->postLong('/v1/php/versions/'.rawurlencode($v).'/install',[],540);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'php.version.install','Installed PHP '.$v);out($r,$r['_status']??200); }
    if($route==='php-version-remove') { mutationGuard($auth,'server.services');$d=bodyJson();$v=(string)($d['version']??'');if(!in_array($v,['8.2','8.3','8.4','8.5'],true))out(['error'=>'Unsupported PHP version'],400);$r=$client->deleteLong('/v1/php/versions/'.rawurlencode($v),[],540);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'php.version.remove','Removed PHP '.$v);out($r,$r['_status']??200); }
    if($route==='component-install') { mutationGuard($auth,'server.services');$d=bodyJson();$id=strtolower(trim((string)($d['id']??'')));if(!preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/',$id))out(['error'=>'Invalid component identifier'],400);$r=$client->postLong('/v1/components/'.rawurlencode($id).'/install',[],540);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'server.component.install','Installed curated server component '.$id);out($r,$r['_status']??200); }
    if($route==='component-remove') { mutationGuard($auth,'server.services');$d=bodyJson();$id=strtolower(trim((string)($d['id']??'')));if(!preg_match('/^[a-z0-9][a-z0-9-]{1,63}$/',$id))out(['error'=>'Invalid component identifier'],400);$r=$client->deleteLong('/v1/components/'.rawurlencode($id),[],540);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'server.component.remove','Removed curated server component '.$id);out($r,$r['_status']??200); }
    if($route==='nameservers') { $auth->requirePermission('resources.write');$r=$client->get('/v1/dns/nameservers');out($r,$r['_status']??200); }
    if($route==='nameservers-set') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/dns/nameservers',['base_domain'=>(string)($d['base_domain']??''),'primary'=>(string)($d['primary']??''),'secondary'=>(string)($d['secondary']??''),'ipv4'=>(string)($d['ipv4']??''),'ipv6'=>(string)($d['ipv6']??''),'default'=>(bool)($d['default']??false)]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.nameservers.set','Configured authoritative nameservers for '.($d['base_domain']??''));out($r,$r['_status']??200); }
    if($route==='nameserver-assignment-set') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$base=strtolower(trim((string)($d['base_domain']??'')));if($domain==='')out(['error'=>'Hosted root domain is required'],400);$r=$client->post('/v1/dns/nameserver-assignment',['domain'=>$domain,'base_domain'=>$base]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.nameserver.assignment','Assigned '.$domain.' to nameserver set '.($base?:'default'));out($r,$r['_status']??200); }
    if($route==='nameservers-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$base=strtolower(trim((string)($d['base_domain']??'')));if($base==='')out(['error'=>'Select a nameserver set to delete'],400);$r=$client->delete('/v1/dns/nameservers',['base_domain'=>$base,'force'=>(bool)($d['force']??false)]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.nameservers.delete','Deleted authoritative nameserver set '.$base);out($r,$r['_status']??200); }
    if($route==='registrar-connect') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/dns/registrar',['provider'=>(string)($d['provider']??''),'adapter_url'=>(string)($d['adapter_url']??''),'token'=>(string)($d['token']??'')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.registrar.connect','Configured registrar adapter '.($d['provider']??''));out($r,$r['_status']??200); }
    if($route==='site-php') { mutationGuard($auth,'php.write');$d=bodyJson();$domain=(string)($d['domain']??'');$version=(string)($d['version']??'');if(!preg_match('/^[A-Za-z0-9.-]{1,253}$/',$domain)||!in_array($version,['8.2','8.3','8.4','8.5'],true))out(['error'=>'Invalid domain/PHP version'],400);$r=$client->post('/v1/sites/'.rawurlencode(strtolower($domain)).'/php',['version'=>$version]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'site.php.set','Changed '.$domain.' to PHP '.$version);out($r,$r['_status']??200); }

    if($route==='packages-features') {
        $auth->requirePermission('hosting.read');
        $accounts=$client->get('/v1/hosting/accounts');$usage=[];
        foreach(($accounts['accounts']??[]) as $a){$name=(string)($a['package']??'');if($name!=='')$usage[$name]=($usage[$name]??0)+1;}
        out(['packages'=>$store->packages(),'feature_lists'=>$store->featureLists(),'accounts_using_package'=>$usage]);
    }
    if($route==='package-save') { requireRootAdministrator($user);
        mutationGuard($auth,'resources.write'); $d=bodyJson();
        try{$pkg=$store->upsertPackage($d);$store->addEvent((string)$user['username'],'package.save','Saved hosting package '.$pkg['name']);out(['ok'=>true,'package'=>$pkg]);}
        catch(Throwable $e){out(['error'=>$e->getMessage()],400);}
    }
    if($route==='package-clone') { requireRootAdministrator($user); mutationGuard($auth,'resources.write');$d=bodyJson();try{$pkg=$store->clonePackage((string)($d['source']??''),(string)($d['target']??''));$store->addEvent((string)$user['username'],'package.clone','Cloned hosting package '.($d['source']??'').' to '.$pkg['name']);out(['ok'=>true,'package'=>$pkg]);}catch(Throwable $e){out(['error'=>$e->getMessage()],409);} }
    if($route==='package-delete') { requireRootAdministrator($user);
        mutationGuard($auth,'resources.write'); $d=bodyJson();$name=trim((string)($d['name']??''));
        $accounts=$client->get('/v1/hosting/accounts');foreach(($accounts['accounts']??[]) as $a){if(strcasecmp((string)($a['package']??''),$name)===0)out(['error'=>'Package is assigned to hosting account '.($a['username']??'unknown')],409);}
        try{$store->deletePackage($name);$store->addEvent((string)$user['username'],'package.delete','Deleted hosting package '.$name);out(['ok'=>true]);}
        catch(Throwable $e){out(['error'=>$e->getMessage()],400);}
    }
    if($route==='feature-save') { requireRootAdministrator($user);
        mutationGuard($auth,'resources.write');$d=bodyJson();
        try{$f=$store->upsertFeatureList((string)($d['name']??''),(array)($d['features']??[]));$store->addEvent((string)$user['username'],'feature-list.save','Saved feature list '.$f['name']);out(['ok'=>true,'feature_list'=>$f]);}
        catch(Throwable $e){out(['error'=>$e->getMessage()],400);}
    }
    if($route==='feature-delete') { requireRootAdministrator($user);
        mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');
        try{$store->deleteFeatureList($name);$store->addEvent((string)$user['username'],'feature-list.delete','Deleted feature list '.$name);out(['ok'=>true]);}
        catch(Throwable $e){out(['error'=>$e->getMessage()],409);}
    }
    if($route==='account-package') {
        mutationGuard($auth,'resources.write');$d=bodyJson();$username=strtolower(trim((string)($d['username']??'')));$name=trim((string)($d['package']??''));requireAdminAccountScope($user,$client,$username);resellerAllowsPackage($user,$client,$name);enforceResellerAllocation($user,$store,$client,$name,$username);
        $pkg=null;foreach($store->packages() as $p){if(strcasecmp((string)($p['name']??''),$name)===0){$pkg=$p;break;}}
        if(!$pkg)out(['error'=>'Package not found'],404);
        $limits=$client->post('/v1/resources/limits',['owner'=>$username,'cpu_percent'=>(int)($pkg['cpu_percent']??100),'memory_mb'=>(int)($pkg['ram_mb']??1024),'pids'=>(int)($pkg['pids']??128),'io_weight'=>(int)($pkg['io_weight']??100),'disk_gb'=>(int)($pkg['disk_gb']??10),'bandwidth_gb'=>(int)($pkg['bandwidth_gb']??100)]);
        if(($limits['_status']??500)>=300)out(['error'=>'Package limits could not be enforced; package assignment was not changed.','limits'=>$limits],409);
        $r=$client->post('/v1/hosting/accounts/'.rawurlencode($username).'/package',['package'=>$pkg['name']]);
        if(($r['_status']??500)>=300)out($r,$r['_status']);
        $store->addEvent((string)$user['username'],'account.package','Assigned '.$pkg['name'].' to '.$username);
        out(['ok'=>true,'account'=>$r['account']??null,'package'=>$pkg,'limits_applied'=>true,'limits'=>$limits]);
    }

    if($route==='reseller-save') { requireRootAdministrator($user); mutationGuard($auth,'resources.write');$d=bodyJson();$name=strtolower(trim((string)($d['name']??'')));$payload=['name'=>$name,'company'=>(string)($d['company']??''),'max_accounts'=>(int)($d['max_accounts']??1),'disk_gb'=>(int)($d['disk_gb']??0),'bandwidth_gb'=>(int)($d['bandwidth_gb']??0),'allowed_packages'=>array_values((array)($d['allowed_packages']??[])),'allowed_feature_lists'=>array_values((array)($d['allowed_feature_lists']??[])),'dns_allowed'=>(bool)($d['dns_allowed']??false),'ssl_allowed'=>(bool)($d['ssl_allowed']??false),'nameserver_bases'=>array_values((array)($d['nameserver_bases']??[])),'status'=>(string)($d['status']??'active')];$existing=false;foreach(($client->get('/v1/resellers')['resellers']??[]) as $rr){if(($rr['name']??'')===$name){$existing=true;break;}}$r=$existing?$client->patch('/v1/resellers/'.rawurlencode($name),$payload):$client->post('/v1/resellers',$payload);if(($r['_status']??500)<300){$store->setResellerAccessActive($name,($payload['status']??'active')==='active');$store->addEvent((string)$user['username'],'reseller.save','Saved reseller '.$name);}out($r,$r['_status']??200); }
    if($route==='reseller-access-set') { requireRootAdministrator($user);mutationGuard($auth,'resources.write');$d=bodyJson();$name=strtolower(trim((string)($d['name']??'')));$password=(string)($d['password']??'');if($password!==(string)($d['password_confirm']??''))out(['error'=>'Passwords do not match'],400);$exists=false;foreach(($client->get('/v1/resellers')['resellers']??[]) as $rr){if(strtolower((string)($rr['name']??''))===$name){$exists=true;if(($rr['status']??'active')!=='active')out(['error'=>'Enable the reseller before configuring login access'],409);break;}}if(!$exists)out(['error'=>'Reseller not found'],404);try{$access=$store->setResellerAccess($name,$password,(string)($d['login']??''));$store->addEvent((string)$user['username'],'reseller.access.set','Configured PCC access for reseller '.$name);out(['ok'=>true,'name'=>$name,'login'=>$access['username'],'password_stored'=>false]);}catch(Throwable $e){out(['error'=>$e->getMessage()],400);} }
    if($route==='reseller-delete') { requireRootAdministrator($user); mutationGuard($auth,'resources.write');$d=bodyJson();$name=strtolower(trim((string)($d['name']??'')));$r=$client->delete('/v1/resellers/'.rawurlencode($name));if(($r['_status']??500)<300){$store->deleteResellerAccess($name);$store->addEvent((string)$user['username'],'reseller.delete','Deleted reseller '.$name);}out($r,$r['_status']??200); }
    if($route==='resources-all') {
        $auth->requirePermission('hosting.read');
        $map=['php_runtimes'=>'/v1/php/runtimes','sftp_accounts'=>'/v1/sftp','firewall_rules'=>'/v1/firewall/rules','applications'=>'/v1/applications','databases'=>'/v1/databases','zones'=>'/v1/dns/zones','certificates'=>'/v1/ssl','backups'=>'/v1/backups','mailboxes'=>'/v1/mailboxes','resellers'=>'/v1/resellers','nodes'=>'/v1/fleet/nodes','instances'=>'/v1/cloud/instances','workloads'=>'/v1/fabric/workloads','automations'=>'/v1/automation/runs'];
        $out=['resource_errors'=>[]];
        foreach($map as $key=>$path){
            try{
                $r=$client->get($path);
                if(($r['_status']??500)>=300) throw new RuntimeException((string)($r['error']??($key.' inventory returned HTTP '.($r['_status']??500))));
                $sourceKey=$key==='php_runtimes'?'runtimes':$key;
                $out[$key]=$r[$sourceKey]??[];
                if($key==='zones'){ $out['dns_diagnostics']=$r['diagnostics']??[]; $out['dns_warnings']=$r['warnings']??[]; }
            }catch(Throwable $e){
                $out[$key]=[]; $out['resource_errors'][$key]=$e->getMessage();
            }
        }

        if(isset($out['resellers']) && is_array($out['resellers'])){
            foreach($out['resellers'] as $i=>$rr){$access=$store->resellerAccessFor((string)($rr['name']??''));$out['resellers'][$i]['access_configured']=is_array($access);$out['resellers'][$i]['access_login']=is_array($access)?(string)($access['username']??''):'';}
        }

        // Independent PCC-side DNS safety net: every website/account domain must
        // remain visible even if the agent's BIND inventory fails. This prevents
        // an authoritative-DNS backend error from masquerading as an empty list.
        $knownDomains=[];
        foreach([['/v1/sites','sites'],['/v1/hosting/accounts','accounts']] as [$path,$key]){
            try{
                $r=$client->get($path);
                if(($r['_status']??500)>=300) continue;
                foreach(($r[$key]??[]) as $row){
                    $domain=strtolower(trim((string)($key==='sites'?($row['domain']??''):($row['primary_domain']??''))));
                    if($domain!=='' && preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/',$domain)) $knownDomains[$domain]=true;
                }
            }catch(Throwable $e){ /* DNS list still remains usable from other sources. */ }
        }
        $zoneByDomain=[]; foreach(($out['zones']??[]) as $z){$d=strtolower(trim((string)($z['domain']??'')));if($d!=='')$zoneByDomain[$d]=$z;}
        foreach(array_keys($knownDomains) as $domain){
            if(isset($zoneByDomain[$domain])) continue;
            $reason='Domain is hosted by Privora, but no local authoritative DNS zone was returned by the DNS inventory.';
            if(isset($out['resource_errors']['zones'])) $reason.=' DNS inventory error: '.$out['resource_errors']['zones'];
            $zoneByDomain[$domain]=['domain'=>$domain,'dnssec'=>false,'records'=>[],'status'=>'not-configured','managed'=>false,'source'=>'pcc-hosted-domain-fallback','zone_file'=>'','status_reason'=>$reason];
        }
        ksort($zoneByDomain); $out['zones']=array_values($zoneByDomain);
        try{$out['summary']=$client->get('/v1/resources/summary');}catch(Throwable $e){$out['summary']=[];$out['resource_errors']['summary']=$e->getMessage();}
        try{$out['host_capabilities']=$client->get('/v1/host/capabilities');}catch(Throwable $e){$out['host_capabilities']=[];$out['resource_errors']['host_capabilities']=$e->getMessage();}
        out($out);
    }

    if($route==='files') { $auth->requirePermission('hosting.read');$user=(string)($_GET['user']??'');$path=(string)($_GET['path']??'.');if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$user))out(['error'=>'Invalid account'],400);$r=$client->get('/v1/files/'.rawurlencode($user).'?path='.rawurlencode($path));out($r,$r['_status']??200); }
    if($route==='file-write') { mutationGuard($auth,'resources.write');$d=bodyJson();$account=(string)($d['user']??'');if(!preg_match('/^[a-z][a-z0-9_]{2,23}$/',$account))out(['error'=>'Invalid account'],400);$r=$client->post('/v1/files/'.rawurlencode($account).'/write',['path'=>(string)($d['path']??''),'content'=>(string)($d['content']??'')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'file.write','Wrote '.($d['path']??''));out($r,$r['_status']??200); }
    if($route==='sftp-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$owner=(string)($d['owner']??'');requireAdminAccountScope($user,$client,$owner);requireAccountCapacity($store,$client,$owner,'sftp');$r=$client->post('/v1/sftp',['username'=>(string)($d['username']??''),'owner'=>(string)($d['owner']??''),'root'=>(string)($d['root']??''),'auth'=>(string)($d['auth']??'ssh-key')]);out($r,$r['_status']??200); }
    if($route==='firewall-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/firewall/rules',['direction'=>(string)($d['direction']??'inbound'),'protocol'=>(string)($d['protocol']??'tcp'),'port'=>(int)($d['port']??0),'source'=>(string)($d['source']??'0.0.0.0/0'),'action'=>(string)($d['action']??'allow')]);out($r,$r['_status']??200); }
    if($route==='application-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/applications',['type'=>(string)($d['type']??'laravel'),'domain'=>(string)($d['domain']??''),'owner'=>(string)($d['owner']??''),'runtime'=>(string)($d['runtime']??'php8.4')]);out($r,$r['_status']??200); }

    if($route==='database-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$owner=(string)($d['owner']??'');requireAdminAccountScope($user,$client,$owner);requireAccountCapacity($store,$client,$owner,'database');requireAccountCapacity($store,$client,$owner,'database_user');$password=(string)($d['password']??'');if($password!=='' && $password!==(string)($d['password_confirm']??''))out(['error'=>'Database password confirmation does not match'],400);$r=$client->post('/v1/databases',['name'=>(string)($d['name']??''),'user'=>(string)($d['user']??''),'password'=>$password,'engine'=>(string)($d['engine']??'mariadb'),'owner'=>(string)($d['owner']??'')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'database.create','Created database '.($d['name']??''));out($r,$r['_status']??200); }
    if($route==='database-password') { mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');$password=(string)($d['password']??'');if($password!=='' && $password!==(string)($d['password_confirm']??''))out(['error'=>'Database password confirmation does not match'],400);$r=$client->post('/v1/databases/'.rawurlencode($name).'/password',['password'=>$password]);out($r,$r['_status']??200); }
    if($route==='database-user') { mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');$password=(string)($d['password']??'');if($password!=='' && $password!==(string)($d['password_confirm']??''))out(['error'=>'Database password confirmation does not match'],400);$r=$client->post('/v1/databases/'.rawurlencode($name).'/user',['user'=>(string)($d['user']??''),'password'=>$password]);out($r,$r['_status']??200); }
    if($route==='database-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');if(($d['confirm_name']??'')!==$name)out(['error'=>'Type the exact database name to confirm deletion'],400);$r=$client->delete('/v1/databases/'.rawurlencode($name).'?confirm='.rawurlencode($name));out($r,$r['_status']??200); }
    if($route==='database-inspect') { $auth->requirePermission('resources.write');$name=(string)($_GET['name']??'');$r=$client->get('/v1/databases/'.rawurlencode($name).'/inspect');out($r,$r['_status']??200); }
    if($route==='database-maintenance') { mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');$action=(string)($d['action']??'');if(!in_array($action,['check','repair','optimize'],true))out(['error'=>'Unsupported maintenance action'],400);$r=$client->postLong('/v1/databases/'.rawurlencode($name).'/maintenance',['action'=>$action],540);out($r,$r['_status']??200); }
    if($route==='database-export') { mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');$r=$client->postLong('/v1/databases/'.rawurlencode($name).'/export',[],900);out($r,$r['_status']??200); }
    if($route==='database-import') { mutationGuard($auth,'resources.write');$d=bodyJson();$name=(string)($d['name']??'');$source=(string)($d['source_path']??'');$r=$client->postLong('/v1/databases/'.rawurlencode($name).'/import',['source_path'=>$source],900);out($r,$r['_status']??200); }
    if($route==='dns-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/dns/zones',['domain'=>(string)($d['domain']??''),'dnssec'=>(bool)($d['dnssec']??false)]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.zone.create','Created DNS zone '.($d['domain']??''));out($r,$r['_status']??200); }
    if($route==='dns-repair-hosted') { mutationGuard($auth,'resources.write');$r=$client->postLong('/v1/dns/repair-hosted',[],180);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.hosted.repair','Reconciled DNS for '.(int)($r['scanned']??0).' hosted websites');out($r,$r['_status']??200); }
    if($route==='dns-zone') { $auth->requirePermission('hosting.read');$domain=strtolower(trim((string)($_GET['domain']??'')));$r=$client->get('/v1/dns/zones/'.rawurlencode($domain));out($r,$r['_status']??200); }
    if($route==='site-repair') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->post('/v1/sites/'.rawurlencode($domain).'/repair',[]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'website.repair','Repaired website configuration for '.$domain);out($r,$r['_status']??200); }
    if($route==='dns-record-save') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->post('/v1/dns/zones/'.rawurlencode($domain).'/records',['type'=>(string)($d['type']??''),'name'=>(string)($d['name']??'@'),'value'=>(string)($d['value']??''),'ttl'=>(int)($d['ttl']??3600)]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.record.save','Updated DNS record for '.$domain);out($r,$r['_status']??200); }
    if($route==='dns-record-replace') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->post('/v1/dns/zones/'.rawurlencode($domain).'/records/replace',['original'=>(array)($d['original']??[]),'replacement'=>(array)($d['replacement']??[])]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.record.replace','Replaced DNS record for '.$domain);out($r,$r['_status']??200); }
    if($route==='dns-record-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->delete('/v1/dns/zones/'.rawurlencode($domain).'/records',['type'=>(string)($d['type']??''),'name'=>(string)($d['name']??'@'),'value'=>(string)($d['value']??''),'ttl'=>(int)($d['ttl']??3600)]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.record.delete','Deleted DNS record for '.$domain);out($r,$r['_status']??200); }
    if($route==='dns-zone-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->delete('/v1/dns/zones/'.rawurlencode($domain));if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'dns.zone.delete','Deleted DNS zone '.$domain);out($r,$r['_status']??200); }
    if($route==='ssl-issue') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->postLong('/v1/ssl/issue',['domain'=>(string)($d['domain']??'')],180);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'ssl.issue','Issued certificate for '.($d['domain']??''));out($r,$r['_status']??200); }
    if($route==='ssl-autossl') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->postLong('/v1/ssl/autossl',['domain'=>strtolower(trim((string)($d['domain']??'')))],180);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'ssl.autossl','AutoSSL scan '.(((string)($d['domain']??''))?:'all active websites'));out($r,$r['_status']??200); }
    if($route==='ssl-inspect') { $auth->requirePermission('resources.write');$domain=strtolower(trim((string)($_GET['domain']??'')));$r=$client->get('/v1/ssl/'.rawurlencode($domain).'/inspect');out($r,$r['_status']??200); }
    if($route==='ssl-csr') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->post('/v1/ssl/'.rawurlencode($domain).'/csr',[]);out($r,$r['_status']??200); }
    if($route==='ssl-custom-install') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->postLong('/v1/ssl/'.rawurlencode($domain).'/custom',['certificate'=>(string)($d['certificate']??''),'private_key'=>(string)($d['private_key']??'')],180);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'ssl.custom.install','Installed custom certificate for '.$domain);out($r,$r['_status']??200); }
    if($route==='ssl-revoke') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$r=$client->postLong('/v1/ssl/'.rawurlencode($domain).'/revoke',[],180);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'ssl.revoke','Revoked certificate for '.$domain);out($r,$r['_status']??200); }
    if($route==='backup-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/backups',['scope'=>(string)($d['scope']??'site'),'resource'=>(string)($d['resource']??''),'destination'=>(string)($d['destination']??'local')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'backup.create','Created backup for '.($d['resource']??''));out($r,$r['_status']??200); }
    if($route==='backup-restore') { mutationGuard($auth,'resources.write');$d=bodyJson();$id=(string)($d['id']??'');if(!preg_match('/^bkp_[a-z0-9]+$/',$id))out(['error'=>'Invalid backup ID'],400);$r=$client->post('/v1/backups/'.rawurlencode($id).'/restore',['confirm_resource'=>(string)($d['confirm_resource']??'')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'backup.restore','Restored backup '.$id);out($r,$r['_status']??200); }
    if($route==='mailbox-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$address=strtolower(trim((string)($d['address']??'')));$domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):'';$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Mailbox domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);requireAccountCapacity($store,$client,$owner,'mailbox');$password=(string)($d['password']??'');$confirm=(string)($d['password_confirm']??'');if(strlen($password)<12)out(['error'=>'Mailbox password must be at least 12 characters'],400);if($password!==$confirm)out(['error'=>'Mailbox password confirmation does not match'],400);$r=$client->post('/v1/mailboxes',['address'=>$address,'quota_mb'=>(int)($d['quota_mb']??1024),'password'=>$password]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'mailbox.create','Created mailbox '.$address);out($r,$r['_status']??200); }
    if(in_array($route,['mailbox-update','mailbox-delete'],true)) { mutationGuard($auth,'resources.write');$d=bodyJson();$address=strtolower(trim((string)($d['address']??'')));$domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):'';$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Mailbox domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$all=$client->get('/v1/mailboxes');$mailbox=null;foreach(($all['mailboxes']??[]) as $row){if(strtolower((string)($row['address']??''))===$address){$mailbox=$row;break;}}if(!$mailbox)out(['error'=>'Mailbox not found'],404);if($route==='mailbox-update'){$password=(string)($d['password']??'');$confirm=(string)($d['password_confirm']??'');if($password!==$confirm)out(['error'=>'Mailbox password confirmation does not match'],400);if($password!==''&&strlen($password)<12)out(['error'=>'Mailbox password must be at least 12 characters'],400);$quota=(int)($d['quota_mb']??($mailbox['quota_mb']??1024));if($quota<100||$quota>102400)out(['error'=>'Mailbox quota must be between 100 and 102400 MB'],400);$r=$client->patch('/v1/mailboxes/'.rawurlencode($address),['quota_mb'=>$quota,'password'=>$password]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'mailbox.update','Updated mailbox '.$address);out($r,$r['_status']??200);}if(($d['confirm_address']??'')!==$address)out(['error'=>'Type the exact mailbox address to confirm deletion'],400);$r=$client->delete('/v1/mailboxes/'.rawurlencode($address));if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'mailbox.delete','Deleted mailbox '.$address);out($r,$r['_status']??200); }
    if($route==='reseller-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/resellers',['name'=>(string)($d['name']??''),'company'=>(string)($d['company']??''),'max_accounts'=>(int)($d['max_accounts']??25)]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'reseller.create','Created reseller '.($d['name']??''));out($r,$r['_status']??200); }
    if($route==='node-create') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/fleet/nodes',['name'=>(string)($d['name']??''),'role'=>(string)($d['role']??'web'),'region'=>(string)($d['region']??''),'endpoint'=>(string)($d['endpoint']??'')]);out($r,$r['_status']??200); }
    if($route==='instance-create') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/cloud/instances',['provider'=>'mock','region'=>(string)($d['region']??''),'size'=>(string)($d['size']??''),'image'=>(string)($d['image']??'ubuntu-lts')]);out($r,$r['_status']??200); }

    if($route==='automation-provision') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/automation/provision',['customer'=>(string)($d['customer']??''),'username'=>(string)($d['username']??''),'domain'=>(string)($d['domain']??''),'package'=>(string)($d['package']??'Starter'),'php_version'=>(string)($d['php_version']??'8.4')]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'automation.provision','Simulated automated provisioning for '.($d['domain']??''));out($r,$r['_status']??200); }

    if($route==='workload-create') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/fabric/workloads',['name'=>(string)($d['name']??''),'type'=>(string)($d['type']??'web'),'region'=>(string)($d['region']??''),'desired_replicas'=>(int)($d['desired_replicas']??2)]);out($r,$r['_status']??200); }

    if($route==='cron-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$owner=(string)($d['owner']??'');requireAdminAccountScope($user,$client,$owner);requireAccountCapacity($store,$client,$owner,'cron');$r=$client->post('/v1/tasks/cron',['owner'=>(string)($d['owner']??''),'schedule'=>(string)($d['schedule']??''),'command'=>(string)($d['command']??'')]);out($r,$r['_status']??200); }
    if($route==='deployment-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/deployments',['kind'=>(string)($d['kind']??'git'),'domain'=>(string)($d['domain']??''),'owner'=>(string)($d['owner']??''),'repository'=>(string)($d['repository']??''),'branch'=>(string)($d['branch']??'main'),'runtime'=>(string)($d['runtime']??'php8.4')]);out($r,$r['_status']??200); }
    if($route==='mail-domain-config') { $auth->requirePermission('hosting.read');$domain=strtolower(trim((string)($_GET['domain']??'')));$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Mail domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$r=$client->getLong('/v1/mail/domains/'.rawurlencode($domain).'/configuration',30);out($r,$r['_status']??200); }
    if($route==='mail-domain-auth-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));if($domain===''||(string)($d['confirm_domain']??'')!==$domain)out(['error'=>'Type the exact domain to confirm authentication removal'],422);$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Mail domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$r=$client->deleteLong('/v1/mail/domains/'.rawurlencode($domain).'/authentication',[],60);out($r,$r['_status']??200); }
    if($route==='mail-domain-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Mail domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$requested=trim((string)($d['owner']??''));if($requested!==''&&strcasecmp($requested,$owner)!==0)out(['error'=>'Selected hosting account does not own this domain'],409);$r=$client->postLong('/v1/mail/domains',['domain'=>$domain,'owner'=>$owner,'dmarc'=>(string)($d['dmarc']??'quarantine')],180);out($r,$r['_status']??200); }
    if($route==='mail-alias-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$address=strtolower(trim((string)($d['address']??'')));$domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):'';$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Forwarder domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$r=$client->post('/v1/mail/aliases',['address'=>$address,'destination'=>(string)($d['destination']??''),'owner'=>$owner]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'mail.alias.create','Created forwarder '.$address);out($r,$r['_status']??200); }
    if(in_array($route,['mail-alias-update','mail-alias-delete'],true)) { mutationGuard($auth,'resources.write');$d=bodyJson();$address=strtolower(trim((string)($d['address']??'')));$domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):'';$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Forwarder domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$all=$client->get('/v1/mail/aliases');$alias=null;foreach(($all['mail_aliases']??[]) as $row){if(strtolower((string)($row['address']??''))===$address){$alias=$row;break;}}if(!$alias)out(['error'=>'Forwarder not found'],404);if(($alias['owner']??'')!==''&&strcasecmp((string)$alias['owner'],$owner)!==0)out(['error'=>'Forwarder ownership does not match the hosted domain'],409);if($route==='mail-alias-update'){$destination=trim((string)($d['destination']??''));if($destination==='')out(['error'=>'Forwarder destination is required'],400);$r=$client->patch('/v1/mail/aliases/'.rawurlencode($address),['destination'=>$destination]);if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'mail.alias.update','Updated forwarder '.$address);out($r,$r['_status']??200);}if(($d['confirm_address']??'')!==$address)out(['error'=>'Type the exact forwarder address to confirm deletion'],400);$r=$client->delete('/v1/mail/aliases/'.rawurlencode($address));if(($r['_status']??500)<300)$store->addEvent((string)$user['username'],'mail.alias.delete','Deleted forwarder '.$address);out($r,$r['_status']??200); }
    if($route==='reputation-check') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/mail/reputation/check',['target'=>(string)($d['target']??'')]);out($r,$r['_status']??200); }
    if($route==='ban-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/security/bans',['service'=>(string)($d['service']??'ssh'),'source'=>(string)($d['source']??''),'reason'=>(string)($d['reason']??'rate threshold exceeded')]);out($r,$r['_status']??200); }
    if($route==='malware-scan') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/security/malware',['scope'=>(string)($d['scope']??'server'),'target'=>(string)($d['target']??'server')]);out($r,$r['_status']??200); }
    if($route==='integrity-check') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/security/integrity',['scope'=>(string)($d['scope']??'system'),'target'=>(string)($d['target']??'system')]);out($r,$r['_status']??200); }
    if($route==='alert-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/monitoring/alerts',['name'=>(string)($d['name']??''),'metric'=>(string)($d['metric']??'cpu'),'operator'=>(string)($d['operator']??'>='),'threshold'=>(float)($d['threshold']??90),'window_minutes'=>(int)($d['window_minutes']??5),'severity'=>(string)($d['severity']??'warning')]);out($r,$r['_status']??200); }
    if($route==='resource-limit-set') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/resources/limits',['owner'=>(string)($d['owner']??''),'cpu_percent'=>(int)($d['cpu_percent']??100),'memory_mb'=>(int)($d['memory_mb']??1024),'pids'=>(int)($d['pids']??128),'io_weight'=>(int)($d['io_weight']??100),'disk_gb'=>(int)($d['disk_gb']??10),'bandwidth_gb'=>(int)($d['bandwidth_gb']??100)]);out($r,$r['_status']??200); }
    if($route==='migration-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/migrations',['source'=>(string)($d['source']??''),'source_type'=>(string)($d['source_type']??'cpanel'),'account'=>(string)($d['account']??''),'destination'=>(string)($d['destination']??'local')]);out($r,$r['_status']??200); }
    if($route==='api-key-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$owner=strtolower(trim((string)($d['owner']??'')));if($owner!=='')requireAdminAccountScope($user,$client,$owner);$scopes=array_values(array_map('strval',(array)($d['scopes']??[])));$cidrs=$d['allowed_cidrs']??[];if(is_string($cidrs))$cidrs=preg_split('/\s*,\s*/',$cidrs,-1,PREG_SPLIT_NO_EMPTY);$payload=['name'=>(string)($d['name']??''),'owner'=>$owner,'scopes'=>$scopes,'allowed_cidrs'=>array_values(array_map('strval',(array)$cidrs))];$expires=trim((string)($d['expires_at']??''));if($expires!==''){try{$payload['expires_at']=(new DateTimeImmutable($expires))->format(DATE_RFC3339);}catch(Throwable $e){out(['error'=>'Invalid API token expiry'],400);}}$r=$client->post('/v1/api-keys',$payload);out($r,$r['_status']??200); }
    if($route==='webhook-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$events=(array)($d['events']??[]);$r=$client->post('/v1/webhooks',['url'=>(string)($d['url']??''),'events'=>$events]);out($r,$r['_status']??200); }
    if($route==='host-plan') { mutationGuard($auth,'server.read');$d=bodyJson();$r=$client->post('/v1/host/plans',$d);out($r,$r['_status']??200); }
    if($route==='cluster-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/clusters',['kind'=>(string)($d['kind']??'dns'),'name'=>(string)($d['name']??''),'nodes'=>(array)($d['nodes']??[]),'mode'=>(string)($d['mode']??'active-active')]);out($r,$r['_status']??200); }
    if($route==='lb-create') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/load-balancers',['name'=>(string)($d['name']??''),'region'=>(string)($d['region']??''),'backends'=>(array)($d['backends']??[]),'algorithm'=>(string)($d['algorithm']??'round-robin')]);out($r,$r['_status']??200); }
    if($route==='plugin-install') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/plugins',['name'=>(string)($d['name']??''),'version'=>(string)($d['version']??'1.0.0'),'type'=>(string)($d['type']??'app')]);out($r,$r['_status']??200); }
    if($route==='invoice-create') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/billing/invoices',['customer'=>(string)($d['customer']??''),'amount_cents'=>(int)($d['amount_cents']??0),'currency'=>(string)($d['currency']??'USD')]);out($r,$r['_status']??200); }
    if($route==='diagnostic-run') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/diagnostics',['scope'=>(string)($d['scope']??'server')]);out($r,$r['_status']??200); }
    if($route==='repair-run') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/repairs',['resource'=>(string)($d['resource']??'nginx'),'action'=>(string)($d['action']??'reload')]);out($r,$r['_status']??200); }
    if($route==='export-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/exports',['account'=>(string)($d['account']??''),'encrypted'=>(bool)($d['encrypted']??true)]);out($r,$r['_status']??200); }
    if($route==='staging-create') { mutationGuard($auth,'resources.write');$d=bodyJson();$r=$client->post('/v1/staging',['production_domain'=>(string)($d['production_domain']??''),'staging_domain'=>(string)($d['staging_domain']??''),'owner'=>(string)($d['owner']??'')]);out($r,$r['_status']??200); }
    if($route==='certification-record') { mutationGuard($auth,'platform.simulate');$d=bodyJson();$r=$client->post('/v1/certification',['name'=>(string)($d['name']??''),'status'=>(string)($d['status']??'blocked'),'evidence'=>(array)($d['evidence']??[]),'blockers'=>(array)($d['blockers']??[])]);out($r,$r['_status']??200); }

    // 6.91-7.0 PCC operational workflows.
    if($route==='mail-queue') { $auth->requirePermission('server.read');requireRootAdministrator($user);$r=$client->getLong('/v1/mail/queue',30);out($r,$r['_status']??200); }
    if(in_array($route,['mail-queue-retry','mail-queue-delete'],true)) { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$id=(string)($d['id']??'');if(!preg_match('/^[A-Fa-f0-9*!]{5,32}$/',$id))out(['error'=>'Invalid Postfix queue ID'],400);$r=$route==='mail-queue-retry'?$client->post('/v1/mail/queue/'.rawurlencode($id).'/retry',[]):$client->delete('/v1/mail/queue/'.rawurlencode($id));out($r,$r['_status']??200); }
    if($route==='mail-delivery') { $auth->requirePermission('server.read');requireRootAdministrator($user);$q=(string)($_GET['query']??'');$r=$client->getLong('/v1/mail/delivery?query='.rawurlencode($q).'&limit=300',30);out($r,$r['_status']??200); }
    if($route==='mail-filters') { $auth->requirePermission('hosting.read');$r=$client->get('/v1/mail/filters');$scope=adminResellerScope($user);if($scope!==null)$r['filters']=array_values(array_filter((array)($r['filters']??[]),fn($f)=>strtolower((string)($f['owner']??''))===$scope));out($r,$r['_status']??200); }
    if($route==='mail-filter-save') { mutationGuard($auth,'resources.write');$d=bodyJson();$address=strtolower(trim((string)($d['address']??'')));$domain=str_contains($address,'@')?substr(strrchr($address,'@'),1):'';$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Mailbox domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$r=$client->postLong('/v1/mail/filters',['id'=>(string)($d['id']??''),'owner'=>$owner,'address'=>$address,'name'=>(string)($d['name']??''),'field'=>(string)($d['field']??'from'),'operator'=>(string)($d['operator']??'contains'),'value'=>(string)($d['value']??''),'action'=>(string)($d['action']??'fileinto'),'destination'=>(string)($d['destination']??''),'enabled'=>true],30);out($r,$r['_status']??200); }
    if($route==='mail-filter-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/mail/filters');$target=null;foreach(($all['filters']??[]) as $f){if((string)($f['id']??'')===$id){$target=$f;break;}}if(!$target)out(['error'=>'Filter not found'],404);requireAdminAccountScope($user,$client,(string)($target['owner']??''));$r=$client->delete('/v1/mail/filters/'.rawurlencode($id));out($r,$r['_status']??200); }
    if($route==='backup-policies') { $auth->requirePermission('hosting.read');$r=$client->get('/v1/backup/policies');$scope=adminResellerScope($user);if($scope!==null)$r['policies']=array_values(array_filter((array)($r['policies']??[]),fn($x)=>strtolower((string)($x['owner']??''))===$scope));out($r,$r['_status']??200); }
    if($route==='backup-policy-save') { mutationGuard($auth,'resources.write');$d=bodyJson();$owner=strtolower(trim((string)($d['owner']??'')));if($owner!=='')requireAdminAccountScope($user,$client,$owner);elseif(adminResellerScope($user)!==null)out(['error'=>'Reseller backup policies must belong to an account'],403);$destination=(string)($d['destination']??'local');if($destination!=='local')out(['error'=>'Remote backup transport is not configured through this control surface yet. Use local until a certified transport is configured.'],409);$r=$client->post('/v1/backup/policies',['id'=>(string)($d['id']??''),'owner'=>$owner,'scope'=>(string)($d['scope']??'site'),'resource'=>(string)($d['resource']??''),'destination'=>'local','schedule'=>(string)($d['schedule']??'daily'),'retention'=>(int)($d['retention']??14),'verify'=>(bool)($d['verify']??true),'enabled'=>true]);out($r,$r['_status']??200); }
    if($route==='backup-policy-run') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->postLong('/v1/backup/policies/'.rawurlencode((string)($d['id']??'')).'/run',[],180);out($r,$r['_status']??200); }
    if($route==='backup-policy-delete') { mutationGuard($auth,'resources.write');$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/backup/policies');$target=null;foreach(($all['policies']??[]) as $x){if((string)($x['id']??'')===$id){$target=$x;break;}}if(!$target)out(['error'=>'Backup policy not found'],404);if(($target['owner']??'')!=='')requireAdminAccountScope($user,$client,(string)$target['owner']);elseif(adminResellerScope($user)!==null)out(['error'=>'Backup policy is outside reseller scope'],403);$r=$client->delete('/v1/backup/policies/'.rawurlencode($id));out($r,$r['_status']??200); }
    if($route==='backup-verify') { mutationGuard($auth,'resources.write');$d=bodyJson();$id=(string)($d['id']??'');if(adminResellerScope($user)!==null)out(['error'=>'Backup verification for reseller sessions requires an account-scoped PPanel operation'],403);$r=$client->postLong('/v1/backups/'.rawurlencode($id).'/verify',[],120);out($r,$r['_status']??200); }
    if($route==='api-keys') { $auth->requirePermission('resources.write');$r=$client->get('/v1/api-keys');$scope=adminResellerScope($user);if($scope!==null){$accounts=filterAdminAccounts($user,$client->get('/v1/hosting/accounts')['accounts']??[]);$owners=array_map(fn($a)=>strtolower((string)($a['username']??'')),$accounts);$r['api_keys']=array_values(array_filter((array)($r['api_keys']??[]),fn($k)=>in_array(strtolower((string)($k['owner']??'')),$owners,true)));}out($r,$r['_status']??200); }
    if(in_array($route,['api-key-revoke','api-key-rotate'],true)) { mutationGuard($auth,'resources.write');$d=bodyJson();$id=(string)($d['id']??'');$all=$client->get('/v1/api-keys');$target=null;foreach(($all['api_keys']??[]) as $k){if((string)($k['id']??'')===$id){$target=$k;break;}}if(!$target)out(['error'=>'API token not found'],404);$owner=(string)($target['owner']??'');if($owner!=='')requireAdminAccountScope($user,$client,$owner);elseif(adminResellerScope($user)!==null)out(['error'=>'Server-wide API token is outside reseller scope'],403);$r=$route==='api-key-revoke'?$client->delete('/v1/api-keys/'.rawurlencode($id)):$client->post('/v1/api-keys/'.rawurlencode($id).'/rotate',[]);out($r,$r['_status']??200); }
    if($route==='monitoring-live') { $auth->requirePermission('server.read');requireRootAdministrator($user);$r=$client->getLong('/v1/monitoring/live?capture=1',30);out($r,$r['_status']??200); }
    if($route==='alert-delete') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->delete('/v1/monitoring/alerts/'.rawurlencode((string)($d['id']??'')));out($r,$r['_status']??200); }
    if($route==='incident-resolve') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->post('/v1/monitoring/incidents/'.rawurlencode((string)($d['id']??'')).'/resolve',[]);out($r,$r['_status']??200); }
    if($route==='security-advisor') { $auth->requirePermission('server.read');requireRootAdministrator($user);$r=$client->getLong('/v1/security/advisor',30);out($r,$r['_status']??200); }
    if($route==='security-advisor-fix') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->postLong('/v1/security/advisor/fix',['fix'=>(string)($d['fix']??'')],60);out($r,$r['_status']??200); }
    if($route==='site-policies') { $auth->requirePermission('hosting.read');$r=$client->get('/v1/sites/policies');$scope=adminResellerScope($user);if($scope!==null){$accounts=filterAdminAccounts($user,$client->get('/v1/hosting/accounts')['accounts']??[]);$owners=array_map(fn($a)=>strtolower((string)($a['username']??'')),$accounts);$r['policies']=array_values(array_filter((array)($r['policies']??[]),fn($p)=>in_array(strtolower((string)($p['owner']??'')),$owners,true)));}out($r,$r['_status']??200); }
    if($route==='site-policy-save') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Website domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$r=$client->postLong('/v1/sites/'.rawurlencode($domain).'/policy',['owner'=>$owner,'force_https'=>(bool)($d['force_https']??false),'hsts'=>(bool)($d['hsts']??false),'hsts_max_age'=>(int)($d['hsts_max_age']??15552000),'redirect_target'=>(string)($d['redirect_target']??''),'directory_index'=>(string)($d['directory_index']??'index.php index.html index.htm'),'hotlink_protection'=>(bool)($d['hotlink_protection']??false)],60);out($r,$r['_status']??200); }
    if($route==='database-activity') { $auth->requirePermission('server.read');requireRootAdministrator($user);$engine=(string)($_GET['engine']??'mariadb');$r=$client->get('/v1/databases/activity?engine='.rawurlencode($engine));out($r,$r['_status']??200); }
    if($route==='database-session-kill') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->post('/v1/databases/activity/'.rawurlencode((string)($d['id']??'')).'/kill',['engine'=>(string)($d['engine']??'mariadb')]);out($r,$r['_status']??200); }
    if($route==='apps-discover') { $auth->requirePermission('hosting.read');$r=$client->getLong('/v1/apps/discover',30);$scope=adminResellerScope($user);if($scope!==null){$accounts=filterAdminAccounts($user,$client->get('/v1/hosting/accounts')['accounts']??[]);$owners=array_map(fn($a)=>strtolower((string)($a['username']??'')),$accounts);$r['applications']=array_values(array_filter((array)($r['applications']??[]),fn($a)=>in_array(strtolower((string)($a['owner']??'')),$owners,true)));}out($r,$r['_status']??200); }
    if($route==='app-action') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$owner=hostingOwnerForDomain($client,$domain);if($owner==='')out(['error'=>'Application domain is not assigned to a hosting account'],409);requireAdminAccountScope($user,$client,$owner);$r=$client->postLong('/v1/apps/'.rawurlencode($domain).'/action',['action'=>(string)($d['action']??'status')],60);out($r,$r['_status']??200); }
    if($route==='dnssec-status') { $auth->requirePermission('hosting.read');$domain=strtolower(trim((string)($_GET['domain']??'')));$owner=hostingOwnerForDomain($client,$domain);if($owner!=='')requireAdminAccountScope($user,$client,$owner);$r=$client->get('/v1/dns/zones/'.rawurlencode($domain).'/dnssec');out($r,$r['_status']??200); }
    if($route==='dnssec-set') { mutationGuard($auth,'resources.write');$d=bodyJson();$domain=strtolower(trim((string)($d['domain']??'')));$owner=hostingOwnerForDomain($client,$domain);if($owner!=='')requireAdminAccountScope($user,$client,$owner);$r=$client->postLong('/v1/dns/zones/'.rawurlencode($domain).'/dnssec',['enabled'=>(bool)($d['enabled']??false)],60);out($r,$r['_status']??200); }
    if($route==='dns-templates') { $auth->requirePermission('server.read');requireRootAdministrator($user);$r=$client->get('/v1/dns/templates');out($r,$r['_status']??200); }
    if($route==='dns-template-save') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->post('/v1/dns/templates',['id'=>(string)($d['id']??''),'name'=>(string)($d['name']??''),'records'=>(array)($d['records']??[])]);out($r,$r['_status']??200); }
    if($route==='dns-template-delete') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->delete('/v1/dns/templates/'.rawurlencode((string)($d['id']??'')));out($r,$r['_status']??200); }
    if($route==='dns-template-apply') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->postLong('/v1/dns/templates/'.rawurlencode((string)($d['id']??'')).'/apply',['domain'=>(string)($d['domain']??'')],60);out($r,$r['_status']??200); }
    if($route==='readiness') { $auth->requirePermission('server.read');requireRootAdministrator($user);$r=$client->getLong('/v1/readiness',30);out($r,$r['_status']??200); }
    if($route==='readiness-history') { $auth->requirePermission('server.read');requireRootAdministrator($user);$r=$client->get('/v1/readiness/history');out($r,$r['_status']??200); }
    if($route==='readiness-repair') { mutationGuard($auth,'resources.write');requireRootAdministrator($user);$d=bodyJson();$r=$client->postLong('/v1/readiness/repair',['action'=>(string)($d['action']??'')],180);out($r,$r['_status']??200); }

    if($route==='events') { $auth->requirePermission('audit.read'); out(['events'=>$store->events()]); }
    out(['error'=>'Unknown route'],404);
} catch (Throwable $e) {
    $status=http_response_code(); if($status<400)$status=503; out(['error'=>$e->getMessage()],$status);
}
