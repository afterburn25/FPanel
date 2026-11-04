<?php

declare(strict_types=1);
require __DIR__.'/../src/bootstrap.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

function apiOut(array $body, int $status=200): never
{
    unset($body['_status']);
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    exit;
}
function apiBody(): array
{
    $raw=file_get_contents('php://input');
    if($raw===false||$raw==='') return [];
    $d=json_decode($raw,true);
    if(!is_array($d)) apiOut(['error'=>'Invalid JSON'],400);
    return $d;
}
function requireScope(array $scopes,string $scope): void
{
    if(!in_array($scope,$scopes,true)) apiOut(['error'=>'API key lacks required scope','required_scope'=>$scope],403);
}

$authorization=(string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
if(!preg_match('/^Bearer\s+(.+)$/i',$authorization,$m)) apiOut(['error'=>'Bearer API key required'],401);
$rawKey=trim($m[1]);
if(!str_starts_with($rawKey,'prv_')||strlen($rawKey)>128) apiOut(['error'=>'Invalid API key'],401);
$socket=getenv('PRIVORA_AGENT_SOCKET') ?: '/run/privora-panel/agent.sock';
$agentToken=getenv('PRIVORA_AGENT_TOKEN') ?: '';
try {
    $bootstrapClient=new AgentClient($socket,$agentToken,'external-api:bootstrap');
    $verified=$bootstrapClient->post('/v1/api-keys/verify',['token'=>$rawKey,'ip'=>(string)($_SERVER['REMOTE_ADDR']??'')]);
    if(($verified['_status']??500)!==200) apiOut(['error'=>'Invalid API key'],401);
    $key=$verified['api_key']??[]; $scopes=array_values(array_filter((array)($key['scopes']??[]),'is_string'));
    $prefix=(string)($key['prefix']??'unknown');
    $owner=strtolower(trim((string)($key['owner']??'')));
    $client=new AgentClient($socket,$agentToken,'api:'.$prefix);
    $resource=strtolower((string)($_GET['resource']??'health'));
    $method=$_SERVER['REQUEST_METHOD'] ?? 'GET';
    if($method==='GET') {
        if($resource==='health'){requireScope($scopes,'health.read');$r=$client->get('/v1/health');apiOut($r,$r['_status']??200);}
        if($resource==='accounts'){requireScope($scopes,'accounts.read');$r=$client->get('/v1/hosting/accounts');if($owner!=='')$r['accounts']=array_values(array_filter((array)($r['accounts']??[]),fn($a)=>strtolower((string)($a['username']??''))===$owner));apiOut($r,$r['_status']??200);}
        if($resource==='sites'){requireScope($scopes,'sites.read');$r=$client->get('/v1/sites');if($owner!=='')$r['sites']=array_values(array_filter((array)($r['sites']??[]),fn($x)=>strtolower((string)($x['username']??''))===$owner));apiOut($r,$r['_status']??200);}
        if($resource==='resources'){requireScope($scopes,'resources.read');$r=$owner!==''?$client->get('/v1/hosting/accounts/'.rawurlencode($owner).'/usage'):$client->get('/v1/resources/summary');apiOut($r,$r['_status']??200);}
        if($resource==='backups'){requireScope($scopes,'backups.read');$r=$client->get('/v1/backups');if($owner!==''){ $sites=$client->get('/v1/sites');$domains=[];foreach(($sites['sites']??[]) as $x){if(strtolower((string)($x['username']??''))===$owner)$domains[]=strtolower((string)($x['domain']??''));}$r['backups']=array_values(array_filter((array)($r['backups']??[]),fn($b)=>strtolower((string)($b['resource']??''))===$owner||in_array(strtolower((string)($b['resource']??'')),$domains,true)));}apiOut($r,$r['_status']??200);}
        if($resource==='dns'){requireScope($scopes,'dns.read');$r=$client->get('/v1/dns/zones');if($owner!==''){ $sites=$client->get('/v1/sites');$domains=[];foreach(($sites['sites']??[]) as $x){if(strtolower((string)($x['username']??''))===$owner)$domains[]=strtolower((string)($x['domain']??''));}$r['zones']=array_values(array_filter((array)($r['zones']??[]),fn($z)=>in_array(strtolower((string)($z['domain']??'')),$domains,true)));}apiOut($r,$r['_status']??200);}
        if($resource==='mail'){requireScope($scopes,'mail.read');$r=$client->get('/v1/mailboxes');if($owner!==''){ $sites=$client->get('/v1/sites');$domains=[];foreach(($sites['sites']??[]) as $x){if(strtolower((string)($x['username']??''))===$owner)$domains[]=strtolower((string)($x['domain']??''));}$r['mailboxes']=array_values(array_filter((array)($r['mailboxes']??[]),fn($m)=>in_array(strtolower((string)($m['domain']??'')),$domains,true)));}apiOut($r,$r['_status']??200);}
        if($resource==='monitoring'){requireScope($scopes,'monitoring.read');$r=$owner!==''?$client->get('/v1/hosting/accounts/'.rawurlencode($owner).'/usage'):$client->get('/v1/monitoring/live?capture=1');apiOut($r,$r['_status']??200);}
        if($resource==='security'){requireScope($scopes,'security.read');if($owner!=='')apiOut(['error'=>'Server security advisor is not exposed to account-scoped keys'],403);$r=$client->get('/v1/security/advisor');apiOut($r,$r['_status']??200);}
        if($resource==='databases'){requireScope($scopes,'databases.read');$r=$client->get('/v1/databases');if($owner!=='')$r['databases']=array_values(array_filter((array)($r['databases']??[]),fn($d)=>strtolower((string)($d['owner']??''))===$owner));apiOut($r,$r['_status']??200);}
        if($resource==='horizons'){requireScope($scopes,'health.read');$r=$client->get('/v1/horizons');apiOut($r,$r['_status']??200);}
        apiOut(['error'=>'Unknown API resource'],404);
    }
    if($method==='POST') {
        $d=apiBody();
        $ownedDomains=[]; if($owner!==''){ $sites=$client->get('/v1/sites');foreach(($sites['sites']??[]) as $x){if(strtolower((string)($x['username']??''))===$owner)$ownedDomains[]=strtolower((string)($x['domain']??''));}}
        if($resource==='accounts'){requireScope($scopes,'accounts.write');if($owner!=='')apiOut(['error'=>'Account-scoped API keys cannot create hosting accounts'],403);$r=$client->post('/v1/hosting/accounts',['username'=>(string)($d['username']??''),'primary_domain'=>(string)($d['primary_domain']??''),'package'=>(string)($d['package']??'Starter')]);apiOut($r,$r['_status']??200);}
        if($resource==='sites'){requireScope($scopes,'sites.write');$targetOwner=strtolower((string)($d['username']??$owner));if($owner!==''&&$targetOwner!==$owner)apiOut(['error'=>'Site owner is outside API key scope'],403);$r=$client->post('/v1/sites',['domain'=>(string)($d['domain']??''),'username'=>$targetOwner,'php_version'=>(string)($d['php_version']??'8.4')]);apiOut($r,$r['_status']??200);}
        if($resource==='backups'){requireScope($scopes,'backups.write');$res=strtolower((string)($d['resource']??''));if($owner!==''&&$res!==$owner&&!in_array($res,$ownedDomains,true))apiOut(['error'=>'Backup target is outside API key scope'],403);$r=$client->post('/v1/backups',['scope'=>(string)($d['scope']??'site'),'resource'=>$res,'destination'=>'local']);apiOut($r,$r['_status']??200);}
        if($resource==='dns'){requireScope($scopes,'dns.write');$domain=strtolower((string)($d['domain']??''));if($owner!==''&&!in_array($domain,$ownedDomains,true))apiOut(['error'=>'DNS domain is outside API key scope'],403);$r=$client->post('/v1/dns/zones',['domain'=>$domain,'dnssec'=>(bool)($d['dnssec']??false)]);apiOut($r,$r['_status']??200);}
        if($resource==='dynamic-dns'){requireScope($scopes,'dns.write');$domain=strtolower(trim((string)($d['domain']??'')));$name=trim((string)($d['name']??'@'));$ip=trim((string)($d['ip']??($_SERVER['REMOTE_ADDR']??'')));if($owner!==''&&!in_array($domain,$ownedDomains,true))apiOut(['error'=>'DNS domain is outside API key scope'],403);if(!filter_var($ip,FILTER_VALIDATE_IP))apiOut(['error'=>'A valid IPv4 or IPv6 address is required'],400);if($name===''||strlen($name)>253||!preg_match('/^(?:@|\*|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)$/',$name))apiOut(['error'=>'Invalid Dynamic DNS host name'],400);$type=str_contains($ip,':')?'AAAA':'A';$ttl=(int)($d['ttl']??300);$ttl=max(60,min(86400,$ttl));$r=$client->post('/v1/dns/zones/'.rawurlencode($domain).'/records',['type'=>$type,'name'=>$name,'value'=>$ip,'ttl'=>$ttl]);if(($r['_status']??500)<300)$r['dynamic_dns']=['domain'=>$domain,'name'=>$name,'type'=>$type,'value'=>$ip,'ttl'=>$ttl];apiOut($r,$r['_status']??200);}
        if($resource==='ssl'){requireScope($scopes,'ssl.write');$domain=strtolower((string)($d['domain']??''));if($owner!==''&&!in_array($domain,$ownedDomains,true))apiOut(['error'=>'SSL domain is outside API key scope'],403);$r=$client->post('/v1/ssl/issue',['domain'=>$domain]);apiOut($r,$r['_status']??200);}
        apiOut(['error'=>'Unknown API resource'],404);
    }
    apiOut(['error'=>'Method not allowed'],405);
} catch(Throwable $e) {
    apiOut(['error'=>$e->getMessage()],503);
}
