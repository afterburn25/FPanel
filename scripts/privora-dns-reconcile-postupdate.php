<?php

declare(strict_types=1);
require '/opt/privora-panel/panel/src/AgentClient.php';

$socket=getenv('PRIVORA_AGENT_SOCKET') ?: '/run/privora-panel/agent.sock';
$token=getenv('PRIVORA_AGENT_TOKEN') ?: '';
$resultPath='/var/lib/privora-panel/dns-reconcile-last.json';
$persist=static function(array $row) use ($resultPath): void {
    $row['ran_at']=gmdate('c');
    @file_put_contents($resultPath,json_encode($row,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n",LOCK_EX);
};
if($token===''){
    $persist(['ok'=>false,'stage'=>'preflight','error'=>'Privora agent token is unavailable.']);
    fwrite(STDERR,"Privora agent token is unavailable.\n");exit(2);
}

// Wait for the *healthy agent*, not merely for the socket pathname. systemd can
// create/remove the Unix socket while the agent process is still transitioning.
$deadline=microtime(true)+90.0;
$client=null; $lastError='agent not ready';
while(microtime(true)<$deadline){
    try{
        if(!file_exists($socket)){throw new RuntimeException('agent socket not present');}
        $probe=new AgentClient($socket,$token,'system:postupdate-dns-reconcile');
        $health=$probe->get('/v1/health');
        $status=(int)($health['_status']??500);
        if($status>=200 && $status<300){$client=$probe;break;}
        $lastError='agent health returned HTTP '.$status;
    }catch(Throwable $e){$lastError=$e->getMessage();}
    usleep(500000);
}
if(!$client){
    $persist(['ok'=>false,'stage'=>'agent-readiness','error'=>$lastError]);
    fwrite(STDERR,"Privora agent did not become healthy: {$lastError}\n");exit(3);
}

// The repair itself can be temporarily rejected immediately after service
// activation while BIND/systemd settle. Retry the repair operation when the
// agent connection or service-readiness path is transient, but persist the last
// response so the PCC can show a real per-domain reason rather than NOT CONFIGURED.
$repairDeadline=microtime(true)+120.0;
$last=[]; $lastError='';
while(microtime(true)<$repairDeadline){
    try{
        $r=$client->postLong('/v1/dns/repair-hosted',[],90);
        $status=(int)($r['_status']??500); unset($r['_status']);
        $last=$r; $last['http_status']=$status;
        if($status<300){
            $last['ok']=true; $last['stage']='complete'; $persist($last);
            echo 'PASS: hosted DNS reconciliation scanned '.(int)($r['scanned']??0).' site(s), managed '.(int)($r['repaired']??0).', action required '.(int)($r['action_required']??0).".\n";
            exit(0);
        }
        $lastError='repair endpoint returned HTTP '.$status;
    }catch(Throwable $e){$lastError=$e->getMessage();}
    usleep(1000000);
}
if(!$last){$last=['http_status'=>503];}
$last['ok']=false; $last['stage']='repair'; $last['error']=$lastError ?: 'hosted DNS reconciliation did not complete';
$persist($last);
fwrite(STDERR,"Hosted DNS reconciliation failed: ".json_encode($last,JSON_UNESCAPED_SLASHES)."\n");
exit(4);
