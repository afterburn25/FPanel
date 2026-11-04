<?php

declare(strict_types=1);

require_once __DIR__.'/../panel/src/AgentClient.php';

$token = getenv('PRIVORA_AGENT_TOKEN') ?: '';
$socket = getenv('PRIVORA_AGENT_SOCKET') ?: '/run/privora-panel/agent.sock';
if ($token === '') {
    fwrite(STDERR, "Privora AutoSSL retry: agent token unavailable\n");
    exit(2);
}
try {
    $client = new AgentClient($socket, $token, 'system:autossl-retry');
    $result = $client->postLong('/v1/ssl/autossl', [], 90);
    $issued = (int)($result['issued'] ?? 0);
    $skipped = (int)($result['skipped'] ?? 0);
    $failed = (int)($result['failed'] ?? 0);
    fwrite(STDOUT, "Privora AutoSSL retry: issued={$issued} skipped={$skipped} failed={$failed}\n");
    // A partial ACME failure is expected while DNS is propagating. Do not make
    // systemd mark the retry service failed; the next timer run will retry.
    exit(0);
} catch (Throwable $e) {
    fwrite(STDERR, "Privora AutoSSL retry unavailable: ".$e->getMessage()."\n");
    exit(1);
}
