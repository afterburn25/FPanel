<?php

declare(strict_types=1);

final class AgentClient
{
    public function __construct(private readonly string $socketPath, private readonly string $token, private readonly string $actor = 'panel') {}
    public function get(string $path): array { return $this->request('GET',$path,null,20); }
    public function getLong(string $path, int $timeout = 60): array { return $this->request('GET',$path,null,max(20,min(600,$timeout))); }
    public function post(string $path, ?array $payload = null): array { return $this->request('POST',$path,$payload,5); }
    public function postLong(string $path, ?array $payload = null, int $timeout = 45): array { return $this->request('POST',$path,$payload,max(5,min(600,$timeout))); }
    public function patch(string $path, ?array $payload = null): array { return $this->request('PATCH',$path,$payload,20); }
    public function delete(string $path, ?array $payload = null): array { return $this->request('DELETE',$path,$payload,20); }
    public function deleteLong(string $path, ?array $payload = null, int $timeout = 60): array { return $this->request('DELETE',$path,$payload,max(20,min(600,$timeout))); }

    private function request(string $method, string $path, ?array $payload, int $timeout = 5): array
    {
        if (!str_starts_with($path,'/v1/')) { throw new InvalidArgumentException('Agent path must use /v1/.'); }
        if ($this->token === '') { throw new RuntimeException('Agent token is not configured.'); }
        $socket = false; $errno = 0; $errstr = '';
        // The agent is deliberately refreshed after a successful core update. During
        // the systemd handoff the Unix socket can disappear briefly. Retrying only
        // the *connection establishment* is safe for both reads and mutations because
        // no HTTP request has been sent until a socket is acquired.
        for ($attempt = 1; $attempt <= 12; $attempt++) {
            $socket = @stream_socket_client('unix://'.$this->socketPath,$errno,$errstr,0.35);
            if ($socket !== false) { break; }
            if ($attempt < 12) { usleep(250000); }
        }
        if ($socket === false) { throw new RuntimeException("Agent unavailable after retry: {$errstr} ({$errno})"); }
        stream_set_timeout($socket,$timeout);
        $body = $payload === null ? '' : json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
        $requestId = bin2hex(random_bytes(8));
        $timestamp = gmdate('Y-m-d\TH:i:s\Z');
        $nonce = bin2hex(random_bytes(16));
        $bodyHash = hash('sha256', $body);
        $signatureInput = $method."\n".$path."\n".$timestamp."\n".$nonce."\n".$bodyHash;
        $signature = hash_hmac('sha256', $signatureInput, $this->token);
        $headers = [
            $method.' '.$path.' HTTP/1.1', 'Host: localhost', 'Connection: close',
            'X-Privora-Timestamp: '.$timestamp,
            'X-Privora-Nonce: '.$nonce,
            'X-Privora-Signature: '.$signature,
            'X-Privora-Actor: '.preg_replace('/[^A-Za-z0-9_.:@-]/','_',substr($this->actor,0,90)),
            'X-Privora-Request-ID: '.$requestId,
            'Content-Type: application/json', 'Content-Length: '.strlen($body), '', ''
        ];
        fwrite($socket, implode("\r\n",$headers).$body);
        $raw = stream_get_contents($socket); $meta = stream_get_meta_data($socket); fclose($socket);
        if (($meta['timed_out'] ?? false) === true) { throw new RuntimeException('Agent response timed out before completion.'); }
        [$head,$responseBody] = array_pad(explode("\r\n\r\n",$raw,2),2,'');
        if (!preg_match('#HTTP/1\\.[01] (\\d{3})#',$head,$m)) { throw new RuntimeException('Invalid response from agent.'); }
        if (preg_match('/(?:^|\r\n)Transfer-Encoding:\s*chunked(?:\r\n|$)/i', $head)) {
            $responseBody = self::decodeChunked($responseBody);
        }
        $status=(int)$m[1]; $decoded=json_decode($responseBody,true);
        if (!is_array($decoded)) { throw new RuntimeException('Agent returned invalid JSON.'); }
        $decoded['_status']=$status; return $decoded;
    }

    private static function decodeChunked(string $body): string
    {
        $out=''; $offset=0; $length=strlen($body);
        while ($offset < $length) {
            $lineEnd=strpos($body,"\r\n",$offset);
            if ($lineEnd===false) { throw new RuntimeException('Malformed chunked agent response.'); }
            $sizeLine=trim(substr($body,$offset,$lineEnd-$offset));
            $semi=strpos($sizeLine,';');
            if($semi!==false){$sizeLine=substr($sizeLine,0,$semi);}
            if ($sizeLine==='' || !ctype_xdigit($sizeLine)) { throw new RuntimeException('Malformed chunk size from agent.'); }
            $size=hexdec($sizeLine); $offset=$lineEnd+2;
            if ($size===0) { return $out; }
            if ($offset+$size+2>$length) { throw new RuntimeException('Truncated chunked agent response.'); }
            $out.=substr($body,$offset,$size); $offset+=$size;
            if (substr($body,$offset,2)!=="\r\n") { throw new RuntimeException('Malformed chunk delimiter from agent.'); }
            $offset+=2;
        }
        throw new RuntimeException('Chunked agent response missing terminator.');
    }
}
