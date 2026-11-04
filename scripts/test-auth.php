<?php

declare(strict_types=1);
require dirname(__DIR__).'/panel/src/Totp.php';

$known = Totp::code('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1);
if ($known !== '287082') { fwrite(STDERR, "TOTP vector failed: {$known}\n"); exit(1); }
putenv('PRIVORA_PANEL_ENCRYPTION_KEY=development-test-key-that-is-at-least-32-bytes-long');
$cipher = SecretBox::encrypt('mfa-secret');
if ($cipher === 'mfa-secret' || SecretBox::decrypt($cipher) !== 'mfa-secret') { fwrite(STDERR, "SecretBox round-trip failed\n"); exit(1); }
echo "Auth crypto tests PASS\n";
