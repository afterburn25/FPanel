<?php

declare(strict_types=1);

final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(int $bytes = 20): string
    {
        if ($bytes < 16 || $bytes > 64) { throw new InvalidArgumentException('Invalid TOTP secret size.'); }
        return self::base32Encode(random_bytes($bytes));
    }

    public static function verify(string $secret, string $code, int $window = 1, ?int $time = null): bool
    {
        $code = preg_replace('/\D/', '', $code) ?? '';
        if (!preg_match('/^\d{6}$/', $code)) { return false; }
        $counter = intdiv($time ?? time(), 30);
        for ($offset = -$window; $offset <= $window; $offset++) {
            if (hash_equals(self::code($secret, $counter + $offset), $code)) { return true; }
        }
        return false;
    }

    public static function code(string $secret, int $counter): string
    {
        $key = self::base32Decode($secret);
        $high = intdiv($counter, 0x100000000);
        $low = $counter & 0xffffffff;
        $binaryCounter = pack('N2', $high, $low);
        $hash = hash_hmac('sha1', $binaryCounter, $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24)
            | ((ord($hash[$offset + 1]) & 0xff) << 16)
            | ((ord($hash[$offset + 2]) & 0xff) << 8)
            | (ord($hash[$offset + 3]) & 0xff);
        return str_pad((string)($value % 1_000_000), 6, '0', STR_PAD_LEFT);
    }

    public static function otpauthUri(string $issuer, string $account, string $secret): string
    {
        $label = rawurlencode($issuer . ':' . $account);
        return 'otpauth://totp/' . $label . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    }

    private static function base32Encode(string $data): string
    {
        $buffer = 0; $bits = 0; $out = '';
        foreach (unpack('C*', $data) as $byte) {
            $buffer = ($buffer << 8) | $byte; $bits += 8;
            while ($bits >= 5) { $bits -= 5; $out .= self::ALPHABET[($buffer >> $bits) & 31]; }
        }
        if ($bits > 0) { $out .= self::ALPHABET[($buffer << (5 - $bits)) & 31]; }
        return $out;
    }

    private static function base32Decode(string $text): string
    {
        $text = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $text) ?? '');
        $buffer = 0; $bits = 0; $out = '';
        foreach (str_split($text) as $char) {
            $value = strpos(self::ALPHABET, $char);
            if ($value === false) { throw new InvalidArgumentException('Invalid base32 secret.'); }
            $buffer = ($buffer << 5) | $value; $bits += 5;
            if ($bits >= 8) { $bits -= 8; $out .= chr(($buffer >> $bits) & 0xff); }
        }
        return $out;
    }
}

final class SecretBox
{
    public static function available(): bool
    {
        return strlen((string)getenv('PRIVORA_PANEL_ENCRYPTION_KEY')) >= 32;
    }

    private static function key(): string
    {
        $raw = (string)getenv('PRIVORA_PANEL_ENCRYPTION_KEY');
        if (strlen($raw) < 32) { throw new RuntimeException('PRIVORA_PANEL_ENCRYPTION_KEY must be at least 32 characters before MFA can be enabled.'); }
        return hash('sha256', $raw, true);
    }

    public static function encrypt(string $plaintext): string
    {
        $key = self::key();
        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
            return 'sb1:' . base64_encode($nonce . $cipher);
        }
        $nonce = random_bytes(12); $tag = '';
        $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        if ($cipher === false) { throw new RuntimeException('Unable to encrypt panel secret.'); }
        return 'gcm1:' . base64_encode($nonce . $tag . $cipher);
    }

    public static function decrypt(string $encoded): string
    {
        $key = self::key();
        if (str_starts_with($encoded, 'sb1:')) {
            $raw = base64_decode(substr($encoded, 4), true);
            if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) { throw new RuntimeException('Invalid encrypted secret.'); }
            $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $key);
            if ($plain === false) { throw new RuntimeException('Unable to decrypt panel secret.'); }
            return $plain;
        }
        if (str_starts_with($encoded, 'gcm1:')) {
            $raw = base64_decode(substr($encoded, 5), true);
            if ($raw === false || strlen($raw) <= 28) { throw new RuntimeException('Invalid encrypted secret.'); }
            $nonce = substr($raw, 0, 12); $tag = substr($raw, 12, 16); $cipher = substr($raw, 28);
            $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
            if ($plain === false) { throw new RuntimeException('Unable to decrypt panel secret.'); }
            return $plain;
        }
        throw new RuntimeException('Unknown secret encoding.');
    }
}
