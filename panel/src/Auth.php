<?php

declare(strict_types=1);

require_once __DIR__ . '/Store.php';
require_once __DIR__ . '/Totp.php';

final class Auth
{
    private const ROLE_PERMS = [
        'root-admin' => ['*'],
        'server-admin' => ['server.read','server.services','server.updates','hosting.read','hosting.write','sites.write','php.write','resources.write','platform.simulate','audit.read'],
        'reseller' => ['hosting.read','hosting.write','sites.write','php.write','resources.write','audit.read'],
        'support-admin' => ['server.read','hosting.read','audit.read'],
        'read-only' => ['server.read','hosting.read','audit.read'],
        'hosting-user' => ['hosting.self.read','sites.self.write','php.self.write','resources.self.write'],
    ];

    private string $loginStatus = 'idle';

    public function __construct(private readonly Store $store) {}

    public static function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) { return; }
        $surface=self::surface();
        session_name($surface==='admin' ? 'privora_pcc_session' : ($surface==='hosting' ? 'privora_ppanel_session' : 'privora_session'));
        session_set_cookie_params(['httponly'=>true,'samesite'=>'Strict','secure'=>self::isHttps(),'path'=>'/']);
        session_start();
        if (!isset($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(24)); }
    }

    public function login(string $username, string $password, ?string $mfaCode = null): bool
    {
        $this->loginStatus = 'invalid';
        $user = $this->store->findUser(trim($username));
        if (!$user || !($user['active'] ?? false) || !password_verify($password, (string)$user['password_hash'])) { return false; }
        if (!self::surfaceAllowsUser($user)) { $this->loginStatus = 'wrong_surface'; return false; }
        if (($user['mfa_enabled'] ?? false) === true) {
            try {
                $secret = SecretBox::decrypt((string)($user['mfa_secret'] ?? ''));
                if (!$mfaCode || !Totp::verify($secret, $mfaCode)) { $this->loginStatus = 'mfa_required'; return false; }
            } catch (Throwable) {
                $this->loginStatus = 'mfa_unavailable';
                return false;
            }
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['last_seen'] = time();
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
        $this->store->addEvent((string)$user['username'], 'auth.login', 'User signed in.');
        $this->loginStatus = 'ok';
        return true;
    }

    public function loginStatus(): string { return $this->loginStatus; }

    public function mfaStatus(): array
    {
        $u = $this->requireUser();
        return ['available'=>SecretBox::available(),'enabled'=>(bool)($u['mfa_enabled'] ?? false),'pending'=>isset($u['mfa_pending_secret'])];
    }

    public function verifyMfaCode(string $code): bool
    {
        $u = $this->requireUser();
        if (($u['mfa_enabled'] ?? false) !== true) { return true; }
        if (!SecretBox::available()) { return false; }
        try {
            $secret = SecretBox::decrypt((string)($u['mfa_secret'] ?? ''));
            return Totp::verify($secret, $code);
        } catch (Throwable) {
            return false;
        }
    }

    public function beginMfa(): array
    {
        $u = $this->requireUser();
        if (!SecretBox::available()) { throw new RuntimeException('Panel encryption key is not configured.'); }
        $secret = Totp::generateSecret();
        $u['mfa_pending_secret'] = SecretBox::encrypt($secret);
        $u['mfa_pending_at'] = gmdate('c');
        $this->store->upsertUser($u);
        $this->store->addEvent((string)$u['username'], 'auth.mfa.begin', 'MFA enrollment started.');
        $issuer=self::surface()==='admin'?'Privora Command Center':'Privora Panel';
        return ['secret'=>$secret,'otpauth_uri'=>Totp::otpauthUri($issuer,(string)$u['username'],$secret)];
    }

    public function confirmMfa(string $code): bool
    {
        $u = $this->requireUser();
        $pending = (string)($u['mfa_pending_secret'] ?? '');
        if ($pending === '') { throw new RuntimeException('No MFA enrollment is pending.'); }
        $secret = SecretBox::decrypt($pending);
        if (!Totp::verify($secret, $code)) { return false; }
        $u['mfa_secret'] = $pending;
        $u['mfa_enabled'] = true;
        unset($u['mfa_pending_secret'], $u['mfa_pending_at']);
        $this->store->upsertUser($u);
        $this->store->addEvent((string)$u['username'], 'auth.mfa.enable', 'MFA enabled.');
        return true;
    }

    public function disableMfa(string $password, string $code): bool
    {
        $u = $this->requireUser();
        if (!password_verify($password, (string)$u['password_hash'])) { return false; }
        if (($u['mfa_enabled'] ?? false) === true) {
            $secret = SecretBox::decrypt((string)($u['mfa_secret'] ?? ''));
            if (!Totp::verify($secret, $code)) { return false; }
        }
        unset($u['mfa_secret'], $u['mfa_pending_secret'], $u['mfa_pending_at']);
        $u['mfa_enabled'] = false;
        $this->store->upsertUser($u);
        $this->store->addEvent((string)$u['username'], 'auth.mfa.disable', 'MFA disabled.');
        return true;
    }

    public function logout(): void
    {
        $u = $this->user(); if ($u) { $this->store->addEvent((string)$u['username'], 'auth.logout', 'User signed out.'); }
        $_SESSION = []; if (ini_get('session.use_cookies')) { $p = session_get_cookie_params(); setcookie(session_name(), '', time()-42000, $p['path'], '', $p['secure'], $p['httponly']); }
        session_destroy();
    }

    public function user(): ?array
    {
        if (!isset($_SESSION['user_id'])) { return null; }
        if ((int)($_SESSION['last_seen'] ?? 0) < time() - 1800) { return null; }
        $_SESSION['last_seen'] = time();
        foreach ($this->store->users() as $user) { if (($user['id'] ?? '') === $_SESSION['user_id'] && ($user['active'] ?? false)) { return self::surfaceAllowsUser($user) ? $user : null; } }
        return null;
    }

    public function requireUser(): array
    {
        $u = $this->user(); if (!$u) { http_response_code(401); throw new RuntimeException('Authentication required.'); } return $u;
    }

    public function can(string $permission): bool
    {
        $u = $this->user(); if (!$u) { return false; }
        $perms = self::ROLE_PERMS[$u['role'] ?? 'read-only'] ?? [];
        return in_array('*',$perms,true) || in_array($permission,$perms,true);
    }

    public function requirePermission(string $permission): void
    {
        if (!$this->can($permission)) { http_response_code(403); throw new RuntimeException('Permission denied.'); }
    }

    public static function surface(): string
    {
        $raw = strtolower(trim((string)($_SERVER['PRIVORA_PANEL_SURFACE'] ?? getenv('PRIVORA_PANEL_SURFACE') ?: '')));
        return in_array($raw, ['admin','hosting'], true) ? $raw : 'combined';
    }

    public static function surfaceAllowsUser(array $user): bool
    {
        $surface = self::surface();
        if ($surface === 'combined') { return true; }
        $hostingUser = (($user['role'] ?? '') === 'hosting-user');
        return $surface === 'hosting' ? $hostingUser : !$hostingUser;
    }

    public static function shellFor(array $user): string
    {
        return (($user['role'] ?? '') === 'hosting-user') ? 'customer' : 'admin';
    }

    public static function accountScope(array $user): ?string
    {
        if (($user['role'] ?? '') !== 'hosting-user') { return null; }
        $account = strtolower(trim((string)($user['account'] ?? '')));
        return preg_match('/^[a-z][a-z0-9_]{2,23}$/', $account) ? $account : null;
    }

    public static function resellerScope(array $user): ?string
    {
        if (($user['role'] ?? '') !== 'reseller') { return null; }
        $scope = strtolower(trim((string)($user['reseller'] ?? $user['username'] ?? '')));
        return preg_match('/^[a-z][a-z0-9_-]{2,63}$/', $scope) ? $scope : null;
    }

    public static function csrf(): string { return (string)($_SESSION['csrf'] ?? ''); }
    public static function verifyCsrf(?string $token): void
    {
        if (!$token || !hash_equals((string)($_SESSION['csrf'] ?? ''), $token)) { http_response_code(419); throw new RuntimeException('Invalid CSRF token.'); }
    }
    private static function isHttps(): bool { return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'); }
}
