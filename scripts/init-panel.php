<?php

declare(strict_types=1);
require dirname(__DIR__).'/panel/src/Store.php';
$state = getenv('PRIVORA_PANEL_STATE') ?: dirname(__DIR__).'/panel/storage/panel-state.json';
$user = $argv[1] ?? 'admin';
$password = $argv[2] ?? getenv('PRIVORA_BOOTSTRAP_PASSWORD');
$role = $argv[3] ?? 'root-admin';
$account = $argv[4] ?? null;
$email = $argv[5] ?? getenv('PRIVORA_BOOTSTRAP_EMAIL') ?: null;
if ($email !== null && !filter_var($email, FILTER_VALIDATE_EMAIL)) { fwrite(STDERR, "Invalid email.\n"); exit(2); }
$roles = ['root-admin','server-admin','reseller','support-admin','read-only','hosting-user'];
if (!$password || strlen($password) < 12) { fwrite(STDERR, "Usage: php scripts/init-panel.php <username> <password>=12+ chars [role] [hosting-account]\n"); exit(2); }
if (!in_array($role,$roles,true)) { fwrite(STDERR, "Invalid role.\n"); exit(2); }
if ($role === 'hosting-user' && (!$account || !preg_match('/^[a-z][a-z0-9_]{2,23}$/',$account))) { fwrite(STDERR, "hosting-user requires a valid hosting account.\n"); exit(2); }
$store = new Store($state); $store->ensurePackageDefaults();
$existing = $store->findUser($user);
$record = ['id'=>$existing['id'] ?? bin2hex(random_bytes(8)),'username'=>$user,'password_hash'=>password_hash($password,PASSWORD_ARGON2ID),'role'=>$role,'active'=>true,'created_at'=>$existing['created_at'] ?? gmdate('c')];
if ($email !== null) { $record['email'] = $email; }
if ($role === 'hosting-user') { $record['account'] = $account; }
$store->upsertUser($record); echo "Privora user initialized: {$user} ({$role})\n";
