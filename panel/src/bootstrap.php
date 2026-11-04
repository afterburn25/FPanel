<?php

declare(strict_types=1);
require_once __DIR__.'/Store.php';
require_once __DIR__.'/Auth.php';
require_once __DIR__.'/AgentClient.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");

$statePath = getenv('PRIVORA_PANEL_STATE') ?: dirname(__DIR__).'/storage/panel-state.json';
$store = new Store($statePath); $store->ensurePackageDefaults(); Auth::startSession(); $auth = new Auth($store);
