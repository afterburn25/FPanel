<?php

declare(strict_types=1);
require __DIR__.'/../src/bootstrap.php';
$privoraBuild=trim((string)@file_get_contents(dirname(__DIR__,2).'/VERSION'));
if(!preg_match('/^5\.0\.0-dev\.(?:6\.[0-9]+|7\.0)$/',$privoraBuild))$privoraBuild='5.0.0-dev.7.0';
$privoraAssetVersion=rawurlencode($privoraBuild);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Privora-Build: '.$privoraBuild);
$error='';
$surface=Auth::surface();
$isHostingSurface=($surface==='hosting');
$panelName=$isHostingSurface?'Privora Panel (PPanel)':'Privora Command Center (PCC)';
if (isset($_GET['logout'])) { $auth->logout(); header('Location: /'); exit; }
if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['login'])) {
    try { Auth::verifyCsrf($_POST['csrf'] ?? null); } catch (Throwable $e) { $error='Your sign-in form expired. Please try again.'; }
    if (!$error) {
        if (!$auth->login((string)($_POST['username'] ?? ''),(string)($_POST['password'] ?? ''),(string)($_POST['mfa_code'] ?? ''))) { $error=match($auth->loginStatus()){'mfa_required'=>'Enter the 6-digit authentication code for this account.','mfa_unavailable'=>'MFA is enabled but the panel encryption key is unavailable.','wrong_surface'=>($isHostingSurface?'This sign-in is for hosting accounts. Server administrators should use Privora Command Center (PCC).':'Hosting users should sign in through Privora Panel (PPanel).'),'invalid'=>'Invalid username or password.',default=>'Sign-in failed.'}; usleep(180000); }
        else { header('Location: /'); exit; }
    }
}
$user=$auth->user();
if (!$user):
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · <?=htmlspecialchars($panelName)?></title><link rel="icon" type="image/png" href="/assets/privora-labs-mark.png?v=6.14"><link rel="stylesheet" href="/assets/app.css?v=<?=$privoraAssetVersion?>"></head><body class="auth-body">
<div class="auth-shell"><section class="auth-brand"><img class="brand-full-logo" src="/assets/privora-labs-full.png?v=6.14" alt="Privora Panel"><span class="eyebrow"><?= $isHostingSurface ? 'PRIVORA PANEL · PPANEL' : 'PRIVORA COMMAND CENTER · PCC' ?></span><h1><?= $isHostingSurface ? 'Manage your websites, email, DNS and hosting tools.' : 'Server administration and hosting control.' ?></h1><p><?= $isHostingSurface ? 'PPanel is reserved for hosting-account access.' : 'PCC is reserved for Privora server administrators and resellers.' ?></p><div class="auth-points"><span>✓ Root-isolated control plane</span><span>✓ Customer account isolation</span><span>✓ Audited privileged actions</span></div></section>
<form class="login-card" method="post" autocomplete="on"><span class="eyebrow">SECURE ACCESS</span><h2>Welcome back</h2><p>Sign in to your Privora workspace.</p><?php if($error):?><div class="alert error"><?=htmlspecialchars($error)?></div><?php endif;?><input type="hidden" name="csrf" value="<?=htmlspecialchars(Auth::csrf())?>"><label><?= $isHostingSurface ? 'PPanel username or primary domain' : 'Username' ?><input name="username" autocomplete="username" required autofocus <?= $isHostingSurface ? 'placeholder="customername or example.com"' : '' ?>></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><label>Authentication code <small>(if MFA is enabled)</small><input name="mfa_code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" placeholder="123456"></label><button class="primary login-btn" name="login" value="1">Sign in</button><small>Sessions expire after 30 minutes of inactivity.</small></form></div></body></html>
<?php exit; endif;
if (Auth::shellFor($user)==='customer') { require __DIR__.'/customer.php'; } else { require __DIR__.'/admin.php'; }
