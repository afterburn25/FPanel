const PRIVORA_PPANEL_UI_BUILD=document.body?.dataset?.privoraBuild||'unknown';
const $ = id => document.getElementById(id);
const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(route, opt = {}) {
  const url = new URL('api.php', document.baseURI);
  const parts = String(route).split('&');
  url.searchParams.set('route', parts.shift());
  for (const part of parts) {
    const i = part.indexOf('=');
    if (i > 0) url.searchParams.set(part.slice(0, i), decodeURIComponent(part.slice(i + 1)));
  }
  let r;
  try {
    r = await fetch(url, {
      method: opt.method || 'GET',
      headers: {'Content-Type':'application/json','X-CSRF-Token':csrf},
      credentials: 'same-origin',
      body: opt.data ? JSON.stringify(opt.data) : undefined,
      cache: 'no-store'
    });
  } catch (_) {
    throw new Error('Privora API connection failed. The panel could not reach its local API bridge.');
  }
  const d = await r.json().catch(() => ({error:'Invalid response'}));
  if (!r.ok) throw new Error(d.error || `Request failed (${r.status})`);
  return d;
}
function toast(msg, bad = false) {
  const t = $('toast'); if (!t) return;
  const message = String(msg ?? '');
  clearTimeout(t._x);
  t.className = 'toast show' + (bad ? ' bad' : '');
  t.replaceChildren();

  const body = document.createElement('div');
  body.className = 'toast-message';
  body.textContent = message;

  const actions = document.createElement('div');
  actions.className = 'toast-actions';

  const copy = document.createElement('button');
  copy.type = 'button'; copy.className = 'toast-btn'; copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(message);
      copy.textContent = 'Copied';
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = message; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); copy.textContent = 'Copied'; }
      finally { ta.remove(); }
    }
    setTimeout(() => copy.textContent = 'Copy', 1600);
  });

  const close = document.createElement('button');
  close.type = 'button'; close.className = 'toast-btn'; close.textContent = 'Close';
  close.addEventListener('click', () => { clearTimeout(t._x); t.className = 'toast'; });

  actions.append(copy, close);
  t.append(body, actions);

  // Errors stay until explicitly dismissed so operators can read/copy them.
  if (!bad) t._x = setTimeout(() => t.className = 'toast', 8000);
}
function generateDatabasePassword(length=24) {
  const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_=+';
  const bytes=new Uint32Array(length); crypto.getRandomValues(bytes);
  return Array.from(bytes,n=>alphabet[n%alphabet.length]).join('');
}
function setGeneratedDatabasePassword(form) {
  if(!form)return;
  const password=form.querySelector('input[name="password"]'),confirmInput=form.querySelector('input[name="password_confirm"]');
  if(!password)return;
  const value=generateDatabasePassword(); password.value=value; if(confirmInput)confirmInput.value=value;
  password.type='text'; if(confirmInput)confirmInput.type='text';
  setTimeout(()=>{password.type='password';if(confirmInput)confirmInput.type='password'},3500);
}
function showCustomerDatabaseCredentials(database,credentials,action='Database credentials') {
  const box=$('cpDatabaseCredentials'),pre=$('cpDatabaseCredentialsText'); if(!box||!pre)return;
  pre.textContent=[`Action: ${action}`,`Database: ${database||''}`,`Username: ${credentials?.user||''}`,`Password: ${credentials?.password||''}`].join('\n');
  box.hidden=false; box.scrollIntoView({behavior:'smooth',block:'center'});
}
async function copyCustomerDatabaseCredentials(id) {
  const text=$(id)?.textContent||''; if(!text)return;
  try { await navigator.clipboard.writeText(text); toast('Database credentials copied'); }
  catch { toast('Could not copy credentials automatically. Select and copy the text.',true); }
}
function customerDatabaseResource(name) { return (resources.databases||[]).find(x=>x.name===name)||null; }
function openCustomerDatabaseEditor(name) {
  const row=customerDatabaseResource(name),modal=$('cpDatabaseEditModal'),form=$('cpDatabaseEditForm');
  if(!row||!modal||!form){toast('Database details are unavailable.',true);return;}
  form.elements.name.value=row.name||'';
  form.elements.database_display.value=row.name||'';
  form.elements.engine_display.value=row.engine||'';
  form.elements.user.value=row.user||'';
  form.elements.password.value=''; form.elements.password_confirm.value='';
  modal.classList.add('open');
}

function generateMailPassword(){const chars='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_=+';const a=new Uint32Array(24);crypto.getRandomValues(a);return Array.from(a,n=>chars[n%chars.length]).join('')}
function setGeneratedMailPassword(form){if(!form)return;const password=form.querySelector('input[name="password"]'),confirmInput=form.querySelector('input[name="password_confirm"]');if(!password)return;const value=generateMailPassword();password.value=value;if(confirmInput)confirmInput.value=value;password.type='text';if(confirmInput)confirmInput.type='text';setTimeout(()=>{password.type='password';if(confirmInput)confirmInput.type='password'},3500)}
function showCustomerMailboxSetup(result,addressFallback=''){const box=$('cpMailSetupCard'),pre=$('cpMailSetupText'),address=String(result?.mailbox?.address||result?.credentials?.address||addressFallback||''),domain=address.includes('@')?address.split('@').pop():'',host=domain?'mail.'+domain:'';if(!box||!pre||!address)return;pre.textContent=`Email: ${address}
Password: the password you entered (not stored in Privora)

Incoming server: ${host}
IMAP: 993 / SSL-TLS
POP3: 995 / SSL-TLS

Outgoing server: ${host}
SMTP: 465 / SSL-TLS
SMTP: 587 / STARTTLS
Username: ${address}
Authentication: Required`;box.hidden=false;box.scrollIntoView({behavior:'smooth',block:'center'})}
function customerMailboxResource(address){return (resources.mailboxes||[]).find(x=>String(x.address||'').toLowerCase()===String(address||'').toLowerCase())||null}
function customerAliasResource(address){return (resources.mail_aliases||[]).find(x=>String(x.address||'').toLowerCase()===String(address||'').toLowerCase())||null}
function openCustomerMailboxEditor(address){const row=customerMailboxResource(address),modal=$('cpMailboxEditModal'),form=$('cpMailboxEditForm');if(!row||!modal||!form){toast('Mailbox details are unavailable.',true);return}form.elements.address.value=row.address||address;form.elements.address_display.value=row.address||address;form.elements.quota_mb.value=row.quota_mb||1024;form.elements.password.value='';form.elements.password_confirm.value='';modal.classList.add('open')}
function openCustomerAliasEditor(address){const row=customerAliasResource(address),modal=$('cpAliasEditModal'),form=$('cpAliasEditForm');if(!row||!modal||!form){toast('Forwarder details are unavailable.',true);return}form.elements.address.value=row.address||address;form.elements.address_display.value=row.address||address;form.elements.destination.value=row.destination||'';modal.classList.add('open')}
function table(id, headers, rows) {
  const el = $(id); if (!el) return;
  if (!rows.length) { el.innerHTML = '<div class="empty">Nothing here yet.</div>'; return; }
  el.innerHTML = `<div class="tr th resource-tr">${headers.map(h => `<span>${esc(h)}</span>`).join('')}</div>` +
    rows.map(r => `<div class="tr resource-tr">${r.map(c => `<span>${c}</span>`).join('')}</div>`).join('');
}

let summary = null, resources = {};
const featureByView = {
  files:'files', sftp:'ftp', backups:'backups',
  domains:'domains', dns:'dns', ssl:'ssl', staging:'domains', redirects:'domains',
  'error-pages':'domains', 'mime-types':'domains', hotlink:'domains', 'directory-privacy':'domains',
  email:'email', webmail:'webmail', forwarders:'email', spam:'email', autoresponders:'email', 'mail-domain':'email',
  databases:'databases', 'app-installer':'applications', apps:'applications', deploy:'applications',
  php:'php', 'php-options':'php', 'php-extensions':'php', cron:'cron', 'disk-usage':'files', metrics:'metrics', visitors:'metrics', analytics:'metrics', bandwidth:'metrics', 'access-logs':'metrics', errors:'metrics'
};
function activeFeatures() {
  const values = summary?.features || resources.features || [];
  return new Set(Array.isArray(values) ? values : []);
}
function applyFeatureVisibility() {
  const enabled = activeFeatures();
  document.querySelectorAll('.tool-tile[data-cp-nav]').forEach(tile => {
    const feature = featureByView[tile.dataset.cpNav];
    if (!feature) return;
    const allowed = enabled.size === 0 || enabled.has(feature);
    tile.hidden = !allowed;
    tile.setAttribute('aria-hidden', allowed ? 'false' : 'true');
  });
  document.querySelectorAll('.tool-group').forEach(group => {
    const visible = [...group.querySelectorAll('.tool-tile')].some(t => !t.hidden);
    group.hidden = !visible;
  });
}
function renderWebmailAvailability() {
  const caps = resources.host_capabilities?.capabilities || [];
  const found = caps.find(x => x.name === 'webmail');
  const tile = $('webmailTile'), tileStatus = $('webmailTileStatus');
  const badge = $('cpWebmailBadge'), status = $('cpWebmailStatus'), launch = $('cpWebmailLaunch'), details = $('cpWebmailDetails');
  const gatewayState = $('cpWebmailGatewayState'), adminHint = $('cpWebmailAdminHint');
  const featureAllowed = activeFeatures().size === 0 || activeFeatures().has('webmail') || activeFeatures().has('email');
  if (tile) tile.hidden = !featureAllowed;
  const available = !!found?.available;
  const launchUrl = String(found?.launch_url || '');
  if (tile) tile.classList.toggle('planned', !available);
  if (tileStatus) tileStatus.textContent = available ? 'Ready' : 'Unavailable';
  if ($('homeWebmailState')) $('homeWebmailState').textContent = available ? 'READY' : 'ADMIN SETUP';
  if ($('homeWebmailDetail')) $('homeWebmailDetail').textContent = available ? `${found?.client || 'Webmail'} is ready to launch.` : 'Roundcube setup is required in PCC.';
  if (badge) { badge.textContent = available ? 'READY' : 'UNAVAILABLE'; badge.className = 'badge ' + (available ? 'online' : 'warning'); }
  if (gatewayState) { gatewayState.textContent = available ? 'READY' : 'ADMIN SETUP'; gatewayState.className = 'status-pill ' + (available ? 'active' : 'warning'); }
  if (adminHint) adminHint.hidden = available;
  if (status) status.textContent = available ? `Detected ${found.client || 'supported webmail'}${launchUrl ? ' with a Privora launch route.' : ', but no launch route is configured.'}` : 'Webmail is not installed/certified for this server yet. Your server administrator can provision Roundcube from PCC.';
  if (launch) { launch.hidden = !(available && launchUrl); if (available && launchUrl) launch.href = launchUrl; }
  if (details) {
    const rows = [[`<b>${esc(found?.client || 'Webmail client')}</b>`, esc(found?.detail || 'Not detected'), available ? '<em class="status-pill active">READY</em>' : '<em class="status-pill sim">GATED</em>']];
    details.innerHTML = '<div class="tr th resource-tr"><span>Client</span><span>Route / detail</span><span>Status</span></div>' + rows.map(r => `<div class="tr resource-tr">${r.map(c => `<span>${c}</span>`).join('')}</div>`).join('');
  }
}
function renderPhpMyAdminAvailability() {
  const cap = resources.host_capabilities?.capabilities || [];
  const found = cap.find(x => x.name === 'phpmyadmin');
  const tile = $('phpMyAdminTile'), em = $('phpMyAdminTileStatus');
  if (!tile) return;
  const featureAllowed = activeFeatures().size === 0 || activeFeatures().has('phpmyadmin') || activeFeatures().has('databases');
  const launchUrl = String(found?.launch_url || '');
  const ready = !!(found?.available && found?.certified && launchUrl);
  tile.hidden = !featureAllowed;
  tile.classList.toggle('planned', !ready);
  if (em) em.textContent = ready ? 'Ready' : 'Unavailable';
  tile.title = ready ? 'Open the panel-protected phpMyAdmin login.' : 'phpMyAdmin is not installed/certified on this server.';
  tile.onclick = ready ? () => window.open(launchUrl, '_blank', 'noopener') : null;
}

let customerExtensionFilter = 'all';
const customerExtensionNames = {
  'php-pdo-mysql':'pdo_mysql',
  'php-pdo-pgsql':'pdo_pgsql',
  'php-pdo-sqlite':'pdo_sqlite',
  'php-bcmath':'bcmath',
  'php-curl':'curl',
  'php-gd':'gd',
  'php-gmp':'gmp',
  'php-imagick':'imagick',
  'php-imap':'imap',
  'php-intl':'intl',
  'php-ldap':'ldap',
  'php-mbstring':'mbstring',
  'php-soap':'soap',
  'php-xml':'xml',
  'php-zip':'zip',
  'php-redis':'redis',
  'php-memcached':'memcached',
  'php-apcu':'apcu'
};
let customerComponentsCache = [];
let customerComponentsLoaded = false;
let customerComponentsLoading = null;
function customerServerComponents(){return customerComponentsCache}
async function loadCustomerComponents(force=false){
  if(customerComponentsLoaded&&!force)return customerComponentsCache;
  if(customerComponentsLoading&&!force)return customerComponentsLoading;
  const root=$('cpExtensionCatalog'),snapshot=$('cpRuntimeSnapshot');
  if(root&&!customerComponentsLoaded)root.innerHTML='<div class="empty">Loading server PHP extension inventory…</div>';
  if(snapshot&&!customerComponentsLoaded)snapshot.innerHTML='<div class="empty">Loading runtime availability…</div>';
  customerComponentsLoading=api('customer-components').then(d=>{
    customerComponentsCache=Array.isArray(d.components)?d.components:[];
    customerComponentsLoaded=true;
    renderCustomerRuntimeAvailability();
    renderCustomerExtensionCatalog();
    return customerComponentsCache;
  }).catch(err=>{
    customerComponentsCache=[]; customerComponentsLoaded=false;
    if(root)root.innerHTML=`<div class="empty">${esc(err.message)}</div>`;
    if(snapshot)snapshot.innerHTML=`<div class="empty">${esc(err.message)}</div>`;
    throw err;
  }).finally(()=>{customerComponentsLoading=null});
  return customerComponentsLoading;
}
function customerPhpComponents(){return customerServerComponents().filter(c=>c.category==='PHP Extensions'||String(c.id||'').startsWith('php-'))}
function customerComponentSearch(c){
  return [c.id,c.name,c.category,c.description,...(c.tags||[]),...(c.packages||[])].join(' ').toLowerCase();
}
function customerExtensionPolicy(domain,name){
  return (resources.account_controls||[]).find(x=>x.kind==='php_extension'&&String(x.domain||'').toLowerCase()===String(domain||'').toLowerCase()&&String(x.name||'')===name)||null;
}
function componentStatusBadge(c){
  if(c.installed)return '<em class="status-pill active">INSTALLED</em>';
  if(c.partial)return '<em class="status-pill warning">PARTIAL</em>';
  if(c.available)return '<em class="status-pill sim">ADMIN INSTALL</em>';
  return '<em class="status-pill failed">UNAVAILABLE</em>';
}
function renderCustomerExtensionCatalog(){
  const root=$('cpExtensionCatalog'); if(!root)return;
  const domain=$('cpExtensionDomain')?.value||'';
  const query=($('cpExtensionSearch')?.value||'').trim().toLowerCase();
  const all=customerPhpComponents();
  const rows=all.filter(c=>{
    if(query&&!customerComponentSearch(c).includes(query))return false;
    if(customerExtensionFilter==='installed')return !!c.installed;
    if(customerExtensionFilter==='available')return !c.installed&&!!c.available;
    if(customerExtensionFilter==='missing')return !c.installed;
    return true;
  });
  const installed=all.filter(c=>c.installed).length, available=all.filter(c=>!c.installed&&c.available).length, missing=all.length-installed;
  if($('cpExtensionCount'))$('cpExtensionCount').textContent=`${all.length} MODULE${all.length===1?'':'S'}`;
  if($('phpExtensionsTileStatus'))$('phpExtensionsTileStatus').textContent=all.length?`${installed}/${all.length} installed`:'Unavailable';
  if($('homeExtensionState'))$('homeExtensionState').textContent=all.length?`${installed} INSTALLED`:'UNAVAILABLE';
  if($('homeExtensionDetail'))$('homeExtensionDetail').textContent=all.length?`${installed} installed · ${available} available for PCC install`:'Server component inventory is unavailable.';
  if($('cpExtensionSummary'))$('cpExtensionSummary').innerHTML=
    `<article><span>Installed</span><b>${installed}</b><small>Ready on server</small></article>`+
    `<article><span>Available</span><b>${available}</b><small>PCC can install</small></article>`+
    `<article><span>Needs admin</span><b>${missing}</b><small>Not active server-wide</small></article>`;
  if(!all.length){
    root.innerHTML='<div class="empty">Server component inventory is unavailable. The administrator may need to finish the 6.71 Extensions & Components setup.</div>';
    return;
  }
  if(!rows.length){root.innerHTML='<div class="empty">No PHP extensions match this search/filter.</div>';return;}
  root.innerHTML=rows.map(c=>{
    const module=customerExtensionNames[c.id]||String(c.id||'').replace(/^php-/,'').replaceAll('-','_');
    const policy=domain?customerExtensionPolicy(domain,module):null;
    const policyText=policy?String(policy.value||'').toUpperCase():'INHERIT';
    const packages=(c.packages||[]).map(p=>`<code>${esc(p)}</code>`).join('');
    const actions=c.installed&&domain
      ? `<div class="component-actions"><button type="button" class="table-btn ${policy?.value==='enabled'?'selected':''}" data-customer-ext-action="enabled" data-extension="${esc(module)}">Enable</button><button type="button" class="table-btn ${policy?.value==='disabled'?'selected':''}" data-customer-ext-action="disabled" data-extension="${esc(module)}">Disable</button></div>`
      : `<div class="component-admin-required">${c.available?'Install from PCC to make this extension available to hosting accounts.':'This package is not available from the server repositories.'}</div>`;
    return `<article class="pp-component-card" data-component-search="${esc(customerComponentSearch(c))}">
      <div class="component-card-head"><div><span class="component-category">PHP 8.4</span><h3>${esc(c.name)}</h3></div>${componentStatusBadge(c)}</div>
      <p>${esc(c.description||c.status_reason||'PHP extension')}</p>
      <div class="component-package-row">${packages}</div>
      <div class="component-policy-row"><span>Site policy</span><b>${esc(policyText)}</b></div>
      ${actions}
    </article>`;
  }).join('');
}
function renderCustomerRuntimeAvailability(){
  const components=customerServerComponents();
  const laravel=components.find(c=>c.id==='laravel-stack');
  const badge=$('cpLaravelBadge'), detail=$('cpLaravelDetail'), packs=$('cpLaravelPackages');
  if(badge){
    const text=laravel?.installed?'READY':laravel?.available?'ADMIN INSTALL':'UNAVAILABLE';
    badge.textContent=text; badge.className='badge '+(laravel?.installed?'online':laravel?.available?'warning':'');
  }
  if(detail){
    detail.textContent=laravel?.installed
      ? 'Laravel server tooling is installed and ready for account application workflows.'
      : laravel?.available
        ? 'Laravel tooling is available for the administrator to install from PCC → Extensions & Components.'
        : 'Laravel tooling is not currently available from the configured server repositories.';
  }
  if(packs)packs.innerHTML=(laravel?.packages||[]).slice(0,10).map(p=>`<code>${esc(p)}</code>`).join('')||'<small>No Laravel package inventory reported.</small>';
  const ids=['composer','nodejs','npm','php-pdo-sqlite'];
  const snapshot=$('cpRuntimeSnapshot');
  if(snapshot){
    snapshot.innerHTML=ids.map(id=>{
      const c=components.find(x=>x.id===id);
      return `<div class="runtime-snapshot-row"><span>${esc(c?.name||id)}</span>${componentStatusBadge(c||{})}</div>`;
    }).join('');
  }
  const ready=ids.filter(id=>components.find(c=>c.id===id)?.installed).length;
  if($('cpRuntimeBadge')){$('cpRuntimeBadge').textContent=`${ready}/${ids.length} READY`;$('cpRuntimeBadge').className='badge '+(ready===ids.length?'online':'warning')}
  const runtimeText=laravel?.installed?'Laravel ready':laravel?.available?'Laravel available':'Laravel unavailable';
  if($('runtimeTileStatus'))$('runtimeTileStatus').textContent=runtimeText;
  if($('homeRuntimeState'))$('homeRuntimeState').textContent=laravel?.installed?'LARAVEL READY':laravel?.available?'ADMIN INSTALL':'UNAVAILABLE';
  if($('homeRuntimeDetail'))$('homeRuntimeDetail').textContent=`${runtimeText} · ${ready}/${ids.length} supporting tools installed`;
}

function ownedDomainSites(){const seen=new Set();return (summary?.sites||[]).filter(s=>{const d=String(s?.domain||'').toLowerCase();if(!d||seen.has(d))return false;seen.add(d);return true}).sort((a,b)=>String(a.domain).localeCompare(String(b.domain)))}
function ownedDomains(){return ownedDomainSites().filter(x=>x.status==='active').map(x=>x.domain)}
function fillDomainInputs(){const zones=new Set((resources.zones||[]).map(z=>String(z.domain||'').toLowerCase()));document.querySelectorAll('select[data-domain-source]').forEach(sel=>{const mode=sel.dataset.domainSource||'existing-active',current=sel.value;const opts=ownedDomainSites().map(s=>{const domain=String(s.domain||'').toLowerCase(),inactive=s.status!=='active',zoned=mode==='zone-available'&&zones.has(domain);return {domain,disabled:inactive||zoned,label:domain+(inactive?' — Needs attention':'')+(zoned?' — DNS zone exists':'')}});sel.innerHTML=opts.length?opts.map(o=>`<option value="${esc(o.domain)}" ${o.disabled?'disabled':''}>${esc(o.label)}</option>`).join(''):'<option value="" disabled selected>No created domains available</option>';const exact=opts.find(o=>o.domain===current&&!o.disabled),first=opts.find(o=>!o.disabled);if(exact)sel.value=exact.domain;else if(first)sel.value=first.domain;else sel.selectedIndex=-1});refreshCustomerBackupResource()}

function refreshCustomerAutoSSLDomainSelector(){const sel=$('cpAutoSSLDomain');if(!sel)return;const current=sel.value,sites=ownedDomainSites().filter(s=>s.status==='active');sel.innerHTML='<option value="">All active websites</option>'+sites.map(s=>`<option value="${esc(s.domain)}">${esc(s.domain)}</option>`).join('');if(current&&sites.some(s=>s.domain===current))sel.value=current;else sel.value=''}
function renderCustomerAutoSSLResults(r){const status=$('cpAutoSSLStatus'),root=$('cpAutoSSLResults'),rows=r.results||[];if(status)status.textContent=`Scanned ${r.scanned||0} · Issued ${r.issued||0} · Already valid ${r.skipped||0} · Pending DNS ${r.pending||0} · HTTP blocked ${r.blocked||0} · Failed ${r.failed||0}`;if(root)table('cpAutoSSLResults',['Domain','Result','Detail'],rows.map(x=>[`<b>${esc(x.domain)}</b>`,`<em class="status-pill ${x.status==='issued'||x.status==='valid'?'active':x.status==='pending'||x.status==='blocked'?'warning':'failed'}">${esc(String(x.status||'unknown').toUpperCase())}</em>`,esc(x.detail||'—')]))}
function refreshCustomerBackupResource(){const form=document.querySelector('form[data-customer-create="customer-backup-create"]'),sel=$('cpBackupResource'),hint=$('cpBackupResourceHint');if(!form||!sel)return;const scope=form.elements.scope.value;if(scope==='site'){const domains=ownedDomains();sel.innerHTML=domains.length?domains.map(d=>`<option value="${esc(d)}">${esc(d)}</option>`).join(''):'<option value="" disabled>No live websites</option>';if(hint)hint.textContent='Choose the website to back up.'}else{const account=summary?.account||{};sel.innerHTML=`<option value="${esc(account.username||'')}">${esc(account.primary_domain||'Hosting account')}</option>`;if(hint)hint.textContent='Back up the entire hosting account.'}}
function fillSubdomainParents() {
  const seen = new Set(), sites = (summary?.sites || []).filter(s => { const d=String(s?.domain||'').toLowerCase(); if(!d || s.kind==='subdomain' || seen.has(d)) return false; seen.add(d); return true; }).sort((a,b)=>String(a.domain).localeCompare(String(b.domain))), sel = $('cpSubdomainParent');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = sites.length ? sites.map(s => `<option value="${esc(s.domain)}" ${s.status==='active'?'':'disabled'}>${esc(s.domain)}${s.status==='active'?'':' — Needs attention'}</option>`).join('') : '<option value="" disabled selected>No existing domains available</option>';
  if (current && sites.some(s => s.domain === current && s.status === 'active')) sel.value = current;
  else { const first=sites.find(s=>s.status==='active'); if(first) sel.value=first.domain; else sel.selectedIndex=-1; }
  updateCustomerSubdomainPreview();
}
function customerSubdomainRootValues() {
  const parent=String($('cpSubdomainParent')?.value||'').trim().toLowerCase(),label=String($('cpSubdomainLabel')?.value||'').trim().toLowerCase(),site=ownedDomainSites().find(s=>String(s.domain||'').toLowerCase()===parent),username=String(site?.username||summary?.account?.username||'').trim(),full=label&&parent?`${label}.${parent}`:'';
  return {parent,label,site,username,full,defaultRoot:username&&full?`/home/${username}/domains/${full}/public`:'',parentRoot:String(site?.document_root||'').trim()||(username&&parent?`/home/${username}/domains/${parent}/public`:'')};
}
function updateCustomerSubdomainRootHint() {
  const input=$('cpSubdomainDocumentRoot'),hint=$('cpSubdomainRootHint'); if(!input||!hint)return;
  const v=customerSubdomainRootValues(),root=String(input.value||'').replace(/\/+$/,'');
  if(root&&v.parentRoot&&root===String(v.parentRoot).replace(/\/+$/,'')) hint.textContent='Shared with the parent website. Deleting this subdomain preserves the parent domain files.';
  else if(root&&v.defaultRoot&&root===String(v.defaultRoot).replace(/\/+$/,'')) hint.textContent='Dedicated default root for this subdomain.';
  else hint.textContent='Custom root inside this hosting account. Shared/custom roots are preserved when the subdomain is removed.';
}
function syncCustomerSubdomainDocumentRoot(force=false) {
  const input=$('cpSubdomainDocumentRoot'); if(!input)return;
  const v=customerSubdomainRootValues(),mode=input.dataset.mode||'default';
  if(force||mode!=='custom') input.value=mode==='parent'?v.parentRoot:v.defaultRoot;
  updateCustomerSubdomainRootHint();
}
function updateCustomerSubdomainPreview() {
  const parent = $('cpSubdomainParent')?.value || '';
  const label = String($('cpSubdomainLabel')?.value || '').trim().toLowerCase();
  const out = $('cpSubdomainPreview'); if (out) out.textContent = label && parent ? `${label}.${parent}` : '—';
  syncCustomerSubdomainDocumentRoot();
}
function fmtBytes(v){const n=Number(v||0);if(!Number.isFinite(n))return '—';const u=['B','KB','MB','GB','TB'];let x=n,i=0;while(x>=1024&&i<u.length-1){x/=1024;i++}return `${x>=100||i===0?x.toFixed(0):x.toFixed(1)} ${u[i]}`}
function fmtUptime(sec){sec=Number(sec||0);if(!sec)return '—';const d=Math.floor(sec/86400),h=Math.floor((sec%86400)/3600),m=Math.floor((sec%3600)/60);return d?`${d}d ${h}h`:`${h}h ${m}m`}
function renderSummary() {
  if (!summary) return;
  const a = summary.account || {}, p = summary.package || {}, sites = summary.sites || [], server=summary.server||{};
  if ($('cpPrimaryDomain')) $('cpPrimaryDomain').textContent = a.primary_domain || 'No primary domain';
  $('railDomain').textContent = a.primary_domain || '—';
  $('railPackage').textContent = a.package || '—';
  if ($('accountChip')) $('accountChip').textContent = a.primary_domain || 'Hosting account';
  if ($('cpStatus')) $('cpStatus').textContent = (a.status || 'active').replace(/^./, c => c.toUpperCase());
  $('railPhp').textContent = sites[0] ? `PHP ${sites[0].php_version}` : '—';
  if($('railServerHostname'))$('railServerHostname').textContent=server.hostname||'—';
  if($('railServerOS'))$('railServerOS').textContent=[server.os,server.architecture].filter(Boolean).join(' · ')||'—';
  if($('railServerCpu'))$('railServerCpu').textContent=server.cpu_cores?`${server.cpu_cores} CPU cores · ${server.architecture||'unknown arch'}`:'—';
  if($('railServerLoad'))$('railServerLoad').textContent=[server.load_1,server.load_5,server.load_15].map(x=>Number(x||0).toFixed(2)).join(' / ');
  if($('railServerMemory')){const total=Number(server.memory_total_mb||0),free=Number(server.memory_free_mb||0);$('railServerMemory').textContent=total?`${Math.max(0,total-free).toLocaleString()} / ${total.toLocaleString()} MB`:'—'}
  if($('railServerUptime'))$('railServerUptime').textContent=fmtUptime(server.uptime_seconds);
  $('statSites').textContent = `${sites.length} / ${p.sites ?? '—'}`;
  $('siteQuota').value = p.sites ? Math.min(100, sites.length / p.sites * 100) : 0;
  const db = (resources.databases || []).length, mail = (resources.mailboxes || []).length;
  $('statDatabases').textContent = `${db} / ${p.databases ?? '—'}`;
  if($('databaseTileStatus'))$('databaseTileStatus').textContent=`${db} database${db===1?'':'s'}`;
  $('dbQuota').value = p.databases ? Math.min(100, db / p.databases * 100) : 0;
  $('statMail').textContent = `${mail} / ${p.mailboxes ?? '—'}`;
  $('mailQuota').value = p.mailboxes ? Math.min(100, mail / p.mailboxes * 100) : 0;
  $('statDisk').textContent = p.disk_gb ? `Limit ${p.disk_gb} GB` : 'Calculating…';
}

const appIcons = {wordpress:'W',joomla:'J',drupal:'D',grav:'G',phpbb:'phpBB',prestashop:'PS',nextcloud:'☁',moodle:'M',matomo:'M',laravel:'L'};
function renderAppCatalog() {
  const catalog = resources.app_catalog || [];
  const target = $('cpInstallerCatalog');
  if (target) target.innerHTML = catalog.length ? catalog.map(app => `
    <article class="installer-card" data-app-search="${esc([app.name,app.category,app.description].join(' ').toLowerCase())}">
      <div class="installer-card-head"><span class="app-logo">${esc(appIcons[app.slug] || app.name.slice(0,2))}</span><div><small>${esc(app.category)}</small><h4>${esc(app.name)}</h4></div></div>
      <p>${esc(app.description)}</p>
      <div class="installer-meta"><span>${esc(app.runtime)}</span><span>${app.database ? esc(app.database) : 'No DB'}</span><span>${esc(app.release_policy)}</span></div>
      <button type="button" class="table-btn" data-install-template="${esc(app.slug)}">Choose ${esc(app.name)}</button>
    </article>`).join('') : '<div class="empty">No installer recipes available.</div>';
  const select = $('cpInstallerTemplate');
  if (select) {
    const current = select.value;
    select.innerHTML = catalog.map(app => `<option value="${esc(app.slug)}">${esc(app.name)} — ${esc(app.category)}</option>`).join('');
    if (current && catalog.some(a => a.slug === current)) select.value = current;
  }
}
function controls(kind) { return (resources.account_controls || []).filter(x => x.kind === kind); }
function controlTable(id, kind, labels = ['Name','Value','Domain','Status']) {
  table(id, labels, controls(kind).map(x => [`<b>${esc(x.name)}</b>`, esc(x.value), esc(x.domain || 'Account-wide'), `<em class="status-pill sim">${esc(x.status)}</em>`]));
}
function renderControlTables() {
  controlTable('cpRedirectsTable','redirect',['Source','Target','Domain','Status']);
  controlTable('cpErrorPagesTable','error_page',['HTTP code','Page','Domain','Status']);
  controlTable('cpMimeTable','mime_type',['Extension','MIME type','Scope','Status']);
  controlTable('cpPrivacyTable','directory_privacy',['Directory','Policy','Domain','Status']);
  controlTable('cpHotlinkTable','hotlink',['Asset class','Policy','Domain','Status']);
  controlTable('cpAutorespondersTable','autoresponder',['Address','Reply','Domain','Status']);
  controlTable('cpSpamTable','spam_policy',['Sensitivity','Action','Domain','Status']);
  controlTable('cpPhpOptionsTable','php_setting',['Setting','Value','Domain','Status']);
  controlTable('cpPhpExtensionsTable','php_extension',['Extension','State','Domain','Status']);
  controlTable('cpIpBlocksTable','ip_block',['IP / CIDR','Action','Scope','Status']);
  controlTable('cpSshKeysTable','ssh_key',['Label','Public key','Scope','Status']);
  controlTable('cpRestoreTable','restore_request',['Backup ID','Restore scope','Scope','Status']);
}


function renderDatabaseEngines(){
  const cap = resources.host_capabilities || {};
  const engines = Array.isArray(cap.database_engines) ? cap.database_engines : [];
  const map = new Map(engines.map(x => [x.engine, x]));
  const labels = {mysql:'MySQL',mariadb:'MariaDB',postgresql:'PostgreSQL'};
  const sel = $('cpDatabaseEngine');
  if (sel) {
    const previous=sel.value; sel.innerHTML='';
    ['mysql','mariadb','postgresql'].forEach(name=>{ const c=map.get(name); const o=document.createElement('option'); o.value=name; o.textContent=labels[name]+((c && c.available && c.certified)?'':' — unavailable on this server'); o.disabled=!(c && c.available && c.certified); sel.appendChild(o); });
    const usable=[...sel.options].find(o=>!o.disabled); if(previous && [...sel.options].some(o=>o.value===previous&&!o.disabled)) sel.value=previous; else if(usable) sel.value=usable.value;
  }
  const hint=$('cpDatabaseEngineHint'); if(hint){ const usable=engines.filter(x=>x.available&&x.certified).map(x=>labels[x.engine]||x.engine); hint.textContent=usable.length?'Available on this VPS: '+usable.join(', '):'No certified database engine is currently available.'; }
  const appSel=$('cpInstallerDatabase'); if(appSel){ [...appSel.options].forEach(o=>{ if(!o.value)return; const c=map.get(o.value); o.disabled=!(c&&c.available&&c.certified); }); }
}

function syncCustomerImapHost(){const sel=$('cpImapDomainSelect'),host=$('cpImapIncomingHost');if(host){const d=String(sel?.value||'').trim().toLowerCase();host.textContent=d?'mail.'+d:'mail.your-domain'}}
let cpActiveMailDomainConfig='';
function cpMailConfigInstructions(c){const rows=(c.services||[]).filter(x=>x.enabled&&x.id!=='smtp-25');let text=`Mail account settings for ${c.domain}\n\nUsername: ${c.username_format}\nPassword: ${c.password_format}\n\n`;for(const x of rows){text+=`${x.protocol} ${x.direction==='outgoing'?'(Outgoing)':'(Incoming)'}\nServer: ${x.server}\nPort: ${x.port}\nSecurity: ${x.security}\nAuthentication: ${x.authentication_required?'Required':'Not required'}${x.authentication?' — '+x.authentication:''}\n\n`}if(c.dkim_selector)text+=`DKIM selector: ${c.dkim_selector}\nDKIM DNS name: ${c.dkim_record_name}\n`;return text.trim()}
function cpRenderMailDomainConfig(c){const pre=$('cpMailDomainConfigText'),root=$('cpMailDomainManageServices'),badge=$('cpMailDomainManageBadge'),status=$('cpMailDomainManageStatus'),title=$('cpMailDomainManageTitle');if(title)title.textContent=`${c.domain} mail setup`;if(pre)pre.textContent=cpMailConfigInstructions(c);if(badge){const ok=c.configured&&c.postfix_active&&c.dovecot_active;badge.textContent=ok?'LIVE CONFIG':'NEEDS ATTENTION';badge.className='status-pill '+(ok?'active':'warning')}if(status)status.textContent=`Mail host ${c.mail_host} · Postfix ${c.postfix_active?'active':'inactive'} · Dovecot ${c.dovecot_active?'active':'inactive'} · TLS ${c.tls_ready?'ready':'pending'} · checked ${new Date(c.checked_at).toLocaleString()}`;if(root)root.innerHTML=(c.services||[]).map(x=>`<div class="mail-client-service ${x.enabled?'':'disabled'}"><div><span>${esc(x.protocol)} · ${esc(x.direction)}</span><strong>${esc(x.server)}:${Number(x.port||0)}</strong></div><dl><div><dt>Security</dt><dd>${esc(x.security)}</dd></div><div><dt>Authentication</dt><dd>${x.authentication_required?'Required':'No'}${x.authentication?' · '+esc(x.authentication):''}</dd></div><div><dt>Service</dt><dd>${x.enabled?'Enabled':'Disabled'} · ${x.listening?'Listening':'Not listening'}</dd></div><div><dt>Use</dt><dd>${esc(x.purpose||'—')}</dd></div></dl></div>`).join('')}
async function cpOpenMailDomainConfig(domain){cpActiveMailDomainConfig=domain;openModal('cpMailDomainManage');const status=$('cpMailDomainManageStatus');if(status)status.textContent='Reading live Postfix, Dovecot and listener configuration…';try{const r=await api('customer-mail-domain-config&domain='+encodeURIComponent(domain));cpRenderMailDomainConfig(r.configuration||{})}catch(err){toast(err.message,true);if(status)status.textContent=err.message}}

function renderResources() {
  const sites = summary?.sites || [];
  $('cpSitesGrid').innerHTML = sites.length ? `<div class="site-list-head cp-site-list-head"><span>Website</span><span>PHP</span><span>SSL</span><span>Status</span><span>Actions</span></div>`+sites.map(s => `<article class="site-list-row cp-site-list-row"><span class="site-domain-cell"><button type="button" class="site-link-button" data-cp-site-edit="${esc(s.domain)}"><i class="site-dot"></i>${esc(s.domain)}</button><small title="${esc(s.document_root)}">${s.kind==='subdomain'?`Subdomain of ${esc(s.parent_domain||'parent')} · `:''}${s.document_root?esc(s.document_root):'Live vhost not currently detected'}</small></span><span><small>PHP</small><b>${esc(s.php_version)}</b></span><span><small>SSL</small><b>${esc(s.ssl)}</b></span><span><em class="status-pill ${s.status==='active'?'active':'failed'}" title="${esc(s.status_reason||'')}">${esc(s.status==='missing'?'Needs attention':s.status==='active'?'Live':s.status)}</em></span><span><button class="table-btn" data-cp-site-edit="${esc(s.domain)}">Edit</button></span></article>`).join('') : '<div class="empty">No websites yet.</div>';
  table('cpPhpTable',['Domain','PHP version','SSL','Status'],sites.map(s => [`<b>${esc(s.domain)}</b>`,s.status==='active'?`<select class="php-select cp-php" data-domain="${esc(s.domain)}"><option ${s.php_version==='8.5'?'selected':''}>8.5</option><option ${s.php_version==='8.4'?'selected':''}>8.4</option><option ${s.php_version==='8.3'?'selected':''}>8.3</option><option ${s.php_version==='8.2'?'selected':''}>8.2</option></select>`:'<small>Unavailable until detected</small>',esc(s.ssl),`<em class="status-pill active">${esc(s.status)}</em>`]));
  table('cpDatabasesTable',['Database','Engine','Database user','Status / actions'],(resources.databases||[]).map(x => {
    const managed=!!x.managed && !!x.user;
    const actions=managed?`<em class="status-pill active">${esc(x.status)}</em> <button class="table-btn" data-customer-db-manage="${esc(x.name)}">Edit</button> <button class="table-btn" data-customer-db-password="${esc(x.name)}">Set / reset password</button> <button class="table-btn danger" data-customer-db-delete="${esc(x.name)}">Delete</button>`:`<em class="status-pill sim">${esc(x.status||'discovered')}</em>`;
    return [`<b>${esc(x.name)}</b>`,esc(x.engine),esc(x.user||'—'),actions];
  }));
  const mailboxes=resources.mailboxes||[],aliases=resources.mail_aliases||[],mailDomains=(summary?.sites||[]).filter(x=>x.status==='active');if($('cpMailCount'))$('cpMailCount').textContent=mailboxes.length;if($('cpMailDomainCount'))$('cpMailDomainCount').textContent=mailDomains.length;if($('cpForwarderCount'))$('cpForwarderCount').textContent=aliases.length;table('cpMailTable',['Mailbox','Domain','Quota','Status / actions'],mailboxes.map(x => [`<b>${esc(x.address)}</b><small>Local mailbox</small>`,esc(x.domain),`${Number(x.quota_mb||0).toLocaleString()} MB`,`<em class="status-pill active">${esc(x.status||'active')}</em> <span class="row-actions"><button type="button" class="table-btn" data-customer-mailbox-edit="${esc(x.address)}">Edit</button><button type="button" class="table-btn danger" data-customer-mailbox-delete="${esc(x.address)}">Delete</button></span>`]));
  table('cpDnsTable',['Domain','DNSSEC','Records','Source'],(resources.zones||[]).map(x => [`<b>${esc(x.domain)}</b>`,x.dnssec?'Enabled':'Off',String((x.records||[]).length),esc(x.source||'Privora state')]));
  const certs=resources.certificates||[];if($('cpActiveCertificateCount'))$('cpActiveCertificateCount').textContent=certs.length;table('cpSslTable',['Domain','Issuer','Expires','Days left','Renewal','Status'],certs.map(x => [`<b>${esc(x.domain)}</b>`,esc(x.provider),x.expires_at?new Date(x.expires_at).toLocaleDateString():'—',Number.isFinite(Number(x.days_remaining))?String(x.days_remaining):'—',x.auto_renew?'Automatic':'Manual',`<em class="status-pill ${x.status==='valid'?'active':'failed'}">${esc(String(x.status||'unknown').toUpperCase())}</em>`]));refreshCustomerAutoSSLDomainSelector();
  table('cpBackupsTable',['Backup','Scope','Resource','Integrity / action'],(resources.backups||[]).map(x => [`<b>${esc(x.id)}</b><small>${x.sha256?esc(x.sha256.slice(0,12))+'…':'legacy'}</small>`,esc(x.scope),esc(x.resource),`${x.sha256?'<em class="status-pill active">SHA-256</em>':'<em class="status-pill sim">LEGACY</em>'} ${x.verified_at?'<em class="status-pill active">VERIFIED</em>':''} ${x.sha256?`<button class="table-btn" data-cpv7-backup-verify="${esc(x.id)}">Verify</button>`:''} ${x.scope==='site'&&x.sha256?`<button class="table-btn danger" data-customer-backup-restore="${esc(x.id)}" data-backup-resource="${esc(x.resource)}">Restore</button>`:''}`]));
  table('cpSftpTable',['User','Root','Auth','Status'],(resources.sftp_accounts||[]).map(x => [`<b>${esc(x.username)}</b>`,esc(x.root),esc(x.auth),`<em class="status-pill active">${esc(x.status)}</em>`]));
  table('cpAppsTable',['Application','Domain','Runtime','Status'],(resources.applications||[]).map(x => [`<b>${esc(x.type)}</b>`,esc(x.domain),esc(x.runtime),`<em class="status-pill active">${esc(x.status)}</em>`]));
  table('cpInstallsTable',['Application','Domain','Path','Status'],(resources.app_installs||[]).map(x => [`<b>${esc(x.name)}</b>`,esc(x.domain),esc(x.path),`<em class="status-pill sim">${esc(x.status)}</em>`]));
  table('cpCronTable',['Schedule','Command','Status','Next'],(resources.cron_jobs||[]).map(x => [`<b>${esc(x.schedule)}</b>`,esc(x.command),`<em class="status-pill active">${esc(x.status)}</em>`,esc((x.next_run||'').slice(0,16))]));
  table('cpDeployTable',['Kind','Domain','Branch','Status'],(resources.deployments||[]).map(x => [`<b>${esc(x.kind)}</b>`,esc(x.domain),esc(x.branch),`<em class="status-pill sim">${esc(x.status)}</em>`]));
  table('cpAliasesTable',['Forwarder','Destination','Status / actions'],aliases.map(x => [`<b>${esc(x.address)}</b>`,esc(x.destination),`<em class="status-pill active">${esc(x.status||'active')}</em> <span class="row-actions"><button type="button" class="table-btn" data-customer-alias-edit="${esc(x.address)}">Edit</button><button type="button" class="table-btn danger" data-customer-alias-delete="${esc(x.address)}">Delete</button></span>`]));
  table('cpMailDomainsTable',['Domain','Mail server','Security','Status / manage'],(resources.mail_domains||[]).map(x => [`<b>${esc(x.domain)}</b>`,esc(x.mail_host||('mail.'+x.domain)),`${x.tls_ready?'TLS ✓':'TLS pending'} · ${x.dkim?'DKIM ✓':'DKIM pending'} · ${x.spf?'SPF ✓':'SPF pending'} · DMARC ${esc(x.dmarc)}`,`${esc(x.status||'pending')} <span class="row-actions"><button class="table-btn" type="button" data-cp-mail-domain-manage="${esc(x.domain)}">Manage / Setup</button><button class="table-btn danger" type="button" data-cp-mail-domain-auth-delete="${esc(x.domain)}">Remove authentication</button></span>`]));
  const dovecot=(resources.host_capabilities?.capabilities||[]).find(x=>x.name==='dovecot'),imapBadge=$('cpImapServiceBadge'),imapStatus=$('cpImapServiceStatus');if(imapBadge){const ready=!!dovecot?.available&&!!dovecot?.certified;imapBadge.textContent=ready?'IMAP READY':dovecot?.available?'DETECTED':'NOT READY';imapBadge.className='status-pill '+(ready?'active':'warning')}if(imapStatus)imapStatus.textContent=dovecot?.available?`Dovecot detected${dovecot.certified?' and Privora-certified':''}. Use mail.<domain>, port 993, SSL/TLS, and your full email address as the username.`:'Dovecot is not currently detected. Configure / Repair IMAP for the selected domain.';syncCustomerImapHost();
  table('cpStagingTable',['Production','Staging','Status'],(resources.staging||[]).map(x => [`<b>${esc(x.production_domain)}</b>`,esc(x.staging_domain),`<em class="status-pill sim">${esc(x.status)}</em>`]));
  renderAppCatalog(); renderControlTables(); renderDatabaseEngines(); renderPhpMyAdminAvailability(); renderWebmailAvailability(); renderCustomerRuntimeAvailability(); renderCustomerExtensionCatalog(); applyFeatureVisibility();
  if($('securitySslCount'))$('securitySslCount').textContent = (resources.certificates || []).length;
  if($('securityIsolationStatus')){const iso=(resources.isolation||[])[0];$('securityIsolationStatus').textContent=iso?`Namespaces ${iso.namespaces?'on':'off'} · cgroups ${iso.cgroups?'on':'off'} · private tmp ${iso.private_tmp?'on':'off'}`:'No isolation profile recorded.';}
  if($('securityControlStatus')){const blocks=controls('ip_block').length,keys=controls('ssh_key').length;$('securityControlStatus').textContent=`${blocks} IP block${blocks===1?'':'s'} · ${keys} SSH public key${keys===1?'':'s'}`;}
  renderSummary(); fillDomainInputs(); fillSubdomainParents(); upgradeCustomerDomainInputs(); refreshCustomerPhpSelectors(); refreshPhpSettingChoices();
}

const CP_PREF_KEY='privora.customer.preferences.v1';
const cpPrefDefaults={theme:'light',density:'comfortable',groups:'expanded',table_density:'standard',motion:'normal'};
function readCustomerPrefs(){try{return {...cpPrefDefaults,...JSON.parse(localStorage.getItem(CP_PREF_KEY)||'{}')}}catch(_){return {...cpPrefDefaults}}}
function cpResolvedTheme(v){if(v!=='system')return v;return matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'}
function applyCustomerPrefs(prefs=readCustomerPrefs()){
  document.body.classList.toggle('ui-customer-dark',cpResolvedTheme(prefs.theme)==='dark');
  document.body.classList.toggle('ui-density-compact',prefs.density==='compact');
  document.body.classList.toggle('ui-table-compact',prefs.table_density==='compact');
  document.body.classList.toggle('ui-motion-reduced',prefs.motion==='reduced');
  document.querySelectorAll('.tool-group').forEach(g=>g.classList.toggle('tool-group-collapsed',prefs.groups==='collapsed'));
}
function syncCustomerPreferenceForm(){const f=$('customerPreferencesForm'),p=readCustomerPrefs();if(!f)return;for(const [k,v] of Object.entries(p))if(f.elements[k])f.elements[k].value=v}

async function refreshCustomerMfa(){
  const badge=$('cpMfaBadge'),status=$('cpMfaStatus'),begin=$('cpMfaBegin'),enroll=$('cpMfaEnrollment'),disable=$('cpMfaDisableForm');
  if(!badge||!status)return;
  try{
    const d=await api('mfa-status');
    const available=!!d.available,enabled=!!d.enabled,pending=!!d.pending;
    badge.textContent=!available?'UNAVAILABLE':enabled?'ENABLED':pending?'SETUP PENDING':'NOT ENABLED';
    badge.className='status-pill '+(!available?'failed':enabled?'active':pending?'warning':'sim');
    status.textContent=!available?'Panel encryption is not configured, so authenticator enrollment is unavailable.':enabled?'Two-factor authentication is enabled for this hosting-panel account.':pending?'Authenticator enrollment is pending confirmation.':'Two-factor authentication is not enabled. Add an authenticator app for stronger panel sign-in protection.';
    if(begin){begin.hidden=!available||enabled;begin.textContent=pending?'Restart authenticator setup':'Set up authenticator';}
    if(disable)disable.hidden=!enabled;
    if(enroll&&!pending)enroll.hidden=true;
  }catch(err){badge.textContent='STATUS ERROR';badge.className='status-pill failed';status.textContent=err.message;}
}
$('cpMfaBegin')?.addEventListener('click',async e=>{const b=e.currentTarget;b.disabled=true;try{const d=await api('mfa-begin',{method:'POST',data:{}});$('cpMfaSecret').value=d.secret||'';$('cpMfaUri').value=d.otpauth_uri||'';$('cpMfaEnrollment').hidden=false;$('cpMfaConfirmForm')?.elements?.code?.focus();toast('Authenticator setup started. Enter the current code to finish.');await refreshCustomerMfa()}catch(err){toast(err.message,true)}finally{b.disabled=false}});
$('cpMfaConfirmForm')?.addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,b=f.querySelector('button[type="submit"]');b.disabled=true;try{await api('mfa-confirm',{method:'POST',data:{code:String(f.elements.code.value||'').trim()}});toast('Two-factor authentication enabled');f.reset();$('cpMfaEnrollment').hidden=true;await refreshCustomerMfa()}catch(err){toast(err.message,true)}finally{b.disabled=false}});
$('cpMfaDisableForm')?.addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget;if(!confirm('Disable two-factor authentication for this hosting-panel account?'))return;const b=f.querySelector('button[type="submit"]');b.disabled=true;try{await api('mfa-disable',{method:'POST',data:{password:f.elements.password.value,code:String(f.elements.code.value||'').trim()}});toast('Two-factor authentication disabled');f.reset();await refreshCustomerMfa()}catch(err){toast(err.message,true)}finally{b.disabled=false}});

function enhanceCustomerToolGroups(){document.querySelectorAll('.tool-group').forEach(group=>{const head=group.querySelector('.tool-group-head');if(!head||head.querySelector('.tool-group-toggle'))return;const b=document.createElement('button');b.type='button';b.className='tool-group-toggle';b.textContent='⌄';b.title='Expand or collapse';b.addEventListener('click',()=>group.classList.toggle('tool-group-collapsed'));head.appendChild(b)})}
function customerPhpVersions(){const rows=resources.php_runtimes||[];const v=rows.filter(x=>x.fpm&&(x.switchable||x.fpm_active)).map(x=>String(x.version));return v.length?v:['8.5','8.4','8.3','8.2']}
function refreshCustomerPhpSelectors(){const versions=customerPhpVersions();document.querySelectorAll('#cpSitePhpVersion,#cpSubdomainForm select[name="php_version"]').forEach(sel=>{const cur=sel.value;sel.innerHTML=versions.map(v=>`<option value="${esc(v)}">PHP ${esc(v)}</option>`).join('');sel.value=versions.includes(cur)?cur:(versions.includes('8.4')?'8.4':versions[0])})}
function upgradeCustomerDomainInputs(){fillDomainInputs()}
const phpSettingChoices={
 memory_limit:[['128M','128 MB'],['256M','256 MB'],['512M','512 MB'],['1G','1 GB'],['2G','2 GB']],
 upload_max_filesize:[['16M','16 MB'],['32M','32 MB'],['64M','64 MB'],['128M','128 MB'],['256M','256 MB'],['512M','512 MB']],
 post_max_size:[['32M','32 MB'],['64M','64 MB'],['128M','128 MB'],['256M','256 MB'],['512M','512 MB'],['1G','1 GB']],
 max_execution_time:[['30','30 seconds'],['60','1 minute'],['120','2 minutes'],['300','5 minutes'],['600','10 minutes']],
 max_input_vars:[['1000','1,000'],['2000','2,000'],['3000','3,000'],['5000','5,000'],['10000','10,000']],
 display_errors:[['Off','Off — recommended'],['On','On — development only']],
 'opcache.enable':[['1','Enabled'],['0','Disabled']]
};
function refreshPhpSettingChoices(){const setting=document.querySelector('[data-cp-view="php-options"] select[name="name"]'),value=$('cpPhpSettingValue');if(!setting||!value)return;const choices=phpSettingChoices[setting.value]||[['','Select value']];const cur=value.value;value.innerHTML=choices.map(([v,l])=>`<option value="${esc(v)}">${esc(l)}</option>`).join('');if(choices.some(x=>x[0]===cur))value.value=cur;const hint=$('cpPhpSettingValueHint');if(hint)hint.textContent=`Validated presets for ${setting.value}.`}
document.querySelector('[data-cp-view="php-options"] select[name="name"]')?.addEventListener('change',refreshPhpSettingChoices);
$('customerPreferencesForm')?.addEventListener('submit',e=>{e.preventDefault();const prefs={...readCustomerPrefs(),...Object.fromEntries(new FormData(e.currentTarget))};localStorage.setItem(CP_PREF_KEY,JSON.stringify(prefs));applyCustomerPrefs(prefs);toast('Panel preferences saved')});
$('resetCustomerPreferences')?.addEventListener('click',()=>{localStorage.removeItem(CP_PREF_KEY);syncCustomerPreferenceForm();applyCustomerPrefs(cpPrefDefaults);toast('Panel preferences reset')});
if(matchMedia){try{matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(readCustomerPrefs().theme==='system')applyCustomerPrefs()})}catch(_){}}
function customerSiteByDomain(domain){const d=String(domain||'').toLowerCase();return (summary?.sites||[]).find(s=>String(s.domain||'').toLowerCase()===d)||null}
function openCustomerSiteEditor(domain){const site=customerSiteByDomain(domain);if(!site)return;const versions=customerPhpVersions();$('cpSiteEditTitle').textContent=`Edit ${site.domain}`;$('cpSiteEditDomain').value=site.domain;$('cpSiteEditDomainDisplay').value=site.domain;$('cpSiteEditRoot').value=site.document_root||'Not currently detected';$('cpSiteEditDNS').textContent=site.dns||'external';$('cpSiteEditSSL').textContent=site.ssl||'unknown';$('cpSiteEditKind').textContent=site.kind==='subdomain'?`Subdomain of ${site.parent_domain||'parent'}`:'Website';$('cpSiteEditDetection').textContent=site.status_reason||(site.status==='active'?'Live':'Needs attention');$('cpSiteEditStatus').textContent=site.status==='active'?'Live':'Needs attention';$('cpSiteEditStatus').className='status-pill '+(site.status==='active'?'active':'failed');const php=$('cpSiteEditPhp');php.innerHTML=versions.map(v=>`<option value="${esc(v)}">PHP ${esc(v)}</option>`).join('');if(versions.includes(String(site.php_version)))php.value=String(site.php_version);php.disabled=site.status!=='active';$('cpSiteEditOpen').dataset.domain=site.domain;$('cpSiteEditDNSOpen').dataset.domain=site.domain;$('cpSiteEditAutoSSL').dataset.domain=site.domain;$('cpSiteEditModal').classList.add('open')}

let fmPath='.', fmItems=[], fmSearchMode=false;
let accountAnalytics=null, accountResourceLimit=null, analyticsLoadedAt=0;
function fmJoin(dir,name){return !dir||dir==='.'?name:`${dir.replace(/\/+$/,'')}/${name}`}
function fmParent(path){if(!path||path==='.')return '.';const a=path.split('/').filter(Boolean);a.pop();return a.length?a.join('/'):'.'}
function fmBase(path){const a=String(path||'').split('/').filter(Boolean);return a[a.length-1]||''}
function fmRenderBreadcrumbs(){const root=$('fmBreadcrumbs');if(!root)return;const parts=fmPath==='.'?[]:fmPath.split('/').filter(Boolean);let cur='.';root.innerHTML=`<button type="button" data-fm-path=".">Home</button>`+parts.map(part=>{cur=cur==='.'?part:`${cur}/${part}`;return `<span>›</span><button type="button" data-fm-path="${esc(cur)}">${esc(part)}</button>`}).join('');if($('fmCurrentPath'))$('fmCurrentPath').textContent=`/home/${summary?.account?.username||''}/${fmPath==='.'?'':fmPath}`}
function fmIcon(x){if(x.type==='directory')return '📁';const n=String(x.name||'').toLowerCase();if(n.endsWith('.zip'))return '🗜️';if(/\.(png|jpe?g|gif|webp|svg)$/.test(n))return '🖼️';if(/\.(php|js|css|html?|json|xml|yml|yaml|md|txt|env|conf|ini)$/.test(n))return '📄';return '📦'}
function fmTextEditable(name){const n=String(name||'').toLowerCase();return /\.(txt|md|markdown|html?|css|scss|less|js|mjs|cjs|ts|tsx|jsx|json|xml|ya?ml|toml|ini|conf|config|env|htaccess|php|phtml|py|rb|pl|sh|bash|zsh|fish|go|rs|c|h|cc|cpp|cxx|hpp|java|sql|log)$/.test(n)||/(^|\/)(dockerfile|makefile|caddyfile|nginx\.conf)$/.test(n)}
function fmRenderRows(rows,search=false){const root=$('fmFilesTable');if(!root)return;fmItems=rows||[];if($('fmItemCount'))$('fmItemCount').textContent=`${fmItems.length} item${fmItems.length===1?'':'s'}`;if(!fmItems.length){root.innerHTML='<div class="empty">No files found.</div>';return}root.innerHTML=`<div class="fm-row fm-head"><span><input type="checkbox" data-fm-select-all aria-label="Select all visible items"></span><span>Name</span><span>Size</span><span>Modified</span><span>Permissions</span><span>Actions</span></div>`+fmItems.map(x=>{const path=x.path||fmJoin(fmPath,x.name),isDir=x.type==='directory',zip=String(x.name||'').toLowerCase().endsWith('.zip');return `<div class="fm-row" data-fm-row="${esc(path)}"><span><input type="checkbox" data-fm-select="${esc(path)}" aria-label="Select ${esc(x.name)}"></span><span class="fm-name"><button type="button" data-fm-open="${esc(path)}" data-fm-type="${esc(x.type)}"><i>${fmIcon(x)}</i><b>${esc(search?path:x.name)}</b></button><small>${esc(x.type)}</small></span><span>${isDir?'—':fmtBytes(x.size)}</span><span>${x.modified?new Date(x.modified).toLocaleString():'—'}</span><span><code>${esc(x.mode||'—')}</code></span><span class="fm-row-actions">${!isDir?`${fmTextEditable(x.name)?`<button type="button" title="Edit" data-fm-action="edit" data-path="${esc(path)}">✏️</button>`:''}<button type="button" title="Download" data-fm-action="download" data-path="${esc(path)}">⬇️</button>`:''}<button type="button" title="Rename / move" data-fm-action="rename" data-path="${esc(path)}">↪️</button><button type="button" title="Copy" data-fm-action="copy" data-path="${esc(path)}">📋</button><button type="button" title="Permissions" data-fm-action="chmod" data-path="${esc(path)}">🔐</button><button type="button" title="Compress" data-fm-action="archive" data-path="${esc(path)}">🗜️</button>${zip?`<button type="button" title="Extract" data-fm-action="extract" data-path="${esc(path)}">📂</button>`:''}<button type="button" title="Delete" class="danger" data-fm-action="delete" data-path="${esc(path)}">🗑️</button></span></div>`}).join('');fmUpdateSelection()}
function fmSelectedPaths(){return [...document.querySelectorAll('[data-fm-select]:checked')].map(x=>x.dataset.fmSelect).filter(Boolean)}
function fmUpdateSelection(){const selected=fmSelectedPaths(),all=[...document.querySelectorAll('[data-fm-select]')],master=document.querySelector('[data-fm-select-all]');if($('fmSelection'))$('fmSelection').textContent=`${selected.length} selected`;if($('fmDeleteSelected'))$('fmDeleteSelected').disabled=selected.length===0;if(master){master.checked=all.length>0&&selected.length===all.length;master.indeterminate=selected.length>0&&selected.length<all.length}}
async function fmDeleteSelected(){const paths=fmSelectedPaths();if(!paths.length)return;if(!confirm(`Permanently delete ${paths.length} selected item${paths.length===1?'':'s'}?\nDirectories are removed recursively.`))return;let failed=[];for(const path of paths){try{await api('customer-file-delete',{method:'POST',data:{path}})}catch(e){failed.push(`${path}: ${e.message}`)}}if(failed.length)toast(`${paths.length-failed.length} deleted; ${failed.length} failed.`,true);else toast(`${paths.length} selected item${paths.length===1?'':'s'} deleted`);await refreshFiles(fmPath)}
async function refreshFiles(path=fmPath){try{fmPath=path||'.';fmSearchMode=false;const d=await api(`customer-files&path=${encodeURIComponent(fmPath)}`);fmRenderBreadcrumbs();fmRenderRows(d.files||[])}catch(e){toast(e.message,true)}}
async function fmOpenEditor(path,newFile=false){try{let content='';if(!newFile){const d=await api(`customer-file-read&path=${encodeURIComponent(path)}`);content=d.file?.content??''}$('fmEditorPath').value=path;$('fmEditorContent').value=content;$('fmEditorTitle').textContent=newFile?'Create file':`Edit ${fmBase(path)}`;$('fmEditorModal').classList.add('open')}catch(e){toast(e.message,true)}}
function arrayBufferToBase64(buffer){const bytes=new Uint8Array(buffer);let binary='';const size=0x8000;for(let i=0;i<bytes.length;i+=size)binary+=String.fromCharCode(...bytes.subarray(i,Math.min(i+size,bytes.length)));return btoa(binary)}
function base64ToBlob(b64,type='application/octet-stream'){const bin=atob(b64),arr=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i);return new Blob([arr],{type})}
async function fmAction(action,path){try{
  if(action==='edit'){await fmOpenEditor(path,false);return}
  if(action==='download'){const d=await api(`customer-file-read&path=${encodeURIComponent(path)}&download=1`);const blob=base64ToBlob(d.file?.content_base64||'');const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=fmBase(path);document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);return}
  if(action==='rename'){const to=prompt('Move or rename to this account-relative path:',path);if(!to||to===path)return;await api('customer-file-rename',{method:'POST',data:{from:path,to}});toast('File moved / renamed')}
  else if(action==='copy'){const to=prompt('Copy to this account-relative path:',`${fmParent(path)}/${fmBase(path)}-copy`.replace(/^\.\//,''));if(!to)return;await api('customer-file-copy',{method:'POST',data:{from:path,to}});toast('Copy completed')}
  else if(action==='chmod'){const mode=prompt('Set octal permissions (examples: 0644 file, 0755 directory):','0644');if(!mode)return;await api('customer-file-chmod',{method:'POST',data:{path,mode}});toast('Permissions updated')}
  else if(action==='archive'){const dest=prompt('Create ZIP archive at:',`${fmParent(path)==='.'?'':fmParent(path)+'/'}${fmBase(path)}.zip`);if(!dest)return;await api('customer-file-archive',{method:'POST',data:{source:path,destination:dest}});toast('ZIP archive created')}
  else if(action==='extract'){const dest=prompt('Extract into this directory:',fmParent(path));if(dest===null)return;await api('customer-file-extract',{method:'POST',data:{archive:path,destination:dest||'.'}});toast('Archive extracted')}
  else if(action==='delete'){if(!confirm(`Permanently delete ${path}?\nDirectories are removed recursively.`))return;await api('customer-file-delete',{method:'POST',data:{path}});toast('Deleted')}
  await refreshFiles(fmPath)
}catch(e){toast(e.message,true)}}
async function fmRunSearch(){const q=$('fmSearchInput')?.value.trim()||'';if(!q){await refreshFiles(fmPath);return}try{const d=await api(`customer-file-search&q=${encodeURIComponent(q)}`);fmSearchMode=true;fmRenderRows(d.files||[],true);if($('fmCurrentPath'))$('fmCurrentPath').textContent=`Search: ${q}`}catch(e){toast(e.message,true)}}
function usagePercent(used,limit){used=Number(used||0);limit=Number(limit||0);return limit>0?Math.max(0,Math.min(100,used/limit*100)):0}
function renderUsageBar(label,used,limit,usedText,limitText){return `<div class="usage-bar"><div><span>${esc(label)}</span><b>${esc(usedText)}${limit?` / ${esc(limitText)}`:''}</b></div><progress max="100" value="${usagePercent(used,limit)}"></progress></div>`}
function renderMiniDaily(rows){const root=$('analyticsDaily');if(!root)return;if(!rows?.length){root.innerHTML='<div class="empty">No access-log traffic yet.</div>';return}const max=Math.max(...rows.map(x=>Number(x.requests||0)),1);root.innerHTML=rows.map(x=>`<div class="mini-bar-row"><span>${esc(x.date.slice(5))}</span><div><i style="width:${Math.max(2,Number(x.requests||0)/max*100)}%"></i></div><b>${Number(x.requests||0).toLocaleString()}</b></div>`).join('')}
function renderAccountAnalytics(){const a=accountAnalytics;if(!a)return;const u=a.usage||{},limit=accountResourceLimit||{},diskLimit=Number(limit.disk_gb||summary?.package?.disk_gb||0)*1024**3,bwLimit=Number(limit.bandwidth_gb||0)*1024**3;
  if($('railServerIPv4'))$('railServerIPv4').textContent=a.ipv4||'Not detected';if($('railFileCount'))$('railFileCount').textContent=Number(u.file_count||0).toLocaleString();if($('railProcessCount'))$('railProcessCount').textContent=Number(u.process_count||0).toLocaleString();if($('statDisk'))$('statDisk').textContent=diskLimit?`${fmtBytes(u.disk_bytes)} / ${fmtBytes(diskLimit)}`:fmtBytes(u.disk_bytes);if($('diskQuota'))$('diskQuota').value=usagePercent(u.disk_bytes,diskLimit);if($('statBandwidth'))$('statBandwidth').textContent=bwLimit?`${fmtBytes(a.bandwidth_bytes)} / ${fmtBytes(bwLimit)}`:fmtBytes(a.bandwidth_bytes);if($('bandwidthQuota'))$('bandwidthQuota').value=usagePercent(a.bandwidth_bytes,bwLimit);
  if($('diskUsageBytes'))$('diskUsageBytes').textContent=fmtBytes(u.disk_bytes);if($('diskUsageLimit'))$('diskUsageLimit').textContent=diskLimit?`of ${fmtBytes(diskLimit)} package limit`:'No disk limit configured';if($('diskUsageBar'))$('diskUsageBar').value=usagePercent(u.disk_bytes,diskLimit);if($('diskUsageFiles'))$('diskUsageFiles').textContent=Number(u.file_count||0).toLocaleString();if($('diskUsageDirs'))$('diskUsageDirs').textContent=Number(u.directory_count||0).toLocaleString();if($('diskUsageScan'))$('diskUsageScan').textContent=u.scan_limited?'Storage scan reached its safety cap; total may be partial.':'Live account storage scan completed.';
  if($('metricDiskUsed'))$('metricDiskUsed').textContent=fmtBytes(u.disk_bytes);if($('metricDiskLimit'))$('metricDiskLimit').textContent=diskLimit?`of ${fmtBytes(diskLimit)} limit`:'account home';if($('metricMemoryUsed'))$('metricMemoryUsed').textContent=fmtBytes(u.memory_bytes);if($('metricProcesses'))$('metricProcesses').textContent=Number(u.process_count||0).toLocaleString();if($('metricCpuTime'))$('metricCpuTime').textContent=`${Number(u.cpu_minutes||0).toFixed(1)} min`;if($('metricFiles'))$('metricFiles').textContent=Number(u.file_count||0).toLocaleString();if($('metricDirs'))$('metricDirs').textContent=`${Number(u.directory_count||0).toLocaleString()} directories`;if($('metricBandwidth'))$('metricBandwidth').textContent=fmtBytes(a.bandwidth_bytes);if($('metricBandwidthPeriod'))$('metricBandwidthPeriod').textContent=a.access_log_period||'current log period';if($('metricScanNote'))$('metricScanNote').textContent=(u.scan_limited||a.log_scan_limited)?'Usage scan reached a safety cap; values may be partial.':'Live account scan completed.';if($('metricLimitBars'))$('metricLimitBars').innerHTML=[renderUsageBar('Disk space',u.disk_bytes,diskLimit,fmtBytes(u.disk_bytes),fmtBytes(diskLimit)),renderUsageBar('Bandwidth',a.bandwidth_bytes,bwLimit,fmtBytes(a.bandwidth_bytes),fmtBytes(bwLimit)),renderUsageBar('Memory',u.memory_bytes,Number(limit.memory_mb||0)*1024**2,fmtBytes(u.memory_bytes),limit.memory_mb?`${limit.memory_mb} MB`:'—'),renderUsageBar('Processes',u.process_count,limit.pids||0,String(u.process_count||0),String(limit.pids||'—'))].join('');
  [['visitorUnique',a.unique_visitors],['visitorRequests',a.requests],['visitor4xx',a.http_4xx],['visitor5xx',a.http_5xx],['bandwidthRequests',a.requests],['bandwidthVisitors',a.unique_visitors],['error4xx',a.http_4xx],['error5xx',a.http_5xx],['errorEvents',(a.recent_errors||[]).length]].forEach(([id,v])=>{if($(id))$(id).textContent=Number(v||0).toLocaleString()});if($('bandwidthTotal'))$('bandwidthTotal').textContent=fmtBytes(a.bandwidth_bytes);if($('bandwidthPeriod'))$('bandwidthPeriod').textContent=a.access_log_period||'current log period';if($('bandwidthLimit'))$('bandwidthLimit').textContent=bwLimit?fmtBytes(bwLimit):'Not configured';if($('errorScanState'))$('errorScanState').textContent=a.log_scan_limited?'Partial':'Complete';
  table('visitorTable',['Time','Domain','Visitor','Request','Status','Referrer'],(a.recent_visitors||[]).slice(0,100).map(x=>[esc(x.time?new Date(x.time).toLocaleString():'—'),`<b>${esc(x.domain)}</b>`,esc(x.ip),`${esc(x.method)} ${esc(x.path)}`,`<em class="status-pill ${x.status>=500?'failed':x.status>=400?'warning':'active'}">${esc(x.status)}</em>`,esc(x.referer==='-'?'Direct':x.referer)]));
  table('accessLogTable',['Time','Domain','IP','Method / URL','Status','Bytes'],(a.recent_visitors||[]).map(x=>[esc(x.time?new Date(x.time).toLocaleString():'—'),esc(x.domain),esc(x.ip),`<b>${esc(x.method)}</b> ${esc(x.path)}`,String(x.status),fmtBytes(x.bytes)]));
  table('errorTable',['Time','Domain','Source','Detail'],(a.recent_errors||[]).map(x=>[esc(x.time?new Date(x.time).toLocaleString():'—'),esc(x.domain),esc(x.source),esc(x.detail)]));
  table('bandwidthDomains',['Domain','Requests','Visitors','Bandwidth','Errors'],(a.domains||[]).map(x=>[`<b>${esc(x.domain)}</b>`,Number(x.requests||0).toLocaleString(),Number(x.visitors||0).toLocaleString(),fmtBytes(x.bytes),Number(x.errors||0).toLocaleString()]));
  table('analyticsTopPaths',['Path','Requests','Bandwidth'],(a.top_paths||[]).map(x=>[`<b>${esc(x.name)}</b>`,Number(x.count||0).toLocaleString(),fmtBytes(x.bytes)]));table('analyticsReferrers',['Referrer','Requests'],(a.top_referrers||[]).map(x=>[`<b>${esc(x.name)}</b>`,Number(x.count||0).toLocaleString()]));table('analyticsStatus',['HTTP status','Requests'],(a.status_codes||[]).map(x=>[`<b>${esc(x.name)}</b>`,Number(x.count||0).toLocaleString()]));renderMiniDaily(a.daily||[]);
}
async function loadAccountAnalytics(force=false){if(!force&&accountAnalytics&&Date.now()-analyticsLoadedAt<30000){renderAccountAnalytics();return accountAnalytics}const d=await api('customer-analytics');accountAnalytics=d.analytics||{};accountResourceLimit=d.resource_limit||null;analyticsLoadedAt=Date.now();renderAccountAnalytics();return accountAnalytics}
async function loadDiskUsage(force=false){if(!force&&accountAnalytics&&Date.now()-analyticsLoadedAt<30000){renderAccountAnalytics();return accountAnalytics}const d=await api('customer-disk-usage');accountAnalytics=d.analytics||{};accountResourceLimit=d.resource_limit||null;analyticsLoadedAt=Date.now();renderAccountAnalytics();return accountAnalytics}

async function refresh() {
  try { [summary, resources] = await Promise.all([api('customer-summary'), api('customer-resources')]); renderResources(); }
  catch (e) { toast(e.message, true); }
}
function nav(name) {
  document.querySelectorAll('.cp-view').forEach(v => v.classList.toggle('active', v.dataset.cpView === name));
  history.replaceState(null,'','#'+name); window.scrollTo({top:0,behavior:'instant'});
  if (name === 'files') refreshFiles(fmPath);
  if (name === 'apps' || name === 'php-extensions') loadCustomerComponents().catch(err=>toast(err.message,true));
  if (name === 'disk-usage') loadDiskUsage().catch(err=>toast(err.message,true));
  if (['metrics','visitors','analytics','bandwidth','access-logs','errors'].includes(name)) loadAccountAnalytics().catch(err=>toast(err.message,true));
  if (name === 'account-security') refreshCustomerMfa();
}

document.addEventListener('click', async e => {
  const fmPathButton=e.target.closest('[data-fm-path]');if(fmPathButton){await refreshFiles(fmPathButton.dataset.fmPath||'.');return}
  const fmOpen=e.target.closest('[data-fm-open]');if(fmOpen){const path=fmOpen.dataset.fmOpen,type=fmOpen.dataset.fmType;if(type==='directory')await refreshFiles(path);else await fmOpenEditor(path,false);return}
  const fmAct=e.target.closest('[data-fm-action]');if(fmAct){await fmAction(fmAct.dataset.fmAction,fmAct.dataset.path);return}
  const metricRefresh=e.target.closest('[data-metrics-refresh]');if(metricRefresh){metricRefresh.disabled=true;try{const active=document.querySelector('.cp-view.active')?.dataset.cpView||'';if(active==='disk-usage'){await loadDiskUsage(true);toast('Disk usage refreshed')}else{await loadAccountAnalytics(true);toast('Metrics refreshed')}}catch(err){toast(err.message,true)}finally{metricRefresh.disabled=false}return}
  const extFilter=e.target.closest('[data-extension-filter]');
  if(extFilter){
    customerExtensionFilter=extFilter.dataset.extensionFilter||'all';
    document.querySelectorAll('[data-extension-filter]').forEach(b=>b.classList.toggle('active',b===extFilter));
    renderCustomerExtensionCatalog(); return;
  }
  const extAction=e.target.closest('[data-customer-ext-action]');
  if(extAction){
    const domain=$('cpExtensionDomain')?.value||'',name=extAction.dataset.extension||'',value=extAction.dataset.customerExtAction||'';
    if(!domain){toast('Choose a website first.',true);return;}
    extAction.disabled=true;
    try{
      await api('customer-control-create',{method:'POST',data:{kind:'php_extension',domain,name,value}});
      toast(`${name} policy set to ${value} for ${domain}`);
      await refresh();
    }catch(err){toast(err.message,true)}finally{extAction.disabled=false}
    return;
  }
  const mailGenerate=e.target.closest('[data-mail-password-generate]');if(mailGenerate){setGeneratedMailPassword(mailGenerate.dataset.mailPasswordGenerate==='customer-edit'?$('cpMailboxEditForm'):$('cpMailboxCreateForm'));return;}
  const mailboxEdit=e.target.closest('[data-customer-mailbox-edit]');if(mailboxEdit){openCustomerMailboxEditor(mailboxEdit.dataset.customerMailboxEdit);return;}
  const mailboxDelete=e.target.closest('[data-customer-mailbox-delete]');if(mailboxDelete){const address=mailboxDelete.dataset.customerMailboxDelete,typed=prompt(`Permanently delete mailbox ${address} and its server-side Maildir?
This cannot be undone. Type the exact email address to continue:`,'');if(typed===null)return;if(typed!==address){toast('Delete cancelled: confirmation did not match.',true);return}mailboxDelete.disabled=true;try{await api('customer-mailbox-delete',{method:'POST',data:{address,confirm_address:typed}});toast(`Mailbox ${address} deleted`);await refresh()}catch(err){toast(err.message,true)}finally{mailboxDelete.disabled=false}return;}
  const aliasEdit=e.target.closest('[data-customer-alias-edit]');if(aliasEdit){openCustomerAliasEditor(aliasEdit.dataset.customerAliasEdit);return;}
  const aliasDelete=e.target.closest('[data-customer-alias-delete]');if(aliasDelete){const address=aliasDelete.dataset.customerAliasDelete,typed=prompt(`Delete forwarder ${address}?
Type the exact forwarder address to continue:`,'');if(typed===null)return;if(typed!==address){toast('Delete cancelled: confirmation did not match.',true);return}aliasDelete.disabled=true;try{await api('customer-mail-alias-delete',{method:'POST',data:{address,confirm_address:typed}});toast(`Forwarder ${address} deleted`);await refresh()}catch(err){toast(err.message,true)}finally{aliasDelete.disabled=false}return;}
  const generate=e.target.closest('[data-db-generate]');
  if(generate){const form=generate.dataset.dbGenerate==='customer-edit'?$('cpDatabaseEditForm'):document.querySelector('form[data-customer-create="customer-database-create"]');setGeneratedDatabasePassword(form);return;}
  const copy=e.target.closest('[data-copy-db-credentials]'); if(copy){await copyCustomerDatabaseCredentials(copy.dataset.copyDbCredentials);return;}
  const dbManage=e.target.closest('[data-customer-db-manage]'); if(dbManage){openCustomerDatabaseEditor(dbManage.dataset.customerDbManage);return;}
  const dbPassword=e.target.closest('[data-customer-db-password]');
  if(dbPassword){
    const name=dbPassword.dataset.customerDbPassword;
    if(!confirm(`Generate a new password for database user on ${name}?\nThe old password will stop working immediately.`))return;
    dbPassword.disabled=true;
    try{const r=await api('customer-database-password',{method:'POST',data:{name,password:'',password_confirm:''}});showCustomerDatabaseCredentials(name,r.credentials||{},'Password reset');toast('Database password reset — save the new credentials now');await refresh();}
    catch(err){toast(err.message,true)} finally{dbPassword.disabled=false} return;
  }
  const dbDelete=e.target.closest('[data-customer-db-delete]');
  if(dbDelete){
    const name=dbDelete.dataset.customerDbDelete,typed=prompt(`Permanently delete database ${name} and its Privora-managed database user?\nThis cannot be undone. Type the exact database name to continue:`,'');
    if(typed===null)return; if(typed!==name){toast('Delete cancelled: confirmation did not match.',true);return;}
    dbDelete.disabled=true;
    try{await api('customer-database-delete',{method:'POST',data:{name,confirm_name:typed}});toast(`Database ${name} and its managed user deleted`);await refresh();}
    catch(err){toast(err.message,true)} finally{dbDelete.disabled=false} return;
  }
  const edit=e.target.closest('[data-cp-site-edit]'); if(edit){openCustomerSiteEditor(edit.dataset.cpSiteEdit);return;}
  const restore = e.target.closest('[data-customer-backup-restore]');
  if (restore) {
    const resource=restore.dataset.backupResource||'';
    const typed=prompt(`Restore ${resource}?\nThe current site is preserved as a rollback copy. Type the exact domain to continue:`,'');
    if (typed===null) return;
    if (typed!==resource) { toast('Restore cancelled: confirmation did not match.',true); return; }
    restore.disabled=true;
    try { const r=await api('customer-backup-restore',{method:'POST',data:{id:restore.dataset.customerBackupRestore,confirm_resource:typed}}); toast(`Restore completed · rollback copy: ${r.restore?.rollback_path||'preserved'}`); await refresh(); }
    catch(err){ toast(err.message,true); }
    finally { restore.disabled=false; }
    return;
  }
  const choose = e.target.closest('[data-install-template]');
  if (choose) {
    nav('app-installer');
    const sel = $('cpInstallerTemplate'); if (sel) sel.value = choose.dataset.installTemplate;
    $('cpInstallerForm')?.scrollIntoView({behavior:'smooth',block:'center'});
    return;
  }
  const n = e.target.closest('[data-cp-nav]'); if (n) { nav(n.dataset.cpNav); return; }
  const m = e.target.closest('[data-cp-modal]'); if (m) { const target=m.dataset.cpModal==='subdomain'?$('cpSubdomainModal'):$('cpSiteModal'); target?.classList.add('open'); return; }
  if (e.target.classList.contains('modal-close') || e.target.classList.contains('modal-cancel') || e.target.id === 'cpSiteModal' || e.target.id === 'cpSubdomainModal' || e.target.id === 'cpSiteEditModal' || e.target.id === 'cpDatabaseEditModal' || e.target.id === 'cpMailboxEditModal' || e.target.id === 'cpAliasEditModal' || e.target.id === 'fmEditorModal') { $('cpSiteModal')?.classList.remove('open'); $('cpSubdomainModal')?.classList.remove('open'); $('cpSiteEditModal')?.classList.remove('open'); $('cpDatabaseEditModal')?.classList.remove('open'); $('cpMailboxEditModal')?.classList.remove('open'); $('cpAliasEditModal')?.classList.remove('open'); $('fmEditorModal')?.classList.remove('open'); }
});
document.addEventListener('change', async e => {
  if (e.target.matches('.cp-php')) {
    try { await api('customer-site-php',{method:'POST',data:{domain:e.target.dataset.domain,version:e.target.value}}); toast('PHP version updated'); await refresh(); }
    catch (err) { toast(err.message,true); await refresh(); }
  }
});
$('cpSiteEditForm')?.addEventListener('submit',async e=>{e.preventDefault();const d=Object.fromEntries(new FormData(e.currentTarget));try{await api('customer-site-php',{method:'POST',data:{domain:d.domain,version:d.version}});toast('Website settings saved');$('cpSiteEditModal').classList.remove('open');await refresh()}catch(err){toast(err.message,true)}});
$('cpDatabaseEditForm')?.addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,d=Object.fromEntries(new FormData(f));if((d.password||'')!==(d.password_confirm||'')){toast('Database passwords do not match.',true);return;}try{const r=await api('customer-database-user',{method:'POST',data:d});showCustomerDatabaseCredentials(d.name,r.credentials||{},'Database access updated');toast('Database access updated — save these credentials now');$('cpDatabaseEditModal')?.classList.remove('open');f.elements.password.value='';f.elements.password_confirm.value='';await refresh()}catch(err){toast(err.message,true)}});
$('cpMailboxEditForm')?.addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,d=Object.fromEntries(new FormData(f));if((d.password||'')!==(d.password_confirm||'')){toast('Mailbox passwords do not match.',true);return}if(d.password&&d.password.length<12){toast('Mailbox password must be at least 12 characters.',true);return}const btn=f.querySelector('button[type="submit"]');btn.disabled=true;try{await api('customer-mailbox-update',{method:'POST',data:{address:d.address,quota_mb:Number(d.quota_mb),password:d.password,password_confirm:d.password_confirm}});toast(`Mailbox ${d.address} updated`);$('cpMailboxEditModal')?.classList.remove('open');await refresh()}catch(err){toast(err.message,true)}finally{btn.disabled=false}});
$('cpAliasEditForm')?.addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,d=Object.fromEntries(new FormData(f)),btn=f.querySelector('button[type="submit"]');btn.disabled=true;try{await api('customer-mail-alias-update',{method:'POST',data:{address:d.address,destination:d.destination}});toast(`Forwarder ${d.address} updated`);$('cpAliasEditModal')?.classList.remove('open');await refresh()}catch(err){toast(err.message,true)}finally{btn.disabled=false}});
$('cpMailSetupCopy')?.addEventListener('click',async()=>{const text=$('cpMailSetupText')?.textContent||'';if(!text)return;try{await navigator.clipboard.writeText(text);toast('Mail settings copied')}catch{toast('Could not copy settings automatically.',true)}});
$('cpSiteEditOpen')?.addEventListener('click',e=>{const d=e.currentTarget.dataset.domain;if(d)window.open(`https://${d}/`,'_blank','noopener')});
$('cpSiteEditDNSOpen')?.addEventListener('click',e=>{$('cpSiteEditModal').classList.remove('open');nav('dns')});
$('cpAutoSSLForm')?.addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,b=f.querySelector('button[type="submit"]'),d=Object.fromEntries(new FormData(f)),original=b.textContent;b.disabled=true;b.textContent='Running AutoSSL…';if($('cpAutoSSLStatus'))$('cpAutoSSLStatus').textContent='Checking DNS and certificate state…';try{const r=await api('customer-ssl-autossl',{method:'POST',data:d});renderCustomerAutoSSLResults(r);toast(`AutoSSL: ${r.issued||0} issued · ${r.skipped||0} already valid · ${r.pending||0} pending DNS · ${r.blocked||0} HTTP blocked · ${r.failed||0} failed`,(r.failed||0)>0||(r.blocked||0)>0);await refresh()}catch(err){if($('cpAutoSSLStatus'))$('cpAutoSSLStatus').textContent='AutoSSL failed: '+err.message;toast(err.message,true)}finally{b.disabled=false;b.textContent=original}});
$('cpSiteEditAutoSSL')?.addEventListener('click',async e=>{const d=e.currentTarget.dataset.domain;if(!d)return;try{const r=await api('customer-ssl-issue',{method:'POST',data:{domain:d}});toast(`${d} AutoSSL: ${r.certificate?.status||r.status||'request completed'}`);await refresh();openCustomerSiteEditor(d)}catch(err){toast(err.message,true)}});
document.querySelector('form[data-customer-create="customer-backup-create"] select[name="scope"]')?.addEventListener('change',refreshCustomerBackupResource);
$('cpSiteForm')?.addEventListener('submit', async e => {
  e.preventDefault(); const d = Object.fromEntries(new FormData(e.currentTarget));
  try { const r=await api('customer-site-create',{method:'POST',data:d}); const ssl=r.ssl?.status||r.site?.ssl||'pending'; toast(`Website created · SSL ${ssl}`); $('cpSiteModal').classList.remove('open'); e.currentTarget.reset(); await refresh(); }
  catch (err) { toast(err.message,true); }
});
$('cpSubdomainParent')?.addEventListener('change', updateCustomerSubdomainPreview);
$('cpSubdomainLabel')?.addEventListener('input', updateCustomerSubdomainPreview);
$('cpSubdomainDocumentRoot')?.addEventListener('input',e=>{e.currentTarget.dataset.mode='custom';updateCustomerSubdomainRootHint()});
$('cpSubdomainUseDefaultRoot')?.addEventListener('click',()=>{const input=$('cpSubdomainDocumentRoot');if(input)input.dataset.mode='default';syncCustomerSubdomainDocumentRoot(true)});
$('cpSubdomainUseParentRoot')?.addEventListener('click',()=>{const input=$('cpSubdomainDocumentRoot');if(input)input.dataset.mode='parent';syncCustomerSubdomainDocumentRoot(true)});
$('cpSubdomainForm')?.addEventListener('submit', async e => {
  e.preventDefault(); const d = Object.fromEntries(new FormData(e.currentTarget));
  if (!d.parent_domain) { toast('Choose the parent website', true); return; }
  try { const r=await api('customer-subdomain-create',{method:'POST',data:d}); const domain=r.site?.domain||`${d.label}.${d.parent_domain}`,ssl=r.ssl?.status||r.site?.ssl||'pending'; toast(`${domain} created · SSL ${ssl}`); $('cpSubdomainModal').classList.remove('open'); e.currentTarget.reset(); if($('cpSubdomainDocumentRoot'))$('cpSubdomainDocumentRoot').dataset.mode='default'; syncCustomerSubdomainDocumentRoot(true); await refresh(); }
  catch (err) { toast(err.message,true); }
});

$('fmEditorForm')?.addEventListener('submit',async e=>{e.preventDefault();const path=$('fmEditorPath').value.trim(),content=$('fmEditorContent').value;try{await api('customer-file-write',{method:'POST',data:{path,content}});toast('File saved');$('fmEditorModal').classList.remove('open');await refreshFiles(fmParent(path))}catch(err){toast(err.message,true)}});
$('fmNewFile')?.addEventListener('click',()=>fmOpenEditor(fmJoin(fmPath,'new-file.txt'),true));
$('fmNewFolder')?.addEventListener('click',async()=>{const name=prompt('New folder name:','new-folder');if(!name)return;try{await api('customer-file-mkdir',{method:'POST',data:{path:fmJoin(fmPath,name)}});toast('Folder created');await refreshFiles(fmPath)}catch(err){toast(err.message,true)}});
$('fmUpload')?.addEventListener('click',()=>$('fmUploadInput')?.click());
$('fmUploadInput')?.addEventListener('change',async e=>{const files=[...e.target.files];for(const file of files){if(file.size>32*1024*1024){toast(`${file.name} exceeds the 32 MiB browser upload limit.`,true);continue}try{const b64=arrayBufferToBase64(await file.arrayBuffer());await api('customer-file-upload',{method:'POST',data:{path:fmJoin(fmPath,file.name),content_base64:b64}});toast(`${file.name} uploaded`)}catch(err){toast(`${file.name}: ${err.message}`,true)}}e.target.value='';await refreshFiles(fmPath)});
$('fmRefresh')?.addEventListener('click',()=>refreshFiles(fmPath));
$('fmSearchToggle')?.addEventListener('click',()=>{const bar=$('fmSearchbar');bar.hidden=!bar.hidden;if(!bar.hidden)$('fmSearchInput')?.focus()});
$('fmSearchRun')?.addEventListener('click',fmRunSearch);$('fmSearchInput')?.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();fmRunSearch()}});$('fmSearchClear')?.addEventListener('click',()=>{if($('fmSearchInput'))$('fmSearchInput').value='';refreshFiles(fmPath)});
document.addEventListener('change',e=>{if(e.target.matches('[data-fm-select-all]')){document.querySelectorAll('[data-fm-select]').forEach(x=>x.checked=e.target.checked);fmUpdateSelection()}else if(e.target.matches('[data-fm-select]'))fmUpdateSelection()});
$('fmDeleteSelected')?.addEventListener('click',fmDeleteSelected);

document.querySelectorAll('form[data-customer-create]').forEach(f => f.addEventListener('submit', async e => {
  e.preventDefault(); const d = Object.fromEntries(new FormData(f));
  if (['customer-mailbox-create','customer-mail-alias-create'].includes(f.dataset.customerCreate)) { d.address = `${String(d.local_part||'').trim().toLowerCase()}@${String(d.domain||'').trim().toLowerCase()}`; delete d.local_part; delete d.domain; }
  if (f.dataset.customerCreate === 'customer-mailbox-create') { if ((d.password||'') !== (d.password_confirm||'')) { toast('Mailbox passwords do not match.',true); return; } if (String(d.password||'').length < 12) { toast('Mailbox password must be at least 12 characters.',true); return; } }
  if (f.querySelector('input[name="dnssec"]')) d.dnssec = f.querySelector('input[name="dnssec"]').checked;
  for (const k of ['quota_mb']) if (k in d) d[k] = Number(d[k]);
  if (f.dataset.customerCreate === 'customer-database-create' && (d.password||'') !== (d.password_confirm||'')) { toast('Database passwords do not match.',true); return; }
  try {
    const result = await api(f.dataset.customerCreate,{method:'POST',data:d});
    if (f.dataset.customerCreate === 'customer-app-install') {
      const box = $('cpInstallCredentials'), pre = $('cpInstallCredentialsText');
      const creds = result.credentials || {};
      if (box && pre && Object.keys(creds).length) {
        pre.textContent = Object.entries(creds).map(([k,v]) => `${k}: ${v}`).join('\n');
        box.hidden = false; box.scrollIntoView({behavior:'smooth',block:'center'});
      }
      toast(result.host_mutation ? 'Application installed' : 'Install plan prepared');
      const pass = f.querySelector('input[name="admin_password"]'); if (pass) pass.value = '';
    } else if (f.dataset.customerCreate === 'customer-database-create') {
      showCustomerDatabaseCredentials(d.name,result.credentials||{},'Database created');
      toast('Database created — save these credentials now');
      f.reset(); renderDatabaseEngines();
    } else if (f.dataset.customerCreate === 'customer-mailbox-create') { showCustomerMailboxSetup(result,d.address); toast(`Mailbox ${result.mailbox?.address||d.address} created`); f.reset(); fillDomainInputs(); } else { toast('Resource created'); if (f.dataset.customerCreate === 'customer-mail-alias-create') { f.reset(); fillDomainInputs(); } }
    document.addEventListener('click',e=>{const b=e.target.closest('[data-cp-mail-domain-manage]');if(b){e.preventDefault();cpOpenMailDomainConfig(b.dataset.cpMailDomainManage)}});document.addEventListener('click',async e=>{const b=e.target.closest('[data-cp-mail-domain-auth-delete]');if(!b)return;e.preventDefault();const domain=b.dataset.cpMailDomainAuthDelete;const confirmDomain=prompt(`Remove DKIM, SPF and DMARC authentication for ${domain}?\n\nYour website, mail host, MX records and mailboxes are preserved.\n\nType the exact domain to confirm:`,'');if(confirmDomain===null)return;if(confirmDomain!==domain){toast('Domain confirmation did not match.',true);return}b.disabled=true;try{await api('customer-mail-domain-auth-delete',{method:'POST',data:{domain,confirm_domain:confirmDomain}});toast(`Domain authentication removed for ${domain}`);await refreshResources()}catch(err){toast(err.message,true)}finally{b.disabled=false}});
    $('cpMailDomainConfigCopy')?.addEventListener('click',()=>navigator.clipboard.writeText($('cpMailDomainConfigText')?.textContent||'').then(()=>toast('Mail settings copied')).catch(()=>toast('Could not copy settings automatically.',true)));
    $('cpMailDomainConfigRefresh')?.addEventListener('click',()=>{if(cpActiveMailDomainConfig)cpOpenMailDomainConfig(cpActiveMailDomainConfig)});
    await $('cpImapDomainSelect')?.addEventListener('change',syncCustomerImapHost);
refresh();
  }
  catch (err) { toast(err.message,true); }
}));
$('cpExtensionSearch')?.addEventListener('input', renderCustomerExtensionCatalog);
$('cpExtensionDomain')?.addEventListener('change', renderCustomerExtensionCatalog);
document.addEventListener('keydown',e=>{const input=$('toolSearch');if(!input)return;const target=e.target;if(target&&['INPUT','TEXTAREA','SELECT'].includes(target.tagName))return;if((e.ctrlKey||e.metaKey)&&String(e.key).toLowerCase()==='k'){e.preventDefault();nav('home');setTimeout(()=>{input.focus();input.select()},20)}else if(e.key==='/'){e.preventDefault();nav('home');setTimeout(()=>input.focus(),20)}});
$('toolSearch')?.addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll('.tool-tile').forEach(t => { t.style.display = (!t.hidden && (!q || t.textContent.toLowerCase().includes(q))) ? 'flex' : 'none'; });
  document.querySelectorAll('.tool-group').forEach(g => { g.style.display = (!g.hidden && [...g.querySelectorAll('.tool-tile')].some(t => t.style.display !== 'none')) ? 'block' : 'none'; });
});
$('installerSearch')?.addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll('.installer-card').forEach(card => { card.style.display = !q || card.dataset.appSearch.includes(q) ? 'flex' : 'none'; });
});
enhanceCustomerToolGroups(); syncCustomerPreferenceForm(); applyCustomerPrefs(); refreshPhpSettingChoices();
const initial = location.hash.slice(1); if (document.querySelector(`[data-cp-view="${CSS.escape(initial)}"]`)) nav(initial);
refresh().then(()=>Promise.allSettled([loadAccountAnalytics(),refreshCustomerMfa()]));
