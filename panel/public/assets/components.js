(()=>{
'use strict';
const BUILD=document.body?.dataset?.privoraBuild||'unknown';
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const model={components:[],category:'all',loading:false,jobs:{}};
function notify(message,bad=false){
  if(typeof window.toast==='function'){window.toast(message,bad);return;}
  const node=$('componentResultCount');
  if(node)node.textContent=String(message||'');
  (bad?console.error:console.info)('[Privora components]',message);
}
function csrfToken(){return document.querySelector('meta[name="csrf-token"]')?.content||'';}
async function request(route,{method='GET',data=null}={}){
  const url=new URL('api.php',document.baseURI);
  const parts=String(route).split('&');
  url.searchParams.set('route',parts.shift());
  for(const part of parts){const i=part.indexOf('=');if(i>0)url.searchParams.set(part.slice(0,i),decodeURIComponent(part.slice(i+1)));}
  const opts={method,headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store'};
  if(method!=='GET'){
    const csrf=csrfToken();
    if(!csrf)throw new Error('Security token missing. Reload Privora and try again.');
    opts.headers['Content-Type']='application/json';
    opts.headers['X-CSRF-Token']=csrf;
    opts.body=JSON.stringify(data||{});
  }
  let response;
  try{response=await fetch(url,opts);}catch(_){throw new Error('Privora API connection failed.');}
  const raw=await response.text();
  let json={};
  try{json=raw?JSON.parse(raw):{};}catch(_){throw new Error(`Server returned HTTP ${response.status} with a non-JSON response.`);}
  if(!response.ok)throw new Error(json.error||`Request failed (HTTP ${response.status})`);
  return json;
}
function matches(component,query){
  const hay=[component.name,component.id,component.category,component.description,...(component.packages||[]),...(component.tags||[])].join(' ').toLowerCase();
  return !query||hay.includes(query);
}
function filtered(){
  const query=String($('componentSearch')?.value||'').trim().toLowerCase();
  return model.components.filter(c=>{
    const categoryOK=model.category==='all'||(model.category==='installed'?!!c.installed:c.category===model.category);
    return categoryOK&&matches(c,query);
  });
}
function sync(){
  document.querySelectorAll('#componentCategoryTabs [data-component-category]').forEach(button=>{
    const active=(button.dataset.componentCategory||'all')===model.category;
    button.classList.toggle('active',active);
    button.setAttribute('aria-selected',active?'true':'false');
  });
  const query=String($('componentSearch')?.value||'').trim();
  const count=$('componentResultCount');
  if(count){const n=filtered().length;count.textContent=`Showing ${n} of ${model.components.length} component${model.components.length===1?'':'s'}${query?` · search “${query}”`:''}`;}
}
function jobFor(target){return model.jobs[target]||null;}
function progressMarkup(target){
  const job=jobFor(target);if(!job)return '';
  const value=Math.max(0,Math.min(100,Number(job.progress||0)));
  const failed=job.status==='failed';
  const label=failed?(job.error||job.message||'Install failed'):(job.message||job.phase||'Working…');
  return `<div class="component-job-progress ${failed?'failed':''}" data-component-progress="${esc(target)}"><div class="component-job-progress-head"><span>${esc(String(job.phase||job.status||'working').replaceAll('-',' '))}</span><strong>${value}%</strong></div><progress class="component-progress-track" max="100" value="${value}" aria-label="Software installation progress"></progress><small>${esc(label)}</small></div>`;
}
function card(component){
  const cls=component.installed?'installed':component.partial?'partial':component.available?'available':'unsupported';
  const label=component.installed?'Installed':component.partial?'Partial':component.available?'Available':'Not supported';
  const busy=!!jobFor(component.id)&&['queued','running'].includes(jobFor(component.id).status);
  const action=component.installed
    ?(component.removable?`<button class="ghost component-remove" type="button" data-component-remove="${esc(component.id)}" ${busy?'disabled':''}>${busy?'Working…':'Remove'}</button>`:'<button class="ghost" type="button" disabled>Installed</button>')
    :(component.available?`<button class="primary" type="button" data-component-install="${esc(component.id)}" ${busy?'disabled':''}>${busy?'Installing…':component.partial?'Complete install':'Install'}</button>`:'<button class="ghost" type="button" disabled>Unavailable</button>');
  return `<article class="panel-card component-card ${component.featured?'featured':''}" data-component-card="${esc(component.id)}"><div class="component-card-head"><div><h4>${esc(component.name)}</h4><span>${esc(component.category)}</span></div><em class="status-pill ${cls==='installed'?'active':cls==='partial'?'warning':cls==='available'?'sim':'failed'}">${label}</em></div><p>${esc(component.description||'')}</p><div class="component-packages"><span>Packages</span><code>${esc((component.packages||[]).join(' · ')||'internal')}</code></div>${component.version?`<small class="component-version">Installed version ${esc(component.version)}</small>`:''}${progressMarkup(component.id)}<div class="component-card-footer"><small>${esc(component.status_reason||'')}</small>${action}</div></article>`;
}
function render(){
  const root=$('componentCatalog');
  if(!root)return;
  const rows=filtered();
  sync();
  if(!rows.length){root.innerHTML='<article class="panel-card"><div class="empty">No components match the selected category and search.</div></article>';return;}
  const groups=[];
  for(const component of rows){let group=groups.find(x=>x.name===component.category);if(!group){group={name:component.category,rows:[]};groups.push(group);}group.rows.push(component);}
  root.innerHTML=groups.map(group=>`<section class="component-group"><div class="component-group-head"><div><h3>${esc(group.name)}</h3></div><small>${group.rows.length} component${group.rows.length===1?'':'s'}</small></div><div class="component-grid">${group.rows.map(card).join('')}</div></section>`).join('');
}
async function refresh(){
  if(model.loading)return;
  const root=$('componentCatalog');
  if(!root)return;
  model.loading=true;
  root.innerHTML='<article class="panel-card"><div class="empty">Refreshing package inventory…</div></article>';
  try{
    const [data,jobsData]=await Promise.all([request('components'),request('software-jobs').catch(()=>({jobs:[]}))]);
    model.components=Array.isArray(data.components)?data.components:[];
    for(const job of (jobsData.jobs||[])){
      if(job.kind==='component'&&['queued','running'].includes(job.status))model.jobs[job.target]=job;
    }
    const counts=data.counts||{};
    if($('componentInstalledCount'))$('componentInstalledCount').textContent=counts.installed??model.components.filter(x=>x.installed).length;
    if($('componentAvailableCount'))$('componentAvailableCount').textContent=counts.available??model.components.filter(x=>x.available&&!x.installed).length;
    if($('componentTotalCount'))$('componentTotalCount').textContent=counts.total??model.components.length;
    render();
    if(typeof window.refreshPHPInventory==='function')Promise.resolve(window.refreshPHPInventory()).catch(()=>{});
  }catch(error){
    root.innerHTML='<article class="panel-card"><div class="empty">Unable to load component inventory.</div></article>';
    notify(error.message||String(error),true);
  }finally{model.loading=false;}
}
async function pollJob(job){
  let misses=0;
  while(job&&['queued','running'].includes(job.status)){
    await new Promise(resolve=>setTimeout(resolve,850));
    try{
      const data=await request('software-job-status&id='+encodeURIComponent(job.id));
      job=data.job||job;model.jobs[job.target]=job;misses=0;render();
    }catch(error){
      misses++;if(misses>=3){const current=model.jobs[job.target];if(current){current.message='Install still running · status retry';render();}}
      if(misses>20)throw new Error('Install is still running but progress status is temporarily unavailable. Refresh this page to reconnect.');
    }
  }
  return job;
}
async function startJob(kind,action,target,phpVersion=''){
  const data=await request('software-job-start',{method:'POST',data:{kind,action,target,php_version:phpVersion}});
  const job=data.job;if(!job?.id)throw new Error('Privora did not return a software job ID.');
  model.jobs[target]=job;render();return pollJob(job);
}
async function install(button){
  const id=button.dataset.componentInstall||'';
  const component=model.components.find(x=>x.id===id);
  if(!component){notify('Component inventory changed. Refresh and try again.',true);return;}
  const packages=(component.packages||[]).join(', ');
  if(!window.confirm(`Install ${component.name}?\n\nPrivora will install only its allow-listed package set:\n${packages}`))return;
  button.disabled=true;
  try{
    const job=await startJob('component','install',component.id);
    if(job.status==='failed')throw new Error(job.error||job.message||'Install failed');
    notify(`${component.name} installed and verified`);
    delete model.jobs[component.id];await refresh();
  }catch(error){
    const existing=model.jobs[component.id];if(existing){existing.status='failed';existing.error=error.message||String(error);model.jobs[component.id]=existing;render();}
    notify(error.message||String(error),true);
  }
}
async function remove(button){
  const id=button.dataset.componentRemove||'';
  const component=model.components.find(x=>x.id===id);
  if(!component){notify('Component inventory changed. Refresh and try again.',true);return;}
  if(!window.confirm(`Remove ${component.name}?\n\nOnly this allow-listed component package will be removed. Privora will not run apt autoremove.`))return;
  button.disabled=true;
  try{
    const job=await startJob('component','remove',component.id);
    if(job.status==='failed')throw new Error(job.error||job.message||'Removal failed');
    notify(`${component.name} removed and verified`);delete model.jobs[component.id];await refresh();
  }catch(error){const existing=model.jobs[component.id];if(existing){existing.status='failed';existing.error=error.message||String(error);model.jobs[component.id]=existing;render();}notify(error.message||String(error),true);}
}
function bind(){
  const search=$('componentSearch'),tabs=$('componentCategoryTabs'),clear=$('componentClearFilter'),catalog=$('componentCatalog'),refreshButton=$('refreshComponents');
  if(!catalog)return;
  search?.addEventListener('input',render);
  search?.addEventListener('search',render);
  tabs?.addEventListener('click',event=>{const button=event.target.closest('[data-component-category]');if(!button)return;event.preventDefault();model.category=button.dataset.componentCategory||'all';render();});
  clear?.addEventListener('click',event=>{event.preventDefault();model.category='all';if(search)search.value='';render();});
  refreshButton?.addEventListener('click',event=>{event.preventDefault();refresh();});
  document.addEventListener('click',event=>{const installButton=event.target.closest('[data-component-install]');if(installButton){event.preventDefault();install(installButton);return;}const removeButton=event.target.closest('[data-component-remove]');if(removeButton){event.preventDefault();remove(removeButton);return;}const nav=event.target.closest('[data-page="components"],[data-nav="components"]');if(nav)setTimeout(refresh,0);});
  refresh();
}
window.PrivoraComponents={active:true,build:BUILD,refresh,render,filteredCount:()=>filtered().length};
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind,{once:true});else bind();
})();
