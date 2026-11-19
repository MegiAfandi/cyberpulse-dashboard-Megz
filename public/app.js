const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const state={tab:'overview',cves:[],page:1,total:0,q:'',cloud:null,kev:null,lastError:null,cveRequest:0,sourceTotal:0,lastCveKey:null};
const WIB={timeZone:'Asia/Jakarta',year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false};
function wib(d){if(!d)return 'Not provided';const x=new Date(CyberDates.timestamp(d));return Number.isNaN(x.valueOf())?'Not provided / invalid':new Intl.DateTimeFormat('id-ID',WIB).format(x)+' WIB';}
function text(el,s){el.textContent=s??'';return el;}
function node(tag,content,cls){const el=document.createElement(tag);if(content!=null)text(el,content);if(cls)el.className=cls;return el;}
function badge(s){const val=String(s||'unknown');let cls=/critical|major|outage|error/i.test(val)?'critical':/high|degraded|investigating|identified|partial|monitoring|minor/i.test(val)?'warning':/resolved|operational|none|normal/i.test(val)?'ok':'muted';return node('span',val,'badge '+cls);}
function notice(s){$('#notice').classList.toggle('hidden',!s);text($('#notice'),s||'');}
function row(container,title,desc,meta,url,status){const r=node('div',null,'row-item'),a=node('div'),b=node('div');a.style.minWidth='0';a.append(node('b',title),node('p',desc||''),node('small',meta||''));if(url&&/^https:\/\//.test(url)){const l=node('a','Official ↗');l.href=url;l.target='_blank';l.rel='noopener noreferrer';b.append(l);}if(status)b.prepend(badge(status));b.style.display='flex';b.style.flexDirection='column';b.style.gap='8px';b.style.alignItems='end';r.append(a,b);container.append(r);}
function showTab(t){state.tab=t;$$('.tab').forEach(e=>e.classList.toggle('active',e.id===t));$$('.nav').forEach(e=>e.classList.toggle('active',e.dataset.tab===t));const info={overview:['Operations overview','Live provider checks and searchable vulnerability intelligence.'],vulnerabilities:['CVE / CWE Explorer','Query NIST NVD and enrich with CISA KEV exploitation evidence.'],kev:['Known exploited vulnerabilities','CISA KEV catalog with searchable vendor and product details.'],cloud:['Cloud service health','Official Cloudflare and Microsoft public status sources.']}[t];text($('#page-title'),info[0]);text($('#page-subtitle'),info[1]);}
$$('[data-tab]').forEach(b=>b.addEventListener('click',()=>showTab(b.dataset.tab)));$$('[data-goto]').forEach(b=>b.addEventListener('click',()=>showTab(b.dataset.goto)));
function itemSummary(v){return `${v.description.slice(0,180)}${v.description.length>180?'…':''}`;}
function renderOverviewCves(){const el=$('#overview-cves');el.replaceChildren();const v=state.cves.slice(0,6);if(!v.length)return el.append(node('div','No CVE results loaded.','empty'));v.forEach(x=>row(el,x.id,itemSummary(x),wib(x.published),x.url,x.severity));}
function renderOverviewCloud(){const el=$('#overview-cloud');el.replaceChildren();const cf=state.cloud?.cloudflare;if(cf?.state==='ok'&&cf.incidents.length)cf.incidents.slice(0,7).forEach(x=>row(el,x.name,(x.affected||[]).join(', ')||x.body.slice(0,120),wib(x.updated),x.url,x.status));else el.append(node('div',cf?.error||'No Cloudflare incidents returned','empty'));}
async function get(url){const r=await fetch(url,{cache:'no-store'});const d=await r.json();if(!r.ok)throw Error(d.error||`HTTP ${r.status}`);return d;}
async function cloud(){try{const d=await get('/api/cloud');state.cloud=d;const cf=d.cloudflare,az=d.azure;
 text($('#ov-cf'),cf.state==='ok'?(cf.status?.description||cf.status?.indicator||'Source available'):'UNAVAILABLE');text($('#ov-cf-sub'),cf.state==='ok'?`Checked ${wib(cf.checkedAt)}`:cf.error);
 text($('#ov-az'),az.state==='feed'?'RSS AVAILABLE':'UNVERIFIED');text($('#ov-az-sub'),az.state==='feed'?`${az.items.length} recent RSS entries • not overall health`:az.error);
 text($('#cf-health'),cf.state==='ok'?(cf.status?.description||'Status published'):'Unavailable');$('#cf-health').className='provider-status '+(cf.state!=='ok'?'error':cf.status?.indicator==='none'?'ok':'warning');text($('#cf-checked'),cf.state==='ok'?`Last checked ${wib(cf.checkedAt)}`:cf.error);
 text($('#az-health'),az.state==='feed'?'RSS FEED REACHABLE':'UNVERIFIED');$('#az-health').className='provider-status '+(az.state==='feed'?'ok':'error');text($('#az-checked'),az.state==='feed'?`${az.items.length} recent feed entries. RSS is not overall health.`:az.error);
 renderIncidents();
 renderOverviewCloud();text($('#last-check'),`Latest cloud check ${wib(d.checkedAt)}`);
 }catch(e){notice('Cloud check: '+e.message);}}
function dateOptions(prefix){
 const from=$('#'+prefix+'-from').value,to=$('#'+prefix+'-to').value;
 const error=(from&&to&&from>to)?'From must be on or before To.':((from&&!Number.isFinite(CyberDates.boundary(from)))||(to&&!Number.isFinite(CyberDates.boundary(to))))?'Enter a valid date.':'';
 text($('#'+prefix+'-date-error'),error);
 return {field:$('#'+prefix+'-date-field').value,order:$(prefix==='cve'?'#sort':'#cloud-sort').value,from,to,score:prefix==='cve'&&$('#sort').value==='score'};
}
function filtered(){
 const sev=$('#severity').value,k=$('#kev-filter').value;
 const a=state.cves.filter(x=>(sev==='all'||x.severity===sev)&&(k==='all'||(k==='kev'?x.kev:!x.kev)));
 return CyberDates.select(a,dateOptions('cve'));
}
function renderIncidents(){
 const options=dateOptions('cloud'),q=$('#cloud-query').value.trim().toLowerCase();
 const cf=state.cloud?.cloudflare,az=state.cloud?.azure;
 const matches=x=>!q||[x.name,x.title,x.body,x.description,x.status,(x.affected||[]).join(' ')].join(' ').toLowerCase().includes(q);
 for(const [id,source,items] of [['#cf-incidents',cf,cf?.incidents||[]],['#az-incidents',az,(az?.items||[]).map(x=>({...x,created:x.date}))]]){
  const el=$(id);el.replaceChildren();
  const selected=CyberDates.select(items.filter(matches),options);
  selected.forEach(x=>row(el,x.name||x.title,x.body?.slice(0,200)||x.description,`Published / Created: ${wib(x.created)} · Last Modified: ${wib(x.updated)}`,x.url,x.status));
  if(!selected.length)el.append(node('div',source?.error||'No matching incidents in the loaded feed.','empty'));
 }
}
function renderCves(){syncDateHeaders();const a=filtered(),body=$('#cve-body');body.replaceChildren();for(const x of a){const tr=node('tr');const fields=[x.id,x.severity,x.score===null?'N/A':`${x.score} (v${x.cvssVersion})`,x.cwe.join(', ')||'Unclassified',x.kev?'YES':'—',wib(x.published),wib(x.lastModified)];fields.forEach((v,i)=>{const td=node('td');if(i===1)td.append(badge(v));else text(td,v);tr.append(td);});const btn=node('button','Details','mini');btn.addEventListener('click',()=>detail(x));const last=node('td');last.append(btn);tr.append(last);body.append(tr);}if(!a.length){const tr=node('tr'),td=node('td','No matching records on this NVD page.','empty');td.colSpan=8;tr.append(td);body.append(tr);}
 text($('#result-meta'),`${a.length} on this page · ${state.total.toLocaleString()} filtered matches · ${state.sourceTotal.toLocaleString()} source matches`);text($('#page-info'),`Page ${state.page} / ${Math.max(1,Math.ceil(state.total/20))}`);$('#prev').disabled=state.page<=1;$('#next').disabled=state.page*20>=state.total;renderOverviewCves();}
async function cves(){
 const request=++state.cveRequest,options=dateOptions('cve');
 syncDateHeaders();
 if($('#cve-date-error').textContent){state.cves=[];state.total=0;renderCves();return;}
 const params=new URLSearchParams({q:state.q,page:String(state.page),field:options.field,order:options.order,from:options.from,to:options.to,severity:$('#severity').value,kev:$('#kev-filter').value});
 const key=params.toString(),keep=state.lastCveKey===key&&state.cves.length>0;
 if(!keep){state.cves=[];state.total=0;state.sourceTotal=0;}
 renderCves();
 const direct=options.field==='published'&&options.order!=='score'&&$('#severity').value==='all'&&$('#kev-filter').value==='all';
 text($('#result-meta'),direct?'Loading requested date page…':'Loading all matching CVEs to apply filters… This can take several minutes.');
 $('#retry-cves').disabled=true;
 $('#prev').disabled=true;$('#next').disabled=true;
 try{
  const d=await get('/api/cves?'+params);
  if(request!==state.cveRequest)return;
  state.cves=d.items;state.total=d.total;state.page=d.page;state.sourceTotal=d.sourceTotal;state.lastCveKey=key;renderCves();
  const warnings=[];
  if(d.kevError)warnings.push('KEV enrichment unavailable: '+d.kevError);
  if(d.stale)warnings.push('Showing the last complete cached snapshot: '+d.error);
  notice(warnings.join(' · '));
  text($('#rate-note'),`Checked ${wib(d.checkedAt)}${d.cached?' · cached':''}`);
  text($('#cve-scope'),d.range?`Scope: ${wib(d.range.from)} → ${wib(d.range.to)} · ${d.field==='published'?'Published':'Last Modified'} · ${d.sourceTotal.toLocaleString()} source matches. All matching records are sorted before pagination.`:'Scope: exact CVE lookup, all publication dates.');
 }catch(e){
  if(request!==state.cveRequest)return;
  if(!keep){state.cves=[];state.total=0;state.sourceTotal=0;}
  renderCves();
  notice('NVD query failed: '+e.message+(keep?' · Showing the previous successful result for the same query.':' · Click Retry NVD to try again.'));
  text($('#rate-note'),keep?'Refresh failed — previous result retained':'Query failed — click Retry NVD');
  if(!keep){text($('#result-meta'),'Unable to load NVD results.');const cell=$('#cve-body').children[0]?.children[0];if(cell)text(cell,'NVD unavailable. Retry the query; this does not mean there are no CVEs.');}
 }finally{
  if(request===state.cveRequest)$('#retry-cves').disabled=false;
 }
}
function reloadCves(){state.page=1;return cves();}
function detail(x){text($('#detail-title'),x.id);const c=$('#detail-content');c.replaceChildren();const intro=node('p',x.description,'detail-copy');c.append(badge(x.severity),intro);const grid=node('div',null,'detail-grid');for(const [k,v] of [['CVSS',x.score===null?'Not scored':`${x.score} (v${x.cvssVersion})`],['CWE',x.cwe.join(', ')||'Not classified'],['Published',wib(x.published)],['Modified',wib(x.lastModified)],['CISA KEV',x.kev?'Listed — confirmed catalog':'Not listed / unknown']]){const d=node('div');d.append(node('small',k),node('b',v));grid.append(d);}c.append(grid);if(x.kevDetail){c.append(node('h3','CISA KEV intelligence'));c.append(node('p',`${x.kevDetail.vendor||''} ${x.kevDetail.product||''} — added ${x.kevDetail.dateAdded||'unknown'}`));c.append(node('p',x.kevDetail.requiredAction||''));}
 c.append(node('h3','Official references'));const ul=node('ul',null,'ref-list');[{url:x.url},...x.references].forEach(r=>{if(!/^https:\/\//.test(r.url||''))return;const li=node('li'),a=node('a',r.url);a.href=r.url;a.target='_blank';a.rel='noopener noreferrer';li.append(a);ul.append(li);});c.append(ul);$('#detail').showModal();}
$('#close-detail').addEventListener('click',()=>$('#detail').close());$('#detail').addEventListener('click',e=>{if(e.target===$('#detail'))$('#detail').close();});
$('#search-form').addEventListener('submit',e=>{e.preventDefault();state.q=$('#query').value.trim();state.page=1;cves();});$('#prev').addEventListener('click',()=>{state.page--;cves();});$('#next').addEventListener('click',()=>{state.page++;cves();});['#severity','#kev-filter','#sort','#cve-date-field','#cve-from','#cve-to'].forEach(id=>$(id).addEventListener('change',reloadCves));
async function kev(q=''){const el=$('#kev-rows');el.replaceChildren(node('div','Loading CISA KEV…','empty'));try{const d=await get('/api/kev?q='+encodeURIComponent(q));text($('#kev-meta'),`Showing ${d.items.length} matching records (max 100) · ${d.total} total catalog · checked ${wib(d.checkedAt)}`);text($('#ov-kev'),d.total.toLocaleString());el.replaceChildren();d.items.forEach(x=>row(el,x.cveID,`${x.vendorProject} · ${x.product} — ${x.vulnerabilityName}`,`Added ${x.dateAdded} · Due ${x.dueDate||'N/A'}`,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog','CISA KEV'));if(!d.items.length)el.append(node('div','No matching KEV entries','empty'));}catch(e){text($('#ov-kev'),'UNAVAILABLE');el.replaceChildren(node('div',e.message,'empty'));}}
$('#kev-search').addEventListener('click',()=>kev($('#kev-query').value.trim()));$('#kev-query').addEventListener('keydown',e=>{if(e.key==='Enter')kev(e.target.value.trim());});
$('#theme').addEventListener('click',()=>{document.body.classList.toggle('light');});
$('#refresh').addEventListener('click',()=>{cloud();cves();kev($('#kev-query').value.trim());});
setInterval(()=>{cloud();kev($('#kev-query').value.trim());},300000);
function tick(){text($('#clock'),new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Jakarta',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date())+' WIB');}tick();setInterval(tick,1000);cloud();cves();kev();

['#cloud-sort','#cloud-date-field','#cloud-from','#cloud-to'].forEach(id=>$(id).addEventListener('change',renderIncidents));
$('#cloud-query').addEventListener('input',renderIncidents);

function syncDateHeaders(){
 const field=$('#cve-date-field').value,order=$('#sort').value;
 $$('[data-date-sort]').forEach(button=>{
  const active=button.dataset.dateSort===field&&order!=='score';
  button.parentElement.setAttribute('aria-sort',active?(order==='oldest'?'ascending':'descending'):'none');
  button.querySelector('.sort-arrow').textContent=active?(order==='oldest'?'↑':'↓'):'↕';
  button.title=active&&order==='newest'?'Sort ascending: oldest first':'Sort descending: newest first';
 });
}
function toggleDateSort(field){
 const same=$('#cve-date-field').value===field;
 $('#sort').value=same&&$('#sort').value==='newest'?'oldest':'newest';
 $('#cve-date-field').value=field;
 reloadCves();
}
$$('[data-date-sort]').forEach(button=>button.addEventListener('click',()=>toggleDateSort(button.dataset.dateSort)));
syncDateHeaders();

$('#retry-cves').addEventListener('click',()=>cves());
