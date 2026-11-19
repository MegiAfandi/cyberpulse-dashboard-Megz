import http from 'node:http';
import './public/dates.js';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const DIR=path.dirname(fileURLToPath(import.meta.url));
const PORT=Number(process.env.PORT||3000);
const HOST=process.env.HOST||'127.0.0.1';
const CF='https://www.cloudflarestatus.com/api/v2';
const KEV='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD='https://services.nvd.nist.gov/rest/json/cves/2.0';
const AZURE='https://azure.status.microsoft/status/feed/';
const cache=new Map();
let nvdNextAt=0;
const NVD_GAP=process.env.NVD_API_KEY?700:6500;
function send(res,status,data,contentType='application/json; charset=utf-8'){
 res.writeHead(status,{'Content-Type':contentType,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"});
 res.end(typeof data==='string'?data:JSON.stringify(data));
}
async function fetchText(url,headers={},timeout=18000){
 const r=await fetch(url,{headers:{'User-Agent':'CyberMonitorLocal/2.0',...headers},signal:AbortSignal.timeout(timeout)});
 if(!r.ok)throw Error(`Provider returned HTTP ${r.status}${r.status===403?' (blocked)':''}${r.status===429?' (rate limited)':''}`);
 return r.text();
}
async function cached(key,ttl,fn){
 const v=cache.get(key);const now=Date.now();
 if(v&&v.expires>now)return {...v.value,cached:true};
 if(v?.pending)return v.pending;
 const pending=(async()=>{try{const value=await fn();cache.set(key,{value,expires:Date.now()+ttl});return {...value,cached:false};}catch(e){if(v?.value){cache.set(key,{value:v.value,expires:v.expires});return {...v.value,stale:true,error:e.message};}cache.delete(key);throw e;}})();
 cache.set(key,{...v,pending});return pending;
}
const decodeXml=s=>s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&').replace(/<[^>]*>/g,'').trim();
const xmlTag=(s,tag)=>{const m=s.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`,'i'));return m?decodeXml(m[1]):'';};
async function cloud(){
 const tasks=await Promise.allSettled([
 cached('cf',60000,async()=>{const [s,i]=await Promise.all([fetchText(CF+'/summary.json'),fetchText(CF+'/incidents.json')]);const summary=JSON.parse(s);const feed=JSON.parse(i);return {checkedAt:new Date().toISOString(),status:summary.status,incidents:(feed.incidents||[]).slice(0,35).map(x=>({id:x.id,name:x.name,status:x.status,impact:x.impact,created:x.created_at,updated:x.updated_at,body:x.incident_updates?.[0]?.body||'',affected:(x.components||[]).map(c=>c.name),url:'https://www.cloudflarestatus.com/incidents/'+encodeURIComponent(x.id)}))};}),
 cached('azure',300000,async()=>{const xml=await fetchText(AZURE);const blocks=[...xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi)].slice(0,15);return {checkedAt:new Date().toISOString(),items:blocks.map(x=>({title:xmlTag(x[1],'title'),description:xmlTag(x[1],'description').slice(0,500),date:xmlTag(x[1],'pubDate'),url:xmlTag(x[1],'link')}))};})
 ]);
 const cf=tasks[0].status==='fulfilled'?{state:'ok',...tasks[0].value}:{state:'error',error:tasks[0].reason.message};
 const az=tasks[1].status==='fulfilled'?{state:'feed',...tasks[1].value}:{state:'error',error:tasks[1].reason.message};
 return {checkedAt:new Date().toISOString(),cloudflare:cf,azure:az,m365:{state:'unverified',reason:'Microsoft 365 tenant-specific Service Health requires Microsoft Graph authentication. Not configured.',url:'https://status.cloud.microsoft/'}};
}
async function kev(){return cached('kev',6*3600e3,async()=>{const j=JSON.parse(await fetchText(KEV));return {checkedAt:new Date().toISOString(),items:j.vulnerabilities||[],catalogVersion:j.catalogVersion||''};});}
function enrich(entry,known){
 const c=entry.cve||{};const m=c.metrics||{};
 const metric=m.cvssMetricV40?.[0]||m.cvssMetricV31?.[0]||m.cvssMetricV30?.[0]||m.cvssMetricV2?.[0];
 const score=metric?.cvssData?.baseScore??null;
 const severity=(metric?.cvssData?.baseSeverity||metric?.baseSeverity||(score===null?'UNSCORED':score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':'LOW')).toUpperCase();
 const k=known.get(c.id);
 return {id:c.id,description:c.descriptions?.find(d=>d.lang==='en')?.value||'No English description available',published:c.published,lastModified:c.lastModified,score,severity,cvssVersion:metric?.cvssData?.version||null,cwe:(c.weaknesses||[]).flatMap(w=>w.description||[]).filter(w=>w.lang==='en').map(w=>w.value).filter((x,i,a)=>a.indexOf(x)===i),references:(c.references||[]).slice(0,12).map(r=>({url:r.url,tags:r.tags||[]})),kev:!!k,kevDetail:k?{vendor:k.vendorProject,product:k.product,name:k.vulnerabilityName,dateAdded:k.dateAdded,requiredAction:k.requiredAction,dueDate:k.dueDate,knownRansomwareCampaignUse:k.knownRansomwareCampaignUse}:null,url:'https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(c.id)};
}
// A complete bounded query is cached independently of sort, filters and UI page.
// NVD API pages are publication-ascending; sorting a single page hides recent CVEs.
let nvdQueue=Promise.resolve();
async function nvdRequest(args){
 const task=nvdQueue.then(async()=>{
  const delay=Math.max(0,nvdNextAt-Date.now());
  if(delay)await new Promise(resolve=>setTimeout(resolve,delay));
  const headers=process.env.NVD_API_KEY?{'apiKey':process.env.NVD_API_KEY}:{};
  try{
   for(let attempt=0;;attempt++){
    try{return JSON.parse(await fetchText(NVD+'?'+args.toString(),headers,60000));}
    catch(e){
     const retryable=/timeout|aborted|fetch failed|network|HTTP (429|5\d\d)/i.test(e.message);
     if(!retryable||attempt>=1)throw e;
     await new Promise(resolve=>setTimeout(resolve,Math.max(NVD_GAP,10000)));
    }
   }
  }
  finally{nvdNextAt=Date.now()+NVD_GAP;}
 });
 nvdQueue=task.catch(()=>{});
 return task;
}
function badRequest(message){const error=Error(message);error.status=400;throw error;}
function validateNvd(raw,offset){
 if(!Array.isArray(raw.vulnerabilities)||!Number.isInteger(raw.totalResults)||raw.totalResults<0)throw Error('Invalid NVD response.');
 if(Number(raw.startIndex)!==offset)throw Error('NVD returned an unexpected page offset. Refresh to retry.');
 if(offset<raw.totalResults&&!raw.vulnerabilities.length)throw Error('NVD returned an incomplete page. Refresh to retry.');
 for(const v of raw.vulnerabilities)if(!v.cve?.id)throw Error('NVD returned a record without a CVE ID.');
}
async function nvdPage(args,offset,count){
 const query=new URLSearchParams(args);query.set('startIndex',String(offset));query.set('resultsPerPage',String(count));
 const key='nvd:page:'+query;
 const pages=[...cache].filter(([k,v])=>k.startsWith('nvd:page:')&&!v.pending);
 while(!cache.has(key)&&pages.length>=60){const [old]=pages.shift();cache.delete(old);}
 return cached(key,10*60000,async()=>{const raw=await nvdRequest(query);validateNvd(raw,offset);return {raw,checkedAt:new Date().toISOString()};});
}
// Fast date pagination. NVD publishes ascending; read from the tail for newest.
// No bulk download is necessary when no local severity/KEV filtering is requested.
async function publishedPage(spec,requestedPage,size,retried=false){
 const count=await nvdPage(spec.args,0,1),total=count.raw.totalResults;
 const page=Math.min(requestedPage,Math.max(1,Math.ceil(total/size)));
 const offset=spec.order==='oldest'?(page-1)*size:Math.max(0,total-page*size);
 const length=spec.order==='oldest'?Math.min(size,total-offset):Math.min(size,total-(page-1)*size);
 const data=total>1?await nvdPage(spec.args,offset,length):count;
 if(data.raw.totalResults!==total){
  for(const [key] of cache)if(key.startsWith('nvd:page:'+spec.args.toString()))cache.delete(key);
  if(!retried)return publishedPage(spec,requestedPage,size,true);
  throw Error('NVD result count changed while loading. Click Retry NVD.');
 }
 if(data.raw.vulnerabilities.length!==length)throw Error('NVD returned an incomplete page. Refresh to retry.');
 const records=[...data.raw.vulnerabilities];
 if(spec.order==='newest')records.reverse();
 let kdata,kevError=null;try{kdata=await kev();}catch(e){kevError=e.message;kdata={items:[]};}
 const known=new Map(kdata.items.map(v=>[v.cveID,v]));
 return {checkedAt:data.checkedAt,query:spec.q,page,size,total,sourceTotal:total,items:records.map(v=>enrich(v,known)),field:spec.field,order:spec.order,
  range:spec.start===null?null:{from:new Date(spec.start).toISOString(),to:new Date(spec.end).toISOString()},
  cached:!!data.cached,stale:!!(data.stale||count.stale),error:data.error||count.error,kevAvailable:!kevError,kevError,
  mode:'direct-date-page',notice:'Date sorting covers all matching NVD results in the selected scope; only the requested page is downloaded.'};
}
function querySpec(params){
 const q=(params.get('q')||'').trim().slice(0,140);
 const field=params.get('field')||'published',order=params.get('order')||'newest';
 if(!['published','lastModified'].includes(field))badRequest('Invalid date field.');
 if(!['newest','oldest','score'].includes(order))badRequest('Invalid sort order.');
 const from=params.get('from')||'',to=params.get('to')||'';
 const day=86400000,parse=globalThis.CyberDates.boundary;
 const exact=/^CVE-\d{4}-\d{4,}$/i.test(q);
 const args=new URLSearchParams();
 if(exact)args.set('cveId',q.toUpperCase());
 else if(/^CWE-\d+$/i.test(q))args.set('cweId',q.toUpperCase());
 else if(q)args.set('keywordSearch',q);
 let start=null,end=null;
 if(from||to||!exact){
  // Blank dates mean the latest 30 days, for either selected date field.
  // Round to the current UTC hour so repeated requests share a cache snapshot.
  const now=Date.now(),hourEnd=(Math.floor(now/3600000)+1)*3600000;
  start=from?parse(from):null;
  end=to?parse(to)+day-1:null;
  if((from&&!Number.isFinite(start))||(to&&!Number.isFinite(end)))badRequest('Enter valid From / To dates.');
  if(start===null)start=(end===null?hourEnd:end)-30*day+1;
  if(from&&start>now)badRequest('From must not be after the current time.');
  if(end===null)end=hourEnd;
  if(start>end)badRequest('From must be on or before To (and not after the current time).');
  if(end-start>120*day)badRequest('Choose a date range of at most 120 days.');
  const prefix=field==='lastModified'?'lastMod':'pub';
  args.set(prefix+'StartDate',new Date(start).toISOString());
  args.set(prefix+'EndDate',new Date(end).toISOString());
 }
 return {q,field,order,from,to,start,end,args};
}
async function vuln(params){
 const spec=querySpec(params),size=20;
 const requestedPage=Math.max(1,parseInt(params.get('page')||'1',10)||1);
 const severity=params.get('severity')||'all',exploitation=params.get('kev')||'all';
 if(!['all','CRITICAL','HIGH','MEDIUM','LOW','UNSCORED'].includes(severity)||!['all','kev','other'].includes(exploitation))badRequest('Invalid severity or exploitation filter.');
 if(spec.field==='published'&&spec.order!=='score'&&severity==='all'&&exploitation==='all')return publishedPage(spec,requestedPage,size);
 const key='nvd:all:'+spec.args.toString();
 // Keep a bounded number of complete snapshots; do not evict in-flight queries.
 const snapshots=[...cache].filter(([k,v])=>k.startsWith('nvd:all:')&&!v.pending);
 while(!cache.has(key)&&snapshots.length>=6){const [key]=snapshots.shift();cache.delete(key);}
 const snapshot=await cached(key,10*60000,async()=>{
  const args=new URLSearchParams(spec.args);let batchSize=500;
  let offset=0,total=null;const records=new Map();
  do{
   args.set('startIndex',String(offset));
   args.set('resultsPerPage',String(batchSize));
   let raw;
   try{raw=await nvdRequest(args);}catch(e){
    if(batchSize>100&&/timeout|aborted|fetch failed|network|HTTP 5\d\d/i.test(e.message)){batchSize=100;continue;}
    throw e;
   }
   if(!Array.isArray(raw.vulnerabilities)||!Number.isInteger(raw.totalResults)||raw.totalResults<0)throw Error('Invalid NVD response.');
   if(total===null)total=raw.totalResults;
   if(raw.totalResults!==total)throw Error('NVD results changed while loading. Refresh to obtain a complete snapshot.');
   if(total>40000)badRequest('More than 40,000 matches. Narrow the date range or search before sorting. No partial results are shown.');
   const batch=raw.vulnerabilities;
   if(offset<total&&!batch.length)throw Error('NVD returned an incomplete page. Refresh to retry.');
   if(Number(raw.startIndex)!==offset)throw Error('NVD returned an unexpected page offset. Refresh to retry.');
   for(const item of batch){if(!item.cve?.id)throw Error('NVD returned a record without a CVE ID.');records.set(item.cve.id,item);}
   offset+=batch.length;
  }while(total===null||offset<total);
  if(records.size!==total)throw Error('NVD results shifted while loading. Refresh to obtain a complete snapshot.');
  return {checkedAt:new Date().toISOString(),records:[...records.values()],total};
 });
 let kdata,kevError=null;try{kdata=await kev();}catch(e){kevError=e.message;kdata={items:[]};}
 const known=new Map(kdata.items.map(v=>[v.cveID,v]));
 const candidates=snapshot.records.map(v=>enrich(v,known)).filter(x=>{
  const time=globalThis.CyberDates.timestamp(x[spec.field]);
  return (spec.start===null||(Number.isFinite(time)&&time>=spec.start&&time<=spec.end))&&
   (severity==='all'||x.severity===severity)&&(exploitation==='all'||(exploitation==='kev'?x.kev:!x.kev));
 });
 if(exploitation!=='all'&&kevError)throw Error('KEV filter unavailable: '+kevError);
 const sorted=globalThis.CyberDates.select(candidates,{field:spec.field,order:spec.order,score:spec.order==='score'});
 const page=Math.min(requestedPage,Math.max(1,Math.ceil(sorted.length/size)));
 return {checkedAt:snapshot.checkedAt,query:spec.q,page,size,total:sorted.length,sourceTotal:snapshot.total,
  items:sorted.slice((page-1)*size,page*size),field:spec.field,order:spec.order,
  range:spec.start===null?null:{from:new Date(spec.start).toISOString(),to:new Date(spec.end).toISOString()},
  cached:!!snapshot.cached,stale:!!snapshot.stale,error:snapshot.error,
  kevAvailable:!kevError,kevError,notice:'Complete date-window results are filtered and sorted before pagination. A CVE listing does not establish exposure in your environment.'};
}
function err(res,e){send(res,e.status||503,{error:e.message,checkedAt:new Date().toISOString()});}
const srv=http.createServer(async(req,res)=>{
 try{
  const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(req.method!=='GET')return send(res,405,{error:'Method not allowed'});
  if(u.pathname==='/healthz')return send(res,200,{status:'ok',app:'CyberPulse',version:'2.3.1'});
  if(u.pathname==='/api/cloud')return send(res,200,await cloud());
  if(u.pathname==='/api/cves')return send(res,200,await vuln(u.searchParams));
  if(u.pathname==='/api/kev'){
   const v=await kev();const q=(u.searchParams.get('q')||'').toLowerCase();const items=v.items.filter(x=>!q||[x.cveID,x.vendorProject,x.product,x.vulnerabilityName].join(' ').toLowerCase().includes(q)).slice(0,100);
   return send(res,200,{checkedAt:v.checkedAt,total:v.items.length,items,cached:v.cached,stale:v.stale});
  }
  if(u.pathname==='/'||u.pathname==='/index.html')return send(res,200,await readFile(path.join(DIR,'public','index.html'),'utf8'),'text/html; charset=utf-8');
  if(u.pathname==='/dates.js')return send(res,200,await readFile(path.join(DIR,'public','dates.js'),'utf8'),'application/javascript; charset=utf-8');
  if(u.pathname==='/app.js')return send(res,200,await readFile(path.join(DIR,'public','app.js'),'utf8'),'application/javascript; charset=utf-8');
  if(u.pathname==='/style.css')return send(res,200,await readFile(path.join(DIR,'public','style.css'),'utf8'),'text/css; charset=utf-8');
  send(res,404,{error:'Not found'});
 }catch(e){err(res,e);}
});
srv.listen(PORT,HOST,()=>console.log(`Cyber Monitor v2 → http://${HOST}:${PORT}`));
