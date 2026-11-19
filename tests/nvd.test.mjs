import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import {fileURLToPath} from 'node:url';
import '../public/dates.js';
const filename=fileURLToPath(new URL('../server.mjs',import.meta.url));
const source=(await readFile(filename,'utf8')).replace(/^import .*;\r?\n/gm,'').replace('fileURLToPath(import.meta.url)',JSON.stringify(filename));
const entry=(id,published,lastModified=published,score=5)=>({cve:{id,published,lastModified,descriptions:[{lang:'en',value:'test fixture'}],metrics:{cvssMetricV31:[{cvssData:{baseScore:score,baseSeverity:score>=7?'HIGH':'MEDIUM',version:'3.1'}}]}}});
function harness(records,options={}){
 let clock=Date.parse('2026-11-18T08:00:00Z'),handler,calls=[],kevCalls=0;
 class Clock extends Date{constructor(...args){super(...(args.length?args:[clock]));}static now(){return clock;}}
 const signals=[];
 const fetch=async (url,init)=>{
  if(!String(url).includes('services.nvd.nist.gov')){kevCalls++;if(options.kevError)throw Error('CISA offline');return {ok:true,text:async()=>JSON.stringify({vulnerabilities:[{cveID:'CVE-2026-99999'}]})};}
  const args=new URL(url).searchParams;calls.push(new URLSearchParams(args));
  signals.push(init.signal);
  if(options.failCount&&calls.length<=options.failCount)throw Error(options.failure||'temporary network failure');
  if(options.failLarge&&Number(args.get('resultsPerPage'))>100)throw Error('The operation was aborted due to timeout');
  if(options.failFirst&&calls.length===1)throw Error('temporary network failure');
  if(options.custom)return {ok:true,text:async()=>JSON.stringify(options.custom(args,calls.length))};
  let a=records;
  const field=args.has('lastModStartDate')?'lastModified':'published',prefix=field==='published'?'pub':'lastMod';
  if(args.has('cveId'))a=a.filter(x=>x.cve.id===args.get('cveId'));
  if(args.has(prefix+'StartDate'))a=a.filter(x=>{const t=globalThis.CyberDates.timestamp(x.cve[field]);return t>=Date.parse(args.get(prefix+'StartDate'))&&t<=Date.parse(args.get(prefix+'EndDate'));});
  const offset=Number(args.get('startIndex')),size=Number(args.get('resultsPerPage'));
  return {ok:true,text:async()=>JSON.stringify({startIndex:offset,totalResults:a.length,vulnerabilities:a.slice(offset,offset+size)})};
 };
 const context=vm.createContext({http:{createServer:f=>{handler=f;return {listen(){}};}},readFile,path,process:{env:{}},URL,URLSearchParams,AbortSignal,console,fetch,Date:Clock,CyberDates:globalThis.CyberDates,setTimeout:(f,ms)=>{clock+=ms;f();}});
 vm.runInContext(source,context);
 return {calls,signals,get kevCalls(){return kevCalls;},async request(query){let status,body;await handler({url:'/api/cves?'+query,method:'GET',headers:{}},{writeHead:s=>{status=s;},end:b=>{body=JSON.parse(b);}});return {status,...body};}};
}
const october=Array.from({length:2000},(_,i)=>entry('CVE-2026-'+(10000+i),'2026-10-20T00:00:00','2026-11-17T01:00:00',5));
const fixtures=[...october,entry('CVE-2026-99998','2026-11-17T01:00:00','2026-11-18T01:00:00',9),entry('CVE-2026-99999','2026-11-18T01:00:00','2026-11-18T02:00:00',8)];
test('regression: default newest fetches November directly without downloading October; oldest and last pages remain correct',async()=>{
 const h=harness(fixtures),newest=await h.request('order=newest');
 assert.equal(newest.status,200);assert.equal(newest.total,2002);assert.equal(newest.items[0].id,'CVE-2026-99999');assert.equal(newest.items[1].id,'CVE-2026-99998');
 assert.equal(h.calls.length,2);assert.equal(h.calls[0].get('resultsPerPage'),'1');assert.equal(h.calls[1].get('startIndex'),'1982');assert.equal(h.calls[1].get('resultsPerPage'),'20');
 const oldest=await h.request('order=oldest');assert.equal(oldest.items[0].id,'CVE-2026-10000');assert.equal(h.calls.length,3);
 const last=await h.request('order=oldest&page=101');assert.equal(last.page,101);assert.equal(last.items.length,2);assert.equal(last.items[0].id,'CVE-2026-99998');
 assert.equal(h.calls.length,4);
 await h.request('order=newest');assert.equal(h.calls.length,4);
});
test('global severity, KEV, score and page clamping include November beyond first upstream page',async()=>{
 const h=harness(fixtures);
 const high=await h.request('severity=HIGH&order=score');assert.equal(high.total,2);assert.equal(high.items[0].score,9);
 const kev=await h.request('kev=kev&page=100');assert.equal(kev.total,1);assert.equal(kev.page,1);assert.equal(kev.items[0].id,'CVE-2026-99999');
 assert.equal(h.calls.length,5);
});
test('November From/To bounds reach NVD in UTC and retain WIB midnight/end-of-day',async()=>{
 const h=harness([entry('before','2026-10-31T16:59:59.999Z'),entry('start','2026-10-31T17:00:00Z'),entry('end','2026-11-18T16:59:59.999Z'),entry('after','2026-11-18T17:00:00Z')]);
 const result=await h.request('from=2026-11-01&to=2026-11-18');assert.equal(result.status,200);
 assert.deepEqual(result.items.map(x=>x.id),['end','start']);
 assert.equal(h.calls[0].get('pubStartDate'),'2026-10-31T17:00:00.000Z');assert.equal(h.calls[0].get('pubEndDate'),'2026-11-18T16:59:59.999Z');
});
test('Last Modified queries modified dates, globally sorts old CVEs updated in November',async()=>{
 const h=harness([entry('old','2020-01-01T00:00:00','2026-11-18T01:00:00'),entry('new','2026-11-17T00:00:00','2026-11-17T00:00:00')]);
 const result=await h.request('field=lastModified&order=newest');assert.equal(result.items[0].id,'old');
 assert.ok(h.calls[0].has('lastModStartDate'));assert.equal(h.calls[0].has('pubStartDate'),false);
});
test('invalid bounds fail before upstream requests; broad results never pretend to be complete',async()=>{
 const h=harness([]);
 for(const query of ['from=2026-11-19','from=2026-11-18&to=2026-11-01','from=2026-02-30','from=2025-01-01&to=2026-01-01','field=wrong'])assert.equal((await h.request(query)).status,400,query);
 assert.equal(h.calls.length,0);
 const huge=harness([],{custom:()=>({startIndex:0,totalResults:40001,vulnerabilities:[]})});assert.equal((await huge.request('order=score')).status,400);
});
test('failed initial query retries instead of caching a rejected promise; exact CVE lookup remains all-time',async()=>{
 const h=harness([entry('CVE-2021-44228','2021-12-10T00:00:00')],{failCount:2});
 assert.equal((await h.request('q=CVE-2021-44228')).status,503);
 const retry=await h.request('q=CVE-2021-44228');assert.equal(retry.status,200);assert.equal(retry.total,1);assert.equal(h.calls[2].has('pubStartDate'),false);
});
test('incomplete and shifting upstream datasets fail explicitly',async()=>{
 for(const custom of [()=>({startIndex:0,totalResults:1,vulnerabilities:[]}),()=>({startIndex:123,totalResults:1,vulnerabilities:[fixtures[0]]}),(_a,n)=>({startIndex:n===1?0:2000,totalResults:n===1?2002:2003,vulnerabilities:n===1?october:fixtures.slice(2000)})]){
  const h=harness([],{custom});assert.equal((await h.request('')).status,503);
 }
});
test('concurrent date requests share their count query; KEV failure is explicit for KEV filters',async()=>{
 const h=harness(fixtures);const [a,b]=await Promise.all([h.request('order=newest'),h.request('order=oldest')]);assert.equal(a.status,200);assert.equal(b.status,200);assert.equal(h.calls.length,3);
 const offline=harness(fixtures,{kevError:true});assert.equal((await offline.request('kev=kev')).status,503);const all=await offline.request('');assert.equal(all.status,200);assert.equal(all.kevAvailable,false);
});
test('timeout is automatically retried and the default view never requests a bulk page',async()=>{
 const h=harness(fixtures,{failFirst:true});
 const result=await h.request('');assert.equal(result.status,200);assert.equal(result.items[0].id,'CVE-2026-99999');
 assert.deepEqual(h.calls.map(a=>a.get('resultsPerPage')),['1','1','20']);
 const timed=harness(fixtures,{failCount:1,failure:'The operation was aborted due to timeout'});
 assert.equal((await timed.request('')).status,200);
});
test('bulk timeout shrinks request size and still sorts the complete filtered dataset',async()=>{
 const h=harness(fixtures,{failLarge:true});const result=await h.request('severity=HIGH');
 assert.equal(result.status,200);assert.equal(result.total,2);assert.equal(result.items[0].id,'CVE-2026-99999');
 assert.equal(h.calls[0].get('resultsPerPage'),'500');assert.equal(h.calls[1].get('resultsPerPage'),'500');assert.equal(h.calls[2].get('resultsPerPage'),'100');
});
test('direct pagination covers each record exactly once across partial final pages in both directions',async()=>{
 const records=Array.from({length:45},(_,i)=>entry('CVE-2026-'+(10000+i),'2026-11-17T00:00:00'));
 const h=harness(records);
 for(const order of ['newest','oldest']){
  const rows=[];
  for(let page=1;page<=3;page++){const result=await h.request('order='+order+'&page='+page);assert.equal(result.status,200);rows.push(...result.items.map(x=>x.id));}
  assert.equal(new Set(rows).size,45);assert.equal(rows.length,45);
  assert.deepEqual(rows,order==='oldest'?records.map(x=>x.cve.id):records.map(x=>x.cve.id).reverse());
 }
 const empty=await harness([]).request('');assert.equal(empty.status,200);assert.equal(empty.total,0);assert.deepEqual(empty.items,[]);
});
test('changed count invalidates cached pages and retries with a fresh count',async()=>{
 const records=Array.from({length:45},(_,i)=>entry('CVE-2026-'+(10000+i),'2026-11-17T00:00:00'));
 const h=harness([],{custom:(args,n)=>{const offset=Number(args.get('startIndex')),size=Number(args.get('resultsPerPage'));return {startIndex:offset,totalResults:n===1?46:45,vulnerabilities:records.slice(offset,offset+size)};}});
 const result=await h.request('');assert.equal(result.status,200);assert.equal(result.total,45);assert.equal(result.items.length,20);assert.equal(result.items[0].id,'CVE-2026-10044');assert.equal(h.calls.length,4);
});
