import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import '../public/dates.js';
const D=globalThis.CyberDates;
const rows=[{id:'a',published:'2026-11-17T17:00:00',score:7},{id:'b',published:'2026-11-17T17:00:00Z',score:9},{id:'c',published:'2026-11-18T16:59:59.999Z',score:9},{id:'d',published:'2026-11-18T17:00:00Z'}, {id:'e',published:null},{id:'f',published:'invalid'}];
const ids=a=>a.map(x=>x.id);
test('inclusive WIB range and offset-free UTC timestamps',()=>{
 assert.equal(D.timestamp(rows[0].published),D.timestamp(rows[1].published));
 assert.deepEqual(ids(D.select(rows,{field:'published',from:'2026-11-18',to:'2026-11-18'})),['c','a','b']);
});
test('stable dates in both directions, invalid dates always last, no mutation',()=>{
 assert.deepEqual(ids(D.select(rows,{field:'published',order:'oldest'})),['a','b','c','d','e','f']);
 assert.deepEqual(ids(D.select(rows,{field:'published'})),['d','c','a','b','e','f']);
 assert.deepEqual(ids(rows),['a','b','c','d','e','f']);
});
test('open boundaries, reversed/invalid dates, absent modified date',()=>{
 assert.deepEqual(ids(D.select(rows,{field:'published',from:'2026-11-19'})),['d']);
 assert.deepEqual(ids(D.select(rows,{field:'published',to:'2026-11-17'})),[]);
 assert.deepEqual(D.select(rows,{field:'published',from:'2026-11-19',to:'2026-11-18'}),[]);
 assert.deepEqual(D.select(rows,{field:'published',from:'2026-02-30'}),[]);
 assert.deepEqual(D.select(rows,{field:'lastModified',from:'2026-11-18'}),[]);
});
test('score sort remains stable after date filtering',()=>{
 assert.deepEqual(ids(D.select(rows,{field:'published',from:'2026-11-18',to:'2026-11-18',score:true})),['b','c','a']);
});
test('app integration: search/filter rendering, date controls and refresh timers',async()=>{
 class El{
  constructor(){this.value='';this.children=[];this.listeners={};this.classList={toggle(){}};this.style={};}
  append(...xs){this.children.push(...xs);} replaceChildren(...xs){this.children=xs;}
  prepend(...xs){this.children.unshift(...xs);} addEventListener(k,f){this.listeners[k]=f;}
 }
 const els=new Map(),get=id=>{if(!els.has(id))els.set(id,new El());return els.get(id);};
 const intervals=[],requests=[];
 const context=vm.createContext({document:{querySelector:get,querySelectorAll:()=>[],createElement:()=>new El()},Intl,Date,URLSearchParams,console,setInterval:(f,t)=>intervals.push(t),fetch:url=>new Promise(resolve=>requests.push({url,reply:data=>resolve({ok:true,json:async()=>data}),fail:()=>resolve({ok:false,json:async()=>({error:'The operation was aborted due to timeout'})})}))});
 vm.runInContext(await readFile(new URL('../public/dates.js',import.meta.url),'utf8'),context);
 vm.runInContext(await readFile(new URL('../public/app.js',import.meta.url),'utf8'),context);
 for(const [id,value] of Object.entries({'#severity':'HIGH','#kev-filter':'kev','#sort':'oldest','#cve-date-field':'lastModified','#cve-from':'2026-11-18','#cve-to':'2026-11-18','#cloud-date-field':'updated','#cloud-sort':'oldest','#cloud-query':'match'}))get(id).value=value;
 vm.runInContext(`state.cves=[
 {id:'1',severity:'HIGH',kev:true,lastModified:'2026-11-18T01:00:00Z'},
 {id:'2',severity:'LOW',kev:true,lastModified:'2026-11-18T00:00:00Z'},
 {id:'3',severity:'HIGH',kev:false,lastModified:'2026-11-18T00:00:00Z'},
 {id:'4',severity:'HIGH',kev:true,lastModified:'2026-11-17T17:00:00Z'}];`,context);
 assert.equal(vm.runInContext('filtered().map(x=>x.id).join(",")',context),'4,1');
 assert.match(vm.runInContext('wib("2026-11-17T17:00:00")',context),/18.*00[.:]00 WIB/);
 vm.runInContext(`state.cloud={cloudflare:{state:'ok',incidents:[{name:'match later',body:'',updated:'2026-11-18T02:00:00Z'},{name:'match earlier',body:'',updated:'2026-11-18T01:00:00Z'},{name:'hidden',body:'',updated:'2026-11-18T00:00:00Z'}]},azure:{state:'feed',items:[]}};renderIncidents();`,context);
 assert.equal(get('#cf-incidents').children.length,2);
 assert.equal(get('#cf-incidents').children[0].children[0].children[0].textContent,'match earlier');
 assert.deepEqual(intervals,[300000,1000]);
 assert.ok(get('#cve-from').listeners.change);
 assert.ok(get('#cloud-query').listeners.input);
 vm.runInContext('state.cves=[];toggleDateSort("published")',context);
 assert.equal(get('#cve-date-field').value,'published');
 assert.equal(get('#sort').value,'newest');
 vm.runInContext('toggleDateSort("published")',context);
 assert.equal(get('#sort').value,'oldest');
 vm.runInContext('toggleDateSort("published")',context);
 assert.equal(get('#sort').value,'newest');
 vm.runInContext('toggleDateSort("lastModified")',context);
 assert.equal(get('#cve-date-field').value,'lastModified');
 assert.equal(get('#sort').value,'newest');
 assert.equal(get('#severity').value,'HIGH');
 assert.equal(get('#kev-filter').value,'kev');
 assert.equal(get('#cve-from').value,'2026-11-18');
 const latestUrl=new URL(requests.at(-1).url,'http://localhost');
 assert.equal(latestUrl.searchParams.get('field'),'lastModified');
 assert.equal(latestUrl.searchParams.get('order'),'newest');
 assert.equal(latestUrl.searchParams.get('from'),'2026-11-18');
 assert.equal(latestUrl.searchParams.get('severity'),'HIGH');
 // A slow older search must not replace results for a more recent search.
 const older=vm.runInContext('state.q="older";cves()',context),oldRequest=requests.at(-1);
 const newer=vm.runInContext('state.q="newer";cves()',context),newRequest=requests.at(-1);
 const payload=total=>({items:[],total,page:1,sourceTotal:total,checkedAt:'2026-11-18T00:00:00Z',range:null});
 newRequest.reply(payload(7));await newer;
 oldRequest.reply(payload(99));await older;
 assert.equal(vm.runInContext('state.total',context),7);
 const valid={id:'CVE-2026-99999',description:'test',severity:'HIGH',kev:true,published:'2026-11-18T01:00:00Z',lastModified:'2026-11-18T01:00:00Z',cwe:[],score:8,cvssVersion:'3.1',url:'https://nvd.nist.gov/'};
 const success=vm.runInContext('cves()',context);requests.at(-1).reply({...payload(1),items:[valid]});await success;
 const refresh=vm.runInContext('cves()',context);requests.at(-1).fail();await refresh;
 assert.equal(vm.runInContext('state.cves.length',context),1);
 assert.match(get('#notice').textContent,/previous successful result/);
 assert.doesNotMatch(get('#result-meta').textContent,/Loading/);
 const changed=vm.runInContext('state.q="another query";cves()',context);requests.at(-1).fail();await changed;
 assert.equal(vm.runInContext('state.cves.length',context),0);
 assert.equal(get('#result-meta').textContent,'Unable to load NVD results.');
 assert.equal(get('#retry-cves').disabled,false);
 assert.match(get('#cve-body').children[0].children[0].textContent,/NVD unavailable/);
});
