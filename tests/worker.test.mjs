import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeWorker,providerURL} from '../worker.mjs';
const request=path=>new Request('https://cyberpulse.workers.dev'+path);
test('dashboard assets, scope labels, worker health and HTTP guards',async()=>{
 const worker=makeWorker({fetcher:()=>{throw Error('Unexpected provider request');},edgeCache:()=>null});
 for(const path of ['/','/index.html','/app.js','/client-api.js','/dates.js','/style.css']){
  const r=await worker.fetch(request(path));assert.equal(r.status,200,path);assert.match(r.headers.get('Content-Security-Policy'),/script-src 'self'/);assert.ok((await r.text()).length>100);
 }
 const health=await worker.fetch(request('/healthz'));assert.equal((await health.json()).version,'3.0-workers');
 assert.equal((await worker.fetch(request('/missing'))).status,404);
 assert.equal((await worker.fetch(new Request('https://cyberpulse.workers.dev/',{method:'POST'}))).status,405);
 assert.equal((await worker.fetch(new Request('https://cyberpulse.workers.dev/',{method:'HEAD'}))).body,null);
});
test('proxy is restricted to official providers and validated query parameters',()=>{
 assert.equal(providerURL(new URL('https://x/api/source/nvd?cveId=CVE-2021-44228&resultsPerPage=20')),'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228&resultsPerPage=20');
 assert.equal(providerURL(new URL('https://x/api/source/proxy?url=http://internal')),null);
 for(const q of ['resultsPerPage=501','startIndex=-1','url=http://internal','cveId=a&cveId=b','resultsPerPage=0'])assert.throws(()=>providerURL(new URL('https://x/api/source/nvd?'+q)));
 assert.throws(()=>providerURL(new URL('https://x/api/source/kev?url=http://internal')));
});
test('NVD response is streamed without JSON parsing; API key stays server-side',async()=>{
 let seen;
 const worker=makeWorker({edgeCache:()=>null,fetcher:async(url,options)=>{seen={url,options};const r=new Response('{"vulnerabilities":[]}');r.json=()=>{throw Error('Worker must not parse JSON');};return r;}});
 const response=await worker.fetch(request('/api/source/nvd?resultsPerPage=20'),{NVD_API_KEY:'test-only-secret'});
 assert.equal(response.status,200);assert.equal(await response.text(),'{"vulnerabilities":[]}');assert.equal(seen.options.headers.apiKey,'test-only-secret');
 const client=await worker.fetch(request('/client-api.js'));assert.doesNotMatch(await client.text(),/test-only-secret|process\.env/);
});
test('cache hit avoids upstream call and successful bodies are cached without parsing',async()=>{
 const storage=new Map(),pending=[];let calls=0;
 const worker=makeWorker({fetcher:async()=>{calls++;return new Response('{"items":[]}');},edgeCache:()=>({match:async key=>storage.get(key.url)?.clone(),put:async(key,value)=>{storage.set(key.url,value);}})});
 const first=await worker.fetch(request('/api/source/kev'),{},{waitUntil:p=>pending.push(p)});await Promise.all(pending);
 assert.equal(first.headers.get('Cache-Control'),'public, max-age=21600');
 const second=await worker.fetch(request('/api/source/kev'));assert.equal(calls,1);assert.equal(second.headers.get('X-CyberPulse-Cache'),'HIT');assert.equal(await second.text(),'{"items":[]}');
});
test('provider failures and rate limits remain visible and are never cached',async()=>{
 for(const status of [403,429,500]){
  let cached=false;
  const worker=makeWorker({fetcher:async()=>new Response('failure',{status}),edgeCache:()=>({match:async()=>null,put:async()=>{cached=true;}})});
  const response=await worker.fetch(request('/api/source/nvd'));assert.equal(response.status,status===429?429:502);assert.match((await response.json()).error,new RegExp(String(status)));assert.equal(cached,false);
 }
 const offline=makeWorker({fetcher:async()=>{throw Error('network');},edgeCache:()=>null});assert.equal((await offline.fetch(request('/api/source/azure'))).status,503);
});
test('invalid parameters do not reach upstream',async()=>{
 const worker=makeWorker({fetcher:()=>{throw Error('Should not be called');},edgeCache:()=>null});
 assert.equal((await worker.fetch(request('/api/source/nvd?redirect=http://internal'))).status,400);
});
