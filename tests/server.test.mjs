import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import '../public/dates.js';
test('server serves all dashboard assets and preserves HTTP guards',async()=>{
 const filename=fileURLToPath(new URL('../server.mjs',import.meta.url));
 let source=await readFile(filename,'utf8');
 source=source.replace(/^import .*;\r?\n/gm,'').replace('fileURLToPath(import.meta.url)',JSON.stringify(filename));
 let handler;
 vm.runInNewContext(source,{http:{createServer:f=>{handler=f;return {listen(){}};}},readFile,path,process:{env:{}},URL,URLSearchParams,AbortSignal,console,CyberDates:globalThis.CyberDates});
 async function request(route,method='GET'){
  let status,headers,body;
  await handler({url:route,method,headers:{host:'localhost'}},{writeHead:(s,h)=>{status=s;headers=h;},end:b=>{body=b;}});
  return {status,headers,body};
 }
  for(const route of ['/','/app.js','/dates.js','/style.css']){
   const res=await request(route);
   assert.equal(res.status,200,route);assert.ok(res.body.length>100);
   assert.match(res.headers['Content-Security-Policy'],/script-src 'self'/);
  }
  assert.equal((await request('/missing')).status,404);
  const health=await request('/healthz');
  assert.equal(health.status,200);
  assert.equal(JSON.parse(health.body).status,'ok');
  assert.equal((await request('/','POST')).status,405);
});
