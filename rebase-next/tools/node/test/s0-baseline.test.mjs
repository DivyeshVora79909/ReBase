import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { checkS0Run, summarizeS0Samples, runS0Baseline, checkS0OverheadPairs } from '../examples/s0-baseline.mjs';
import { deriveS0Action } from '../examples/s0-contract.mjs';

const fixture=name=>new URL(`../../../research/fixtures/${name}`,import.meta.url);
const manifestBytes=await readFile(fixture('s0-workload-manifest.json'));
const inputBytes=await readFile(fixture('s0-inputs.json'));
const manifest=JSON.parse(manifestBytes),inputs=JSON.parse(inputBytes);
const traceSchema=JSON.parse(await readFile(fixture('s0-trace.schema.json')));
const hash=v=>createHash('sha256').update(v).digest('hex');
function uuid5(name){const bytes=createHash('sha1').update(Buffer.from('6ba7b8129dad11d180b400c04fd430c8','hex')).update(name).digest().subarray(0,16);bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;const h=bytes.toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;}
const files=[{path:'src/test.rs',sha256:'a'.repeat(64)}];
const source={kind:'working-tree',baseCommit:'b'.repeat(40),binarySha256:'c'.repeat(64),probeInputSha256:hash(`src/test.rs\0${'a'.repeat(64)}\n`),probeInputCount:1,probeInputs:structuredClone(files)};
const options={manifest,manifestBytes,inputBytes,traceSchema,source};
const work=()=>Object.fromEntries(['work_units','command_visits','route_entries','selector_visits','node_visits','key_loads','loaded_bytes','staged_patches','candidates','evaluations','rotations','causal_candidates','causal_evaluations','dependency_edges','dependency_checks','graph_nodes','scheduler_visits','reader_checks','inventory_visits','allocations','detached_outputs','final_dirty_keys','encoded_bytes'].map(k=>[k,0]));
function run(){
  const corpus=inputs.corpora[0],derived=deriveS0Action(corpus,'prefix'),root={id:corpus.nByRoot[0].owner,slot:2},member={id:derived.beforeMembers[0].id,slot:1};
  const revision='dddddddd-dddd-4ddd-8ddd-dddddddddddd',summary={kind:'financial',value:derived.beforeRoots[0].summary};
  const key=(tag,id,slot)=>`${tag.toString(16).padStart(2,'0')}${id.replaceAll('-','')}${slot===undefined?'':slot.toString(16).padStart(4,'0')}`;
  const row=(key,type,data)=>{const decoded={type,data};return{key,value:Buffer.from(JSON.stringify(decoded)).toString('hex'),decoded};};
  const rows=corpus.setupCommands.map(command=>row(key(1,command.id),'record',{contract:command.contract,tenant:corpus.tenant,owner:corpus.actor,reader:corpus.actor,version:revision,input:command.fields,derived:null}));
  rows.push(row(key(2,root.id,root.slot),'root',{kind:1,head:member,first:member,last:member,height:1,span:{first:'0',last:'0'},summary,revision}));
  rows.push(row(key(3,member.id,member.slot),'node',{kind:1,root,key:{value:'0',id:member.id,slot:1},leaf:{kind:'financial',value:'1'},parent:null,left:null,right:null,prev:null,next:null,height:1,span:{first:'0',last:'0'},summary}));
  const snapshot={complete:true,tables:['native_kv'],rows};
  const setupCommandBatches=Array.from({length:Math.ceil(corpus.setupCommands.length/64)},(_,index)=>corpus.setupCommands.slice(index*64,(index+1)*64));
  const sample={corpusId:'entry-1',action:'prefix',actionId:'focused/entry-1/prefix/0/false',operationId:null,sampleIndex:0,pairIndex:null,traceEnabled:false,readOnly:true,setupCommands:corpus.setupCommands,setupCommandBatches,actionCommands:[],allocations:[],before:snapshot,after:snapshot,result:'1',work:work(),trace:null,setupNs:1,warmupNs:1,beforeObservationNs:1,afterObservationNs:1,observationNs:2,operationNs:10,commitNs:null,commitBoundaryNs:null,outcome:'success',error:null};
  const report={format:'rebase-s0-probe-report-1',backend:'redb',phase:'focused',manifestSha256:hash(manifestBytes),inputsSha256:hash(inputBytes),sourceFingerprint:{algorithm:'sha256(path + NUL + sha256(file) + LF), sorted paths',sha256:source.probeInputSha256,files:structuredClone(files)},complete:true,incompleteReasons:[],samples:[{...sample,cachePhase:'attempt-first'},{...sample,cachePhase:'attempt-repeat'}],cleanup:{complete:true}};
  return structuredClone({format:'rebase-s0-run-1',request:{format:'rebase-s0-probe-input-1',backend:'redb',location:'/tmp/s0-owned-test',namespace:null,clusterFile:null,phase:'focused',cases:[{corpus:'entry-1',action:'prefix'}],samples:1,trace:false,manifestSha256:hash(manifestBytes),inputsSha256:hash(inputBytes)},source,binarySha256:source.binarySha256,report,complete:true,incompleteReasons:[],cleanup:{processStopped:true}});
}

function tracedRun(){
  const result=run();result.request.trace=true;
  const first=result.report.samples[0],repeat=result.report.samples[1],actionId='focused/entry-1/prefix/0/true';
  const prefix=Buffer.alloc(8);prefix.writeBigUInt64BE(BigInt(actionId.length));
  const token=key=>createHash('sha256').update(prefix).update(actionId).update(Buffer.from(key,'hex')).digest('hex');
  const root=first.before.rows.find(r=>r.decoded.type==='root'),node=first.before.rows.find(r=>r.decoded.type==='node');
  const rootToken=token(root.key),nodeToken=token(node.key),rootBytes=root.value.length/2,nodeBytes=node.value.length/2,totalBytes=rootBytes+nodeBytes;
  const event=(id,layer,operation,keyToken,overrides={})=>({id,parentId:null,executionPredecessorId:null,layer,operation,role:'native',startNs:id*3,endNs:id*3+1,keyToken,keyKnowledge:'invocation',keyDiscoveredBy:null,controlDependencies:[],outcome:'found',rows:1,keyBytes:0,valueBytes:0,discoveredKeyTokens:[],...overrides});
  const counters={logicalTouches:2,attemptCacheHits:0,attemptLoadAttempts:2,attemptLoadedValueBytes:totalBytes,nodeVisits:1,selectorVisits:0,facadeGet:2,facadeScan:0,facadePut:0,facadeRemove:0,bindingGet:null,bindingGetRange:null,bindingSet:null,bindingClear:null,bindingClearRange:null,bindingApproximateSize:null,returnedRows:2,readKeyBytes:38,readValueBytes:totalBytes,writeKeyBytes:0,writeValueBytes:0,sdk:null,retryCount:0};
  const trace={format:'rebase-s0-trace-1',actionId,attemptId:actionId,operationId:null,backend:'redb',path:'native-tree',phase:'attempt-first',complete:true,incompleteReasons:[],outcome:'success',durationNs:20,commitNs:null,initialKeys:[{token:rootToken,origin:'invocation'}],counters,dependency:{complete:true,incompleteReason:null,observedReadDepth:2,remoteReadRounds:null},events:[
    event(0,'attempt','load',rootToken,{endNs:4,valueBytes:rootBytes,discoveredKeyTokens:[nodeToken]}),
    event(1,'facade','get',rootToken,{parentId:0,keyBytes:19,valueBytes:rootBytes}),
    event(2,'attempt','load',nodeToken,{endNs:10,keyKnowledge:'result-discovered',keyDiscoveredBy:0,valueBytes:nodeBytes}),
    event(3,'facade','get',nodeToken,{parentId:2,keyBytes:19,valueBytes:nodeBytes,keyKnowledge:'previously-known',keyDiscoveredBy:null})]};
  Object.assign(first,{actionId,traceEnabled:true,trace,work:{...work(),work_units:3,node_visits:1,key_loads:2,loaded_bytes:totalBytes}});
  Object.assign(repeat,{actionId,traceEnabled:true,trace:{...structuredClone(trace),phase:'attempt-repeat',initialKeys:[{token:rootToken,origin:'attempt-cache'},{token:nodeToken,origin:'attempt-cache'}],events:[],counters:{...counters,logicalTouches:0,attemptLoadAttempts:0,attemptLoadedValueBytes:0,nodeVisits:0,facadeGet:0,returnedRows:0,readKeyBytes:0,readValueBytes:0},dependency:{complete:true,incompleteReason:null,observedReadDepth:0,remoteReadRounds:null}}});
  return result;
}

test('S0 report checks actual raw source, root, member bytes and complete sample set',()=>{
  const checked=checkS0Run(run(),options);assert.equal(checked.status,'incomplete');assert.equal(checked.checkedSamples,2);assert.ok(checked.incompleteReasons.includes('adapter-control-missing'));assert.ok(checked.incompleteReasons.includes('application-rollback-control-missing'));
  const duplicate=run();duplicate.report.samples.push(duplicate.report.samples[0]);assert.throws(()=>checkS0Run(duplicate,options),/duplicate raw sample/);
  const missing=run();missing.report.samples.pop();assert.throws(()=>checkS0Run(missing,options),/omitted selected raw/);
  const partial=run();partial.report.samples.pop();partial.report.complete=false;partial.report.incompleteReasons=['event-bound'];assert.equal(checkS0Run(partial,options).status,'incomplete');
  const wrong=run();wrong.report.samples[0].result='2';assert.throws(()=>checkS0Run(wrong,options),/query result differs/);
  const badWitness=run();badWitness.report.samples[0].before.rows[0].decoded.data.input={native_unit:9};assert.throws(()=>checkS0Run(badWitness,options),/decoded witness/);
  const badBytes=run();const row=badBytes.report.samples[0].before.rows.find(r=>r.decoded.type==='node');row.decoded.data.leaf.value='2';row.value=Buffer.from(JSON.stringify(row.decoded)).toString('hex');assert.throws(()=>checkS0Run(badBytes,options),/summary|source membership/);
  const rollback=run();rollback.report.controls=[{name:'calculation-root-complete-time-invariant-rollback',timed:false,outcome:'success',unchanged:true,errorCode:'invariant',operationStatus:{status:'not_observed'}}];assert.ok(!checkS0Run(rollback,options).incompleteReasons.includes('application-rollback-control-missing'));
  rollback.report.controls[0].operationStatus.status='not-observed';assert.throws(()=>checkS0Run(rollback,options),/application rollback control failed/);
});

test('S0 posting revalue checks both financial memberships and quote membership at native slot three',()=>{
  const corpus=inputs.corpora.find(c=>c.id==='posting-1'),action=corpus.actions.find(a=>a.id==='revalue-posting'),derived=deriveS0Action(corpus,action.id);
  const revision='dddddddd-dddd-4ddd-8ddd-dddddddddddd',afterRevision='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',actionId='focused/posting-1/revalue-posting/0/false';
  const nativeKey=(tag,id,slot)=>`${tag.toString(16).padStart(2,'0')}${id.replaceAll('-','')}${slot===undefined?'':slot.toString(16).padStart(4,'0')}`;
  const encode=(key,decoded)=>({key,value:Buffer.from(JSON.stringify(decoded)).toString('hex'),decoded});
  const snapshot=(records,financial,roots,recordRevision=revision)=>{
    const rows=records.map(record=>{
      const amounts=financial.filter(member=>member.id===record.id);
      const recordDerived=record.contract===6?{native_minor:amounts.find(m=>m.slot===1).amount,reporting_minor:amounts.find(m=>m.slot===2).amount}:null;
      return encode(nativeKey(1,record.id),{type:'record',data:{contract:record.contract,tenant:corpus.tenant,owner:corpus.actor,reader:corpus.actor,version:recordRevision,input:record.fields,derived:recordDerived}});
    });
    const trees=[{kind:2,owner:corpus.setupCommands.find(c=>c.contract===2).id,slot:1,members:corpus.setupCommands.filter(c=>c.contract===3).map(c=>({id:c.id,slot:3,time:c.fields.at,leaf:{kind:'quote',value:c.fields.rate}})),summaryKind:'quote'}];
    for(const root of roots)trees.push({kind:1,owner:root.owner,slot:root.slot,members:financial.filter(member=>member.owner===root.owner&&member.rootSlot===root.slot).map(member=>({id:member.id,slot:member.slot,time:member.key,leaf:{kind:'financial',value:member.amount}})),summaryKind:'financial',summary:root.summary});
    for(const tree of trees){
      const [member]=tree.members;assert.ok(member,'fixture tree has one member');
      const address={id:member.id,slot:member.slot},summary=tree.summaryKind==='quote'?{kind:'quote',value:{count:1,first:member.time,last:member.time}}:{kind:'financial',value:tree.summary};
      rows.push(encode(nativeKey(2,tree.owner,tree.slot),{type:'root',data:{kind:tree.kind,head:address,first:address,last:address,height:1,span:{first:member.time,last:member.time},summary,revision:recordRevision}}));
      rows.push(encode(nativeKey(3,member.id,member.slot),{type:'node',data:{kind:tree.kind,root:{id:tree.owner,slot:tree.slot},key:{value:member.time,id:member.id,slot:member.slot},leaf:member.leaf,parent:null,left:null,right:null,prev:null,next:null,height:1,span:{first:member.time,last:member.time},summary}}));
    }
    return {complete:true,tables:['native_kv'],rows};
  };
  const makeSample=(records,financial,roots)=>({corpusId:corpus.id,action:action.id,actionId,operationId:uuid5(`s0-native-avl-1/${actionId}/operation/0`),sampleIndex:0,pairIndex:null,traceEnabled:false,readOnly:false,setupCommands:corpus.setupCommands,setupCommandBatches:Array.from({length:Math.ceil(corpus.setupCommands.length/64)},(_,i)=>corpus.setupCommands.slice(i*64,(i+1)*64)),actionCommands:[{op:'update',id:action.record,if_version:revision,set:action.set,unset:[]}],allocations:[],before:snapshot(derived.beforeRecords,derived.beforeMembers,derived.beforeRoots),after:snapshot(records,financial,roots,afterRevision),result:{revision:afterRevision},work:work(),trace:null,setupNs:1,warmupNs:1,beforeObservationNs:1,afterObservationNs:1,observationNs:2,operationNs:10,commitNs:null,commitBoundaryNs:null,outcome:'success',error:null,cachePhase:'attempt-first'});
  const result=run(),sample=makeSample(derived.afterRecords,derived.afterMembers,derived.afterRoots);
  result.request.cases=[{corpus:corpus.id,action:action.id}];result.report.samples=[sample];
  assert.equal(checkS0Run(result,options).checkedSamples,1);
  const wrongSlot=structuredClone(result),bad=wrongSlot.report.samples[0].before;
  const quoteRoot=bad.rows.find(row=>row.decoded.type==='root'&&row.decoded.data.kind===2);
  const quoteNode=bad.rows.find(row=>row.decoded.type==='node'&&row.decoded.data.leaf.kind==='quote');
  quoteRoot.decoded.data.head.slot=1;quoteRoot.decoded.data.first.slot=1;quoteRoot.decoded.data.last.slot=1;
  quoteNode.decoded.data.key.slot=1;quoteNode.key=nativeKey(3,quoteNode.decoded.data.key.id,1);
  quoteRoot.value=Buffer.from(JSON.stringify(quoteRoot.decoded)).toString('hex');quoteNode.value=Buffer.from(JSON.stringify(quoteNode.decoded)).toString('hex');
  assert.throws(()=>checkS0Run(wrongSlot,options),/membership|member|inventory|slot|tree/i);
});

test('S0 source/build identity, exact commands and Work are checked independently',()=>{
  const changed=run();changed.source={...source,probeInputSha256:'0'.repeat(64)};assert.throws(()=>checkS0Run(changed,options),/source map digest/);
  const modified=run();modified.report.sourceFingerprint.files[0]={path:'src/other.rs',sha256:'a'.repeat(64)};assert.throws(()=>checkS0Run(modified,options),/source map differs/);
  // Restore the shared authored test fingerprint after deliberate corruption.
  files[0]={path:'src/test.rs',sha256:'a'.repeat(64)};
  const command=run();command.report.samples[0].actionCommands=[{op:'delete'}];assert.throws(()=>checkS0Run(command,options),/tree action/);
  const batches=run();batches.report.samples[0].setupCommandBatches[0].pop();assert.throws(()=>checkS0Run(batches,options),/setup command batches/);
  const workMismatch=run();workMismatch.report.samples[0].work.work_units=1;assert.throws(()=>checkS0Run(workMismatch,options),/charged total/);
});

test('S0 working-tree evidence explicitly names its base and is restricted to focused verification',()=>{
  const missingKind=run();delete missingKind.source.kind;assert.throws(()=>checkS0Run(missingKind,options),/source kind/);
  const mixed=run();mixed.source.exactSourceCommit=mixed.source.baseCommit;assert.throws(()=>checkS0Run(mixed,options),/mutually exclusive/);
  const missingMap=run();delete missingMap.source.probeInputs;assert.throws(()=>checkS0Run(missingMap,options),/source identity fields/);
  const baseline=run();baseline.request.phase='baseline';baseline.request.samples=30;baseline.request.cases=manifest.cases.flatMap(c=>c.corpusIds.flatMap(corpus=>c.selectedActionIds.map(action=>({corpus,action}))));
  assert.throws(()=>checkS0Run(baseline,options),/limited to focused/);
  const committed=run();const {baseCommit,...rest}=source;const exact={...rest,kind:'committed',exactSourceCommit:baseCommit};committed.source=exact;
  assert.equal(checkS0Run(committed,{...options,source:exact}).checkedSamples,2);
});

test('S0 FDB requests use the same bounded owned namespace accepted by the native probe',()=>{
  const fdb=run();fdb.request.backend='foundationdb-local';fdb.report.backend='foundationdb-local';fdb.request.namespace='rebase-s0-owned-test';fdb.request.clusterFile='/tmp/s0-owned.cluster';
  assert.equal(checkS0Run(fdb,options).checkedSamples,2);
  fdb.request.namespace='s0_unowned';assert.throws(()=>checkS0Run(fdb,options),/owned FDB namespace/);
});

test('S0 read trace discloses exactly actual decoded native addresses with faithful invocation seeds',()=>{
  assert.equal(checkS0Run(tracedRun(),options).checkedSamples,2);
  const fabricated=tracedRun();fabricated.report.samples[0].trace.events[0].discoveredKeyTokens.push('f'.repeat(64));assert.throws(()=>checkS0Run(fabricated,options),/disclosure witness differs/);
  const seeded=tracedRun(),trace=seeded.report.samples[0].trace,nodeToken=trace.events[2].keyToken;
  trace.initialKeys.push({token:nodeToken,origin:'invocation'});trace.events[2].keyKnowledge='invocation';trace.events[2].keyDiscoveredBy=null;trace.dependency.observedReadDepth=1;
  assert.throws(()=>checkS0Run(seeded,options),/invocation native key seeds differ/);
});

test('S0 unknown outcomes stay incomplete and preserve original commands and IDs',()=>{
  const unknown=run();unknown.report.samples=unknown.report.samples.slice(0,1);unknown.report.samples[0].outcome='unknown';unknown.report.samples[0].result=null;unknown.report.complete=false;unknown.report.incompleteReasons=['unknown'];
  const checked=checkS0Run(unknown,options);assert.equal(checked.status,'incomplete');assert.equal(checked.statistics[0].quantiles,null);assert.equal(unknown.report.samples[0].actionId,'focused/entry-1/prefix/0/false');
  const killed=run();killed.report=null;killed.complete=false;killed.incompleteReasons=['backend-deadline'];assert.equal(checkS0Run(killed,options).status,'incomplete');
});

test('S0 nearest-rank quantiles come from all raw durations with p99=max at n=30',()=>{
  const stats=summarizeS0Samples(Array.from({length:30},(_,i)=>({operationNs:i+1,outcome:'success'})));
  assert.deepEqual(stats,{n:30,min:1,p50:15,p95:29,p99:30,max:30});
  assert.throws(()=>summarizeS0Samples([{operationNs:10,outcome:'unknown'}]),/successful/);
  assert.throws(()=>summarizeS0Samples([]),/raw statistics/);
});

test('S0 matched thirty overhead pairs retain alternating raw samples and native Work',()=>{
  const samples=Array.from({length:30},(_,index)=>(index%2===0?[false,true]:[true,false]).map(enabled=>({sampleIndex:index,cachePhase:'attempt-first',traceEnabled:enabled,operationNs:enabled?20:10,outcome:'success',work:work()}))).flat();
  const checked=checkS0OverheadPairs(samples);assert.equal(checked.pairs.length,30);assert.deepEqual(checked.incompleteReasons,[]);assert.ok(checked.pairs.every(p=>p.ratio===2));
  const missing=structuredClone(samples);missing.pop();assert.deepEqual(checkS0OverheadPairs(missing).incompleteReasons,['overhead-pair-incomplete:29']);
  const reordered=structuredClone(samples);[reordered[2],reordered[3]]=[reordered[3],reordered[2]];assert.throws(()=>checkS0OverheadPairs(reordered),/must alternate/);
  const changed=structuredClone(samples);changed[0].work.node_visits=1;assert.throws(()=>checkS0OverheadPairs(changed),/changed native Work/);
  const unknown=structuredClone(samples);unknown[0].outcome='unknown';const partial=checkS0OverheadPairs(unknown);assert.equal(partial.pairs[0].ratio,null);assert.ok(partial.incompleteReasons.includes('overhead-ratio-unavailable:0'));
});

test('S0 runner requires explicit absolute probe before starting a process',async()=>{
  await assert.rejects(runS0Baseline({probe:'s0_baseline'}),/absolute compiled probe/);
  await assert.rejects(runS0Baseline({probe:'/missing/probe'}),/explicit child environment/);
});

test('S0 bounded child errors retain original request and explicit incomplete cleanup',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'s0-node-process-'));
  try{
    for(const [name,body,timeoutMs,reason]of[
      ['malformed',"process.stdin.once('data',()=>{process.stdout.write('{');process.exit(0)})",2000,'invalid-or-partial-report'],
      ['stderr',"process.stdin.once('data',()=>{process.stderr.write('x'.repeat(70000));setInterval(()=>{},1000)})",2000,'stderr-byte-bound'],
      ['deadline',"process.stdin.once('data',()=>setInterval(()=>{},1000))",100,'backend-deadline'],
    ]){
      const probe=path.join(directory,name),bytes=Buffer.from(`#!${process.execPath}\n${body}\n`);
      await writeFile(probe,bytes,{mode:0o700});
      const request={...run().request,location:path.join(directory,`${name}-owned`)};
      const result=await runS0Baseline({probe,environment:{},request,source:{...source,binarySha256:hash(bytes)},timeoutMs});
      assert.equal(result.complete,false);assert.equal(result.report,null);assert.ok(result.incompleteReasons.includes(reason),`${name}: ${result.incompleteReasons.join(',')}`);assert.equal(result.cleanup.processStopped,true);
      assert.ok(result.resources.length>=2);assert.ok(result.resources.some(row=>row.stage==='startup'));assert.ok(result.resources.some(row=>row.stage==='end'));
      assert.equal(result.resourceObservation.format,'rebase-s0-resources-1');assert.equal(result.resourceObservation.complete,false);
      assert.deepEqual(result.request.cases,request.cases);assert.equal(result.request.location,request.location);
    }
    const recovered={format:'rebase-s0-probe-report-1',complete:false,incompleteReasons:['unknown'],failedAction:{actionId:'focused/entry-1/prefix/0/false',operationId:null,commands:[{op:'update',if_version:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'}],outcome:'unknown'}};
    const probe=path.join(directory,'structured-failure'),bytes=Buffer.from(`#!${process.execPath}\nprocess.stdin.once('data',()=>process.stdout.end(${JSON.stringify(JSON.stringify(recovered))},()=>process.exit(1)));\n`);
    await writeFile(probe,bytes,{mode:0o700});
    const result=await runS0Baseline({probe,environment:{},request:{...run().request,location:path.join(directory,'failure-owned')},source:{...source,binarySha256:hash(bytes)},timeoutMs:2000});
    assert.equal(result.complete,false);assert.ok(result.incompleteReasons.includes('probe-process-failed'));assert.deepEqual(result.report,recovered);assert.equal(result.cleanup.processStopped,true);
    assert.ok(result.resources.some(row=>row.stage==='startup'));assert.equal(result.resourceObservation.complete,false);
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('S0 runner observes native work only at a paused, independently checked checkpoint',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'s0-node-resources-'));
  try{
    const data=path.join(directory,'store');await mkdir(data);await writeFile(path.join(data,'segment.dat'),'physical evidence');
    const fixture=run(),samples=fixture.report.samples,request={...fixture.request,location:path.join(directory,'owned-location')};
    const start={format:'rebase-s0-start-1',sourceFingerprint:fixture.report.sourceFingerprint,backend:request.backend,phase:request.phase,manifestSha256:request.manifestSha256,inputsSha256:request.inputsSha256};
    const checkpointFrames=samples.map(sample=>({format:'rebase-s0-checkpoint-1',sample}));
    const finalReport=fixture.report;
    const makeBody=report=>`const readline=require('node:readline');const fs=require('node:fs');const rl=readline.createInterface({input:process.stdin,crlfDelay:Infinity});let first=true,ack;const waitAck=()=>new Promise(resolve=>{ack=resolve});rl.on('line',async line=>{if(first){first=false;const req=JSON.parse(line);fs.mkdirSync(req.location,{recursive:true});console.log(${JSON.stringify(JSON.stringify(start))});for(const frame of ${JSON.stringify(checkpointFrames)}){console.log(JSON.stringify(frame));const answer=await waitAck();if(!answer.continue){process.exit(0);return;}}console.log(${JSON.stringify(JSON.stringify(report))});process.exit(0);return;}const value=JSON.parse(line);if(ack){const done=ack;ack=null;done(value);}});`;
    const body=makeBody(finalReport);
    const probe=path.join(directory,'checkpoint-probe'),bytes=Buffer.from(`#!${process.execPath}\n${body}\n`);
    await writeFile(probe,bytes,{mode:0o700});
    const result=await runS0Baseline({probe,environment:{},request,source:{...source,binarySha256:hash(bytes)},timeoutMs:3000,resourcePaths:[data]});
    const checkpointResource=result.resources.find(row=>row.stage==='checkpoint');
    assert.equal(result.resources.filter(row=>row.stage==='checkpoint').length,samples.length,'one raw observation is retained per native checkpoint');
    assert.ok(checkpointResource,'checkpoint resource observation is retained');
    assert.equal(checkpointResource.actionId,samples[0].actionId);assert.equal(checkpointResource.cachePhase,samples[0].cachePhase);
    assert.ok(checkpointResource.physical?.available,JSON.stringify(checkpointResource.physical));assert.ok(checkpointResource.physical.bytes>0);assert.ok(checkpointResource.physical.paths.includes(data));
    assert.deepEqual(result.resourceObservation.roles,['probe']);assert.ok(result.resourceObservation.paths.includes(request.location));assert.ok(result.resourceObservation.paths.includes(data));
    assert.equal(result.resourceObservation.disk.available,true);assert.equal(result.resourceObservation.maxSamples,3842);
    assert.equal(result.resourceObservation.complete,true);assert.equal(result.checkpoints.checked,samples.length);
    assert.equal(result.complete,true);assert.deepEqual(result.incompleteReasons,[]);
    assert.ok(result.resources.every(row=>row.stage==='startup'||row.stage==='checkpoint'||row.stage==='end'));
    const independentlyChecked=checkS0Run(result,{...options,source:{...source,binarySha256:hash(bytes)}});
    assert.equal(independentlyChecked.status,'incomplete');
    assert.ok(independentlyChecked.incompleteReasons.includes('adapter-control-missing'));
    assert.ok(independentlyChecked.incompleteReasons.includes('application-rollback-control-missing'));
    assert.ok(independentlyChecked.incompleteReasons.every(reason=>!reason.startsWith('resource-')),'complete resource evidence adds no checker incompleteness');

    const nativeReason='native-resource-or-bound-example',incompleteReport={...structuredClone(finalReport),complete:false,incompleteReasons:[nativeReason]};
    const incompleteProbe=path.join(directory,'native-incomplete'),incompleteBytes=Buffer.from(`#!${process.execPath}\n${makeBody(incompleteReport)}\n`);
    await writeFile(incompleteProbe,incompleteBytes,{mode:0o700});
    const incomplete=await runS0Baseline({probe:incompleteProbe,environment:{},request:{...request,location:path.join(directory,'native-incomplete-location')},source:{...source,binarySha256:hash(incompleteBytes)},timeoutMs:3000,resourcePaths:[data]});
    assert.equal(incomplete.report.complete,false);assert.deepEqual(incomplete.report.incompleteReasons,[nativeReason]);
    assert.equal(incomplete.complete,false);assert.ok(incomplete.incompleteReasons.includes(nativeReason));

    const wrong=structuredClone(samples[0]);wrong.result='2';const badCheckpoint={format:'rebase-s0-checkpoint-1',sample:wrong};
    const badBody=`const readline=require('node:readline');const rl=readline.createInterface({input:process.stdin,crlfDelay:Infinity});let first=true,ack;const waitAck=()=>new Promise(resolve=>{ack=resolve});rl.on('line',async line=>{if(first){first=false;console.log(${JSON.stringify(JSON.stringify(start))});console.log(${JSON.stringify(JSON.stringify(badCheckpoint))});const answer=await waitAck();if(answer.continue)console.log(${JSON.stringify(JSON.stringify(checkpointFrames[1]))});process.exit(0);return;}const value=JSON.parse(line);if(ack){const done=ack;ack=null;done(value);}});`;
    const badProbe=path.join(directory,'rejected-checkpoint'),badBytes=Buffer.from(`#!${process.execPath}\n${badBody}\n`);
    await writeFile(badProbe,badBytes,{mode:0o700});
    const rejected=await runS0Baseline({probe:badProbe,environment:{},request:{...request,location:path.join(directory,'rejected-location')},source:{...source,binarySha256:hash(badBytes)},timeoutMs:3000,resourcePaths:[data]});
    assert.ok(rejected.incompleteReasons.includes('independent-correctness-mismatch'));
    assert.equal(rejected.checkpoints.checked,0);assert.match(rejected.checkpoints.rejected.error,/query result differs/);
    assert.deepEqual(rejected.checkpoints.rejected.checkpoint,badCheckpoint,'the exact rejected checkpoint envelope is retained');
    assert.equal(rejected.resources.filter(row=>row.stage==='checkpoint').length,1);
    assert.equal(rejected.report.samples.length,1,'the rejected sample remains in incomplete evidence');
  }finally{await rm(directory,{recursive:true,force:true});}
});
