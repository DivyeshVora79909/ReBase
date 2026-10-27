import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkS0Inputs, prepareS0TraceCheck, foldS0Financial, deriveS0Action, checkS0Work } from '../examples/s0-contract.mjs';

const fixture = name => new URL(`../../../research/fixtures/${name}`, import.meta.url);
const schema = JSON.parse(await readFile(fixture('s0-trace.schema.json'), 'utf8'));
const check = prepareS0TraceCheck(schema);
const event = (id, overrides = {}) => ({ id, parentId:null, executionPredecessorId:null, layer:'attempt', operation:'load', role:'native', startNs:2*id,endNs:2*id+1,keyToken:'0'.repeat(64),keyKnowledge:'invocation',keyDiscoveredBy:null,controlDependencies:[],outcome:'found',rows:1,keyBytes:1,valueBytes:1,discoveredKeyTokens:[],...overrides });
const trace = () => ({ format:'rebase-s0-trace-1',operationId:null,initialKeys:[{token:'0'.repeat(64),origin:'invocation'}],actionId:'a',attemptId:'a/0',backend:'redb',path:'native-tree',phase:'attempt-first',complete:true,incompleteReasons:[],outcome:'success',durationNs:20,commitNs:null,counters:{logicalTouches:2,attemptCacheHits:0,attemptLoadAttempts:2,attemptLoadedValueBytes:2,nodeVisits:1,selectorVisits:0,facadeGet:0,facadeScan:0,facadePut:0,facadeRemove:0,bindingGet:null,bindingGetRange:null,bindingSet:null,bindingClear:null,bindingClearRange:null,bindingApproximateSize:null,returnedRows:0,readKeyBytes:0,readValueBytes:0,writeKeyBytes:0,writeValueBytes:0,sdk:null,retryCount:0},dependency:{complete:true,incompleteReason:null,observedReadDepth:2,remoteReadRounds:null},events:[event(0,{discoveredKeyTokens:['1'.repeat(64)]}),event(1,{keyToken:'1'.repeat(64),keyKnowledge:'result-discovered',keyDiscoveredBy:0})] });
const rejects = (change, pattern) => { const t=trace(); change(t); assert.throws(()=>check(t),pattern); };

test('S0 selected tree edges and independently known keys have different depth', () => {
  assert.equal(check(trace()).dependencyComplete,true);
  const t=trace(); t.initialKeys.push({token:'1'.repeat(64),origin:'invocation'}); t.events[1].keyKnowledge='invocation'; t.events[1].keyDiscoveredBy=null; t.dependency.observedReadDepth=1;
  assert.equal(check(t).events,2);
  rejects(t=>{t.events[1].keyKnowledge='invocation';},/discovery edge|invocation-known/);
  rejects(t=>{t.dependency.observedReadDepth=1;},/incorrect key read depth/);
  rejects(t=>{t.events[0].discoveredKeyTokens=[];},/first-known witness/);
  rejects(t=>{t.events[1].keyToken='2'.repeat(64);},/first-known witness/);
  rejects(t=>{t.initialKeys.push({token:'1'.repeat(64),origin:'invocation'});},/first-known witness/);
});

test('S0 checks IDs, time bounds, scope containment and completed dependency sources', () => {
  rejects(t=>{t.events[1].id=0;},/duplicate/);
  rejects(t=>{t.events[1].keyDiscoveredBy=88;},/dependency must exist|first-known witness/);
  rejects(t=>{t.events[1].keyDiscoveredBy=1;},/dependency must exist|first-known witness/);
  rejects(t=>{t.events[0].endNs=5;},/finish earlier|first-known witness/);
  rejects(t=>{t.events[1].parentId=0;},/parent scope/);
  rejects(t=>{t.events[1].endNs=99;},/event time/);
  const t=trace(); t.initialKeys.push({token:'1'.repeat(64),origin:'invocation'});t.events[0].endNs=10; t.events[1].parentId=0;t.events[1].keyDiscoveredBy=null;t.events[1].keyKnowledge='invocation';t.dependency.observedReadDepth=1;
  assert.equal(check(t).events,2);
});

test('S0 unsupported metrics stay absent and counts match event retention', () => {
  rejects(t=>{t.counters.bindingGet=0;},/binding counter must be absent/);
  rejects(t=>{t.counters.attemptLoadAttempts=3;},/does not match/);
  rejects(t=>{t.counters.attemptLoadedValueBytes=3;},/does not match/);
  rejects(t=>{t.events[1].operation='set';},/layer\/operation/);
  rejects(t=>{t.backend='foundationdb';},/complete FDB trace/);
  rejects(t=>{t.events[0].startNs=Number.MAX_SAFE_INTEGER+1;},/event time|unsafe/);
  const t=trace();t.complete=false;t.incompleteReasons=['event_bound'];t.dependency={complete:false,incompleteReason:'event_bound',observedReadDepth:null,remoteReadRounds:null};t.counters.attemptLoadAttempts=3;
  assert.equal(check(t).dependencyComplete,false);
  rejects(t=>{t.complete=false;t.incompleteReasons=['event_bound'];},/cannot prove depth/);
  rejects(t=>{t.events[0].keyKnowledge='unknown';},/unknown key lineage/);
});

test('S0 repeat is measured inside same Attempt with no new load', () => {
  const t=trace();t.phase='attempt-repeat';t.initialKeys.push({token:'1'.repeat(64),origin:'attempt-cache'});t.events=t.events.map(e=>({...e,operation:'cache-hit',discoveredKeyTokens:[],keyKnowledge:'previously-known',keyDiscoveredBy:null}));t.counters.attemptLoadAttempts=0;t.counters.attemptCacheHits=2;t.counters.attemptLoadedValueBytes=0;t.dependency.observedReadDepth=0;
  assert.equal(check(t).dependencyComplete,true);
});

test('S0 schema rejects unknown fields and incomplete metrics without reason', () => {
  rejects(t=>{t.secret='unexpected';},/additionalProperties/);
  rejects(t=>{t.dependency.complete=false;t.dependency.observedReadDepth=null;},/type/);
  rejects(t=>{t.complete=false;},/minItems/);
  rejects(t=>{t.incompleteReasons=['event-bound'];},/maxItems/);
});

test('S0 frozen source facts independently reproduce actual n/m/r and expected actions', async () => {
  const manifest=JSON.parse(await readFile(fixture('s0-workload-manifest.json'),'utf8'));
  const bytes=await readFile(fixture('s0-inputs.json'),'utf8');
  assert.deepEqual(checkS0Inputs(manifest,bytes),{status:'checked',corpora:8});
  assert.throws(()=>checkS0Inputs(manifest,bytes+' '),/hash mismatch/);
  const inputs=JSON.parse(bytes);inputs.corpora[0].m=2;
  const changed=JSON.stringify(inputs);const changedManifest=structuredClone(manifest);changedManifest.inputs.sha256=createHash('sha256').update(changed).digest('hex');
  assert.throws(()=>checkS0Inputs(changedManifest,changed),/member slots|manifest corpus\/m/);
  const wrong=structuredClone(manifest);wrong.cases[0].n=[7];
  assert.throws(()=>checkS0Inputs(wrong,bytes),/manifest n mismatch/);
});

test('S0 full occurrence fold handles UUID/slot ties, negative and zero amounts and complete-time extrema', () => {
  const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
  const members=[{id:id(2),slot:1,key:'-1',amount:'9'}, {id:id(1),slot:2,key:'-1',amount:'-5'},
    {id:id(1),slot:1,key:'-1',amount:'2'}, {id:id(3),slot:1,key:'0',amount:'0'}, {id:id(4),slot:1,key:'2',amount:'-8'}];
  assert.deepEqual(foldS0Financial(members),{count:5,first:'-1',last:'2',sum:'-2',min_prefix:'-3',max_prefix:'6',boundary_min:'6',boundary_max:'6'});
  assert.deepEqual(foldS0Financial(members,{from:'0',until:'2'}),{count:1,first:'0',last:'0',sum:'0',min_prefix:'0',max_prefix:'0',boundary_min:null,boundary_max:null});
  assert.equal(foldS0Financial(members,{until:'-1'}).count,0);
  assert.equal(foldS0Financial(members,{from:'-1',until:'0'}).sum,'6');
  assert.equal(foldS0Financial(members,{from:'2',until:'2'}).count,0);
  assert.throws(()=>foldS0Financial([...members,members[0]]),/duplicate member/);
  assert.throws(()=>foldS0Financial([{id:id(1),slot:1,key:'0',amount:String(1n<<127n)}]),/outside native bounds/);
  assert.throws(()=>foldS0Financial([{id:id(1),slot:1,key:'0',amount:String((1n<<127n)-1n)},{id:id(2),slot:1,key:'1',amount:'1'}]),/overflow/);
});

test('S0 source oracle selects exact dated quote and rejects unresolved parents', async () => {
  const inputs=JSON.parse(await readFile(fixture('s0-inputs.json'),'utf8'));
  const corpus=structuredClone(inputs.corpora.find(c=>c.id==='posting-1'));
  const quote=corpus.setupCommands.find(c=>c.contract===3);
  quote.fields.rate='7';
  corpus.setupCommands.push({...structuredClone(quote),id:'00000000-0000-4000-8000-00000000abcd',fields:{...quote.fields,at:'100',rate:'11'}});
  const expected=deriveS0Action(corpus,'revalue-posting');
  assert.equal(expected.beforeMembers.find(m=>m.slot===2).amount,'14');
  assert.equal(expected.afterMembers.find(m=>m.slot===2).amount,'28');
  const broken=structuredClone(corpus);broken.setupCommands=broken.setupCommands.filter(c=>c.contract!==1);
  assert.throws(()=>deriveS0Action(broken,'revalue-posting'),/reference contract unresolved/);
  const absent=structuredClone(corpus);absent.setupCommands.filter(c=>c.contract===3).forEach(c=>{c.fields.at='100';});
  assert.throws(()=>deriveS0Action(absent,'revalue-posting'),/ambiguous quote|selection unresolved/);
});

test('S0 commit outcomes, read-only and Work counters must match actual scopes', () => {
  const t=trace();t.path='native-settlement';t.outcome='unknown';t.commitNs=2;
  t.events.push(event(2,{layer:'commit',operation:'commit',role:'other',startNs:8,endNs:10,keyToken:null,keyKnowledge:'not-applicable',outcome:'unknown',rows:0,keyBytes:0,valueBytes:0}));
  assert.equal(check(t,{readOnly:false}).status,'checked');
  assert.throws(()=>check(t,{readOnly:true}),/read-only/);
  t.outcome='definite-abort';assert.throws(()=>check(t,{readOnly:false}),/outcome differs/);
  t.outcome='unknown';t.commitNs=1;assert.throws(()=>check(t,{readOnly:false}),/duration differs/);
  const missing=trace();missing.path='native-settlement';assert.throws(()=>check(missing),/requires successful commit/);
  const work=Object.fromEntries(['work_units','command_visits','route_entries','selector_visits','node_visits','key_loads','loaded_bytes','staged_patches','candidates','evaluations','rotations','causal_candidates','causal_evaluations','dependency_edges','dependency_checks','graph_nodes','scheduler_visits','reader_checks','inventory_visits','allocations','detached_outputs','final_dirty_keys','encoded_bytes'].map(k=>[k,0]));
  Object.assign(work,{work_units:3,node_visits:1,key_loads:2,loaded_bytes:2});
  assert.equal(checkS0Work(trace(),work).status,'checked');
  assert.throws(()=>checkS0Work(trace(),{...work,work_units:2}),/charged total/);
  assert.throws(()=>checkS0Work(trace(),{...work,loaded_bytes:3}),/differs from trace/);
});

test('S0 physical wrapper unknown key does not inflate native discovery depth', () => {
  const t=trace();t.events.push(event(2,{layer:'facade',operation:'get',role:'data',keyKnowledge:'unknown',keyToken:'2'.repeat(64),startNs:10,endNs:11,rows:0,valueBytes:0}));
  t.counters.facadeGet=1;t.counters.readKeyBytes=1;
  assert.equal(check(t).dependencyComplete,true);
  const repeat=trace();repeat.phase='attempt-repeat';repeat.initialKeys.push({token:'1'.repeat(64),origin:'previously-known'});
  repeat.events=repeat.events.map(e=>({...e,operation:'cache-hit',keyDiscoveredBy:null,keyKnowledge:'previously-known',discoveredKeyTokens:[]}));
  repeat.counters.attemptLoadAttempts=0;repeat.counters.attemptLoadedValueBytes=0;repeat.counters.attemptCacheHits=2;repeat.dependency.observedReadDepth=0;
  assert.equal(check(repeat).dependencyComplete,true);
});

test('S0 binding invocations distinguish SDK successful GETs and missing-key byte definitions',()=>{
  const t=trace();t.backend='foundationdb';t.path='Store-control';t.phase='control';t.initialKeys=[];t.dependency.observedReadDepth=0;
  t.events=[event(0,{layer:'binding',operation:'get',role:'catalog',keyKnowledge:'unknown',outcome:'found',keyBytes:2,valueBytes:3}),
    event(1,{layer:'binding',operation:'get',role:'data',keyKnowledge:'unknown',outcome:'missing',rows:0,keyBytes:0,valueBytes:0}),
    event(2,{layer:'binding',operation:'get',role:'data',keyKnowledge:'unknown',outcome:'unknown',rows:0,keyBytes:0,valueBytes:0}),
    ...[3,4,5].map(id=>event(id,{layer:'binding',operation:'get-range',role:'data',keyKnowledge:'unknown',outcome:'success',rows:2,keyBytes:4,valueBytes:6}))];
  Object.assign(t.counters,{logicalTouches:0,attemptLoadAttempts:0,attemptLoadedValueBytes:0,nodeVisits:0,bindingGet:3,bindingGetRange:3,bindingSet:0,bindingClear:0,bindingClearRange:0,bindingApproximateSize:0,returnedRows:7,readKeyBytes:14,readValueBytes:21,
    sdk:{callGet:2,callSet:0,callClear:0,callClearRange:0,rowsFetched:7,bytesRead:42,bytesWritten:0,retries:0,conflicts:0,commitMs:0}});
  assert.equal(check(t,{readOnly:true}).dependencyComplete,true);
  for(const [operation,counter,sdk]of[['set','bindingSet','callSet'],['clear','bindingClear','callClear'],['clear-range','bindingClearRange','callClearRange']]){
    const written=structuredClone(t);written.events.push(event(6,{layer:'binding',operation,role:'data',keyKnowledge:'unknown',outcome:'success',rows:0,keyBytes:2,valueBytes:0}));written.counters[counter]=1;written.counters.writeKeyBytes=2;written.counters.sdk[sdk]=1;
    assert.throws(()=>check(written,{readOnly:true}),/read-only action/);
  }
  t.counters.sdk.callGet=3;assert.throws(()=>check(t,{readOnly:true}),/completed-success count/);
  t.counters.sdk.callGet=2;t.counters.sdk.bytesRead=34;assert.throws(()=>check(t,{readOnly:true}),/below returned binding bytes/);
});
