import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { checkS0Inputs, prepareS0TraceCheck } from '../examples/s0-contract.mjs';

const fixture = name => new URL(`../../../research/fixtures/${name}`, import.meta.url);
const schema = JSON.parse(await readFile(fixture('s0-trace.schema.json'), 'utf8'));
const check = prepareS0TraceCheck(schema);
const event = (id, overrides = {}) => ({ id, parentId:null, executionPredecessorId:null, layer:'attempt', operation:'load', role:'native', startNs:2*id,endNs:2*id+1,keyToken:'0'.repeat(64),keyKnowledge:'invocation',keyDiscoveredBy:null,controlDependencies:[],outcome:'found',rows:1,keyBytes:1,valueBytes:1,discoveredKeyTokens:[],...overrides });
const trace = () => ({ format:'rebase-s0-trace-1',operationId:null,initialKeys:[{token:'0'.repeat(64),origin:'invocation'}],actionId:'a',attemptId:'a/0',backend:'redb',path:'native-tree',phase:'attempt-first',complete:true,incompleteReasons:[],outcome:'success',durationNs:20,commitNs:null,counters:{logicalTouches:2,attemptCacheHits:0,attemptLoadAttempts:2,attemptLoadedValueBytes:2,nodeVisits:1,selectorVisits:0,facadeGet:0,facadeScan:0,facadePut:0,facadeRemove:0,bindingGet:null,bindingGetRange:null,bindingSet:null,bindingClear:null,bindingClearRange:null,returnedRows:0,readKeyBytes:0,readValueBytes:0,writeKeyBytes:0,writeValueBytes:0,sdk:null,retryCount:0},dependency:{complete:true,incompleteReason:null,observedReadDepth:2,remoteReadRounds:null},events:[event(0,{discoveredKeyTokens:['1'.repeat(64)]}),event(1,{keyToken:'1'.repeat(64),keyKnowledge:'result-discovered',keyDiscoveredBy:0})] });
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
