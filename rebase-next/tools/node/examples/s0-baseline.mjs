// Ordinary bounded S0 probe composition. Importing this module performs no IO.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, statfs } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { observeResources } from '../observe.mjs';
import { checkBackupStructure } from '../storage-check.mjs';
import { parseFrame, encodeFrame } from '../private/json-codec.mjs';
import { checkS0Inputs, deriveS0Action, prepareS0TraceCheck, checkS0Work } from './s0-contract.mjs';

const MAX_REPORT=67_108_864, MAX_REQUEST=1_048_576, MAX_STDERR=65_536;
const demand=(value,message)=>{if(!value)throw new Error(`S0 run: ${message}`);};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const stable=value=>Array.isArray(value)?`[${value.map(stable).join(',')}]`:value&&typeof value==='object'
  ?`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`:JSON.stringify(value);
const same=(actual,expected,message)=>demand(stable(actual)===stable(expected),message);
const count=(value,message)=>demand(Number.isSafeInteger(value)&&value>=0,message);
const SHA=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const fixture=name=>new URL(`../../../research/fixtures/${name}`,import.meta.url);
function validateSource(source,phase) {
  demand(source&&['committed','working-tree'].includes(source.kind),'explicit source kind required');
  const working=source.kind==='working-tree';
  demand(!working||phase==='focused','working-tree source is limited to focused verification');
  const identity=working?'baseCommit':'exactSourceCommit',excluded=working?'exactSourceCommit':'baseCommit';
  demand(/^[a-f0-9]{40}$/.test(source[identity]??'')&&!Object.hasOwn(source,excluded),'mutually exclusive source commit identity');
  const fields=['kind',identity,'probeInputSha256','probeInputCount','probeInputs','binarySha256'];
  demand(Object.keys(source).length===fields.length&&fields.every(key=>Object.hasOwn(source,key)),'exact source identity fields required');
  demand(SHA.test(source.probeInputSha256??'')&&SHA.test(source.binarySha256??'')&&Number.isSafeInteger(source.probeInputCount)&&source.probeInputCount>0&&source.probeInputCount<=1024,'exact source hashes/count required');
  demand(Array.isArray(source.probeInputs)&&source.probeInputs.length===source.probeInputCount,'full observer source map required');
  const digest=createHash('sha256');let previous='';
  for(const file of source.probeInputs){demand(typeof file.path==='string'&&file.path.length<=1024&&file.path>previous&&!file.path.startsWith('/')&&!file.path.split('/').includes('..')&&SHA.test(file.sha256),'ordered observer source map');previous=file.path;digest.update(file.path+'\0'+file.sha256+'\n');}
  demand(digest.digest('hex')===source.probeInputSha256,'observer source map digest differs');
}
function uuid5(name) {
  const bytes=createHash('sha1').update(Buffer.from('6ba7b8129dad11d180b400c04fd430c8','hex')).update(name).digest().subarray(0,16);
  bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;
  const h=bytes.toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
const nativeKey=(tag,address)=>Buffer.from(`${tag.toString(16).padStart(2,'0')}${address.id.replaceAll('-','')}${address.slot.toString(16).padStart(4,'0')}`,'hex');
function checkTreeWitness(sample,corpus) {
  const trace=sample.trace,prefix=Buffer.alloc(8);prefix.writeBigUInt64BE(BigInt(Buffer.byteLength(trace.actionId)));
  const token=key=>createHash('sha256').update(prefix).update(trace.actionId).update(key).digest('hex');
  const rows=new Map(sample.before.rows.map(row=>[token(Buffer.from(row.key,'hex')),row.decoded]));
  if(sample.cachePhase==='attempt-first')same(trace.initialKeys.filter(key=>rows.has(key.token)),[{token:token(nativeKey(2,{id:corpus.nByRoot[0].owner,slot:corpus.nByRoot[0].slot})),origin:'invocation'}],'read invocation native key seeds differ');
  const known=new Set(trace.initialKeys.map(k=>k.token));
  for(const event of trace.events){
    if(event.layer!=='attempt'||event.operation!=='load'||event.outcome!=='found')continue;
    const decoded=rows.get(event.keyToken);demand(decoded,'tree load must match actual native snapshot key');
    const data=decoded.data,keys=decoded.type==='root'?[data.head,data.first,data.last].filter(Boolean).map(a=>nativeKey(3,a))
      :decoded.type==='node'?[nativeKey(2,data.root),...[data.parent,data.left,data.right,data.prev,data.next].filter(Boolean).map(a=>nativeKey(3,a))]:[];
    const actual=[];for(const key of keys){const t=token(key);if(!known.has(t)){known.add(t);actual.push(t);}}
    same(event.discoveredKeyTokens,actual,'decoded native address disclosure witness differs');
  }
}

function validateRequest(request,manifest,inputs) {
  demand(request?.format==='rebase-s0-probe-input-1','request format');
  demand(['redb','surrealkv','foundationdb-local'].includes(request.backend),'backend');
  demand(typeof request.location==='string'&&path.isAbsolute(request.location),'explicit absolute owned location');
  demand(['focused','pilot','baseline','overhead'].includes(request.phase),'phase');
  demand(Number.isSafeInteger(request.samples)&&request.samples>0&&request.samples<=manifest.samplesPerCase,'sample bound');
  demand(typeof request.trace==='boolean','explicit trace selection');
  if(request.backend==='foundationdb-local'){
    demand(typeof request.namespace==='string'&&/^rebase-s0-[A-Za-z0-9-]{1,118}$/.test(request.namespace),'explicit owned FDB namespace');
    demand(typeof request.clusterFile==='string'&&path.isAbsolute(request.clusterFile),'explicit FDB cluster file');
  }
  demand(Array.isArray(request.cases)&&request.cases.length>0&&request.cases.length<=64,'bounded explicit cases');
  const selected=new Set();
  for(const item of request.cases){
    const token=`${item.corpus}/${item.action}`;
    demand(!selected.has(token),'duplicate selected action');selected.add(token);
    demand(inputs.corpora.some(c=>c.id===item.corpus&&c.actions.some(a=>a.id===item.action)),'unknown selected action');
    demand(manifest.cases.some(c=>c.corpusIds.includes(item.corpus)&&c.selectedActionIds.includes(item.action)),'unfrozen selected action');
  }
  if(['pilot','focused'].includes(request.phase))demand(request.samples===1,'pilot/focused must retain exactly one sample');
  if(request.phase==='baseline')demand(request.samples===manifest.samplesPerCase,'baseline sample count');
  if(request.phase==='baseline'){
    const all=manifest.cases.flatMap(c=>c.corpusIds.flatMap(corpus=>c.selectedActionIds.map(action=>`${corpus}/${action}`))).sort();
    same([...selected].sort(),all,'baseline must cover every frozen selected action');
  }
  if(request.phase==='overhead'){
    demand(request.samples===manifest.overheadControl.matchedTraceOffOnPairs,'overhead pair count');
    same(request.cases,[{corpus:manifest.overheadControl.corpus,action:manifest.overheadControl.action}],'overhead named case');
  }
}

const sampleKey=sample=>`${sample?.corpusId}/${sample?.action}/${sample?.sampleIndex}/${sample?.traceEnabled}/${sample?.cachePhase}`;
function checkSelectedSample(sample,request,inputs) {
  demand(sample&&request.cases.some(item=>item.corpus===sample.corpusId&&item.action===sample.action),'unexpected checkpoint action');
  demand(Number.isSafeInteger(sample.sampleIndex)&&sample.sampleIndex>=0&&sample.sampleIndex<request.samples,'checkpoint sample index');
  demand(request.phase==='overhead'||sample.traceEnabled===request.trace,'checkpoint trace selection');
  const action=inputs.corpora.find(c=>c.id===sample.corpusId).actions.find(a=>a.id===sample.action);
  demand((action.kind.startsWith('tree-')?['attempt-first','attempt-repeat']:['attempt-first']).includes(sample.cachePhase),'checkpoint cache phase');
}

function checkFingerprint(fingerprint,source) {
  demand(fingerprint?.sha256===source.probeInputSha256&&Array.isArray(fingerprint.files)&&fingerprint.files.length===source.probeInputCount,'probe native source fingerprint differs');
  same(fingerprint.files,source.probeInputs,'compiled observer source map differs from execution source map');
  demand(fingerprint.algorithm==='sha256(path + NUL + sha256(file) + LF), sorted paths','source fingerprint algorithm');
  const fingerprintHash=createHash('sha256');let previous='';
  for(const file of fingerprint.files){demand(typeof file.path==='string'&&file.path>previous&&!file.path.startsWith('/')&&!file.path.split('/').includes('..')&&SHA.test(file.sha256),'ordered source fingerprint inventory');previous=file.path;fingerprintHash.update(file.path+'\0'+file.sha256+'\n');}
  demand(fingerprintHash.digest('hex')===fingerprint.sha256,'native source fingerprint inventory digest differs');
}

/** Run only an explicitly compiled probe, with caller-owned target and environment. */
export async function runS0Baseline({probe,environment,request,source,timeoutMs=600_000,resourceProcesses=[],resourcePaths=[]}={}) {
  demand(typeof probe==='string'&&path.isAbsolute(probe),'absolute compiled probe required');
  demand(environment&&typeof environment==='object'&&!Array.isArray(environment)&&Object.values(environment).every(v=>typeof v==='string'),'explicit child environment');
  demand(Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=600_000,'deadline bound');
  demand(Array.isArray(resourceProcesses)&&resourceProcesses.length<=4&&resourceProcesses.every(p=>p&&typeof p.role==='string'&&p.role.length>0&&p.role.length<=64&&p.role!=='probe'&&Number.isSafeInteger(p.pid)&&p.pid>0)&&new Set(resourceProcesses.map(p=>p.role)).size===resourceProcesses.length,'bounded explicitly owned resource processes');
  demand(Array.isArray(resourcePaths)&&resourcePaths.length<=4&&resourcePaths.every(p=>typeof p==='string'&&path.isAbsolute(p)),'bounded explicit physical resource paths');
  const [manifestBytes,inputBytes,probeBytes,schemaBytes]=await Promise.all([readFile(fixture('s0-workload-manifest.json')),readFile(fixture('s0-inputs.json')),readFile(probe),readFile(fixture('s0-trace.schema.json'))]);
  const manifest=parseFrame(manifestBytes),inputs=parseFrame(inputBytes);
  checkS0Inputs(manifest,inputBytes);validateRequest(request,manifest,inputs);
  demand((await lstat(probe)).isFile(),'probe must be a regular file');
  validateSource(source,request.phase);
  const binarySha256=hash(probeBytes);
  demand(source.binarySha256===binarySha256,'compiled binary identity differs');
  try{await lstat(request.location);throw new Error('S0 run: owned location already exists');}catch(error){if(error.code!=='ENOENT')throw error;}
  const invocation={...request,manifestSha256:hash(manifestBytes),inputsSha256:hash(inputBytes)};
  const bytes=encodeFrame(invocation,MAX_REQUEST);
  const child=spawn(probe,[],{env:{...environment},shell:false,stdio:['pipe','pipe','pipe'],windowsHide:true});
  const resources=[],resourceReasons=new Set(),resourceRoles=['probe',...resourceProcesses.map(p=>p.role)],physicalPaths=[...new Set([request.location,...resourcePaths])];
  const resourceObservation={format:'rebase-s0-resources-1',timing:'startup, paused native checkpoints, and process end; outside native measured spans',maxSamples:3842,maxFiles:1024,roles:resourceRoles,paths:physicalPaths,
    limitations:['Checkpoint RSS is not lifetime peak RSS; CPU ticks end at the last available live sample and exclude unobserved intervals.',
      'Observer work can warm OS caches or contend with an owned backend outside timed spans; durations are retained, not subtracted.',
      'Physical bytes cover explicitly supplied paths only; disk capacity is filesystem availability, not physical IO counters.'],disk:null,complete:false,incompleteReasons:[]};
  let stdoutBytes=0,stderrBytes=0,reason=null,killTimer,terminating=false,buffer=Buffer.alloc(0),pending=Promise.resolve(),report=null,start=null,checkpointFailure=null;
  const checkpointSamples=[],checkpointDigests=new Map(),checkTrace=prepareS0TraceCheck(parseFrame(schemaBytes));
  const stop=why=>{reason??=why;if(terminating)return;terminating=true;child.kill('SIGTERM');killTimer=setTimeout(()=>child.kill('SIGKILL'),1000);killTimer.unref();};
  child.stderr.on('data',chunk=>{stderrBytes+=chunk.length;if(stderrBytes>MAX_STDERR)stop('stderr-byte-bound');});
  child.stdin.on('error',()=>{});
  const completed=new Promise(resolve=>{child.once('error',error=>resolve({error:error.code??'spawn-error',code:null,signal:null}));child.once('close',(code,signal)=>resolve({code,signal}));});
  const deadline=setTimeout(()=>stop('backend-deadline'),timeoutMs);
  const sampleResources=async (stage,sample=null)=>{
    if(resources.length>=resourceObservation.maxSamples){resourceReasons.add('resource-sample-bound');return;}
    try{
      if(!child.pid){resourceReasons.add('resource-probe-pid-unavailable');resources.push({stage,available:false,error:'probe-pid-unavailable'});return;}
      const observed=await observeResources({processes:[{role:'probe',pid:child.pid},...resourceProcesses],native:{binary:probe,sha256:binarySha256,model:'calculation',backend:request.backend},paths:physicalPaths,maxFiles:resourceObservation.maxFiles});
      resources.push({stage,...(sample?{actionId:sample.actionId,cachePhase:sample.cachePhase}:{}),...observed});
    }catch(error){resourceReasons.add('resource-observation-failed');resources.push({stage,available:false,error:typeof error.code==='string'?error.code:'observation-failed'});}
  };
  const consume=async frame=>{
    if(frame?.format==='rebase-s0-start-1'){
      demand(start===null&&checkpointSamples.length===0&&report===null,'duplicate or late probe start');
      demand(frame.backend===invocation.backend&&frame.phase===invocation.phase&&frame.manifestSha256===invocation.manifestSha256&&frame.inputsSha256===invocation.inputsSha256,'checkpoint frozen invocation differs');
      checkFingerprint(frame.sourceFingerprint,source);start=frame;return;
    }
    if(frame?.format==='rebase-s0-checkpoint-1'){
      demand(start&&report===null&&!checkpointFailure,'checkpoint outside active probe');
      const sample=frame.sample,key=sampleKey(sample);
      demand(checkpointSamples.length<3840&&!checkpointDigests.has(key),'duplicate or excessive checkpoint');
      checkpointSamples.push(sample);
      try{checkSelectedSample(sample,invocation,inputs);checkS0Sample(sample,{request:invocation,inputs,checkTrace,incomplete:new Set()});}
      catch(error){checkpointFailure={checkpoint:frame,sample,error:error.message};reason??='independent-correctness-mismatch';await sampleResources('checkpoint',sample);child.stdin.write(encodeFrame({actionId:sample.actionId,cachePhase:sample.cachePhase,continue:false},1024));return;}
      checkpointDigests.set(key,hash(stable(sample)));await sampleResources('checkpoint',sample);child.stdin.write(encodeFrame({actionId:sample.actionId,cachePhase:sample.cachePhase,continue:true},1024));return;
    }
    demand(frame?.format==='rebase-s0-probe-report-1'&&report===null,'invalid-report-format');report=frame;
  };
  const consumeLines=async final=>{
    let newline;
    while((newline=buffer.indexOf(10))!==-1){const line=buffer.subarray(0,newline);buffer=buffer.subarray(newline+1);if(line.length)await consume(parseFrame(line));}
    if(final&&buffer.length){const line=buffer;buffer=Buffer.alloc(0);await consume(parseFrame(line));}
  };
  child.stdout.on('data',chunk=>{
    stdoutBytes+=chunk.length;if(stdoutBytes>MAX_REPORT){stop('report-byte-bound');return;}
    child.stdout.pause();buffer=Buffer.concat([buffer,chunk]);
    pending=pending.then(()=>consumeLines(false)).catch(error=>{checkpointFailure??={sample:null,error:error.message};stop(error.message.includes('invalid-report-format')?'invalid-report-format':'invalid-or-partial-report');}).finally(()=>child.stdout.resume());
  });
  try {
    await sampleResources('startup');
    child.stdin.write(bytes);
    const exit=await completed;
    await pending;
    try{await consumeLines(true);}catch{reason??='invalid-or-partial-report';}
    child.stdin.end();
    await sampleResources('end');
    try{const disk=await statfs(path.dirname(request.location));resourceObservation.disk={available:true,path:path.dirname(request.location),blockSize:disk.bsize,availableBytes:disk.bavail*disk.bsize,totalBytes:disk.blocks*disk.bsize};}
    catch(error){resourceObservation.disk={available:false,path:path.dirname(request.location),reason:typeof error.code==='string'?error.code:'statfs-failed'};resourceReasons.add('resource-disk-space-unavailable');}
    for(const role of resourceRoles){
      const checkpoints=resources.filter(row=>row.stage==='checkpoint'),live=checkpoints.filter(row=>row.processes?.[role]?.available);
      if(!live.length||live.length!==checkpoints.length)resourceReasons.add(`resource-process-unavailable:${role}`);
      else if(live.some(row=>!['rssBytes','cpuTicks','startTicks'].every(field=>Number.isSafeInteger(row.processes[role][field])&&row.processes[role][field]>=0)))resourceReasons.add(`resource-process-counters-unavailable:${role}`);
      if(new Set(live.map(row=>row.processes[role].startTicks)).size>1)resourceReasons.add(`resource-process-identity-changed:${role}`);
    }
    if(!resources.some(row=>row.stage==='checkpoint'))resourceReasons.add('resource-checkpoint-missing');
    if(!resources.some(row=>row.stage==='checkpoint'&&row.physical?.available)||resources.some(row=>row.stage==='checkpoint'&&!row.physical?.available))resourceReasons.add('resource-physical-unavailable');
    if(request.backend==='foundationdb-local'&&resourceProcesses.length===0)resourceReasons.add('resource-owned-backend-process-unavailable');
    if(request.backend==='foundationdb-local'&&resourcePaths.length===0)resourceReasons.add('resource-owned-backend-path-unavailable');
    resourceObservation.incompleteReasons=[...resourceReasons];resourceObservation.complete=resourceReasons.size===0;
    if(exit.error)reason??=exit.error;
    if(exit.code!==0)reason??='probe-process-failed';
    if(!report){reason??='invalid-or-partial-report';if(start&&checkpointSamples.length)report={...start,format:'rebase-s0-probe-report-1',samples:checkpointSamples,controls:[],cleanup:{complete:false},complete:false,incompleteReasons:[reason]};}
    if(start&&report&&!checkpointFailure){
      try{demand(report.samples.length===checkpointDigests.size,'final report/checkpoint sample set differs');for(const sample of report.samples)demand(checkpointDigests.get(sampleKey(sample))===hash(stable(sample)),'final report changed an acknowledged sample');}
      catch(error){checkpointFailure={sample:null,error:error.message};reason??='checkpoint-report-mismatch';}
    }
    const reportReasons=[];
    if(report){
      if(typeof report.complete!=='boolean'||!Array.isArray(report.incompleteReasons)||report.incompleteReasons.some(value=>typeof value!=='string'||value.length===0)||report.complete!==(report.incompleteReasons.length===0))reason??='invalid-report-completion';
      else reportReasons.push(...report.incompleteReasons);
    }
    if(!start)reason??='checkpoint-start-missing';
    const incompleteReasons=[...new Set([...(reason?[reason]:[]),...resourceReasons,...reportReasons])];
    return {format:'rebase-s0-run-1',request:invocation,source:{...source},binarySha256,resources,resourceObservation,
      host:{platform:os.platform(),release:os.release(),arch:os.arch(),cpus:os.cpus().map(({model,speed})=>({model,speed})),totalMemory:os.totalmem(),node:process.version},
      report,checkpoints:{checked:checkpointDigests.size,rejected:checkpointFailure},complete:incompleteReasons.length===0,incompleteReasons,cleanup:{processStopped:Boolean(exit.error)||child.exitCode!==null||child.signalCode!==null,exitCode:exit.code,signal:exit.signal,stdoutBytes,stderrBytes}};
  } finally {clearTimeout(deadline);clearTimeout(killTimer);if(child.exitCode===null&&child.signalCode===null){stop('runner-cleanup');await completed;clearTimeout(killTimer);}await pending;}
}

function expectedInventory(records,financial) {
  const roots=new Map(),members=new Map();
  for(const record of records){
    const slot=record.contract===2?1:record.contract===4?2:record.contract===5?3:null;
    if(slot!==null)roots.set(`${record.id}/${slot}`,{kind:record.contract===2?2:1});
    if(record.contract===3)members.set(`${record.id}/3`,{root:{id:record.fields.curve,slot:1},time:record.fields.at,leaf:{kind:'quote',value:record.fields.rate}});
  }
  for(const member of financial)members.set(`${member.id}/${member.slot}`,{root:{id:member.owner,slot:member.rootSlot},time:member.key,leaf:{kind:'financial',value:member.amount}});
  return {expectedMembers:members,expectedRoots:roots};
}

// Reuse the independent physical AVL checker on the actual native rows. Empty
// application tables are enclosing checker input, not observed Store evidence.
function checkSnapshot(snapshot,records,members,roots,corpus) {
  demand(snapshot?.complete===true,'complete raw native snapshot required');
  same(snapshot.tables,['native_kv'],'snapshot table scope');
  demand(Array.isArray(snapshot.rows)&&snapshot.rows.length<=81920,'native snapshot row bound');
  const rows=snapshot.rows.map(row=>{
    demand(typeof row.key==='string'&&typeof row.value==='string'&&/^(?:[0-9a-f]{2})+$/.test(row.value),'raw native bytes required');
    same(parseFrame(Buffer.from(row.value,'hex')),row.decoded,'decoded witness differs from actual value bytes');
    return {key:row.key,value:row.value};
  });
  const tables=Object.fromEntries(['effect_due','effect_executions','effect_facts','effect_inbox','effect_runtime','local_runtime','native_kv','operations','public_records','query_epochs','receipt_slots'].map(name=>[name,name==='native_kv'?rows:[]]));
  const payload={format:'rebase-authorized-observation-1',complete:true,tables};
  const checked=checkBackupStructure(JSON.stringify({format:'rebase-backup-1',sha256:hash(stable(payload)),payload}),{...expectedInventory(records,members),includeObservation:true});
  demand(checked.status==='passed','independent physical structure check did not pass');
  const observed=checked.observation;
  demand(observed.records.length===records.length,'actual source record inventory differs');
  const recordMap=new Map(observed.records.map(row=>[row.id,row.record]));
  for(const expected of records){
    const actual=recordMap.get(expected.id);demand(actual?.contract===expected.contract,'actual record contract differs');
    same(actual.input,expected.fields,'actual source input differs');
    demand(actual.tenant===corpus.tenant&&actual.owner===corpus.actor&&actual.reader===corpus.actor&&UUID.test(actual.version),'source authority/version differs');
    if(expected.contract===6){const native=members.find(m=>m.id===expected.id&&m.slot===1),reporting=members.find(m=>m.id===expected.id&&m.slot===2);
      same(actual.derived,{native_minor:native.amount,reporting_minor:reporting.amount},'actual derived Posting amounts differ');
    } else demand(actual.derived===null,'unexpected derived source fields');
  }
  for(const expected of roots){
    const actual=observed.roots.find(row=>row.root.id===expected.owner&&row.root.slot===expected.slot);
    same(actual?.summary,{kind:'financial',value:expected.summary},'independent full-key root fold differs');
  }
  return recordMap;
}

/** Nearest-rank statistics always come from retained raw successful samples. */
export function summarizeS0Samples(samples) {
  demand(Array.isArray(samples)&&samples.length>0,'raw statistics samples required');
  const values=samples.map(s=>{count(s.operationNs,'raw duration');demand(s.outcome==='success','statistics require successful raw outcomes');return s.operationNs;}).sort((a,b)=>a-b);
  const at=p=>values[Math.ceil(values.length*p)-1];
  return {n:values.length,min:values[0],p50:at(.5),p95:at(.95),p99:at(.99),max:values.at(-1)};
}

export function checkS0OverheadPairs(samples,expectedPairs=30) {
  demand(Array.isArray(samples)&&Number.isSafeInteger(expectedPairs)&&expectedPairs>0&&expectedPairs<=30,'bounded overhead pairs');
  const pairs=[],incompleteReasons=[];
  for(let index=0;index<expectedPairs;index++){
    const pair=samples.filter(s=>s.sampleIndex===index&&s.cachePhase==='attempt-first');
    demand(pair.length<=2,'duplicate overhead pair sample');
    if(pair.length!==2){incompleteReasons.push(`overhead-pair-incomplete:${index}`);continue;}
    same(pair.map(s=>s.traceEnabled),index%2===0?[false,true]:[true,false],'overhead pair order must alternate');
    const off=pair.find(s=>!s.traceEnabled),on=pair.find(s=>s.traceEnabled);
    same(off.work,on.work,'matched overhead pair changed native Work');
    for(const sample of pair)count(sample.operationNs,'raw overhead duration');
    const measured=pair.every(s=>s.outcome==='success')&&off.operationNs>0;
    pairs.push({sampleIndex:index,offNs:off.operationNs,onNs:on.operationNs,ratio:measured?on.operationNs/off.operationNs:null});
    if(!measured)incompleteReasons.push(`overhead-ratio-unavailable:${index}`);
  }
  return {pairs,incompleteReasons};
}

// Shared by the paused native checkpoint and final whole-run checker.
function checkS0Sample(sample,{request,inputs,checkTrace,incomplete}) {
    demand(typeof sample.traceEnabled==='boolean','actual trace selection required');
    demand(typeof sample.actionId==='string'&&sample.actionId.length>0&&sample.actionId.length<=256,'original action identity required');
    demand(sample.actionId===`${request.phase}/${sample.corpusId}/${sample.action}/${sample.sampleIndex}/${sample.traceEnabled}`,'deterministic original action identity differs');
    demand(sample.operationId===null||UUID.test(sample.operationId),'original operation identity');
    demand(['success','definite-abort','conflict','unknown'].includes(sample.outcome),'actual outcome class');
    for(const field of ['sampleIndex','setupNs','warmupNs','beforeObservationNs','afterObservationNs','observationNs','operationNs'])count(sample[field],field);
    demand(sample.observationNs===sample.beforeObservationNs+sample.afterObservationNs,'observation duration sum differs');
    demand(sample.commitNs===null||(Number.isSafeInteger(sample.commitNs)&&sample.commitNs>=0),'actual commit duration');
    demand(sample.commitBoundaryNs===null||(Number.isSafeInteger(sample.commitBoundaryNs)&&sample.commitBoundaryNs>=0),'outer commit boundary duration');
    if(sample.commitNs!==null)demand(sample.commitBoundaryNs!==null&&sample.commitBoundaryNs>=sample.commitNs,'outer commit boundary must enclose retained commit event');
    const corpus=inputs.corpora.find(c=>c.id===sample.corpusId),action=corpus?.actions.find(a=>a.id===sample.action);
    demand(action,'unknown checkpoint action');const derived=deriveS0Action(corpus,sample.action);
    demand(!sample.correctnessError,'native correctness mismatch');
    demand(sample.readOnly===action.kind.startsWith('tree-'),'read-only action classification');
    same(sample.setupCommands,corpus.setupCommands,'exact setup commands differ');
    same(sample.setupCommandBatches,Array.from({length:Math.ceil(corpus.setupCommands.length/64)},(_,index)=>corpus.setupCommands.slice(index*64,(index+1)*64)),'exact bounded setup command batches differ');
    const before=checkSnapshot(sample.before,derived.beforeRecords,derived.beforeMembers,derived.beforeRoots,corpus);
    if(sample.readOnly){same(sample.actionCommands,[],'tree action has native commands');demand(sample.commitNs===null&&sample.commitBoundaryNs===null,'read committed');}
    else if(action.kind==='native-create')same(sample.actionCommands,action.commands,'exact create commands differ');
    else {demand(sample.actionCommands?.length===1,'one exact mutation command');const command=sample.actionCommands[0];
      same(command,action.kind==='native-update'?{op:'update',id:action.record,if_version:before.get(action.record).version,set:action.set,unset:[]}:{op:'delete',id:action.record,if_version:before.get(action.record).version},'mutation must retain exact original version and fields');}
    demand(Array.isArray(sample.allocations)&&sample.allocations.every(a=>['setup','action'].includes(a.phase)&&Number.isSafeInteger(a.counter)&&a.counter>=0&&UUID.test(a.id)),'explicit deterministic allocation history');
    demand(new Set(sample.allocations.map(a=>a.id)).size===sample.allocations.length,'duplicate allocated UUID');
    const nextAllocation={setup:0,action:0};
    for(const allocation of sample.allocations){demand(allocation.counter===nextAllocation[allocation.phase]++,'allocation counter sequence');demand(allocation.id===uuid5(`s0-native-avl-1/${sample.actionId}/${allocation.phase}/${allocation.counter}`),'deterministic allocation differs');}
    demand(sample.operationId===(sample.readOnly?null:uuid5(`s0-native-avl-1/${sample.actionId}/operation/0`)),'deterministic original operation ID differs');
    if(sample.outcome==='success'){
      const after=checkSnapshot(sample.after,derived.afterRecords,derived.afterMembers,derived.afterRoots,corpus);
      const recalculated=[...after].filter(([id,record])=>record.contract===6&&stable(before.get(id)?.derived)!==stable(record.derived)).map(([id])=>id).sort();
      same(recalculated,derived.recalculatedRecords,'actual changed Posting calculation closure differs');
      if(sample.readOnly)same(sample.result,action.kind==='tree-range'?{kind:'financial',value:derived.result}:derived.result,'actual query result differs from independent fold');
      else {
        demand(sample.result&&Object.keys(sample.result).length===1&&UUID.test(sample.result.revision),'actual settlement revision required');
        const changedIds=action.kind==='native-create'?action.commands.map(c=>c.id):action.kind==='native-update'?[action.record,...derived.recalculatedRecords]:[];
        for(const id of changedIds)demand(after.get(id)?.version===sample.result.revision,'committed record version differs from actual settlement revision');
      }
    } else {incomplete.add(`outcome:${sample.outcome}:${sample.actionId}`);if(['definite-abort','conflict'].includes(sample.outcome))same(sample.after,sample.before,'definite failed action changed raw state');}
    if(sample.traceEnabled){
      demand(sample.trace!==null&&sample.trace.actionId===sample.actionId&&sample.trace.phase===sample.cachePhase&&sample.trace.outcome===sample.outcome&&sample.trace.operationId===sample.operationId,'trace original identity/outcome differs');
      demand(sample.trace.attemptId===sample.actionId&&sample.trace.backend===(request.backend==='foundationdb-local'?'foundationdb':request.backend)&&sample.trace.path===(sample.readOnly?'native-tree':'native-settlement'),'trace actual transaction/backend/path differs');
      demand(sample.trace.commitNs===sample.commitNs,'trace commit duration differs');
      checkTrace(sample.trace,{readOnly:sample.readOnly,work:sample.work});
      if(sample.readOnly&&sample.trace.complete)checkTreeWitness(sample,corpus);
      if(!sample.trace.complete)incomplete.add(`trace-incomplete:${sample.actionId}`);
      if(!sample.trace.dependency.complete)incomplete.add(`dependency-incomplete:${sample.actionId}`);
    } else {demand(sample.trace===null&&sample.commitNs===null,'trace-off sample retained trace or commit event duration');checkS0Work({counters:{attemptLoadAttempts:sample.work.key_loads,attemptLoadedValueBytes:sample.work.loaded_bytes,nodeVisits:sample.work.node_visits,selectorVisits:sample.work.selector_visits}},sample.work);}
    if(sample.cachePhase==='attempt-repeat')demand(sample.work.key_loads===0&&sample.work.loaded_bytes===0,'trace-off repeat made charged backend loads');
}

function checkS0ResourceEvidence(run,incomplete) {
  const observation=run.resourceObservation;
  if(!observation||!Array.isArray(run.resources)){incomplete.add('resource-evidence-missing');return;}
  demand(observation.format==='rebase-s0-resources-1'&&observation.maxSamples===3842&&observation.maxFiles===1024&&run.resources.length<=3842,'bounded resource evidence required');
  demand(typeof observation.complete==='boolean'&&Array.isArray(observation.incompleteReasons)&&observation.complete===(observation.incompleteReasons.length===0),'explicit resource completion reasons');
  for(const reason of observation.incompleteReasons){demand(run.incompleteReasons.includes(reason),'resource failure omitted from run reasons');incomplete.add(reason);}
  demand(Array.isArray(observation.roles)&&observation.roles[0]==='probe'&&new Set(observation.roles).size===observation.roles.length&&observation.roles.length<=5,'explicit resource roles');
  demand(Array.isArray(observation.paths)&&observation.paths.includes(run.request.location)&&observation.paths.every(p=>typeof p==='string'&&path.isAbsolute(p)),'explicit physical paths');
  for(const row of run.resources){
    demand(['startup','checkpoint','end'].includes(row.stage),'resource sampling outside paused boundaries');
    if(row.available===false){demand(typeof row.error==='string'&&!observation.complete,'resource collection error requires incomplete evidence');continue;}
    demand(row.native?.sha256===run.binarySha256&&row.native.backend===run.request.backend&&row.native.model==='calculation','resource native identity differs');
    demand(typeof row.observerMs==='number'&&Number.isFinite(row.observerMs)&&row.observerMs>=0,'resource observer duration');
    same(row.physical?.paths,observation.paths,'resource physical paths differ');
    if(row.stage==='checkpoint'){
      demand(typeof row.actionId==='string'&&['attempt-first','attempt-repeat'].includes(row.cachePhase),'resource checkpoint identity');
      for(const role of observation.roles){const process=row.processes?.[role];if(!process?.available)incomplete.add(`resource-process-unavailable:${role}`);else for(const field of ['pid','rssBytes','cpuTicks','startTicks'])count(process[field],`resource process ${field}`);}
      if(!row.physical?.available)incomplete.add('resource-physical-unavailable');else{count(row.physical.bytes,'resource physical bytes');count(row.physical.files,'resource physical files');}
    }
  }
  if(!run.resources.some(row=>row.stage==='checkpoint'))incomplete.add('resource-checkpoint-missing');
  if(!observation.disk?.available)incomplete.add('resource-disk-space-unavailable');else{count(observation.disk.availableBytes,'resource available disk bytes');count(observation.disk.totalBytes,'resource total disk bytes');}
}

/** Check exact identities, source facts, real snapshots, Work and retained traces. */
export function checkS0Run(run,{manifest,manifestBytes,inputBytes,traceSchema,source}={}) {
  demand(run?.format==='rebase-s0-run-1','run format');
  demand(typeof run.complete==='boolean'&&Array.isArray(run.incompleteReasons)&&run.incompleteReasons.every(reason=>typeof reason==='string'&&reason.length>0)&&run.complete===(run.incompleteReasons.length===0),'explicit run completion reasons');
  demand(typeof manifestBytes==='string'||Buffer.isBuffer(manifestBytes)||manifestBytes instanceof Uint8Array,'exact manifest bytes required');
  same(parseFrame(Buffer.from(manifestBytes)),manifest,'manifest object differs from frozen bytes');
  checkS0Inputs(manifest,inputBytes);const inputs=parseFrame(Buffer.from(inputBytes));
  validateRequest(run.request,manifest,inputs);
  demand(run.request.manifestSha256===hash(manifestBytes),'manifest byte identity required');
  demand(run.request.inputsSha256===hash(inputBytes),'inputs identity');
  validateSource(source,run.request.phase);validateSource(run.source,run.request.phase);
  same(run.source,source,'executed source identity differs');
  demand(SHA.test(run.binarySha256??'')&&source.binarySha256===run.binarySha256,'executed binary identity differs');
  demand(run.cleanup?.processStopped===true,'probe process cleanup incomplete');
  if(!run.report){demand(run.complete===false&&run.incompleteReasons?.length>0,'missing report needs explicit incomplete reason');return {status:'incomplete',checkedSamples:0,incompleteReasons:[...run.incompleteReasons],statistics:[]};}
  const report=run.report;
  demand(Buffer.byteLength(JSON.stringify(report))<=MAX_REPORT,'report byte bound');
  demand(report.format==='rebase-s0-probe-report-1'&&report.backend===run.request.backend&&report.phase===run.request.phase,'probe report identity');
  demand(typeof report.complete==='boolean'&&Array.isArray(report.incompleteReasons)&&report.incompleteReasons.every(reason=>typeof reason==='string'&&reason.length>0)&&report.complete===(report.incompleteReasons.length===0),'explicit probe completion reasons');
  demand(report.manifestSha256===run.request.manifestSha256&&report.inputsSha256===run.request.inputsSha256,'probe frozen fixture identity');
  checkFingerprint(report.sourceFingerprint,source);
  demand(Array.isArray(report.samples),'raw samples required');
  const checkTrace=prepareS0TraceCheck(traceSchema),groups=new Map(),seen=new Set(),incomplete=new Set(run.incompleteReasons??[]);
  checkS0ResourceEvidence(run,incomplete);
  const rollback=report.controls?.find(c=>c.name==='calculation-root-complete-time-invariant-rollback');
  if(!rollback)incomplete.add('application-rollback-control-missing');
  else demand(rollback.timed===false&&rollback.outcome==='success'&&rollback.unchanged===true&&rollback.errorCode==='invariant'&&rollback.operationStatus?.status==='not_observed','actual application rollback control failed');
  const adapter=report.controls?.find(c=>c.format==='rebase-s0-adapter-control-1');
  if(adapter){
    demand(adapter.format==='rebase-s0-adapter-control-1'&&adapter.rows===131&&adapter.valueBytes===8192&&adapter.exactRowsVerified===true,'actual adapter control inventory');
    checkTrace(adapter.rangeTrace,{readOnly:true});checkTrace(adapter.mutationTrace,{readOnly:false});
    for(const control of adapter.protectedReadControls?.cases??[]){demand(control.outcome==='conflict'&&control.completeBytesPreserved===true,'protected read conflict preserved bytes');checkTrace(control.trace,{readOnly:false});}
    if(!adapter.protectedReadControls?.executed)incomplete.add('adapter-protected-read-control-unavailable');
  } else incomplete.add('adapter-control-missing');
  if(report.cleanup?.complete!==true)incomplete.add('owned-target-cleanup-incomplete');
  const overhead=run.request.phase==='overhead';
  const expected=new Set();
  for(const item of run.request.cases){const corpus=inputs.corpora.find(c=>c.id===item.corpus),action=corpus.actions.find(a=>a.id===item.action);
    for(let index=0;index<run.request.samples;index++)for(const on of overhead?[false,true]:[run.request.trace])for(const phase of action.kind.startsWith('tree-')?['attempt-first','attempt-repeat']:['attempt-first'])expected.add(`${item.corpus}/${item.action}/${index}/${on}/${phase}`);
  }
  for(const sample of report.samples){
    const key=`${sample.corpusId}/${sample.action}/${sample.sampleIndex}/${sample.traceEnabled}/${sample.cachePhase}`;
    demand(expected.has(key)&&!seen.has(key),'unexpected or duplicate raw sample');seen.add(key);
    checkS0Sample(sample,{request:run.request,inputs,checkTrace,incomplete});
    const group=`${sample.corpusId}/${sample.action}/${sample.cachePhase}/${sample.traceEnabled}`;
    if(!groups.has(group))groups.set(group,[]);groups.get(group).push(sample);
  }
  if(seen.size!==expected.size)incomplete.add('raw-sample-set-incomplete');
  if(report.complete!==true){demand(Array.isArray(report.incompleteReasons)&&report.incompleteReasons.length>0,'incomplete probe needs reason');report.incompleteReasons.forEach(r=>incomplete.add(r));}
  else demand(seen.size===expected.size,'complete probe omitted selected raw samples');
  const statistics=[...groups].map(([group,samples])=>({group,...(samples.every(s=>s.outcome==='success')?summarizeS0Samples(samples):{n:samples.length,quantiles:null})}));
  const overheadResult=overhead?checkS0OverheadPairs(report.samples,run.request.samples):{pairs:[],incompleteReasons:[]};
  overheadResult.incompleteReasons.forEach(reason=>incomplete.add(reason));
  const overheadPairs=overheadResult.pairs;
  return {status:incomplete.size?'incomplete':'checked',checkedSamples:seen.size,incompleteReasons:[...incomplete],statistics,overheadPairs,
    scope:'direct real-adapter Attempt/tree/native settlement; excludes authenticated HTTP, Store receipt/authority overhead and multi-host performance'};
}
