'use strict';
const assert = require('node:assert/strict');
const { scan, equal } = require('./oracle');
const project = (value,path) => path ? path.split('.').reduce((v,k)=>v?.[k],value) : value;
const scalarCompare = (a,b) => a<b?-1:a>b?1:0;

// Reconstruct each consumed query from independently authored source entries.
// Never call a database read/capture/invalidation function as the oracle.
function verifyReads(data, rows, entries, compare) {
  const reads=data.rebase_read||[],groups=data.rebase_read_group||[],frames=data.rebase_read_frame||[];
  const byId=new Map(rows.map(row=>[row.id,row]));
  for(const read of reads) {
    const reader=byId.get(read.reader),source=byId.get(read.source_root);
    assert(reader&&source,'live subscriber and source'); assert.equal(reader.tenant,source.tenant); assert.equal(read.tenant,reader.tenant);
    const frame=frames.find(row=>row.id===`rebase_read_frame:[${read.reader}, '${read.phase}']`);
    assert(frame,'evaluation generation exists'); assert.equal(read.version,frame.version,'no obsolete subscription');
    let result;
    if(read.kind==='record')result=project(source,read.path);
    else {
      const sequence=entries.filter(entry=>entry.owner.rid===read.source_root&&entry.owner.slot===read.source_slot).sort((a,b)=>compare(a.key,b.key));
      let selected;
      if(read.kind==='latest')selected=sequence.filter(entry=>compare(entry.key,read.arguments[0])<0||read.arguments[1]&&compare(entry.key,read.arguments[0])===0).at(-1);
      else if(read.kind==='next')selected=sequence.find(entry=>compare(entry.key,read.arguments[0])>0||read.arguments[1]&&compare(entry.key,read.arguments[0])===0);
      else if(read.kind==='exact')selected=sequence.find(entry=>compare(entry.key.slice(0,-2),read.arguments)===0);
      let value;
      if(['latest','next','exact'].includes(read.kind))value=selected?{...scan([selected]),record:selected.link.rid,key:selected.key}:undefined;
      else if(read.kind==='before')value=scan(sequence.filter(entry=>compare(entry.key,read.arguments)<0));
      else if(read.kind==='range')value=scan(sequence.filter(entry=>compare(entry.key,read.arguments[0])>=0&&compare(entry.key,read.arguments[1])<0));
      else {assert.equal(read.kind,'summary');value=scan(sequence);}
      result=project(value,read.path);
    }
    const expected=result??read.fallback.value;
    equal(read.observed.value,expected,`${read.reader}: cached ${read.kind}/${read.path}`);
  }
  for(const group of groups) {
    const members=reads.filter(read=>read.group===group.id);
    assert(members.length>0,`${group.id}: no empty read group`);
    const range=group.kind==='range',slot=range?'z_interval':'z_position',root=range?'z_intervals':'z_positions';
    assert.equal(group[range?'z_positions':'z_intervals'].summary.count,0);
    const indexed=range?members.filter(read=>compare(read.arguments[0],read.arguments[1])<0):members;
    const byRead=new Map(indexed.map(read=>[read.id,read])),seen=new Set();
    const keyCompare=(a,b)=>compare(a[0],b[0])||scalarCompare(a[1],b[1])||scalarCompare(a[2],b[2]);
    const owner={rid:group.id,slot:root};
    function visit(link,parent,lower,upper) {
      if(!link)return {height:0,keys:[],end:undefined};
      const row=byRead.get(link.rid);assert(row,'indexed read exists');assert(!seen.has(row.id),'read index cycle');seen.add(row.id);
      const node=row[slot];assert.deepEqual(node.owner,owner);assert.deepEqual(node.parent,parent);
      assert.deepEqual(node.key,[row.position,row.id,slot]);
      if(range)assert.deepEqual(node.value.end_key,row.arguments[1]);
      if(lower)assert(keyCompare(lower,node.key)<0);if(upper)assert(keyCompare(node.key,upper)<0);
      const left=visit(node.left,link,lower,node.key),right=visit(node.right,link,node.key,upper);
      const keys=[...left.keys,node.key,...right.keys];
      const end=range?[left.end,row.arguments[1],right.end].filter(Boolean).sort(compare).at(-1):undefined;
      assert.deepEqual(node.summary.end_key,end);assert.equal(node.summary.count,keys.length);
      assert.deepEqual(node.summary.first,keys[0]);assert.deepEqual(node.summary.last,keys.at(-1));
      assert.equal(node.height,1+Math.max(left.height,right.height));assert(Math.abs(left.height-right.height)<=1,'read index AVL balance');
      return {height:node.height,keys,end};
    }
    const tree=visit(group[root].root,owner);
    assert.equal(seen.size,indexed.length);assert.equal(group[root].height,tree.height);
    assert.equal(group[root].summary.count,indexed.length);assert.deepEqual(group[root].summary.end_key,tree.end);
    assert.equal(group[root].refreshing,false);assert.equal(group[root].dirty,undefined);
  }
  for(const frame of frames)assert(reads.some(read=>frame.id===`rebase_read_frame:[${read.reader}, '${read.phase}']`),'no orphan evaluation frame');
}
module.exports={verifyReads};
