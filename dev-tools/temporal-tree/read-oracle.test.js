'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { verifyReads } = require('./read-oracle');
const { fixture } = require('./read-oracle-fixture');

function copyFixture() {
  const value = fixture();
  value.data = structuredClone(value.data);
  value.sourceRows = structuredClone(value.sourceRows);
  value.entries = structuredClone(value.entries);
  return value;
}

function run(value) {
  return verifyReads(value.data, value.sourceRows, value.entries, value.compare, value.checkOptions);
}

function group(value, kind) {
  return value.data.rebase_read_group.find(row => row.kind === kind);
}

function read(value, reader) {
  return value.data.rebase_read.find(row => row.reader === reader);
}

test('private read checker accepts a complete, independently described point and interval fixture', () => {
  const value = fixture();
  assert.deepEqual(verifyReads(value.data, value.sourceRows, value.entries, value.compare, value.checkOptions),
    { reads: 6, groups: 3, frames: 6 });
});

test('private read checker rejects missing metadata and each demonstrated topology blind spot', () => {
  const cases = [
    ['missing successor', value => { delete read(value, 'read_reader:c').z_position.next; }],
    ['wrong leaf summary', value => { read(value, 'read_reader:c').z_position.value.count = 77; }],
    ['wrong root first key', value => { group(value, 'latest').z_positions.summary.first = ['wrong']; }],
    ['wrong root count', value => { group(value, 'latest').z_positions.summary.count++; }],
    ['wrong subtree last key', value => { read(value, 'read_reader:d').z_position.summary.last = ['wrong']; }],
    ['wrong interval maximum', value => { group(value, 'range').z_intervals.summary.end_key = [999]; }],
    ['wrong interval leaf bound', value => { read(value, 'read_reader:e').z_interval.value.end_key = [999]; }],
    ['stale cursor', value => { group(value, 'latest').z_positions.cursor = { rid: 'stale', slot: 'z_position' }; }],
    ['unfinished refresh', value => { group(value, 'latest').z_positions.refreshing = true; }],
    ['unsettled tree change', value => { group(value, 'latest').tree_changed = true; }],
    ['orphan group', value => { group(value, 'latest').z_positions.dirty = [7]; }],
    ['missing point node', value => { delete read(value, 'read_reader:c').z_position; }],
    ['wrong inactive root', value => { group(value, 'latest').z_intervals.root = { rid: 'read_reader:c', slot: 'z_interval' }; }],
    ['wrong node owner', value => { read(value, 'read_reader:c').z_position.owner.rid = 'wrong:owner'; }],
    ['wrong parent', value => { read(value, 'read_reader:c').z_position.parent = { rid: 'wrong:parent', slot: 'z_position' }; }],
    ['cycle', value => { const row = read(value, 'read_reader:d'); row.z_position.left = { rid: row.id, slot: 'z_position' }; }],
    ['duplicate child', value => { const root = group(value, 'latest').z_positions.root; const row = value.data.rebase_read.find(item => item.id === root.rid); row.z_position.right = row.z_position.left; }],
    ['dangling child', value => { const root = group(value, 'latest').z_positions.root; value.data.rebase_read.find(item => item.id === root.rid).z_position.right = { rid: 'missing:read', slot: 'z_position' }; }],
    ['read with missing group', value => { read(value, 'read_reader:c').group = 'missing:group'; }],
    ['missing frame', value => { value.data.rebase_read_frame = value.data.rebase_read_frame.filter(frame => !frame.id.includes('read_reader:c')); }],
    ['stale frame generation', value => { value.data.rebase_read_frame.find(frame => frame.id.includes('read_reader:c')).version++; }],
    ['orphan frame', value => { value.data.rebase_read_frame.push({ id: "rebase_read_frame:[read_reader:missing, 'refresh']", version: 1 }); }],
    ['orphan read lock source', value => { value.data.rebase_read_lock[0].id = 'rebase_read_lock:[read_curve:missing]'; }],
    ['wrong read fence tenant', value => { value.data.rebase_read_lock[0].tenant = 'tenant:other'; }],
    ['invalid read fence revision', value => { value.data.rebase_read_lock[0].revision = 0; }],
    ['wrong read tenant', value => { read(value, 'read_reader:c').tenant = 'tenant:other'; }],
    ['wrong stable reader identity', value => { read(value, 'read_reader:c').reader_identity = 'read_reader:other'; }],
    ['wrong group channel', value => { group(value, 'latest').channel = 'order'; }],
    ['wrong query position', value => { read(value, 'read_reader:c').position = [[100]]; }],
    ['wrong cached value', value => { read(value, 'read_reader:c').observed.value = 42; }],
    ['entire registration inventory removed', value => {
      value.data.rebase_read = []; value.data.rebase_read_group = []; value.data.rebase_read_frame = [];
    }],
  ];
  for (const [name, corrupt] of cases) {
    const value = copyFixture();
    corrupt(value);
    assert.throws(() => run(value), undefined, name);
  }
});

test('private read checks do not depend on database row enumeration order', () => {
  const value = copyFixture();
  value.data.rebase_read.reverse();
  value.data.rebase_read_group.reverse();
  value.data.rebase_read_frame.reverse();
  value.sourceRows.reverse();
  value.entries.reverse();
  assert.deepEqual(run(value), { reads: 6, groups: 3, frames: 6 });
});

test('schema root inventory rejects an otherwise self-consistent read of an undeclared source slot', () => {
  const value = fixture();
  value.checkOptions = { ...value.checkOptions, rootSpecs: [{ table: 'read_curve', slot: 'z_missing' }] };
  assert.throws(() => run(value), /declared business root/);
});
