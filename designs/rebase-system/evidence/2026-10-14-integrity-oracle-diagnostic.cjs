'use strict';

// Standalone fault-injection control for the shared private-read checker.
// The valid fixture contains complete schema-shaped roots, records, frames and
// independently described reads. Every corruption changes one invariant only.
const { verifyReads } = require('../../../dev-tools/temporal-tree/read-oracle');
const { fixture } = require('../../../dev-tools/temporal-tree/read-oracle-fixture');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const clone = value => {
  const copy = fixture();
  copy.data = structuredClone(value.data);
  copy.sourceRows = structuredClone(value.sourceRows);
  copy.entries = structuredClone(value.entries);
  return copy;
};
const read = (value, name) => value.data.rebase_read.find(row => row.reader === `read_reader:${name}`);
const group = (value, kind) => value.data.rebase_read_group.find(row => row.kind === kind);
const checks = value => verifyReads(value.data, value.sourceRows, value.entries, value.compare, value.checkOptions);

const valid = fixture();
checks(valid);
const pointRoot = group(valid, 'latest').z_positions.root;
const intervalRoot = group(valid, 'range').z_intervals.root;
const faults = [
  ['missing successor', value => { delete read(value, 'c').z_position.next; }],
  ['wrong leaf count', value => { read(value, 'c').z_position.value.count = 77; }],
  ['wrong root first key', value => { group(value, 'latest').z_positions.summary.first = ['wrong']; }],
  ['wrong root count', value => { group(value, 'latest').z_positions.summary.count++; }],
  ['stale cursor', value => { group(value, 'latest').z_positions.cursor = { rid: 'stale', slot: 'z_position' }; }],
  ['wrong interval maximum', value => { group(value, 'range').z_intervals.summary.end_key = [999]; }],
  ['missing node', value => { delete read(value, 'c').z_position; }],
  ['wrong inactive root', value => { group(value, 'latest').z_intervals.root = { rid: 'read_reader:c', slot: 'z_interval' }; }],
  ['wrong parent', value => { read(value, 'c').z_position.parent = { rid: 'wrong:parent', slot: 'z_position' }; }],
  ['cycle', value => { const row = value.data.rebase_read.find(item => item.id === pointRoot.rid); row.z_position.left = { rid: row.id, slot: 'z_position' }; }],
  ['dangling child', value => { const row = value.data.rebase_read.find(item => item.id === pointRoot.rid); row.z_position.right = { rid: 'missing:read', slot: 'z_position' }; }],
  ['stale frame', value => { value.data.rebase_read_frame.find(frame => frame.id.includes('read_reader:c')).version++; }],
  ['missing read group', value => { read(value, 'c').group = 'missing:group'; }],
  ['all registrations absent', value => { value.data.rebase_read = []; value.data.rebase_read_group = []; value.data.rebase_read_frame = []; }],
  ['wrong interval node', value => { const row = value.data.rebase_read.find(item => item.id === intervalRoot.rid); row.z_interval.value.end_key = [999]; }],
];

const results = [['valid control', () => checks(clone(valid))], ...faults.map(([label, mutate]) => [label, () => {
  const value = clone(valid);
  mutate(value);
  checks(value);
}])].map(([label, check]) => {
  try { check(); return { label, accepted: true }; }
  catch (error) { return { label, accepted: false, error: error.message.split('\n')[0] }; }
});
const permuted = clone(valid);
permuted.data.rebase_read.reverse();
permuted.data.rebase_read_group.reverse();
permuted.data.rebase_read_frame.reverse();
permuted.sourceRows.reverse();
permuted.entries.reverse();
checks(permuted);
results.push({ label: 'row-order permutation', accepted: true });

const report = { purpose: 'Prove the shared private read oracle rejects corrupt state and accepts valid row permutations',
  readOracleSha256: crypto.createHash('sha256').update(fs.readFileSync(path.resolve(__dirname, '../../../dev-tools/temporal-tree/read-oracle.js'))).digest('hex'),
  validFixture: { reads: valid.data.rebase_read.length, groups: valid.data.rebase_read_group.length, frames: valid.data.rebase_read_frame.length },
  results };
if (results.some(result => result.label === 'valid control' && !result.accepted)
  || results.some(result => result.label !== 'valid control' && result.label !== 'row-order permutation' && result.accepted)
  || !results.find(result => result.label === 'row-order permutation')?.accepted) process.exitCode = 1;
console.log(JSON.stringify(report, null, 2));
