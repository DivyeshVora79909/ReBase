'use strict';

// Lead investigation: synthetic, independently described oracle inputs.
// This does not reproduce the database writer failures or certify a repair.
// Run from any directory. A result of accepted:true for a corrupt input exposes
// an oracle blind spot. Missing-registration detection needs an expected-read
// inventory as well; an inspection of surviving metadata cannot supply it.
const { verifyReads } = require('../../../dev-tools/temporal-tree/read-oracle');
const { scan } = require('../../../dev-tools/temporal-tree/oracle');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function fixture() {
  const group = 'rebase_read_group:probe', tenant = 'rebase_tenant:default';
  const slot = 'z_position', owner = { rid: group, slot: 'z_positions' };
  const rows = [{ id: 'curve:probe', tenant, initial: 3 },
    { id: 'reader:a', tenant }, { id: 'reader:b', tenant }];
  const reads = ['a', 'b'].map(name => ({ id: `rebase_read:${name}`, tenant,
    reader: `reader:${name}`, source_root: 'curve:probe', source_slot: '',
    kind: 'record', path: 'initial', phase: 'refresh', version: 1,
    position: [], group, fallback: { value: 0 }, observed: { value: 3 } }));
  const keys = reads.map(row => [row.position, row.id, slot]);
  const links = reads.map(row => ({ rid: row.id, slot }));
  const entry = index => ({ key: keys[index], measures: {}, tags: {}, spans: {}, dependent: false });
  reads[0][slot] = { owner, parent: owner, right: links[1], next: links[1],
    key: keys[0], value: scan([entry(0)]), summary: scan([entry(0), entry(1)]), height: 2 };
  reads[1][slot] = { owner, parent: links[0], prev: links[0], key: keys[1],
    value: scan([entry(1)]), summary: scan([entry(1)]), height: 1 };
  const data = { rebase_read: reads, rebase_read_group: [{ id: group, kind: 'record',
    z_positions: { root: links[0], height: 2, summary: scan([entry(0), entry(1)]), refreshing: false },
    z_intervals: { summary: { count: 0 } } }],
    rebase_read_frame: reads.map(row => ({ id: `rebase_read_frame:[${row.reader}, '${row.phase}']`, version: 1 })) };
  return { data, rows };
}

const compare = (a, b) => {
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] < b[index]) return -1;
    if (a[index] > b[index]) return 1;
  }
  return a.length - b.length;
};
const mutations = [
  ['valid control', () => {}],
  ['missing successor', data => { delete data.rebase_read[0].z_position.next; }],
  ['wrong leaf count', data => { data.rebase_read[0].z_position.value.count = 77; }],
  ['wrong root first key', data => {
    data.rebase_read_group[0].z_positions.summary.first = data.rebase_read[1].z_position.key;
  }],
  ['stale cursor', data => { data.rebase_read_group[0].z_positions.cursor = [[], 'wrong', 'z_position']; }],
  ['read with nonexistent group', data => { data.rebase_read_group = []; }],
  ['all registrations absent', data => {
    data.rebase_read = []; data.rebase_read_group = []; data.rebase_read_frame = [];
  }],
];

function run() {
  const results = mutations.map(([label, mutate]) => {
    const { data, rows } = fixture();
    mutate(data);
    try { verifyReads(data, rows, [], compare); return { label, accepted: true }; }
    catch (error) { return { label, accepted: false, error: error.message }; }
  });
  const source = path.resolve(__dirname, '../../../dev-tools/temporal-tree/read-oracle.js');
  return { purpose: 'Diagnose oracle coverage, not database writer correctness',
    readOracleSha256: crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex'), results };
}

if (require.main === module) process.stdout.write(JSON.stringify(run(), null, 2) + '\n');
module.exports = { fixture, run };
