'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { verifyReads } = require('./read-oracle');
const { fixture } = require('./read-oracle-fixture');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema, compareKey } = require('./harness');
const observed = require('./observed-probe');
const { snapshot: accountingSnapshot } = require('../accounting/source-oracle');

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

function rootNode(value, kind) {
  const interval = kind === 'range';
  const link = group(value, kind)[interval ? 'z_intervals' : 'z_positions'].root;
  return value.data.rebase_read.find(row => row.id === link.rid)[link.slot];
}

function pruneEmptyReadOwners(value) {
  const reads = value.data.rebase_read;
  const groups = new Set(reads.map(item => item.group));
  const frames = new Set(reads.map(item => `rebase_read_frame:[${item.reader}, '${item.phase}']`));
  value.data.rebase_read_group = value.data.rebase_read_group.filter(item => groups.has(item.id));
  value.data.rebase_read_frame = value.data.rebase_read_frame.filter(item => frames.has(item.id));
}

function rewriteString(value, from, to) {
  if (typeof value === 'string') return value.replaceAll(from, to);
  if (Array.isArray(value)) return value.map(item => rewriteString(item, from, to));
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key,
      key === 'canonical_id' ? item : rewriteString(item, from, to)]));
  return value;
}

test('private read checker accepts a complete, independently described point and interval fixture', () => {
  const value = fixture();
  assert.deepEqual(verifyReads(value.data, value.sourceRows, value.entries, value.compare, value.checkOptions),
    { reads: 6, groups: 3, frames: 6 });
});

test('private read checker rejects missing metadata and each demonstrated topology blind spot', () => {
  const cases = [
    ['missing successor', value => { delete read(value, 'read_reader:c').z_position.next; }],
    ...['latest', 'range'].flatMap(kind => [
      [`${kind} root missing predecessor`, value => { delete rootNode(value, kind).prev; }],
      [`${kind} root self successor`, value => {
        const head = group(value, kind)[kind === 'range' ? 'z_intervals' : 'z_positions'];
        rootNode(value, kind).next = head.root;
      }],
    ]),
    ['wrong leaf summary', value => { read(value, 'read_reader:c').z_position.value.count = 77; }],
    ['wrong root first key', value => { group(value, 'latest').z_positions.summary.first = ['wrong']; }],
    ['wrong root count', value => { group(value, 'latest').z_positions.summary.count++; }],
    ['wrong subtree last key', value => { read(value, 'read_reader:d').z_position.summary.last = ['wrong']; }],
    ['wrong interval maximum', value => { group(value, 'range').z_intervals.summary.end_key = [999]; }],
    ['wrong interval leaf bound', value => { read(value, 'read_reader:e').z_interval.value.end_key = [999]; }],
    ['stale cursor', value => { group(value, 'latest').z_positions.cursor = { rid: 'stale', slot: 'z_position' }; }],
    ['unfinished refresh', value => { group(value, 'latest').z_positions.refreshing = true; }],
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
    ['missing required read fence', value => { value.data.rebase_read_lock = []; }],
    ['duplicate read fence identity', value => { value.data.rebase_read_lock.push(structuredClone(value.data.rebase_read_lock[0])); }],
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

test('read group and fingerprint identities cannot be relocated with self-consistent links', () => {
  const relocated = copyFixture();
  const oldGroup = group(relocated, 'latest').id;
  const wrongGroup = oldGroup.replace('read_curve:probe', 'read_curve:other');
  relocated.data = rewriteString(relocated.data, oldGroup, wrongGroup);
  assert.throws(() => run(relocated), /canonical group identity rebuilt/);

  const fingerprint = copyFixture();
  const oldRead = read(fingerprint, 'read_reader:c').id;
  const wrongRead = oldRead.replace('fingerprint:c:refresh', 'fingerprint:wrong:refresh');
  fingerprint.data = rewriteString(fingerprint.data, oldRead, wrongRead);
  assert.throws(() => run(fingerprint), /canonical read identity rebuilt/);
});

test('read identity witnesses are required on every verification call', () => {
  const value = copyFixture();
  delete group(value, 'latest').canonical_id;
  assert.throws(() => run(value), /canonical group identity rebuilt/);
  const readValue = copyFixture();
  delete read(readValue, 'read_reader:c').canonical_id;
  assert.throws(() => run(readValue), /canonical read identity rebuilt/);
});

test('native identity snapshots cover nested IDs and nanosecond keys through the observed caller', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-read-identity-'));
  let server;
  try {
    const source = fs.readFileSync(path.join(__dirname, 'observed-fixture.surql'), 'utf8');
    fs.writeFileSync(path.join(directory, 'fixture.surql'), source);
    const compiled = generateBundle(loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] }));
    server = await start({ engine: 'memory' });
    const q = client(server.url);
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, observed.instrument(compiled.bundle));
    await q("CREATE read_dates:['probe'] SET owned_by=rebase_tenant:default, initial=1.250dec; " +
      "CREATE read_quote:only SET owned_by=rebase_tenant:default, curve=read_dates:['probe'], " +
      "at=d'2027-01-06T00:00:00Z', rate=3.750dec; " +
      "CREATE read_dated:only SET owned_by=rebase_tenant:default, curve=read_dates:['probe'], " +
      "at=d'2027-01-06T00:00:00Z';");
    const state = await observed.snapshot(q);
    assert.match(state.groups.find(row => row.kind === 'latest').id, /read_dates:\['probe'\]/);
    assert.match(state.reads.find(row => row.kind === 'latest').id, /2027-01-06T00:00:00\.000000001Z/);
    const accountingState = await accountingSnapshot(q, []);
    assert(accountingState.rebase_read.every(row => row.canonical_id === row.id));
    assert(accountingState.rebase_read_group.every(row => row.canonical_id === row.id));
    const sourceRows = [...state.dates, ...state.quotes, ...state.dated, ...state.tenants, ...state.users];
    const entries = state.quotes.map(row => ({ link: { rid: row.id, slot: 'z_rate' }, owner: { rid: row.curve, slot: 'z_rates' },
      key: [row.at, row.id, 'z_rate'], measures: { rate: Number(row.rate) }, tags: {}, spans: {}, dependent: false })),
      checkOptions = { rootSpecs: [{ table: 'read_dates', slot: 'z_rates' }], expectedReads: observed.expectedReads(state) };
    const verifyAccountingSnapshot = data => verifyReads({
      rebase_read: data.rebase_read,
      rebase_read_group: data.rebase_read_group,
      rebase_read_frame: data.rebase_read_frame,
      rebase_read_lock: data.rebase_read_lock,
      rebase_read_stage: data.rebase_read_stage,
    }, sourceRows, entries, compareKey, checkOptions);
    verifyAccountingSnapshot(accountingState);
    observed.oracle(state);

    // The database-computed witnesses remain fixed while persisted identities
    // and all of their references are relocated self-consistently.
    const rewriteExceptWitness = (value, from, to) => {
      if (typeof value === 'string') return value.replaceAll(from, to);
      if (Array.isArray(value)) return value.map(item => rewriteExceptWitness(item, from, to));
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) =>
        [key, key === 'canonical_id' ? item : rewriteExceptWitness(item, from, to)]));
      return value;
    };
    const latestGroup = state.groups.find(row => row.kind === 'latest');
    const relocatedGroup = latestGroup.id.replace("read_dates:['probe']", "read_dates:['other']");
    assert.notEqual(relocatedGroup, latestGroup.id);
    assert.throws(() => observed.oracle(rewriteExceptWitness(state, latestGroup.id, relocatedGroup)),
      /canonical group identity rebuilt/);
    assert.throws(() => verifyAccountingSnapshot(rewriteExceptWitness(accountingState, latestGroup.id, relocatedGroup)),
      /canonical group identity rebuilt/);

    const latestRead = state.reads.find(row => row.kind === 'latest');
    const fingerprint = latestRead.id.match(/([0-9a-f]{64})(?='\])/i)?.[1];
    assert(fingerprint, 'native read identity exposes its fingerprint component');
    const relocatedRead = latestRead.id.replace(fingerprint, '0'.repeat(64));
    assert.notEqual(relocatedRead, latestRead.id);
    assert.throws(() => observed.oracle(rewriteExceptWitness(state, latestRead.id, relocatedRead)),
      /canonical read identity rebuilt/);
    assert.throws(() => verifyAccountingSnapshot(rewriteExceptWitness(accountingState, latestRead.id, relocatedRead)),
      /canonical read identity rebuilt/);
  } finally {
    if (server) await server.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('singleton point and interval subscription trees pass controls and reject corrupted roots', () => {
  for (const [name, reader, kind, head] of [
    ['point', 'c', 'latest', 'z_positions'],
    ['interval', 'e', 'range', 'z_intervals'],
  ]) {
    const value = fixture({ includeReaders: [reader] });
    assert.deepEqual(run(value), { reads: 1, groups: 1, frames: 1 }, `${name}: valid singleton control`);
    const owner = group(value, kind)[head];
    owner.summary.count++;
    assert.throws(() => run(value), /root summary|complete root summary/, `${name}: corrupted singleton root`);
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

test('source fences accept nested record IDs and reject a forged enclosing identity', () => {
  const value = fixture({ sourceId: "read_curve:['probe']" });
  assert.deepEqual(run(value), { reads: 6, groups: 3, frames: 6 });
  value.data.rebase_read_lock[0].id += ']';
  assert.throws(() => run(value), /fence belongs to a live source row/);
});

test('independent inventory detects a missing reader, group, conditional fallback, and validate-only call', () => {
  const cases = [
    ['one reader and its frame', fixture({ includeReaders: ['a', 'c'] }), value => {
      value.data.rebase_read = value.data.rebase_read.filter(item => item.reader !== 'read_reader:a');
      value.data.rebase_read_frame = value.data.rebase_read_frame.filter(item => !item.id.includes('read_reader:a'));
      pruneEmptyReadOwners(value);
    }],
    ['one complete group', fixture(), value => {
      const removed = new Set(value.data.rebase_read.filter(item => item.kind === 'range').map(item => item.id));
      value.data.rebase_read = value.data.rebase_read.filter(item => !removed.has(item.id));
      pruneEmptyReadOwners(value);
    }],
    ['conditional initial-value fallback call', fixture({ conditionalFallback: true }), value => {
      value.data.rebase_read = value.data.rebase_read.filter(item => !(item.reader === 'read_reader:g'
        && item.kind === 'record' && item.path === 'seed.initial'));
      pruneEmptyReadOwners(value);
    }],
    ['validate-only call', fixture({ includeReaders: ['d'] }), value => {
      value.data.rebase_read = value.data.rebase_read.filter(item => item.phase !== 'validate');
      pruneEmptyReadOwners(value);
    }],
  ];
  for (const [name, value, corrupt] of cases) {
    assert.deepEqual(run(value), { reads: value.expectedReads.length, groups: value.data.rebase_read_group.length,
      frames: value.data.rebase_read_frame.length }, `${name}: valid control`);
    corrupt(value);
    assert.throws(() => run(value), /exact logical read coverage/, name);
  }
});

test('an empty read inventory is a valid explicit zero-read control', () => {
  const value = fixture({ includeReaders: [] });
  assert.deepEqual(run(value), { reads: 0, groups: 0, frames: 0 });
});
