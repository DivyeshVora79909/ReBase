import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(rootDir, 'target/n2-native-default/rebase-next');
const hasBinary = existsSync(binary);
const ROOT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NODE_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

test('checks a bounded complete backup captured from the real N2 operator', { skip: !hasBinary && `missing ${binary}` }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n5-structure-'));
  const tenant = '11111111-1111-4111-8111-111111111111';
  const actor = '22222222-2222-4222-8222-222222222222';
  const pairs = generateKeyPairSync('ed25519');
  const publicKey = pairs.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = pairs.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const identity = { issuer: 'n5-checker', audience: 'n5-checker', public_keys: { local: publicKey }, max_token_seconds: 300 };
  const serviceConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10, effects: null };
  const methods = ['store.backup', 'service.start', 'service.stop', 'identity.issue'];
  const config = resolveConfig({ overrides: {
    native: { binary, environment: {}, configuration: {
      model: 'equipment', backend: { kind: 'redb', cluster_file: null },
      target: { mode: 'create', path: path.join(directory, 'store.redb'), tenant, actor }, operator_methods: methods,
    } },
    runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
  } });
  let native, service;
  try {
    native = await openNative(config);
    const operator = openOperator(native, { scope: native.scope, methods });
    service = await operator.startService({ config: serviceConfig });
    const token = (await operator.issueIdentity({ identity,
      request: { tenant, actor, epoch: 0, ttl: 120, key_id: 'local' }, privateKeyPem })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector: 'equipment' });
    const pool = randomUUID(), delivery = randomUUID();
    const plan = await client.prepare(model.draftFixture([
      { contract: 'Pool', id: pool, fields: { unit: 1 } },
      { contract: 'Delivery', id: delivery, fields: { pool, at: '1', quantity: '10' } },
    ]));
    await client.execute(plan);
    const backupPath = path.join(directory, 'fixture.backup.json');
    await operator.snapshot({ destination: backupPath });
    const backupBytes = await readFile(backupPath);
    const result = checkBackupStructure(backupBytes);
    assert.equal(result.status, 'passed');
    assert.ok(result.nodeCount >= 1);
    assert.ok(result.nativeKvRows > result.nodeCount);
  } finally {
    if (native) {
      try { if (service) await native.stopService({ service: service.service }); } catch {}
      await native.close().catch(() => {});
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects duplicate JSON keys, invalid checksums and incomplete snapshots', () => {
  assert.throws(() => checkBackupStructure(Buffer.from('{"format":"a","format":"b"}')), /JSON|backup/i);
  const valid = backupWith(treeRows());
  assert.equal(checkBackupStructure(JSON.stringify(valid)).nodeCount, 1);
  const bufferInput = Buffer.from(JSON.stringify(valid), 'utf8');
  assert.equal(checkBackupStructure(bufferInput).nodeCount, 1);
  assert.equal(checkBackupStructure(new Uint8Array(bufferInput.buffer, bufferInput.byteOffset, bufferInput.byteLength)).nodeCount, 1);
  const badHash = structuredClone(valid);
  badHash.sha256 = '0'.repeat(64);
  assert.throws(() => checkBackupStructure(JSON.stringify(badHash)), /checksum/i);
  const incomplete = structuredClone(valid);
  incomplete.payload.complete = false;
  resign(incomplete);
  assert.throws(() => checkBackupStructure(JSON.stringify(incomplete)), /complete/i);
});

test('preflights supported input lengths before copying and rejects non-byte views', () => {
  const oversizedBytes = new Uint8Array(9);
  const oversizedUtf8 = 'é'.repeat(5);
  const originalFrom = Buffer.from;
  let copied = false;
  Buffer.from = function (...args) { copied = true; return originalFrom.apply(this, args); };
  try {
    assert.throws(() => checkBackupStructure(oversizedBytes, { maxBytes: 8 }), /byte limit/i);
    assert.throws(() => checkBackupStructure(oversizedUtf8, { maxBytes: 8 }), /byte limit/i);
    assert.equal(copied, false);
  } finally {
    Buffer.from = originalFrom;
  }
  for (const input of [new ArrayBuffer(1), new DataView(new ArrayBuffer(1)), new Uint16Array(1), [1], { length: 1 }]) {
    assert.throws(() => checkBackupStructure(input), /string, Buffer, or Uint8Array/i);
  }
});

test('rejects disconnected nodes, cycles, broken links, heights, spans and summaries', () => {
  const corruptions = [
    rows => rows.push(nodeRow({ ...node(), key: { value: '2', id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', slot: 1 } }, 'cccccccc-cccc-4ccc-8ccc-cccccccccccc')),
    rows => { const n = decodedNode(rows); n.left = { id: NODE_ID, slot: 1 }; replaceNode(rows, n); },
    rows => { const n = decodedNode(rows); n.height = 2; replaceNode(rows, n); },
    rows => { const n = decodedNode(rows); n.span.first = '0'; replaceNode(rows, n); },
    rows => { const n = decodedNode(rows); n.summary.value.sum = '11'; replaceNode(rows, n); },
    rows => { const n = decodedNode(rows); n.next = { id: ROOT_ID, slot: 1 }; replaceNode(rows, n); },
  ];
  for (const corrupt of corruptions) {
    const rows = treeRows(); corrupt(rows);
    const backup = backupWith(rows);
    assert.throws(() => checkBackupStructure(JSON.stringify(backup)));
  }
});

test('uses source expectations only as an independent membership check', () => {
  const expectedMembers = new Map([[`${NODE_ID}/1`, {
    root: { id: ROOT_ID, slot: 1 }, time: '1', leaf: { kind: 'financial', value: '10' },
  }]]);
  assert.equal(checkBackupStructure(JSON.stringify(backupWith(treeRows())), { expectedMembers }).status, 'passed');
  expectedMembers.set(`${NODE_ID}/1`, { root: { id: ROOT_ID, slot: 1 }, time: '1', leaf: { kind: 'financial', value: '9' } });
  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith(treeRows())), { expectedMembers }), /source membership leaf/i);
});

test('checks the complete source root inventory, including empty roots and kinds', () => {
  const rows = [emptyRootRow(ROOT_ID)];
  const backup = backupWith(rows);
  const expectedRoots = new Map([[`${ROOT_ID}/1`, { kind: 1 }]]);
  assert.equal(checkBackupStructure(JSON.stringify(backup), { expectedRoots }).rootCount, 1);
  assert.throws(() => checkBackupStructure(JSON.stringify(backup), { expectedRoots: new Map() }), /root inventory size/i);
  assert.throws(() => checkBackupStructure(JSON.stringify(backup), {
    expectedRoots: new Map([[`${ROOT_ID}/1`, { kind: 2 }]]),
  }), /root kind/i);
  assert.throws(() => checkBackupStructure(JSON.stringify(backup), {
    expectedRoots: new Map([[`${ROOT_ID}/1`, { kind: 1 }], [`${NODE_ID}/1`, { kind: 1 }]]),
  }), /root inventory size/i);
  assert.throws(() => checkBackupStructure(JSON.stringify(backup), {
    expectedRoots: new Map([[`${ROOT_ID}/0`, { kind: 1 }]]),
  }), /expected root address/i);
});

test('returns an inspect-compatible projection from the validated native KV parse', () => {
  const rows = treeRows();
  const record = { contract: 101, tenant: '11111111-1111-4111-8111-111111111111',
    owner: '22222222-2222-4222-8222-222222222222', reader: '33333333-3333-4333-8333-333333333333',
    version: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', input: { unit: 1 }, derived: null };
  const query = { source: { id: ROOT_ID, slot: 1 }, operation: 'sum', phase: 'calculate', channel: 'amount',
    range: { from: null, through: null } };
  const binding = { output: NODE_ID, retired: false };
  const sourceRole = { id: ROOT_ID, slot: 11 };
  const reservedRole = { id: ROOT_ID, slot: 29 };
  rows.push(
    { key: encodeKey(1, NODE_ID).slice(0, -4), value: hex(JSON.stringify({ type: 'record', data: record })) },
    { key: encodeKey(4, ROOT_ID), value: hex(JSON.stringify({ type: 'query', data: query })) },
    { key: encodeKey(8, ROOT_ID).replace(/0001$/, '000b'), value: hex(JSON.stringify({ type: 'role', data: binding })) },
    { key: encodeKey(9, NODE_ID).slice(0, -4), value: hex(JSON.stringify({ type: 'reserved', data: reservedRole })) },
  );
  const result = checkBackupStructure(JSON.stringify(backupWith(rows)), { includeObservation: true });
  assert.deepEqual(result.observation.records, [{ id: NODE_ID, record }]);
  assert.deepEqual(result.observation.roots, [{ root: { id: ROOT_ID, slot: 1 }, revision: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', summary: financialSummary() }]);
  assert.deepEqual(result.observation.queries, [{ query: { id: ROOT_ID, slot: 1 }, descriptor: query }]);
  assert.deepEqual(result.observation.roles, [{ source_role: sourceRole, binding }]);
  assert.deepEqual(result.observation.reserved, [{ id: NODE_ID, source_role: reservedRole }]);
  assert.equal(Object.isFrozen(result.observation.records), true);
});

test('checks shared quote and Measurement index summary folds without model calculations', () => {
  const quote = singleTree(2, { kind: 'quote', value: '300' },
    { kind: 'quote', value: { count: 1, first: '1', last: '1' } });
  assert.equal(checkBackupStructure(JSON.stringify(backupWith(quote))).nodeCount, 1);
  const measurement = singleTree(7, { unit: 3, value: '5' },
    { count: 1, sum: '5', min: '5', max: '5', dimension: { kind: 'unit', code: 3 } });
  assert.equal(checkBackupStructure(JSON.stringify(backupWith(measurement))).nodeCount, 1);
});

test('rejects noncanonical typed leaves, nested address fields and noncanonical stored-value bytes', () => {
  for (const value of ['0300', true, 300]) {
    const quote = singleTree(2, { kind: 'quote', value },
      { kind: 'quote', value: { count: 1, first: '1', last: '1' } });
    assert.throws(() => checkBackupStructure(JSON.stringify(backupWith(quote))), /canonical|quote leaf/i);
  }
  const addressRows = treeRows();
  const addressBackup = backupWith(addressRows);
  const root = JSON.parse(Buffer.from(addressRows[0].value, 'hex').toString('utf8'));
  root.data.head.extra = 'unexpected';
  addressRows[0].value = hex(JSON.stringify(root));
  resign(addressBackup);
  assert.throws(() => checkBackupStructure(JSON.stringify(addressBackup)), /tree address fields/i);

  const whitespaceRows = treeRows();
  const value = JSON.parse(Buffer.from(whitespaceRows[1].value, 'hex').toString('utf8'));
  whitespaceRows[1].value = hex(` ${JSON.stringify(value)}`);
  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith(whitespaceRows))), /canonical serde JSON/i);

  for (const index of [0, 1]) {
    const reorderedRows = treeRows();
    const reordered = JSON.parse(Buffer.from(reorderedRows[index].value, 'hex').toString('utf8'));
    reordered.data = Object.fromEntries(Object.entries(reordered.data).reverse());
    reorderedRows[index].value = hex(JSON.stringify(reordered));
    assert.throws(() => checkBackupStructure(JSON.stringify(backupWith(reorderedRows))), /canonical serde JSON/i);
  }
});

test('combines each subtree summary bottom-up across a three-node financial tree', () => {
  const left = { id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', slot: 1 };
  const middle = { id: NODE_ID, slot: 1 };
  const right = { id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', slot: 1 };
  const nodeValue = (address, time, amount, parent, leftLink, rightLink, prev, next, height, summary, span) => ({
    kind: 1, root: { id: ROOT_ID, slot: 1 }, key: { value: String(time), id: address.id, slot: address.slot },
    leaf: { kind: 'financial', value: String(amount) }, parent, left: leftLink, right: rightLink, prev, next,
    height, span, summary,
  });
  const leafSummary = (time, amount) => ({ kind: 'financial', value: {
    count: 1, first: String(time), last: String(time), sum: String(amount),
    min_prefix: String(Math.min(0, amount)), max_prefix: String(Math.max(0, amount)),
    boundary_min: null, boundary_max: null,
  } });
  const rootSummary = { kind: 'financial', value: {
    count: 3, first: '-1', last: '1', sum: '7', min_prefix: '-2', max_prefix: '8',
    boundary_min: '-2', boundary_max: '8',
  } };
  const rootValue = { kind: 1, head: middle, first: left, last: right, height: 2,
    span: { first: '-1', last: '1' }, summary: rootSummary, revision: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  const rows = [
    { key: encodeKey(2, ROOT_ID), value: hex(JSON.stringify({ type: 'root', data: rootValue })) },
    nodeRow({ type: 'node', data: nodeValue(left, -1, -2, middle, null, null, null, middle, 1, leafSummary(-1, -2), { first: '-1', last: '-1' }) }, left.id),
    nodeRow({ type: 'node', data: nodeValue(middle, 0, 10, null, left, right, left, right, 2, rootSummary, { first: '-1', last: '1' }) }),
    nodeRow({ type: 'node', data: nodeValue(right, 1, -1, middle, null, null, middle, null, 1, leafSummary(1, -1), { first: '1', last: '1' }) }, right.id),
  ];
  assert.equal(checkBackupStructure(JSON.stringify(backupWith(rows))).nodeCount, 3);
});

test('folds equal-time financial leaves in full UUID key order and rejects grouped prefixes', () => {
  const left = { id: '11111111-1111-4111-8111-111111111111', slot: 1 };
  const middle = { id: '22222222-2222-4222-8222-222222222222', slot: 1 };
  const right = { id: '33333333-3333-4333-8333-333333333333', slot: 1 };
  const leafSummary = amount => ({ kind: 'financial', value: {
    count: 1, first: '1', last: '1', sum: String(amount),
    min_prefix: String(Math.min(0, amount)), max_prefix: String(Math.max(0, amount)),
    boundary_min: null, boundary_max: null,
  } });
  const fullSummary = { kind: 'financial', value: {
    count: 3, first: '1', last: '1', sum: '4', min_prefix: '-4', max_prefix: '4',
    boundary_min: null, boundary_max: null,
  } };
  const nodeValue = (address, amount, parent, leftLink, rightLink, prev, next, height, summary) => ({
    kind: 1, root: { id: ROOT_ID, slot: 1 }, key: { value: '1', id: address.id, slot: address.slot },
    leaf: { kind: 'financial', value: String(amount) }, parent, left: leftLink, right: rightLink,
    prev, next, height, span: { first: '1', last: '1' }, summary,
  });
  const rows = [
    { key: encodeKey(2, ROOT_ID), value: hex(JSON.stringify({ type: 'root', data: {
      kind: 1, head: middle, first: left, last: right, height: 2,
      span: { first: '1', last: '1' }, summary: fullSummary, revision: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    } })) },
    nodeRow({ type: 'node', data: nodeValue(left, -2, middle, null, null, null, middle, 1, leafSummary(-2)) }, left.id),
    nodeRow({ type: 'node', data: nodeValue(middle, -2, null, left, right, left, right, 2, fullSummary) }, middle.id),
    nodeRow({ type: 'node', data: nodeValue(right, 8, middle, null, null, middle, null, 1, leafSummary(8)) }, right.id),
  ];
  const expectedMembers = new Map([
    [`${left.id}/1`, { root: { id: ROOT_ID, slot: 1 }, time: '1', leaf: { kind: 'financial', value: '-2' } }],
    [`${middle.id}/1`, { root: { id: ROOT_ID, slot: 1 }, time: '1', leaf: { kind: 'financial', value: '-2' } }],
    [`${right.id}/1`, { root: { id: ROOT_ID, slot: 1 }, time: '1', leaf: { kind: 'financial', value: '8' } }],
  ]);
  assert.equal(checkBackupStructure(JSON.stringify(backupWith(rows)), { expectedMembers }).nodeCount, 3);

  const groupedPrefixRows = structuredClone(rows);
  const groupedRoot = JSON.parse(Buffer.from(groupedPrefixRows[0].value, 'hex').toString('utf8'));
  groupedRoot.data.summary.value.min_prefix = '0';
  groupedPrefixRows[0].value = hex(JSON.stringify(groupedRoot));
  const middleHex = middle.id.replaceAll('-', '');
  const groupedMiddleRow = groupedPrefixRows.find(row => Buffer.from(row.key, 'hex').subarray(1, 17).toString('hex') === middleHex);
  const groupedMiddle = JSON.parse(Buffer.from(groupedMiddleRow.value, 'hex').toString('utf8')).data;
  groupedMiddle.summary.value.min_prefix = '0';
  groupedMiddleRow.value = hex(JSON.stringify({ type: 'node', data: groupedMiddle }));
  assert.throws(() => checkBackupStructure(JSON.stringify(backupWith(groupedPrefixRows))), /summary differs/i);
});

function treeRows() {
  const address = { id: NODE_ID, slot: 1 };
  const row = node();
  return [
    { key: encodeKey(2, ROOT_ID), value: hex(JSON.stringify({ type: 'root', data: {
      kind: 1, head: address, first: address, last: address, height: 1,
      span: { first: '1', last: '1' }, summary: financialSummary(), revision: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    } })) },
    nodeRow(row, NODE_ID),
  ];
}
function emptyRootRow(id) {
  return { key: encodeKey(2, id), value: hex(JSON.stringify({ type: 'root', data: {
    kind: 1, head: null, first: null, last: null, height: 0, span: null,
    summary: { kind: 'financial', value: { count: 0, first: null, last: null, sum: '0',
      min_prefix: '0', max_prefix: '0', boundary_min: null, boundary_max: null } },
    revision: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  } })) };
}
function singleTree(kind, leaf, summary) {
  const address = { id: NODE_ID, slot: 1 };
  const rootValue = { kind, head: address, first: address, last: address, height: 1,
    span: { first: '1', last: '1' }, summary, revision: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  const nodeValue = { kind, root: { id: ROOT_ID, slot: 1 }, key: { value: '1', id: NODE_ID, slot: 1 }, leaf,
    parent: null, left: null, right: null, prev: null, next: null, height: 1,
    span: { first: '1', last: '1' }, summary };
  return [
    { key: encodeKey(2, ROOT_ID), value: hex(JSON.stringify({ type: 'root', data: rootValue })) },
    nodeRow({ type: 'node', data: nodeValue }),
  ];
}
function node() {
  return { type: 'node', data: {
    kind: 1, root: { id: ROOT_ID, slot: 1 },
    key: { value: '1', id: NODE_ID, slot: 1 }, leaf: { kind: 'financial', value: '10' },
    parent: null, left: null, right: null, prev: null, next: null, height: 1,
    span: { first: '1', last: '1' }, summary: financialSummary(),
  } };
}
function financialSummary() {
  return { kind: 'financial', value: { count: 1, first: '1', last: '1', sum: '10', min_prefix: '0',
    max_prefix: '10', boundary_min: null, boundary_max: null } };
}
function nodeRow(value = node(), id = NODE_ID) { return { key: encodeKey(3, id), value: hex(JSON.stringify(value)) }; }
function encodeKey(tag, id) { return `${tag.toString(16).padStart(2, '0')}${id.replaceAll('-', '')}0001`; }
function hex(text) { return Buffer.from(text, 'utf8').toString('hex'); }
function backupWith(rows) {
  const payload = { format: 'rebase-authorized-observation-1', complete: true, tables: { native_kv: rows } };
  for (const name of ['effect_due', 'effect_executions', 'effect_facts', 'effect_inbox', 'effect_runtime',
    'local_runtime', 'operations', 'public_records', 'query_epochs', 'receipt_slots']) payload.tables[name] = [];
  const backup = { format: 'rebase-backup-1', sha256: '', payload };
  resign(backup);
  return backup;
}
function resign(backup) { backup.sha256 = createHash('sha256').update(canonicalJson(backup.payload)).digest('hex'); }
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
function decodedNode(rows) { return JSON.parse(Buffer.from(rows.find(row => Buffer.from(row.key, 'hex')[0] === 3).value, 'hex').toString()).data; }
function replaceNode(rows, value) { rows.find(row => Buffer.from(row.key, 'hex')[0] === 3).value = hex(JSON.stringify({ type: 'node', data: value })); }
