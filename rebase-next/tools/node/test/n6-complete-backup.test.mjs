import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { checkSourceBackup, checkSourceSnapshot, evaluateSources, stageSources } from '../oracles.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const methods = ['store.backup', 'service.start', 'service.stop', 'identity.issue'];

async function workflow(selector, run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), `rebase-n6-${selector}-`));
  const tenant = randomUUID(), actor = randomUUID();
  let native;
  try {
    native = await openNative(resolveConfig({ overrides: {
      native: { binary, environment: {}, configuration: {
        model: selector, backend: { kind: 'redb', cluster_file: null },
        target: { mode: 'create', path: path.join(directory, 'store.redb'), tenant, actor }, operator_methods: methods,
      } }, runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000 },
    } }));
    const operator = openOperator(native, { scope: native.scope, methods });
    const keys = generateKeyPairSync('ed25519');
    const identity = { issuer: 'n6-backup', audience: 'n6-backup',
      public_keys: { local: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }, max_token_seconds: 300 };
    const service = await operator.startService({ config: { listen: '127.0.0.1:0', identity,
      max_inflight: 4, request_timeout_seconds: 10, effects: null } });
    const token = (await operator.issueIdentity({ identity,
      request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    let facts = {}, sequence = 0;
    const mutate = async commands => {
      const receipt = await client.execute(await client.prepare({ model: native.scope.model, commands, returning: [] }));
      assert.equal(receipt.status, 'committed'); facts = stageSources(facts, commands);
      return receipt;
    };
    const capture = async () => {
      const destination = path.join(directory, `capture-${sequence++}.json`);
      await operator.snapshot({ destination });
      return readFile(destination);
    };
    const update = async (id, set) => {
      const record = await client.call('records.get', { model: native.scope.model, id });
      return mutate([{ op: 'update', id, if_version: record.version, set, unset: [] }]);
    };
    await run({ native, client, mutate, update, capture, facts: () => facts });
  } finally {
    if (native) await native.close();
    await rm(directory, { recursive: true, force: true });
  }
}

const create = (id, contract, fields) => ({ op: 'create', id, contract, fields });
function mustPass(result) { assert.equal(result.status, 'passed', JSON.stringify(result)); }
function mustFail(result, name) {
  assert.equal(result.status, 'failed', JSON.stringify(result));
  assert.ok(result.obligations.some(row => row.name === name && row.status === 'failed'), JSON.stringify(result));
}
test('N6 complete backup rejects unsupported and oversized input before copying bytes', () => {
  for (const backup of [undefined, [], new ArrayBuffer(8), new DataView(new ArrayBuffer(8)), new Uint16Array(8)]) {
    mustFail(checkSourceBackup({ model: 'quantity', facts: {}, backup }), 'complete-backup');
  }
  const tooLarge = new Uint8Array(64 * 1024 * 1024 + 1);
  const originalFrom = Buffer.from;
  let copies = 0;
  Buffer.from = (...args) => { copies += 1; return originalFrom(...args); };
  try {
    const result = checkSourceBackup({ model: 'quantity', facts: {}, backup: tooLarge });
    mustFail(result, 'complete-backup');
    assert.equal(result.obligations[0].reason, 'backup byte limit');
    assert.equal(copies, 0, 'the byte limit must reject before making a snapshot copy');
  } finally { Buffer.from = originalFrom; }
});
function identities(observation) {
  return observation.roles.map(row => ({ producer: row.source_role.id, role: row.source_role.slot, output: row.binding.output }));
}

test('N6 complete Equipment backup binds generated leaves, mixed-sign full keys and retained role history', { skip: !available && `missing ${binary}` }, async t => {
  await workflow('equipment', async ({ native, client, mutate, update, capture, facts }) => {
    const pool = randomUUID(), emptyPool = randomUUID(), otherPool = randomUUID();
    const delivery = randomUUID(), a = randomUUID(), b = randomUUID(), c = randomUUID(), zero = randomUUID();
    await mutate([
      create(pool, 101, { unit: 7 }), create(emptyPool, 101, { unit: 7 }), create(otherPool, 101, { unit: 7 }),
      create(delivery, 205, { pool, at: '0', quantity: '10' }),
      create(randomUUID(), 205, { pool: otherPool, at: '0', quantity: '10' }),
      create(a, 410, { pool, starts: '10', ends: '20', requested: '8', active: true }),
      create(b, 410, { pool, starts: '20', ends: '30', requested: '2', active: true }),
      create(c, 410, { pool, starts: '20', ends: '30', requested: '2', active: true }),
      create(zero, 410, { pool, starts: '40', ends: '50', requested: '0', active: true }),
    ]);
    let bytes = await capture();
    assert.equal(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes }).status, 'incomplete',
      'current facts cannot establish the absence of missing historical reservations');
    const observation = checkBackupStructure(bytes, { includeObservation: true }).observation;
    const history = identities(observation);
    assert.equal(history.length, 8, 'zero allocations still allocate two output roles');
    mustPass(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes, roleHistory: history }));
    const malformedOutputs = [
      value => { value.data.input.at = Number(value.data.input.at); value.data.input.quantity = Number(value.data.input.quantity); },
      value => { value.data.input.forged = true; },
      value => { value.data.derived = { available_before: '999', allocated: '999' }; },
    ];
    for (const corrupt of malformedOutputs) {
      const malformed = rewrite(bytes, value => { if (value.type === 'record' && value.data.contract === 900) corrupt(value); });
      assert.equal(checkBackupStructure(malformed).status, 'passed', 'physical checking alone does not validate private output codecs');
      mustFail(checkSourceBackup({ model: 'equipment', facts: facts(), backup: malformed, roleHistory: history }), 'private-output-records');
    }
    const expected = evaluateSources('equipment', facts());
    assert.equal(expected.roots.find(row => row.owner === pool).prefixOrderKnown, false);
    const bound = new Map(history.map(row => [`${row.producer}/${row.role}`, row.output]));
    const leaves = Object.entries(facts()).filter(([, row]) => row.contract === 205 && row.fields.pool === pool)
      .map(([id, row]) => ({ id, slot: 17, time: BigInt(row.fields.at), quantity: BigInt(row.fields.quantity) }));
    leaves.push(...expected.privateRecords.filter(row => row.pool === pool).map(row => ({
      id: bound.get(`${row.producer}/${row.role}`), slot: 23, time: BigInt(row.at), quantity: BigInt(row.quantity),
    })));
    leaves.sort((left, right) => left.time < right.time ? -1 : left.time > right.time ? 1
      : left.id < right.id ? -1 : left.id > right.id ? 1 : left.slot - right.slot);
    let total = 0n, minimum = 0n, maximum = 0n;
    for (const leaf of leaves) { total += leaf.quantity; minimum = total < minimum ? total : minimum; maximum = total > maximum ? total : maximum; }
    const summary = observation.roots.find(row => row.root.id === pool).summary.value;
    assert.equal(summary.min_prefix, String(minimum)); assert.equal(summary.max_prefix, String(maximum));
    t.diagnostic(JSON.stringify({ model: 'equipment', sameTime: leaves.filter(row => row.time === 20n).map(row => ({ ...row, time: String(row.time), quantity: String(row.quantity) })), minimum: String(minimum), maximum: String(maximum) }));
    assert.equal(checkSourceSnapshot({ model: 'equipment', facts: facts(), snapshot: observation }).status, 'incomplete');

    const shifted = rewrite(bytes, value => {
      if (value.type === 'node') value.data.key.value = String(BigInt(value.data.key.value) + 100n);
      if (value.type === 'node' || value.type === 'root') {
        for (const key of ['first', 'last']) if (value.data.span) value.data.span[key] = String(BigInt(value.data.span[key]) + 100n);
        for (const key of ['first', 'last']) if (value.data.summary.value[key] !== null) value.data.summary.value[key] = String(BigInt(value.data.summary.value[key]) + 100n);
      }
    });
    assert.equal(checkBackupStructure(shifted).status, 'passed', 'self-consistent physical times alone do not prove source membership');
    mustFail(checkSourceBackup({ model: 'equipment', facts: facts(), backup: shifted }), 'source-physical-membership');
    const wrongWitness = structuredClone(history); wrongWitness[0].output = randomUUID();
    mustFail(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes, roleHistory: wrongWitness }), 'role-binding-contents');
    mustFail(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes, roleHistory: [...history, history[0]] }), 'role-history');
    const wrongInverse = rewrite(bytes, value => {
      if (value.type === 'reserved' && value.data.slot === 11) value.data.slot = 29;
    });
    mustFail(checkSourceBackup({ model: 'equipment', facts: facts(), backup: wrongInverse, roleHistory: history }), 'role-reservation-inverse');

    await update(b, { pool: otherPool });
    bytes = await capture();
    mustPass(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes, roleHistory: history }));
    await update(b, { active: false });
    bytes = await capture();
    const withoutHistory = checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes });
    assert.equal(withoutHistory.status, 'incomplete');
    assert.ok(withoutHistory.obligations.some(row => row.name === 'role-history-inventory' && row.status === 'incomplete'));
    mustPass(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes, roleHistory: history }));
    await update(b, { active: true });
    mustPass(checkSourceBackup({ model: 'equipment', facts: facts(), backup: await capture(), roleHistory: history }));
    const record = await client.call('records.get', { model: native.scope.model, id: b });
    await mutate([{ op: 'delete', id: b, if_version: record.version }]);
    bytes = await capture();
    mustPass(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes, roleHistory: history }));
    assert.equal(checkSourceBackup({ model: 'equipment', facts: facts(), backup: bytes }).status, 'incomplete');
    const lostHistory = JSON.parse(bytes);
    lostHistory.payload.tables.native_kv = lostHistory.payload.tables.native_kv.filter(row => {
      const value = JSON.parse(Buffer.from(row.value, 'hex').toString('utf8'));
      return !(row.key.startsWith(`08${b.replaceAll('-', '')}`) || (value.type === 'reserved' && value.data.id === b));
    });
    const erased = seal(lostHistory);
    assert.equal(checkBackupStructure(erased).status, 'passed');
    mustFail(checkSourceBackup({ model: 'equipment', facts: facts(), backup: erased, roleHistory: history }), 'role-inventory');
    assert.equal(checkSourceBackup({ model: 'equipment', facts: facts(), backup: erased }).status, 'incomplete',
      'missing historical reservations cannot be certified absent without the retained witness');
    const before = bytes;
    await assert.rejects(client.execute(await client.prepare({ model: native.scope.model,
      commands: [create(b, 410, { pool, starts: '20', ends: '30', requested: '2', active: true })], returning: [] })),
    error => error.code === 'unavailable_reference');
    const after = await capture();
    assert.deepEqual(JSON.parse(before).payload, JSON.parse(after).payload, 'rejected reuse preserves the complete image');
  });
});

test('N6 complete Measurement backup checks range summaries, ties, absent selection and independent member values', { skip: !available && `missing ${binary}` }, async () => {
  await workflow('measurement', async ({ mutate, capture, facts }) => {
    const instrument = randomUUID(), emptyInstrument = randomUUID(), first = randomUUID(), second = randomUUID();
    const report = randomUUID(), empty = randomUUID(), latest = randomUUID(), absent = randomUUID();
    await mutate([
      create(instrument, 101, { unit: 7 }), create(emptyInstrument, 101, { unit: 9 }),
      create(first, 211, { instrument, at: '10', value: '5', unit: 7 }),
      create(second, 211, { instrument, at: '10', value: '-8', unit: 7 }),
      create(report, 307, { instrument, unit: 7, range: { lower: { included: '10' }, upper: { included: '10' } }, threshold: '-8' }),
      create(empty, 307, { instrument, unit: 7, range: { lower: { included: '10' }, upper: { excluded: '10' } }, threshold: '0' }),
      create(latest, 419, { instrument, unit: 7, at: '10' }), create(absent, 419, { instrument, unit: 7, at: '9' }),
    ]);
    const bytes = await capture();
    mustPass(checkSourceBackup({ model: 'measurement', facts: facts(), backup: bytes }));
    const observation = checkBackupStructure(bytes, { includeObservation: true }).observation;
    assert.equal(observation.queries.find(row => row.query.id === latest).descriptor.selected, null);
    assert.equal(observation.queries.find(row => row.query.id === latest).descriptor.result.identity, [first, second].sort().at(-1));
    const badSelection = rewrite(bytes, value => {
      if (value.type === 'query' && value.data.operation === 'latest' && value.data.result) value.data.result.member_slot = 23;
    });
    mustFail(checkSourceBackup({ model: 'measurement', facts: facts(), backup: badSelection }), 'query-descriptor-contents');
    const badUnit = rewrite(bytes, value => {
      if (value.type === 'node') value.data.leaf.unit += 1;
      if ((value.type === 'node' || value.type === 'root') && value.data.summary.dimension.kind === 'unit') value.data.summary.dimension.code += 1;
    });
    assert.equal(checkBackupStructure(badUnit).status, 'passed');
    mustFail(checkSourceBackup({ model: 'measurement', facts: facts(), backup: badUnit }), 'source-physical-membership');
  });
});

test('N6 complete Quantity backup checks exact source arithmetic and requires empty physical inventories', { skip: !available && `missing ${binary}` }, async () => {
  await workflow('quantity', async ({ mutate, capture, facts }) => {
    const source = randomUUID(), scale = randomUUID(), join = randomUUID();
    await mutate([
      create(source, 101, { value: '13' }),
      create(scale, 205, { parent: source, factor: { numerator: '0', denominator: '1' }, rounding: 'exact' }),
      create(join, 309, { left: source, right: scale }),
    ]);
    const bytes = await capture();
    const result = checkSourceBackup({ model: 'quantity', facts: facts(), backup: bytes });
    mustPass(result); assert.equal(result.physical.rootCount, 0); assert.equal(result.physical.nodeCount, 0);
    const altered = rewrite(bytes, value => {
      if (value.type === 'record' && value.data.derived?.quantity === '0') value.data.derived.quantity = '1';
    });
    mustFail(checkSourceBackup({ model: 'quantity', facts: facts(), backup: altered }), 'source-derived-values');
    const extraRoot = JSON.parse(bytes);
    extraRoot.payload.tables.native_kv.push({ key: `02${randomUUID().replaceAll('-', '')}0007`, value: Buffer.from(JSON.stringify({ type: 'root', data: {
      kind: 1, head: null, first: null, last: null, height: 0, span: null,
      summary: { kind: 'financial', value: { count: 0, first: null, last: null, sum: '0', min_prefix: '0', max_prefix: '0', boundary_min: null, boundary_max: null } }, revision: randomUUID(),
    } })).toString('hex') });
    const selfConsistent = seal(extraRoot);
    assert.equal(checkBackupStructure(selfConsistent).status, 'passed');
    mustFail(checkSourceBackup({ model: 'quantity', facts: facts(), backup: selfConsistent }), 'source-physical-membership');
  });
});

function rewrite(bytes, edit) {
  const backup = JSON.parse(bytes);
  for (const row of backup.payload.tables.native_kv) {
    const value = JSON.parse(Buffer.from(row.value, 'hex').toString('utf8'));
    edit(value); row.value = Buffer.from(JSON.stringify(value)).toString('hex');
  }
  return seal(backup);
}
function seal(backup) {
  backup.sha256 = createHash('sha256').update(canonical(backup.payload)).digest('hex');
  return Buffer.from(JSON.stringify(backup));
}
function canonical(value) {
  return Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
      : JSON.stringify(value);
}
