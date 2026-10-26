import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { checkSourceSnapshot, evaluateSources, OracleError, sourceOracle, stageSources } from '../oracles.mjs';
import { checkRun, runWorkload } from '../workload.mjs';
import { explore, logicalReplay, shrinkFailure, walk } from '../experiments.mjs';
import { replayOriginalIntents } from '../examples/n4-original-intent-replay.mjs';

const profile = { durationMs: 1_000, ratePerSecond: 10_000, maxActions: 16,
  concurrency: 1, maxPending: 1, maxObservations: 16, maxArtifactBytes: 65_536,
  sampleIntervalMs: 100 };

test('Quantity oracle derives exact values and validates declared zero-factor cycles', () => {
  const facts = {
    s: { contract: 101, fields: { value: '13' } },
    l: { contract: 205, fields: { parent: 's', factor: { numerator: '1', denominator: '2' }, rounding: 'half_away_from_zero' } },
    r: { contract: 205, fields: { parent: 's', factor: { numerator: '1', denominator: '2' }, rounding: 'floor' } },
    j: { contract: 309, fields: { left: 'l', right: 'r' } },
  };
  assert.deepEqual(evaluateSources('quantity', facts).derived, {
    s: { quantity: '13' }, l: { quantity: '7' }, r: { quantity: '6' }, j: { quantity: '13' },
  });
  const cyclic = structuredClone(facts);
  cyclic.l.fields.parent = 'j';
  cyclic.l.fields.factor = { numerator: '0', denominator: '1' };
  assert.throws(() => evaluateSources('quantity', cyclic), error => error instanceof OracleError && error.kind === 'feedback');
  const inexact = structuredClone(facts);
  inexact.l.fields.rounding = 'exact';
  assert.throws(() => evaluateSources('quantity', inexact), error => error.kind === 'inexact');
});

test('Equipment oracle uses strict prefixes, chronological allocation and independent roots', () => {
  const facts = {
    pool: { contract: 101, fields: { unit: 7 } },
    d: { contract: 205, fields: { pool: 'pool', at: '10', quantity: '10' } },
    a: { contract: 410, fields: { pool: 'pool', starts: '20', ends: '30', requested: '8', active: true } },
    b: { contract: 410, fields: { pool: 'pool', starts: '30', ends: '40', requested: '7', active: true } },
  };
  const result = evaluateSources('equipment', facts);
  assert.deepEqual(result.derived, { a: { available_before: '10', allocated: '8' }, b: { available_before: '2', allocated: '2' } });
  assert.deepEqual(result.roots, [{ owner: 'pool', slot: 7, prefixOrderKnown: false, summary: { kind: 'financial', value: {
    count: 5, first: '10', last: '40', sum: '10', min_prefix: '0', max_prefix: '10', boundary_min: '2', boundary_max: '10',
  } } }]);
  assert.equal(result.dependencies.find(row => row.source === 'a').range.upper.excluded, '20');
});

test('Measurement oracle honors exact windows and deterministic latest identity ties', () => {
  const facts = {
    i: { contract: 101, fields: { unit: 7 } },
    a: { contract: 211, fields: { instrument: 'i', at: '10', value: '5', unit: 7 } },
    b: { contract: 211, fields: { instrument: 'i', at: '10', value: '8', unit: 7 } },
    r: { contract: 307, fields: { instrument: 'i', unit: 7, range: { lower: { included: '10' }, upper: { excluded: '10' } }, threshold: '0' } },
    s: { contract: 419, fields: { instrument: 'i', unit: 7, at: '10' } },
  };
  const value = evaluateSources('measurement', facts);
  assert.deepEqual(value.derived.r, { count: 0, min: null, max: null, unit: 7, at_least_threshold: false });
  assert.deepEqual(value.derived.s.selection, { identity: 'b', member_slot: 17, time: '10', unit: 7, value: '8' });
  assert.equal(value.roots[0].summary.sum, '13');
});

test('Measurement snapshots check exact query payloads, empty statistics and selected observation contents', () => {
  const facts = {
    i: { contract: 101, fields: { unit: 7 } },
    a: { contract: 211, fields: { instrument: 'i', at: '10', value: '5', unit: 7 } },
    b: { contract: 211, fields: { instrument: 'i', at: '10', value: '-8', unit: 7 } },
    report: { contract: 307, fields: { instrument: 'i', unit: 7, range: { lower: { included: '10' }, upper: { included: '10' } }, threshold: '-8' } },
    empty: { contract: 307, fields: { instrument: 'i', unit: 7, range: { lower: { included: '10' }, upper: { excluded: '10' } }, threshold: '0' } },
    latest: { contract: 419, fields: { instrument: 'i', unit: 7, at: '10' } },
    absent: { contract: 419, fields: { instrument: 'i', unit: 7, at: '9' } },
  };
  const expected = evaluateSources('measurement', facts);
  assert.deepEqual(expected.queryResults.report, { count: 2, sum: '-3', min: '-8', max: '5', dimension: { kind: 'unit', code: 7 } });
  assert.deepEqual(expected.queryResults.empty, { count: 0, sum: '0', min: null, max: null, dimension: { kind: 'empty' } });
  assert.equal(expected.queryResults.absent, null);
  const snapshot = {
    records: Object.entries(facts).map(([id, row]) => ({ id, record: { contract: row.contract, input: row.fields, derived: expected.derived[id] ?? null } })),
    roots: [{ root: { id: 'i', slot: 7 }, revision: 'retained-revision',
      summary: { count: 2, sum: '-3', min: '-8', max: '5', dimension: { kind: 'unit', code: 7 } } }],
    queries: expected.dependencies.map(dep => ({ query: { id: dep.source, slot: dep.query_slot }, descriptor: {
      source: { id: dep.instrument, slot: 7 }, operation: facts[dep.source].contract === 307 ? 'summary' : 'latest',
      phase: 'calculate', channel: facts[dep.source].contract === 307 ? 'statistics' : 'observation',
      range: dep.range, selected: null, result: expected.queryResults[dep.source],
    } })), roles: [],
  };
  const check = value => checkSourceSnapshot({ model: 'measurement', facts, snapshot: value });
  assert.equal(check(snapshot).obligations.some(row => row.status === 'failed'), false);
  assert.equal(check(snapshot).status, 'incomplete', 'inspect alone still lacks physical trees');
  const corruptions = [
    value => { value.queries[0].descriptor.result.sum = '3'; },
    value => { value.queries[0].descriptor.result.dimension.code = 8; },
    value => { value.queries[1].descriptor.result.dimension = { kind: 'unit', code: 7 }; },
    ...['identity', 'member_slot', 'time', 'unit', 'value'].map(field => value => {
      value.queries[2].descriptor.result[field] = { identity: 'a', member_slot: 23, time: '9', unit: 8, value: '8' }[field];
    }),
    value => { value.queries[2].descriptor.selected = 'b'; },
    value => { value.queries[3].descriptor.result = expected.queryResults.latest; },
    value => { value.queries[0].descriptor.extra = true; },
  ];
  for (const corrupt of corruptions) {
    const value = structuredClone(snapshot); corrupt(value);
    assert.ok(check(value).obligations.some(row => row.name === 'query-descriptor-contents' && row.status === 'failed'));
  }
  const wrongEnvelope = structuredClone(snapshot);
  wrongEnvelope.roots[0].summary = { kind: 'measurement', value: wrongEnvelope.roots[0].summary };
  assert.ok(check(wrongEnvelope).obligations.some(row => row.name === 'root-summaries' && row.status === 'failed'));
});

test('source mutation staging is detached and rejects a child before its parent', () => {
  const facts = {};
  assert.throws(() => stageSources(facts, [{ op: 'create', id: 'child', contract: 205,
    fields: { parent: 'parent' } }]), error => error.kind === 'unavailable_reference');
  const next = stageSources(facts, [{ op: 'create', id: 'parent', contract: 101, fields: { value: '2' } }]);
  assert.deepEqual(facts, {});
  assert.equal(next.parent.fields.value, '2');
});

test('source oracle rejects changed raw source observations by named obligation', async () => {
  const facts = { q: { contract: 101, fields: { value: '12' } } };
  const snapshot = { records: [{ id: 'q', record: { contract: 101, input: { value: '12' }, derived: { quantity: '12' } } }],
    roots: [], queries: [], roles: [] };
  const oracle = sourceOracle({ model: 'quantity', facts,
    select: value => ({ sourceId: value.sourceId, derived: value.derived }) });
  const run = await runWorkload({ state: {}, profile: { ...profile, maxActions: 2, maxObservations: 1 },
    scenario: async function* () { yield { id: 'q-read', kind: 'read', run: async () => ({ sourceId: 'q', derived: { quantity: '12' }, snapshot }) }; } });
  assert.equal((await checkRun({ run, oracle })).status, 'incomplete');
  const corrupt = structuredClone(run);
  corrupt.observations[0].value.derived.quantity = '11';
  const checked = await checkRun({ run: corrupt, oracle });
  assert.equal(checked.status, 'failed');
  assert.ok(checked.obligations.some(row => row.name === 'source:q-read' && row.status === 'failed'));
});

test('source snapshot checker rejects duplicate/missing/extra source rows and corrupt inputs, derived values or roots', () => {
  const facts = {
    pool: { contract: 101, fields: { unit: 7 } },
    delivery: { contract: 205, fields: { pool: 'pool', at: '0', quantity: '10' } },
    reservation: { contract: 410, fields: { pool: 'pool', starts: '10', ends: '20', requested: '8', active: true } },
  };
  const expected = evaluateSources('equipment', facts);
  const snapshot = {
    records: [...Object.entries(facts).map(([id, row]) => ({ id, record: { contract: row.contract, input: row.fields,
      derived: expected.derived[id] ?? null } })),
      { id: 'private-start', record: { contract: 900, input: { producer: 'reservation', role: 11, pool: 'pool', at: '10', quantity: '-8' }, derived: null } },
      { id: 'private-end', record: { contract: 900, input: { producer: 'reservation', role: 29, pool: 'pool', at: '20', quantity: '8' }, derived: null } }],
    roots: [{ root: { id: 'pool', slot: 7 }, revision: 'opaque-revision',
      summary: { kind: 'financial', value: { count: 3, first: '0', last: '20', sum: '10', min_prefix: '0', max_prefix: '10', boundary_min: '2', boundary_max: '10' } } }],
    queries: [{ query: { id: 'reservation', slot: 31 }, descriptor: { source: { id: 'pool', slot: 7 },
      operation: 'sum', phase: 'calculate', channel: 'amount', range: { lower: null, upper: { excluded: '10' } }, result: '10', selected: null } }],
    roles: [{ source_role: { id: 'reservation', slot: 11 }, binding: { output: 'private-start', retired: false } },
      { source_role: { id: 'reservation', slot: 29 }, binding: { output: 'private-end', retired: false } }],
  };
  const completeSource = checkSourceSnapshot({ model: 'equipment', facts, snapshot });
  assert.equal(completeSource.status, 'incomplete');
  assert.ok(completeSource.obligations.filter(row => ['source-inventory', 'source-contract-and-inputs', 'source-derived-values',
    'private-output-records', 'root-inventory', 'root-summaries', 'query-inventory', 'role-inventory'].includes(row.name)).every(row => row.status === 'passed'));
  assert.deepEqual(completeSource.obligations.filter(row => row.status === 'incomplete').map(row => row.name), [
    'tree-node-inventory', 'tree-child-links', 'tree-heights', 'tree-leaf-order', 'tree-node-aggregates',
  ]);
  const cases = [
    ['source-inventory', value => value.records.push(structuredClone(value.records[0]))],
    ['source-inventory', value => value.records.pop()],
    ['source-inventory', value => value.records.push({ id: 'extra', record: {} })],
    ['source-contract-and-inputs', value => { value.records[0].record.contract = 205; }],
    ['source-contract-and-inputs', value => { value.records[0].record.input.unit = 9; }],
    ['source-derived-values', value => { value.records[2].record.derived.allocated = '1'; }],
    ['root-summaries', value => { value.roots[0].summary.value.sum = '11'; }],
    ['root-summaries', value => { value.roots[0].summary = { decoy: { kind: 'financial', value: { count: 3, sum: '10' } } }; }],
    ['root-inventory', value => { value.roots[0].root.slot = 8; }],
    ['query-descriptor-contents', value => { value.queries[0].descriptor.operation = 'latest'; }],
    ['role-binding-contents', value => { value.roles[0].binding.retired = true; }],
    ['private-output-records', value => { value.records[3].record.input.at = 10; value.records[3].record.input.quantity = -8; }],
    ['private-output-records', value => { value.records[3].record.input.forged = true; }],
    ['private-output-records', value => { value.records[3].record.derived = { available_before: '999', allocated: '999' }; }],
    ['private-output-records', value => {
      value.records[4].record.input = { producer: 'reservation', role: 11, pool: 'pool', at: '10', quantity: '-8' };
      value.roles[1].binding = { output: 'private-start', retired: false };
    }],
    ['private-output-records', value => {
      value.records[4].record.input = { producer: 'reservation', role: 11, pool: 'pool', at: '10', quantity: '-8' };
      value.roles[1].binding = { output: 'private-start', retired: false };
    }],
  ];
  for (const [name, corrupt] of cases) {
    const value = structuredClone(snapshot);
    corrupt(value);
    const checked = checkSourceSnapshot({ model: 'equipment', facts, snapshot: value });
    assert.equal(checked.status, 'failed', name);
    assert.ok(checked.obligations.some(row => row.name === name && row.status === 'failed'), name);
  }
});

test('walk preserves original request details and logical replay creates fresh operation IDs', async () => {
  const oldOperation = randomUUID();
  const original = await runWorkload({ state: { record: randomUUID() }, profile: { ...profile, maxActions: 2, maxObservations: 1 },
    scenario: async function* ({ state }) { yield { id: 'write', kind: 'mutation', mutation: true,
      request: { request: { operation_id: oldOperation, context: 'old-context', record: state.record } },
      run: async () => ({ sourceId: state.record }) }; } });
  assert.equal(walk(original)[0].request.request.operation_id, oldOperation);
  const replay = await logicalReplay({ trace: original.observations, createTarget: async () => ({ state: { record: randomUUID() } }),
    profile: { ...profile, maxActions: 2, maxObservations: 1 }, oracle: () => true,
    rebuild: async function* ({ state }) { yield { id: 'fresh-write', kind: 'mutation', mutation: true,
      request: { request: { operation_id: randomUUID(), context: 'fresh-context', record: state.record } },
      run: async () => ({ sourceId: state.record }) }; } });
  assert.equal(replay.status, 'passed');
  assert.notEqual(replay.run.observations[0].request.request.operation_id, oldOperation);
  assert.notEqual(replay.run.observations[0].request.request.record, original.observations[0].request.request.record);
});

test('original-intent example resends exact known plans and status-reconciles uncertain outcomes only', async () => {
  const known = { request: { operation_id: 'original-known', context: 'ctx-known', commands: [] } };
  const unknown = { request: { operation_id: 'original-unknown', context: 'ctx-unknown', commands: [] } };
  const lostReply = { request: { operation_id: 'original-lost-reply', context: 'ctx-original', commands: [] } };
  const sends = [], reconciles = [];
  const client = {
    async execute(plan) {
      sends.push(plan);
      if (plan === lostReply) throw Object.assign(new Error('reply lost'), { code: 'outcome_unknown' });
      return { status: 'committed' };
    },
    async status(plan) { reconciles.push(plan); return { status: 'not_observed' }; },
  };
  const report = await replayOriginalIntents(client, [
    { id: 'known', plan: known }, { id: 'unknown', plan: unknown, outcomeUnknown: true }, { id: 'lost-reply', plan: lostReply },
  ]);
  assert.equal(report.status, 'incomplete');
  assert.equal(sends.length, 2);
  assert.equal(sends[0], known);
  assert.equal(sends[1], lostReply);
  assert.deepEqual(reconciles, [unknown, lostReply]);
  assert.equal(report.results[1].outcome.status, 'not_observed');
  assert.equal(report.results[1].status, 'incomplete');
  assert.equal(report.results[1].plan.request.operation_id, 'original-unknown');
});

test('seeded explore runs a bounded scenario and reports raw corruption through its oracle', async () => {
  const report = await explore({ seed: 17, createTarget: async () => ({ state: {} }), profile: { ...profile, maxActions: 3, maxObservations: 2 },
    scenario: async function* ({ random }) { for (let i = 0; i < 2; i += 1) yield {
      id: `seed-${Math.floor(random() * 1e6)}-${i}`, kind: 'read', run: async () => ({ value: i }) }; },
    oracle: ({ observations }) => observations.every(row => row.value.value >= 0) });
  assert.equal(report.status, 'passed');
  assert.equal(report.kind, 'explore');
  assert.equal(report.run.completed, 2);
});

test('failure shrink retains the original trace and obeys attempt bound', async () => {
  const trace = [{ id: 'a' }, { id: 'b' }, { id: 'c' }, { id: 'd' }];
  let replays = 0;
  const result = await shrinkFailure({ trace, targetKind: 'bad-source', maxAttempts: undefined,
    limits: { maxAttempts: 3, timeMs: 1_000 }, createTarget: async () => ({ state: {} }), profile,
    oracle: () => [{ name: 'bad-source', status: 'failed' }],
    replay: async function* ({ trace: candidate }) { replays += 1; yield { id: 'evidence', kind: 'failure', run: async () => ({ length: candidate.length }) }; },
  });
  assert.equal(result.status, 'minimized');
  assert.equal(result.sameFailureReproduced, true);
  assert.ok(result.attempts <= 3);
  assert.equal(replays, result.attempts);
  assert.equal(result.originalTrace.length, 4);
  assert.deepEqual(result.originalTrace, trace);
  assert.ok(result.minimizedTrace.length < trace.length);
});
