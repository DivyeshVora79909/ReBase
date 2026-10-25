import assert from 'node:assert/strict';
import test from 'node:test';
import { accept, preparePopulation, propose, reject } from '../population.mjs';

const modelId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const parentId = '11111111-1111-4111-8111-111111111111';
const target = {
  url: 'http://127.0.0.1:8080/rpc', model: modelId,
  store: '22222222-2222-4222-8222-222222222222',
  tenant: '33333333-3333-4333-8333-333333333333',
  actor: '44444444-4444-4444-8444-444444444444', credential_epoch: 0,
};
const uuidSchema = { type: 'string', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' };
const decimalSchema = { type: 'string', pattern: '^(0|-?[1-9][0-9]*)$' };
const catalog = {
  model: modelId,
  contracts: [
    { name: 'Parent', code: 101, visibility: 'public', schema: { type: 'object', required: ['value'], properties: { value: decimalSchema }, additionalProperties: false }, references: [] },
    { name: 'Child', code: 201, visibility: 'public', schema: { type: 'object', required: ['parent', 'value'], properties: { parent: uuidSchema, value: decimalSchema }, additionalProperties: false }, references: [{ field: 'parent', targets: [101], optional: false }] },
  ],
  capabilities: { limits: { public_records: 16, commands: 64, per_contract: {} } },
};
const model = {
  catalog,
  validate(name, value) {
    const valid = name === 'Parent'
      ? Object.keys(value ?? {}).join() === 'value' && typeof value.value === 'string' && /^(0|-?[1-9][0-9]*)$/.test(value.value)
      : Object.keys(value ?? {}).sort().join() === 'parent,value' && typeof value.parent === 'string'
        && /^[0-9a-f-]{36}$/.test(value.parent) && typeof value.value === 'string' && /^(0|-?[1-9][0-9]*)$/.test(value.value);
    return { valid, errors: valid ? [] : [{ keyword: 'shape', message: 'invalid test shape' }] };
  },
};

function makePlan(proposal, operationId) {
  return {
    format: 'rebase-operation-plan-1', target,
    request: { model: modelId, context: 'original-context', operation_id: operationId, commands: proposal.commands, returning: proposal.returning },
  };
}

test('population reports blocked prerequisites and rejects custom choices outside typed compatible pools', async () => {
  const blocked = preparePopulation(model, { Child: 1 }, { seed: 1, strategies: { Child: () => ({ value: '7' }) } });
  await assert.rejects(propose(blocked, {}), error => error.code === 'stalled');
  assert.equal(blocked.cursor, 0);
  assert.equal(blocked.pending, null);

  const state = preparePopulation(model, { Child: 1 }, {
    seed: 2,
    existing: { Parent: [{ id: parentId, contract: 'Parent', fields: { value: '5' } }] },
    strategies: { Child: () => ({ value: '7' }) },
    selectReference: () => ['Child', parentId],
  });
  await assert.rejects(propose(state, {}), error => error.code === 'invalid_selection');
  assert.equal(state.cursor, 0);
  assert.equal(state.pending, null);
});

test('population callbacks see selected typed IDs, exact strings survive, and progress needs exact receipt', async () => {
  const phases = [];
  const state = preparePopulation(model, { Child: 2 }, {
    seed: 'semantic', batchSize: 1,
    existing: { Parent: [{ id: parentId, contract: 'Parent', fields: { value: '5' } }] },
    strategies: { Child: () => ({ value: '0' }) },
    selectReference(child, field, pools) {
      phases.push(`selected:${child}:${field}`);
      assert.deepEqual(Object.keys(pools), ['Parent']);
      return ['Parent', parentId];
    },
    rules: { Child(fields, context, refs) {
      phases.push(`ruled:${refs.parent}`);
      return { ...fields, value: context.exactValue };
    } },
  });
  let contextCalls = 0;
  const proposal = await propose(state, async (child, refs, cursor) => {
    contextCalls += 1;
    phases.push(`context:${child}:${refs.parent}:${cursor}`);
    return { exactValue: '9007199254740993' };
  });
  assert.deepEqual(phases, [
    'selected:Child:parent',
    `context:Child:${parentId}:0`,
    `ruled:${parentId}`,
  ]);
  assert.equal(contextCalls, 1);
  assert.equal(proposal.commands[0].fields.value, '9007199254740993');

  const operationId = '55555555-5555-4555-8555-555555555555';
  const plan = makePlan(proposal, operationId);
  assert.throws(() => {
    state.pending.plan = { format: 'rebase-operation-plan-1', target: { model: modelId }, request: { model: modelId } };
  }, error => error.code === 'plan_invalid');
  state.pending.plan = plan;
  assert.equal(Object.isFrozen(state.pending), true);
  assert.equal(Object.hasOwn(state.pending, 'planSnapshot'), false);
  const detached = state.pending.plan;
  detached.request.context = 'modified';
  assert.equal(state.pending.plan.request.context, 'original-context');
  assert.throws(() => { state.pending.plan = makePlan(proposal, '66666666-6666-4666-8666-666666666666'); }, error => error.code === 'plan_rebound');
  assert.throws(() => accept(state, proposal, plan, { status: 'committed', result: { operation_id: '66666666-6666-4666-8666-666666666666', revision: '77777777-7777-4777-8777-777777777777', records: [{ id: proposal.returning[0] }] } }), error => error.code === 'receipt_invalid');
  assert.equal(state.accepted.Child, 0);
  const committed = { status: 'committed', result: { operation_id: operationId, revision: '77777777-7777-4777-8777-777777777777', records: [{ id: proposal.returning[0] }] } };
  accept(state, proposal, plan, committed);
  assert.equal(state.accepted.Child, 1);
  assert.equal(state.referenceUsage[`Child\0parent\0Parent\0${parentId}`], 1);
  assert.throws(() => accept(state, proposal, plan, committed), error => error.code === 'pending_mismatch');

  const next = await propose(state, { exactValue: '8' });
  const nextPlan = makePlan(next, '88888888-8888-4888-8888-888888888888');
  state.pending.plan = nextPlan;
  assert.throws(() => reject(state, next, nextPlan, Object.assign(new Error('uncertain'), { name: 'RpcError', code: 'outcome_unknown', httpStatus: 200 })), error => error.code === 'outcome_uncertain');
  assert.equal(state.pending.proposal, next);
  assert.equal(state.accepted.Child, 1);
  reject(state, next, nextPlan, Object.assign(new Error('definite no-commit'), { name: 'RpcError', code: 'invalid_input', httpStatus: 200 }));
  assert.equal(state.pending, null);
  assert.equal(state.accepted.Child, 1);
  assert.equal(state.cursor, 2);
});

test('population rejects overlapping proposals while an async context read is in flight', async () => {
  const state = preparePopulation(model, { Child: 1 }, {
    seed: 'overlap',
    existing: { Parent: [{ id: parentId, contract: 'Parent', fields: { value: '5' } }] },
    strategies: { Child: () => ({ value: '7' }) },
    selectReference: () => ['Parent', parentId],
  });
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const first = propose(state, async () => { await blocked; return { exactValue: '7' }; });
  await assert.rejects(propose(state, { exactValue: '8' }), error => error.code === 'proposal_pending');
  release();
  const proposal = await first;
  assert.equal(state.pending.proposal, proposal);
});

test('population overlays nested arrays, optional references, polymorphic unions, and self references', async () => {
  const altId = '99999999-9999-4999-8999-999999999999';
  const childAnchor = '88888888-8888-4888-8888-888888888888';
  const multiCatalog = {
    model: modelId,
    contracts: [
      catalog.contracts[0],
      { name: 'Alt', code: 102, visibility: 'public', schema: catalog.contracts[0].schema, references: [] },
      {
        name: 'Child', code: 201, visibility: 'public',
        schema: { type: 'object', required: ['primary', 'self', 'links'], properties: {
          primary: uuidSchema, self: uuidSchema,
          links: { type: 'array', items: { type: 'object', required: ['parent'], properties: { parent: uuidSchema } } },
          optionalParent: uuidSchema,
        } },
        references: [
          { field: 'primary', targets: [101, 102], optional: false },
          { field: 'self', targets: [201], optional: false },
          { field: 'links[*].parent', targets: [101, 102], optional: false },
          { field: 'optionalParent', targets: [101], optional: true },
        ],
      },
    ],
    capabilities: catalog.capabilities,
  };
  const polyModel = { catalog: multiCatalog, validate: (_name, value) => ({ valid: value !== null && typeof value === 'object' && !Array.isArray(value), errors: [] }) };
  const state = preparePopulation(polyModel, { Child: 1 }, {
    seed: 'polymorphic',
    existing: {
      Parent: [{ id: parentId, contract: 'Parent', fields: { value: '5' } }],
      Alt: [{ id: altId, contract: 'Alt', fields: { value: '6' } }],
      Child: [{ id: childAnchor, contract: 'Child', fields: { primary: altId, self: childAnchor, links: [{ parent: parentId }, { parent: altId }] } }],
    },
    strategies: { Child: () => ({ links: [{ parent: '' }, { parent: '' }] }) },
    selectReference(_child, path, pools) {
      if (path === 'primary') { assert.deepEqual(Object.keys(pools).sort(), ['Alt', 'Parent']); return ['Alt', altId]; }
      if (path === 'self') { assert.deepEqual(Object.keys(pools), ['Child']); return ['Child', childAnchor]; }
      if (path === 'links[*].parent') { assert.deepEqual(Object.keys(pools).sort(), ['Alt', 'Parent']); return ['Parent', parentId]; }
      assert.fail(`optional missing path should not be selected: ${path}`);
    },
  });
  const proposal = await propose(state, {});
  const fields = proposal.commands[0].fields;
  assert.equal(fields.primary, altId);
  assert.equal(fields.self, childAnchor);
  assert.deepEqual(fields.links, [{ parent: parentId }, { parent: parentId }]);
  assert.equal(Object.hasOwn(fields, 'optionalParent'), false);
  assert.equal(proposal.usage[`Child\0links[*].parent\0Parent\0${parentId}`], 2);
});

test('prepared faker streams are deterministic and isolated across interleaved population states', async () => {
  const fakerCatalog = {
    model: modelId,
    contracts: [{ name: 'Parent', code: 101, visibility: 'public', references: [], schema: {
      type: 'object', required: ['value'], additionalProperties: false,
      properties: { value: { type: 'string', enum: ['red', 'blue', 'green'] } },
    } }],
    capabilities: catalog.capabilities,
  };
  const fakerModel = { catalog: fakerCatalog, validate: (_name, value) => ({ valid: ['red', 'blue', 'green'].includes(value?.value), errors: [] }) };
  const first = preparePopulation(fakerModel, { Parent: 2 }, { seed: 'isolated-faker', batchSize: 1 });
  const parallel = preparePopulation(fakerModel, { Parent: 1 }, { seed: 'other-faker', batchSize: 1 });
  const replay = preparePopulation(fakerModel, { Parent: 2 }, { seed: 'isolated-faker', batchSize: 1 });
  const firstRow = await propose(first, {});
  const parallelRow = await propose(parallel, {});
  const replayFirst = await propose(replay, {});
  assert.deepEqual(firstRow.commands[0].fields, replayFirst.commands[0].fields);
  reject(first, firstRow);
  reject(replay, replayFirst);
  reject(parallel, parallelRow);
  const firstNext = await propose(first, {});
  const replayNext = await propose(replay, {});
  assert.deepEqual(firstNext.commands[0].fields, replayNext.commands[0].fields);
});
