import assert from 'node:assert/strict';
import test from 'node:test';
import { accept, preparePopulation, propose } from '../population.mjs';

const modelId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const baseId = '11111111-1111-4111-8111-111111111111';
const target = {
  url: 'http://127.0.0.1:8080/rpc', model: modelId,
  store: '22222222-2222-4222-8222-222222222222', tenant: '33333333-3333-4333-8333-333333333333',
  actor: '44444444-4444-4444-8444-444444444444', credential_epoch: 0,
};
const uuid = { type: 'string', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' };
const decimal = { type: 'string', pattern: '^(0|-?[1-9][0-9]*)$' };
const catalog = {
  model: modelId,
  contracts: [
    { name: 'Base', code: 101, visibility: 'public', schema: { type: 'object', required: ['value'], properties: { value: decimal }, additionalProperties: false }, references: [] },
    { name: 'Alternate', code: 102, visibility: 'public', schema: { type: 'object', required: ['value'], properties: { value: decimal }, additionalProperties: false }, references: [] },
    { name: 'Derived', code: 201, visibility: 'public', schema: {
      type: 'object', required: ['base', 'self', 'links'], additionalProperties: false,
      properties: {
        base: uuid, self: uuid,
        links: { type: 'array', minItems: 2, items: { type: 'object', required: ['parent'], properties: { parent: uuid }, additionalProperties: false } },
        maybe: uuid,
        value: decimal,
      },
    }, references: [
      { field: 'base', targets: [101, 102], optional: false },
      { field: 'self', targets: [201], optional: false },
      { field: 'links[*].parent', targets: [101, 102], optional: false },
      { field: 'maybe', targets: [101], optional: true },
    ] },
  ],
  capabilities: { limits: { public_records: 12, commands: 64, per_contract: { '101': 5 } } },
};
const model = {
  catalog,
  validate(name, row) {
    const valid = name === 'Derived'
      ? typeof row?.base === 'string' && typeof row?.self === 'string' && Array.isArray(row?.links)
        && row.links.length === 2 && row.links.every(link => typeof link.parent === 'string')
        && typeof row?.value === 'string' && /^(0|-?[1-9][0-9]*)$/.test(row.value)
        && (!Object.hasOwn(row, 'maybe') || typeof row.maybe === 'string')
      : typeof row?.value === 'string' && /^(0|-?[1-9][0-9]*)$/.test(row.value);
    return { valid, errors: valid ? [] : [{ keyword: 'shape' }] };
  },
};

function planFor(proposal, operation = '55555555-5555-4555-8555-555555555555') {
  return {
    format: 'rebase-operation-plan-1', target,
    request: { model: modelId, context: 'original-context', operation_id: operation, commands: proposal.commands, returning: proposal.returning },
  };
}

test('typed reference overlays cover nested arrays, optional edges, self targets and polymorphic unions', async () => {
  const alternateId = '99999999-9999-4999-8999-999999999999';
  const selfId = '88888888-8888-4888-8888-888888888888';
  const state = preparePopulation(model, { Derived: 1 }, {
    seed: 'typed-refs',
    existing: {
      Base: [{ id: baseId, contract: 'Base', fields: { value: '7' } }],
      Alternate: [{ id: alternateId, contract: 'Alternate', fields: { value: '8' } }],
      Derived: [{ id: selfId, contract: 'Derived', fields: { base: alternateId, self: selfId, links: [{ parent: baseId }, { parent: alternateId }], value: '9' } }],
    },
    strategies: { Derived: () => ({ links: [{ parent: '' }, { parent: '' }], value: '10' }) },
    selectReference(_child, path, pools) {
      if (path === 'base') { assert.deepEqual(Object.keys(pools).sort(), ['Alternate', 'Base']); return ['Alternate', alternateId]; }
      if (path === 'self') return ['Derived', selfId];
      if (path === 'links[*].parent') return ['Base', baseId];
      assert.fail(`optional reference should remain absent: ${path}`);
    },
  });
  const proposal = await propose(state, {});
  const fields = proposal.commands[0].fields;
  assert.equal(fields.base, alternateId);
  assert.equal(fields.self, selfId);
  assert.deepEqual(fields.links, [{ parent: baseId }, { parent: baseId }]);
  assert.equal(Object.hasOwn(fields, 'maybe'), false);
  assert.equal(proposal.usage[`Derived\0links[*].parent\0Base\0${baseId}`], 2);
});

test('binding validates complete plans and rejects mutation and reordered receipt IDs without progress', async () => {
  const state = preparePopulation(model, { Base: 2 }, {
    seed: 100, batchSize: 2, strategies: { Base: () => ({ value: '123' }) },
  });
  const proposal = await propose(state, {});
  assert.equal(proposal.returning.length, 2);
  assert.throws(() => { state.pending.plan = { format: 'rebase-operation-plan-1', target: { model: modelId }, request: { model: modelId } }; }, error => error.code === 'plan_invalid');
  const plan = planFor(proposal);
  proposal.commands[0].fields.value = 'mutated';
  assert.throws(() => { state.pending.plan = plan; }, error => error.code === 'proposal_changed');
  assert.equal(state.accepted.Base, 0);

  const clean = preparePopulation(model, { Base: 2 }, {
    seed: 101, batchSize: 2, strategies: { Base: () => ({ value: '123' }) },
  });
  const rows = await propose(clean, {});
  const boundPlan = planFor(rows, '66666666-6666-4666-8666-666666666666');
  clean.pending.plan = boundPlan;
  const reversed = [...rows.returning].reverse();
  assert.throws(() => accept(clean, rows, boundPlan, {
    status: 'committed', result: {
      operation_id: boundPlan.request.operation_id,
      revision: '77777777-7777-4777-8777-777777777777',
      records: reversed.map(id => ({ id })),
    },
  }), error => error.code === 'receipt_invalid');
  assert.equal(clean.accepted.Base, 0);
  assert.equal(clean.cursor, 0);
  assert.equal(clean.pending.proposal, rows);
});

test('native catalog quotas, command bounds, and serialized proposal bytes fail before binding', async () => {
  assert.throws(() => preparePopulation(model, { Base: 13 }, { seed: 1 }), /public_records/);
  assert.throws(() => preparePopulation(model, { Base: 1 }, { seed: 1, batchSize: 65 }), /batchSize/);
  assert.throws(() => preparePopulation(model, { Base: 6 }, {
    seed: 1, existing: { Base: Array.from({ length: 5 }, (_, i) => ({ id: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`, contract: 'Base', fields: { value: '1' } })) },
  }), /per-contract/);

  const oversized = preparePopulation(model, { Base: 1 }, {
    seed: 1, strategies: { Base: () => ({ value: '1'.repeat(65_536) }) },
  });
  await assert.rejects(propose(oversized, {}), error => error.code === 'proposal_too_large');
  assert.equal(oversized.pending, null);
  assert.equal(oversized.cursor, 0);
});
