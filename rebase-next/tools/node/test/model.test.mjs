import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { connect } from '../client.mjs';
import { prepareModel } from '../model.mjs';

const schema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object', additionalProperties: false,
  required: ['amount', 'parent'],
  properties: {
    amount: { type: 'string', pattern: '^(0|-?[1-9][0-9]*)$', 'x-rebase-range': ['-9007199254740993', '9007199254740993'] },
    parent: { type: 'string', pattern: '^[0-9a-f-]{36}$', 'x-rebase-binding': 'uuid' },
  },
};
const catalog = {
  model: 'a'.repeat(64), schema_dialect: 'https://json-schema.org/draft/2020-12/schema',
  contracts: [{ code: 7, name: 'Child', visibility: 'public', schema,
    references: [{ slot: 1, field: 'parent', targets: [3], optional: false }] }],
};
const fields = { amount: '9007199254740993', parent: '11111111-1111-4111-8111-111111111111' };

test('prepareModel detaches catalog and compiles native Ajv schema metadata once', () => {
  const input = structuredClone(catalog);
  const model = prepareModel(input, { selector: 'quantity' });
  input.contracts[0].schema.properties.amount.type = 'number';

  assert.equal(model.identity, catalog.model);
  assert.equal(model.contract('Child').code, 7);
  assert.deepEqual(model.contract(7).references, catalog.contracts[0].references);
  assert.deepEqual(model.validate('Child', fields), { valid: true, errors: [] });
  assert.equal(model.validate(7, { ...fields, amount: '090' }).valid, false);
  assert.equal(model.validate(7, { ...fields, amount: '9007199254740994' }).valid, false);
  assert.throws(() => model.validate(7, { ...fields, amount: 9007199254740992 }), /unsafe number/);
  assert.equal(Object.isFrozen(model.catalog.contracts[0].schema), true);
});

test('prepareModel refuses malformed identities, duplicate contracts, wrong dialect, and external refs', () => {
  assert.throws(() => prepareModel({ ...catalog, model: 'bad' }, { selector: 'quantity' }), /identity/);
  assert.throws(() => prepareModel({ ...catalog, contracts: [catalog.contracts[0], catalog.contracts[0]] }, { selector: 'quantity' }), /unique/);
  assert.throws(() => prepareModel({ ...catalog, schema_dialect: 'draft-07' }, { selector: 'quantity' }), /dialect/);
  const external = structuredClone(catalog);
  external.contracts[0].schema.properties.amount = { $ref: 'https://example.invalid/value.json' };
  assert.throws(() => prepareModel(external, { selector: 'quantity' }), /schema reference/);
  assert.throws(() => prepareModel(catalog, {
    selector: 'quantity',
    native: { selection: { selector: 'equipment', model: 'b'.repeat(64) } },
  }), /does not match/);
});

test('native explain, validation, rendering and fixture values are returned without rewriting', async () => {
  const calls = [];
  const results = {
    explain: { model: catalog.model, declarations: 'src/model.rs', contract: { name: 'Child' } },
    validate: { status: 'valid', model: catalog.model, input: fields },
    render: { model: catalog.model, html: '<!doctype html><p>native</p>' },
    fixtureCatalog: { fixtures: ['native-authored'] },
    fixturePlan: { commands: [{ id: '11111111-1111-4111-8111-111111111111' }] },
  };
  const native = Object.fromEntries(Object.keys(results).map(method => [method, async params => {
    calls.push([method, params]);
    return results[method];
  }]));
  native.selection = { selector: 'quantity', model: catalog.model };
  const model = prepareModel(catalog, { native, selector: 'quantity' });

  assert.equal(await model.explain(7), results.explain);
  assert.equal(await model.validateNative('Child', fields), results.validate);
  assert.equal(await model.render({ scope: 'model' }), results.render);
  assert.equal(await model.fixtureCatalog(), results.fixtureCatalog);
  assert.equal(await model.fixturePlan({ name: 'demo', namespace: '22222222-2222-4222-8222-222222222222' }), results.fixturePlan);
  assert.deepEqual(calls.map(([method, params]) => [method, params]), [
    ['explain', { selector: 'Child' }],
    ['validate', { code: 7, input: fields }],
    ['render', { scope: 'model' }],
    ['fixtureCatalog', undefined],
    ['fixturePlan', { name: 'demo', namespace: '22222222-2222-4222-8222-222222222222' }],
  ]);
});

test('draftFixture produces the client records.mutate draft from caller supplied public values', async () => {
  const model = prepareModel(catalog, { selector: 'quantity' });
  const recordId = '33333333-3333-4333-8333-333333333333';
  const draft = model.draftFixture([{ contract: 'Child', id: recordId, fields }], { returning: [recordId] });
  assert.deepEqual(draft, {
    model: catalog.model,
    commands: [{ op: 'create', id: recordId, contract: 7, fields }],
    returning: [recordId],
  });
  assert.throws(() => model.draftFixture([{ contract: 'Child', id: recordId, fields: { ...fields, amount: 12 } }]), /schema/);
  assert.throws(() => model.draftFixture([{ contract: 'Child', id: recordId, fields }], { returning: ['44444444-4444-4444-8444-444444444444'] }), /supplied fixture records/);
  assert.throws(() => model.fixturePlan({ name: 'demo', namespace: 'not-a-uuid' }), /canonical UUID/);

  let requestBody;
  const identity = { model: catalog.model, operation_context: 'ctx-original', store: '11111111-1111-4111-8111-111111111111',
    tenant: '22222222-2222-4222-8222-222222222222', actor: '33333333-3333-4333-8333-333333333333', credential_epoch: 4 };
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    requestBody = JSON.parse(body);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: requestBody.id, result: identity }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    const client = connect({ endpoint: `http://127.0.0.1:${address.port}/rpc`, credential: 'fixture-token' });
    const plan = await client.prepare(draft);
    assert.deepEqual(plan.request.commands, draft.commands);
    assert.equal(plan.request.model, catalog.model);
    assert.deepEqual(plan.request.returning, [recordId]);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

test('native exact integer formats enforce canonical strings and bounds before fixture drafts or native calls', () => {
  const formatted = structuredClone(catalog);
  formatted.contracts[0].schema = {
    $schema: schema.$schema, type: 'object', additionalProperties: false,
    required: ['time', 'amount', 'code', 'unit'],
    properties: {
      time: { type: 'string', format: 'i64' },
      amount: { type: 'string', format: 'i128' },
      code: { type: 'string', format: 'u16' },
      unit: { type: 'integer', minimum: 1, maximum: 65535 },
    },
  };
  let nativeCalls = 0;
  const model = prepareModel(formatted, {
    selector: 'quantity',
    native: { selection: { model: catalog.model, selector: 'quantity' }, validate() { nativeCalls += 1; } },
  });
  const valid = { time: '0', amount: '0', code: '1', unit: 1 };
  const id = '33333333-3333-4333-8333-333333333333';
  for (const [field, bounds] of [
    ['time', ['-9223372036854775808', '9223372036854775807']],
    ['amount', ['-170141183460469231731687303715884105728', '170141183460469231731687303715884105727']],
    ['code', ['1', '65535']],
  ]) {
    for (const value of bounds) {
      assert.equal(model.validate('Child', { ...valid, [field]: value }).valid, true);
      assert.equal(model.draftFixture([{ contract: 'Child', id, fields: { ...valid, [field]: value } }]).commands.length, 1);
    }
    for (const value of ['', '-0', '+1', '01', '-01', '1.0', '1e0', ' 1', '1 ', 1, null]) {
      const fields = { ...valid, [field]: value };
      assert.equal(model.validate('Child', fields).valid, false, `${field}: ${String(value)}`);
      assert.throws(() => model.draftFixture([{ contract: 'Child', id, fields }]), /schema/);
      assert.throws(() => model.validateNative('Child', fields), /schema/);
    }
  }
  for (const [field, values] of [
    ['time', ['-9223372036854775809', '9223372036854775808']],
    ['amount', ['-170141183460469231731687303715884105729', '170141183460469231731687303715884105728']],
    ['code', ['0', '-1', '65536']],
    ['unit', ['1', 0, 65536]],
  ]) {
    for (const value of values) {
      const fields = { ...valid, [field]: value };
      assert.equal(model.validate('Child', fields).valid, false, `${field}: ${String(value)}`);
      assert.throws(() => model.draftFixture([{ contract: 'Child', id, fields }]), /schema/);
      assert.throws(() => model.validateNative('Child', fields), /schema/);
    }
  }
  assert.equal(nativeCalls, 0);
  formatted.contracts[0].schema.properties.time.format = 'unsupported-native-format';
  assert.throws(() => prepareModel(formatted, { selector: 'quantity' }), /unknown format/);
});
