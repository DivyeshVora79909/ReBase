#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');

const root = path.resolve(__dirname, '../..');
const n = (x) => Number(String(x ?? 0).replace(/dec$/i, ''));
const rid = (x) => String(x ?? '');
const rows = (x) => Array.isArray(x) ? x : [];
const byId = (list, key) => rows(list).find((x) => rid(x.id) === key);
const timeKey = (x) => String(x);

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', (e) => e ? reject(e) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`H7 assembly SurrealDB exited with ${child.exitCode}`);
    const connected = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const done = (v) => { socket.destroy(); resolve(v); };
      socket.setTimeout(100, () => done(false));
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H7 assembly SurrealDB did not become ready');
}

async function state(db) {
  return queryResult(await db.query(`RETURN {
    recipes: (SELECT * FROM assembly_recipe_version ORDER BY id),
    batches: (SELECT * FROM assembly_batch ORDER BY id),
    inputs: (SELECT * FROM assembly_input ORDER BY id),
    outputs: (SELECT * FROM assembly_output ORDER BY id),
    stockIn: (SELECT * FROM stock_in ORDER BY id),
    stockOut: (SELECT * FROM stock_out ORDER BY id),
    stockReturns: (SELECT * FROM stock_return ORDER BY id),
    stockTransfers: (SELECT * FROM stock_transfer ORDER BY id),
    accounts: (SELECT * FROM stock_account ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label, pattern) {
  const before = await state(db);
  try {
    await assert.rejects(() => db.query(statement), pattern, label);
  } catch (error) {
    if (pattern) console.error(`${label}: rejection detail`, error.actual?.toString?.(), error.actual);
    throw error;
  }
  assert.deepEqual(await state(db), before, `${label}: source rows, managed children, and all stock/capacity roots roll back`);
}

function batchRoles(data, batch) {
  const recipe = byId(data.recipes, rid(batch.recipe_version));
  assert(recipe, `${batch.id}: selected immutable recipe exists`);
  return [
    { table: 'assembly_input', role: 'input_a', account: rid(recipe.input_a_account), quantity: n(batch.batch_count) * n(recipe.input_a_quantity) },
    { table: 'assembly_input', role: 'input_b', account: rid(recipe.input_b_account), quantity: n(batch.batch_count) * n(recipe.input_b_quantity) },
    { table: 'assembly_output', role: 'output_a', account: rid(recipe.output_a_account), quantity: n(batch.batch_count) * n(recipe.output_a_quantity) },
    { table: 'assembly_output', role: 'output_b', account: rid(recipe.output_b_account), quantity: n(batch.batch_count) * n(recipe.output_b_quantity) }
  ];
}

function stockOracle(data, accountId) {
  const events = new Map();
  const add = (at, delta) => {
    const key = timeKey(at);
    events.set(key, (events.get(key) ?? 0) + delta);
  };
  for (const row of rows(data.stockIn)) if (rid(row.to_account) === accountId) add(row.effective_at, n(row.quantity));
  for (const row of rows(data.stockOut)) if (rid(row.from_account) === accountId) add(row.effective_at, -n(row.quantity));
  for (const row of rows(data.stockReturns)) if (rid(row.destination_account) === accountId) add(row.effective_at, n(row.quantity));
  for (const row of rows(data.stockTransfers)) {
    if (rid(row.from_account) === accountId) add(row.effective_at, -n(row.quantity));
    if (rid(row.to_account) === accountId) add(row.effective_at, n(row.quantity));
  }
  for (const batch of rows(data.batches).filter((x) => x.state === 'complete')) {
    for (const role of batchRoles(data, batch)) if (role.account === accountId) {
      add(batch.effective_at, role.table === 'assembly_input' ? -role.quantity : role.quantity);
    }
  }
  let sum = 0;
  let instantMin = 0;
  for (const key of [...events.keys()].sort()) {
    sum += events.get(key);
    instantMin = Math.min(instantMin, sum);
  }
  return { sum, instantMin };
}

function grossOracle(data, accountId) {
  return rows(data.batches).filter((batch) => batch.state === 'complete').reduce((total, batch) => {
    return total + batchRoles(data, batch)
      .filter((role) => role.table === 'assembly_input' && role.account === accountId)
      .reduce((sum, role) => sum + role.quantity, 0);
  }, 0);
}

function capacityOracle(data, outputId) {
  const events = new Map();
  const add = (at, delta) => {
    const key = timeKey(at);
    events.set(key, (events.get(key) ?? 0) + delta);
  };
  for (const row of rows(data.stockOut).filter((x) => rid(x.assembly_output) === outputId)) add(row.effective_at, -n(row.quantity));
  let sum = 0;
  let instantMin = 0;
  for (const key of [...events.keys()].sort()) {
    sum += events.get(key);
    instantMin = Math.min(instantMin, sum);
  }
  return { sum, instantMin };
}

function assertOracle(data) {
  const completed = rows(data.batches).filter((x) => x.state === 'complete');
  const expectedByChild = new Map();
  for (const batch of completed) {
    for (const role of batchRoles(data, batch)) {
      expectedByChild.set(`${role.table}|${rid(batch.id)}|${role.role}`, { batch, role });
    }
  }
  assert.equal(rows(data.inputs).length, [...expectedByChild.keys()].filter((key) => key.startsWith('assembly_input|')).length,
    'only completed batches expose both input children');
  assert.equal(rows(data.outputs).length, [...expectedByChild.keys()].filter((key) => key.startsWith('assembly_output|')).length,
    'only completed batches expose both output children');
  for (const child of [...rows(data.inputs), ...rows(data.outputs)]) {
    const childTable = child.rebase_managed_role.startsWith('input_') ? 'assembly_input' : 'assembly_output';
    const expected = expectedByChild.get(`${childTable}|${child.rebase_managed_source}|${child.rebase_managed_role}`);
    assert(expected, `${child.id}: stable role child is expected from its recipe and batch`);
    assert.equal(child.rebase_managed_source, rid(expected.batch.id));
    assert.equal(child.rebase_managed_role, expected.role.role);
    assert.equal(rid(child.stock_account), expected.role.account);
    assert.equal(n(child.quantity), expected.role.quantity);
    assert.equal(timeKey(child.effective_at), timeKey(expected.batch.effective_at));
  }
  for (const account of rows(data.accounts)) {
    const expected = stockOracle(data, rid(account.id));
    assert.equal(n(account?.z_history?.summary?.measures?.quantity?.sum), expected.sum,
      `${account.id}: history sum matches direct stock sources and immutable recipe roles`);
    assert.equal(n(account?.z_history?.summary?.measures?.quantity?.instant_min), expected.instantMin,
      `${account.id}: complete-time stock floor matches independent source rows`);
    assert.equal(n(account?.z_gross_input?.summary?.measures?.gross_input?.sum), grossOracle(data, rid(account.id)),
      `${account.id}: gross input root matches completed recipe input roles`);
  }
  for (const output of rows(data.outputs)) {
    const expected = capacityOracle(data, rid(output.id));
    assert.equal(n(output?.z_capacity?.summary?.measures?.quantity?.sum), expected.sum,
      `${output.id}: output use root matches linked stock_out facts`);
    assert.equal(n(output?.z_capacity?.summary?.measures?.quantity?.instant_min), expected.instantMin,
      `${output.id}: complete-time output usage matches linked stock_out facts`);
    assert.ok(-expected.instantMin <= n(output.quantity), `${output.id}: consumers do not exceed source output`);
  }
  return data;
}

async function assertOracleAt(db) { return assertOracle(await state(db)); }

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h7_assembly_${Date.now().toString(36)}`;
  const child = spawn('surreal', ['start', 'memory', '--user', 'root', '--pass', 'root', '--bind', `127.0.0.1:${port}`, '--no-banner', '--log', 'error'],
    { cwd: root, stdio: ['ignore', 'ignore', 'ignore'] });
  const db = new Surreal();
  try {
    await waitForPort(port, child);
    await db.connect(`ws://127.0.0.1:${port}/rpc`);
    await db.signin({ username: 'root', password: 'root' });
    await db.query(`DEFINE NAMESPACE ${namespace};`);
    await db.use({ namespace });
    await db.query('DEFINE DATABASE probe;');
    await db.use({ namespace, database: 'probe' });
    await db.query(schema);
    await db.query(`
      CREATE ONLY organization:entity SET owned_by = rebase_group:root, name = 'Entity';
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY misc_account:opening SET owned_by = rebase_group:root, label = 'Opening stock';
      CREATE ONLY misc_account:customer SET owned_by = rebase_group:root, label = 'Customer';
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', dimension = 'count', name = 'Each';
      CREATE ONLY measure_unit:kg SET owned_by = rebase_group:root, code = 'kg', dimension = 'mass', name = 'Kilogram';
      CREATE ONLY item:shared SET owned_by = rebase_group:root, name = 'Shared', unit = measure_unit:each;
      CREATE ONLY item:input_a SET owned_by = rebase_group:root, name = 'Input A', unit = measure_unit:each;
      CREATE ONLY item:input_b SET owned_by = rebase_group:root, name = 'Input B', unit = measure_unit:each;
      CREATE ONLY item:output_a SET owned_by = rebase_group:root, name = 'Output A', unit = measure_unit:each;
      CREATE ONLY item:output_b SET owned_by = rebase_group:root, name = 'Output B', unit = measure_unit:each;
      CREATE ONLY item:bulk SET owned_by = rebase_group:root, name = 'Bulk', unit = measure_unit:kg;
      CREATE ONLY operating_unit:shared SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Shared', code = 'shared';
      CREATE ONLY operating_unit:zero SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Zero', code = 'zero';
      CREATE ONLY operating_unit:cap_a SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Capacity A', code = 'cap_a';
      CREATE ONLY operating_unit:cap_b SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Capacity B', code = 'cap_b';
      CREATE ONLY operating_unit:range SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Range', code = 'range';
      CREATE ONLY operating_unit:input_a SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Input A', code = 'input_a';
      CREATE ONLY operating_unit:input_b SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Input B', code = 'input_b';
      CREATE ONLY operating_unit:output_a SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Output A', code = 'output_a';
      CREATE ONLY operating_unit:output_b SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Output B', code = 'output_b';
      CREATE ONLY operating_unit:wrong_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity, name = 'Wrong entity', code = 'wrong_entity';
      CREATE ONLY operating_unit:wrong_unit SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Wrong unit', code = 'wrong_unit';
      CREATE ONLY stock_account:shared SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:shared, resource = item:shared;
      CREATE ONLY stock_account:zero SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:zero, resource = item:shared;
      CREATE ONLY stock_account:cap_a SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:cap_a, resource = item:shared;
      CREATE ONLY stock_account:cap_b SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:cap_b, resource = item:shared;
      CREATE ONLY stock_account:range SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:range, resource = item:shared;
      CREATE ONLY stock_account:input_a SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:input_a, resource = item:input_a, minimum_quantity = -100dec;
      CREATE ONLY stock_account:input_b SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:input_b, resource = item:input_b, minimum_quantity = -100dec;
      CREATE ONLY stock_account:output_a SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:output_a, resource = item:output_a, minimum_quantity = -100dec;
      CREATE ONLY stock_account:output_b SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:output_b, resource = item:output_b, minimum_quantity = -100dec;
      CREATE ONLY stock_account:wrong_unit SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:wrong_unit, resource = item:bulk;
      CREATE ONLY stock_account:wrong_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity, operating_unit = operating_unit:wrong_entity, resource = item:shared;
      CREATE ONLY stock_in:open_shared SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:shared, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_cap_a SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:cap_a, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_cap_b SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:cap_b, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_range SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:range, quantity = 6dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_input_a SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:input_a, quantity = 20dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_input_b SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:input_b, quantity = 20dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY assembly_recipe_version:shared SET owned_by = rebase_group:root, recipe_key = 'shared', version = '1', economic_entity = organization:entity,
        input_a_account = stock_account:shared, input_a_quantity = 3, input_b_account = stock_account:shared, input_b_quantity = 3,
        output_a_account = stock_account:shared, output_a_quantity = 1, output_b_account = stock_account:shared, output_b_quantity = 1;
      CREATE ONLY assembly_recipe_version:zero SET owned_by = rebase_group:root, recipe_key = 'zero', version = '1', economic_entity = organization:entity,
        input_a_account = stock_account:zero, input_a_quantity = 1, input_b_account = stock_account:zero, input_b_quantity = 1,
        output_a_account = stock_account:zero, output_a_quantity = 1, output_b_account = stock_account:zero, output_b_quantity = 1;
      CREATE ONLY assembly_recipe_version:cap_a SET owned_by = rebase_group:root, recipe_key = 'cap_a', version = '1', economic_entity = organization:entity,
        input_a_account = stock_account:cap_a, input_a_quantity = 3, input_b_account = stock_account:cap_a, input_b_quantity = 3,
        output_a_account = stock_account:cap_a, output_a_quantity = 1, output_b_account = stock_account:cap_a, output_b_quantity = 1;
      CREATE ONLY assembly_recipe_version:cap_b SET owned_by = rebase_group:root, recipe_key = 'cap_b', version = '1', economic_entity = organization:entity,
        input_a_account = stock_account:cap_b, input_a_quantity = 3, input_b_account = stock_account:cap_b, input_b_quantity = 3,
        output_a_account = stock_account:cap_b, output_a_quantity = 1, output_b_account = stock_account:cap_b, output_b_quantity = 1;
      CREATE ONLY assembly_recipe_version:range SET owned_by = rebase_group:root, recipe_key = 'range', version = '1', economic_entity = organization:entity,
        input_a_account = stock_account:range, input_a_quantity = 3, input_b_account = stock_account:range, input_b_quantity = 3,
        output_a_account = stock_account:output_a, output_a_quantity = 1, output_b_account = stock_account:output_b, output_b_quantity = 1;
      CREATE ONLY assembly_recipe_version:output_use SET owned_by = rebase_group:root, recipe_key = 'output_use', version = '1', economic_entity = organization:entity,
        input_a_account = stock_account:input_a, input_a_quantity = 1, input_b_account = stock_account:input_b, input_b_quantity = 1,
        output_a_account = stock_account:output_a, output_a_quantity = 1, output_b_account = stock_account:output_b, output_b_quantity = 1;
    `);

    await rejectsUnchanged(db, `CREATE ONLY assembly_recipe_version:missing SET owned_by = rebase_group:root,
      recipe_key = 'missing', version = '1', economic_entity = organization:entity,
      input_b_account = stock_account:shared, input_b_quantity = 1,
      output_a_account = stock_account:shared, output_a_quantity = 1,
      output_b_account = stock_account:shared, output_b_quantity = 1;`, 'recipe version with a missing typed role rejects');
    await rejectsUnchanged(db, `UPDATE assembly_recipe_version:shared SET input_a_quantity = 99;`,
      'immutable recipe version cannot be changed');
    await rejectsUnchanged(db, `CREATE ONLY assembly_recipe_version:bad_entity SET owned_by = rebase_group:root,
      recipe_key = 'bad_entity', version = '1', economic_entity = organization:entity,
      input_a_account = stock_account:wrong_entity, input_a_quantity = 1,
      input_b_account = stock_account:input_b, input_b_quantity = 1,
      output_a_account = stock_account:output_a, output_a_quantity = 1,
      output_b_account = stock_account:output_b, output_b_quantity = 1;`,
    'recipe entity mismatch is rejected');
    await rejectsUnchanged(db, `CREATE ONLY assembly_recipe_version:bad_unit SET owned_by = rebase_group:root,
      recipe_key = 'bad_unit', version = '1', economic_entity = organization:entity,
      input_a_account = stock_account:wrong_unit, input_a_quantity = 1,
      input_b_account = stock_account:input_b, input_b_quantity = 1,
      output_a_account = stock_account:output_a, output_a_quantity = 1,
      output_b_account = stock_account:output_b, output_b_quantity = 1;`,
    'non-count role unit rejects recipe version');

    // Drafts have no managed legs and no stock effect until all four roles are reconciled.
    await db.query(`CREATE ONLY assembly_batch:draft SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:shared, batch_count = 1, state = 'draft', effective_at = d'2026-07-02T00:00:00Z';`);
    let data = await assertOracleAt(db);
    assert.equal(data.inputs.length, 0);
    assert.equal(data.outputs.length, 0);
    assert.equal(n(byId(data.accounts, 'stock_account:shared').z_history.summary.measures.quantity.sum), 10,
      'draft has no stock effect');
    await db.query(`UPDATE assembly_batch:draft SET state = 'complete';`);
    data = await assertOracleAt(db);
    assert.equal(data.inputs.length, 2, 'completion creates both required input roles');
    assert.equal(data.outputs.length, 2, 'completion creates both required output roles');
    assert.equal(n(byId(data.accounts, 'stock_account:shared').z_history.summary.measures.quantity.sum), 6,
      'same-account two-input/two-output recipe posts net stock once across distinct child identities');
    assert.equal(n(byId(data.accounts, 'stock_account:shared').z_gross_input.summary.measures.gross_input.sum), 6,
      'same-account input roles aggregate gross demand on their separate root');
    await rejectsUnchanged(db, `CREATE ONLY assembly_batch:draft SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:shared, batch_count = 1, state = 'complete', effective_at = d'2026-07-02T00:00:00Z';`,
    'duplicate batch source retry rejects with unchanged managed children and roots');
    const completeBeforeRepeat = await state(db);
    await db.query(`UPDATE assembly_batch:draft SET state = 'complete';`);
    assert.deepEqual(await state(db), completeBeforeRepeat,
      'repeating completion preserves stable children and all root summaries');

    await rejectsUnchanged(db, `CREATE ONLY assembly_batch:zero_self_funding SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:zero, batch_count = 1, state = 'complete', effective_at = d'2026-07-02T00:00:00Z';`,
    'same-time assembly outputs cannot fund zero-prior gross inputs', /ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY/);
    let accountZero = byId(await state(db).then((s) => s.accounts), 'stock_account:zero');
    assert.equal(n(accountZero?.z_history?.summary?.measures?.quantity?.sum ?? 0), 0,
      'failed zero-prior batch leaves same-time net output/input at zero');

    // Shared same-time capacity is checked against all completed input roles,
    // not just the member or ID that sorts first.
    await db.query(`CREATE ONLY assembly_batch:a_first SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:cap_a, batch_count = 1, state = 'complete', effective_at = d'2026-07-02T00:00:00Z';`);
    await rejectsUnchanged(db, `CREATE ONLY assembly_batch:z_second SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:cap_a, batch_count = 1, state = 'complete', effective_at = d'2026-07-02T00:00:00Z';`,
    'aggregate same-time input 12 exceeds stock 10', /ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY/);
    data = await assertOracleAt(db);
    assert.equal(n(byId(data.accounts, 'stock_account:cap_a').z_history.summary.measures.quantity.sum), 6);
    assert.equal(n(byId(data.accounts, 'stock_account:cap_a').z_gross_input.summary.measures.gross_input.sum), 6);

    await db.query(`CREATE ONLY assembly_batch:z_first SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:cap_b, batch_count = 1, state = 'complete', effective_at = d'2026-07-02T00:00:00Z';`);
    await rejectsUnchanged(db, `CREATE ONLY assembly_batch:a_second SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:cap_b, batch_count = 1, state = 'complete', effective_at = d'2026-07-02T00:00:00Z';`,
    'reverse ID order aggregate same-time input 12 exceeds stock 10', /ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY/);
    await assertOracleAt(db);

    // Nanosecond-bounded same-time demand: future demand/replenishment are
    // already present when the earlier batch is created.
    await db.query(`CREATE ONLY assembly_batch:range_later SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:range, batch_count = 1, state = 'complete', effective_at = d'2026-07-04T00:00:00.000750Z';`);
    await db.query(`CREATE ONLY stock_in:range_replenish SET owned_by = rebase_group:root,
      from_party = misc_account:opening, to_account = stock_account:range, quantity = 6dec, effective_at = d'2026-07-04T00:00:00.000500Z';`);
    await db.query(`CREATE ONLY assembly_batch:range_earlier SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:range, batch_count = 1, state = 'complete', effective_at = d'2026-07-04T00:00:00.000000Z';`);
    data = await assertOracleAt(db);
    assert.equal(n(byId(data.accounts, 'stock_account:range').z_history.summary.measures.quantity.sum), 0,
      'sub-millisecond assembly inputs and intermediate stock grant reconstruct to zero');
    const asOf = await queryResult(await db.query(`RETURN fn::tree::before(
      { rid: stock_account:range, slot: 'z_history' }, [d'2026-07-04T00:00:00.000000Z']
    ).measures.quantity.sum;`));
    assert.equal(n(asOf), 6, 'future batches and intermediate receipt do not change earlier as-of stock');
    const rangeCheck = await queryResult(await db.query(`LET $at = d'2026-07-04T00:00:00.000000000Z';
      LET $one_ns = $at + 1ns;
      RETURN {
        distinct: $at != $one_ns,
        exact: fn::tree::range({ rid: stock_account:range, slot: 'z_gross_input' }, [$at], [$one_ns]).measures.gross_input.sum,
        one_ms: fn::tree::range({ rid: stock_account:range, slot: 'z_gross_input' }, [$at], [$at + 1ms]).measures.gross_input.sum
      };`));
    assert.equal(rangeCheck.distinct, true, 'SurrealDB preserves a nanosecond timestamp successor');
    assert.equal(n(rangeCheck.exact), 6, 'exact interval includes only this timestamp’s input demand');
    assert.equal(n(rangeCheck.one_ms), 12, 'millisecond interval would combine a distinct later demand');

    // Per-output dated use capacity preserves a stock_out's one physical debit.
    await db.query(`CREATE ONLY assembly_batch:output_use SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:output_use, batch_count = 2, state = 'complete', effective_at = d'2026-07-05T00:00:00Z';`);
    data = await assertOracleAt(db);
    const outputId = rid(data.outputs.find((x) => x.rebase_managed_source === 'assembly_batch:output_use'
      && x.rebase_managed_role === 'output_a')?.id);
    const otherOutputId = rid(data.outputs.find((x) => x.rebase_managed_source === 'assembly_batch:output_use'
      && x.rebase_managed_role === 'output_b')?.id);
    await db.query(`CREATE ONLY stock_out:output_dispatch SET owned_by = rebase_group:root,
      from_account = stock_account:output_a, to_party = misc_account:customer, assembly_output = ${outputId},
      quantity = 2dec, effective_at = d'2026-07-05T00:00:00Z';`);
    data = await assertOracleAt(db);
    assert.equal(n(byId(data.accounts, 'stock_account:output_a').z_history.summary.measures.quantity.sum), 2,
      'linked dispatch records exactly one stock debit');
    assert.equal(n(byId(data.outputs, outputId).z_capacity.summary.measures.quantity.sum), -2,
      'linked dispatch consumes the output’s dated use capacity once');
    await db.query(`CREATE ONLY stock_out:ordinary_dispatch SET owned_by = rebase_group:root,
      from_account = stock_account:output_b, to_party = misc_account:customer,
      quantity = 1dec, effective_at = d'2026-07-05T00:00:00Z';`);
    await rejectsUnchanged(db, `CREATE ONLY stock_out:wrong_output_account SET owned_by = rebase_group:root,
      from_account = stock_account:output_b, to_party = misc_account:customer, assembly_output = ${outputId},
      quantity = 1dec, effective_at = d'2026-07-05T00:00:00Z';`,
    'linked dispatch rejects a source account that differs from its output account', /ACCOUNTING_STOCK_OUT_ASSEMBLY_ACCOUNT_MISMATCH/);
    await rejectsUnchanged(db, `UPDATE stock_out:output_dispatch SET assembly_output = NONE;`,
      'linked output reference cannot be cleared after dispatch creation');
    await rejectsUnchanged(db, `UPDATE stock_out:output_dispatch SET assembly_output = ${otherOutputId};`,
      'linked output reference cannot be changed to a different role after dispatch creation');
    await rejectsUnchanged(db, `CREATE ONLY stock_out:output_overdraw SET owned_by = rebase_group:root,
      from_account = stock_account:output_a, to_party = misc_account:customer, assembly_output = ${outputId},
      quantity = 1dec, effective_at = d'2026-07-06T00:00:00Z';`,
    'shared linked output capacity rejects consumption beyond source quantity', /ACCOUNTING_ASSEMBLY_OUTPUT_CAPACITY/);
    await rejectsUnchanged(db, `UPDATE assembly_batch:output_use SET batch_count = 1;`,
      'output reduction below linked consumption rejects the complete source edit', /ACCOUNTING_ASSEMBLY_OUTPUT_CAPACITY/);
    await rejectsUnchanged(db, `UPDATE assembly_batch:output_use SET effective_at = d'2026-07-06T00:00:01Z';`,
      'moving output after linked consumption rejects through reactive date shadow', /ACCOUNTING_STOCK_OUT_BEFORE_ASSEMBLY_OUTPUT/);
    await rejectsUnchanged(db, `UPDATE assembly_batch:output_use SET state = 'draft';`,
      'removing consumed output children is rejected by the typed stock_out reference');
    await rejectsUnchanged(db, `DELETE assembly_batch:output_use;`,
      'deleting a batch with a consumed output is rejected atomically');
    data = await assertOracleAt(db);

    // Updating an existing completed source is atomic across sibling legs and roots.
    await db.query(`CREATE ONLY assembly_batch:editable SET owned_by = rebase_group:root,
      recipe_version = assembly_recipe_version:output_use, batch_count = 1, state = 'draft', effective_at = d'2026-07-02T00:00:00Z';`);
    data = await assertOracleAt(db);
    assert.equal(data.inputs.filter((x) => x.rebase_managed_source === 'assembly_batch:editable').length, 0,
      'an incomplete edit fixture has no managed children');
    await db.query(`UPDATE assembly_batch:editable SET batch_count = 2, state = 'complete';`);
    data = await assertOracleAt(db);
    assert.equal(data.inputs.filter((x) => x.rebase_managed_source === 'assembly_batch:editable').length, 2,
      'complete batch output identity stays two explicit input roles');
    await rejectsUnchanged(db, `UPDATE stock_in:open_input_a SET quantity = 1dec;`,
      'reducing an earlier stock grant rechecks and preserves later batch capacity', /ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY/);
    await rejectsUnchanged(db, `DELETE stock_in:open_input_a;`,
      'deleting an earlier stock grant rechecks and preserves later batch capacity', /ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY/);
    await rejectsUnchanged(db, `UPDATE assembly_batch:editable SET effective_at = d'2026-06-30T12:00:00Z';`,
      'backdated stock edit that invalidates inputs is rolled back', /ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY/);
    await assertOracleAt(db);

    await db.query('DELETE stock_out:output_dispatch;');
    await db.query(`UPDATE assembly_batch:output_use SET state = 'draft';`);
    data = await assertOracleAt(db);
    assert.equal(data.inputs.filter((x) => x.rebase_managed_source === 'assembly_batch:output_use').length, 0);
    assert.equal(data.outputs.filter((x) => x.rebase_managed_source === 'assembly_batch:output_use').length, 0);
    await db.query(`UPDATE assembly_batch:output_use SET state = 'complete';`);
    data = await assertOracleAt(db);
    assert.equal(data.outputs.filter((x) => x.rebase_managed_source === 'assembly_batch:output_use').length, 2,
      'recompletion re-adds stable output IDs and capacity roots');
    await db.query(`CREATE ONLY stock_out:output_dispatch SET owned_by = rebase_group:root,
      from_account = stock_account:output_a, to_party = misc_account:customer, assembly_output = ${outputId},
      quantity = 2dec, effective_at = d'2026-07-05T00:00:00Z';`);
    await assertOracleAt(db);

    console.log('H7 immediate assembly, exact-time gross capacity, managed role lifecycle, and linked output-use capacity passed');
  } finally {
    await db.close().catch(() => {});
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
