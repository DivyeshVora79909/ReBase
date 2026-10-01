#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');
const { treeFields } = require('../../src/generators/tree');

const root = path.resolve(__dirname, '../..');
const n = (x) => Number(String(x ?? 0).replace(/dec$/i, ''));
const rid = (x) => String(x ?? '');
const rows = (x) => Array.isArray(x) ? x : [];

function extendFunction(schema, name, edit) {
  const escaped = name.replaceAll(':', '\\:');
  const match = schema.match(new RegExp(`DEFINE FUNCTION OVERWRITE ${escaped}\\([\\s\\S]*?\\} PERMISSIONS (?:FULL|NONE);`));
  assert.ok(match, `compiled profile contains ${name}`);
  return schema.replace(match[0], edit(match[0]));
}

function h8TreeFields() {
  const references = [
    { table: 'h8_stock_grant', slot: 'z_stock' },
    { table: 'h8_stock_debit', slot: 'z_stock' },
    { table: 'h8_run_fact', slot: 'z_reserve' },
    { table: 'h8_run_fact', slot: 'z_cancel_release' },
    { table: 'h8_run_fact', slot: 'z_end' },
  ];
  const nodes = references.map((reference) => ({
    ...reference,
    keyType: 'datetime',
    field: { definition: 'TYPE option<object> PERMISSIONS FULL' },
    owners: [{ table: 'stock_account', slot: 'z_history' }],
    peers: references,
  }));
  return `${treeFields({ roots: [], nodes })}
DEFINE FIELD OVERWRITE z_history.root ON stock_account
TYPE option<{ rid: record<h8_stock_grant | h8_stock_debit | h8_run_fact>, slot: string }>
ASSERT $value = NONE OR (record::tb($value.rid) = 'h8_stock_grant' AND $value.slot = 'z_stock')
    OR (record::tb($value.rid) = 'h8_stock_debit' AND $value.slot = 'z_stock')
    OR (record::tb($value.rid) = 'h8_run_fact' AND $value.slot IN ['z_reserve', 'z_cancel_release', 'z_end']);`;
}

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
    if (child.exitCode !== null) throw new Error(`H8 feasibility SurrealDB exited with ${child.exitCode}`);
    const connected = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const done = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => done(false));
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H8 feasibility SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    recipes: (SELECT * FROM h8_recipe ORDER BY id),
    runs: (SELECT * FROM h8_run_fact ORDER BY id),
    grants: (SELECT * FROM h8_stock_grant ORDER BY id),
    debits: (SELECT * FROM h8_stock_debit ORDER BY id),
    accounts: (SELECT * FROM stock_account ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label, pattern) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), pattern, label);
  assert.deepEqual(await snapshot(db), before, `${label}: source rows and all roots roll back`);
}

function oracle(data, accountId) {
  const events = new Map();
  const add = (at, quantity = 0, available = 0) => {
    const key = String(at);
    const row = events.get(key) ?? { quantity: 0, available: 0 };
    row.quantity += quantity;
    row.available += available;
    events.set(key, row);
  };
  for (const grant of rows(data.grants)) if (rid(grant.stock_account) === accountId) {
    add(grant.effective_at, n(grant.quantity), n(grant.quantity));
  }
  for (const debit of rows(data.debits)) if (rid(debit.stock_account) === accountId) {
    add(debit.effective_at, -n(debit.quantity), -n(debit.quantity));
  }
  for (const run of rows(data.runs).filter((row) => rid(row.stock_account) === accountId)) {
    if (run.status === 'draft' || (run.status === 'cancelled' && String(run.cancelled_at) < String(run.planned_start))) continue;
    add(run.planned_start, 0, -n(run.input_quantity));
    if (run.status === 'cancelled') add(run.cancelled_at, 0, n(run.input_quantity));
    else {
      // Physical input use, reservation release, and output are independent
      // source facts at end. Their availability effects coalesce to output.
      add(run.end_at, -n(run.input_quantity), -n(run.input_quantity));
      add(run.end_at, 0, n(run.input_quantity));
      add(run.end_at, n(run.output_quantity), n(run.output_quantity));
    }
  }
  let quantity = 0;
  let available = 0;
  let quantityMin = 0;
  let availableMin = 0;
  for (const at of [...events.keys()].sort()) {
    quantity += events.get(at).quantity;
    available += events.get(at).available;
    quantityMin = Math.min(quantityMin, quantity);
    availableMin = Math.min(availableMin, available);
  }
  return { quantity, available, quantityMin, availableMin };
}

async function assertOracle(db) {
  const data = await snapshot(db);
  for (const account of rows(data.accounts)) {
    const expected = oracle(data, rid(account.id));
    const measures = account?.z_history?.summary?.measures ?? {};
    assert.equal(n(measures.quantity?.sum), expected.quantity, `${account.id} physical quantity sum`);
    assert.equal(n(measures.quantity?.instant_min), expected.quantityMin, `${account.id} physical complete-time floor`);
    assert.equal(n(measures.available?.sum), expected.available, `${account.id} free availability sum`);
    assert.equal(n(measures.available?.instant_min), expected.availableMin, `${account.id} free complete-time floor`);
    const gross = rows(data.runs).filter((row) => rid(row.stock_account) === rid(account.id) && row.status === 'scheduled')
      .reduce((sum, row) => sum + n(row.input_quantity), 0);
    assert.equal(n(measures.gross_input?.sum), gross, `${account.id} end-time gross input sum`);
  }
  return data;
}

async function asOf(db, account, at) {
  const measures = await queryResult(await db.query(`RETURN fn::tree::before(
    { rid: ${account}, slot: 'z_history' }, [d'${at}' + 1ns]
  ).measures;`));
  return { quantity: n(measures?.quantity?.sum), available: n(measures?.available?.sum) };
}

async function main() {
  let profile = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const fixture = fs.readFileSync(path.join(__dirname, 'h8-production-feasibility-fixture.surql'), 'utf8');
  profile = extendFunction(profile, 'fn::rebase::membership_allowed', (body) => body.replace(
    'RETURN false;',
    "IF record::tb($link.rid) IN ['h8_stock_grant', 'h8_stock_debit', 'h8_run_fact'] AND record::tb($owner.rid) = 'stock_account' AND $owner.slot = 'z_history' { RETURN $link.slot IN ['z_stock', 'z_reserve', 'z_cancel_release', 'z_end']; };\nRETURN false;"));
  profile = extendFunction(profile, 'fn::rebase::slots', (body) => body.replace(
    'RETURN [];',
    "IF record::tb($rid) = 'h8_stock_grant' OR record::tb($rid) = 'h8_stock_debit' { RETURN ['z_stock']; };\nIF record::tb($rid) = 'h8_run_fact' { RETURN ['z_reserve', 'z_cancel_release', 'z_end']; };\nRETURN [];"));
  profile = extendFunction(profile, 'fn::rebase::members', (body) => body.replace(
    '\nRETURN []; } PERMISSIONS NONE;',
    "\nIF record::tb($row.id) = 'h8_stock_grant' { RETURN fn::h8::grant_members($row); };\nIF record::tb($row.id) = 'h8_stock_debit' { RETURN fn::h8::debit_members($row); };\nIF record::tb($row.id) = 'h8_run_fact' { RETURN fn::h8::run_members($row); };\nRETURN []; } PERMISSIONS NONE;"));
  profile = extendFunction(profile, 'fn::rebase::validate', (body) => body.replace(
    '\n}',
    "\nIF record::tb($row.id) = 'h8_stock_debit' { fn::h8::debit_validate($row); };\nIF record::tb($row.id) = 'h8_run_fact' { fn::h8::run_validate($row); };\n}"));
  const port = await freePort();
  const namespace = `h8_feasibility_${Date.now().toString(36)}`;
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
    await db.query(profile);
    await db.query(fixture);
    await db.query(h8TreeFields());
    await db.query(`
      CREATE ONLY organization:entity SET owned_by = rebase_group:root, name = 'H8';
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', dimension = 'count', name = 'Each';
      CREATE ONLY item:stock SET owned_by = rebase_group:root, name = 'Stock', unit = measure_unit:each;
      CREATE ONLY operating_unit:overlap SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Overlap', code = 'overlap';
      CREATE ONLY operating_unit:reverse SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Reverse', code = 'reverse';
      CREATE ONLY operating_unit:complete SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Complete', code = 'complete';
      CREATE ONLY operating_unit:same SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Same', code = 'same';
      CREATE ONLY operating_unit:self SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Self', code = 'self';
      CREATE ONLY operating_unit:cancel_before SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Cancel before', code = 'cancel_before';
      CREATE ONLY operating_unit:cancel_after SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Cancel after', code = 'cancel_after';
      CREATE ONLY stock_account:overlap SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:overlap, resource = item:stock;
      CREATE ONLY stock_account:reverse SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:reverse, resource = item:stock;
      CREATE ONLY stock_account:complete SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:complete, resource = item:stock;
      CREATE ONLY stock_account:same SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:same, resource = item:stock;
      CREATE ONLY stock_account:self SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:self, resource = item:stock;
      CREATE ONLY stock_account:cancel_before SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:cancel_before, resource = item:stock;
      CREATE ONLY stock_account:cancel_after SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:cancel_after, resource = item:stock;
      CREATE ONLY h8_recipe:two_hours SET duration = 2h;
      CREATE ONLY h8_stock_grant:open_overlap SET stock_account = stock_account:overlap, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY h8_stock_grant:open_reverse SET stock_account = stock_account:reverse, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY h8_stock_grant:open_complete SET stock_account = stock_account:complete, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY h8_stock_grant:open_same SET stock_account = stock_account:same, quantity = 2dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY h8_stock_grant:open_cancel_before SET stock_account = stock_account:cancel_before, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY h8_stock_grant:open_cancel_after SET stock_account = stock_account:cancel_after, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
    `);

    // Overlapping 6+6 holds against 10 reject in both source-ID orders.
    await db.query(`CREATE ONLY h8_run_fact:a_first SET recipe = h8_recipe:two_hours, stock_account = stock_account:overlap,
      input_quantity = 6dec, output_quantity = 0dec, planned_start = d'2026-07-02T08:00:00Z', status = 'scheduled';`);
    await assertOracle(db);
    await rejectsUnchanged(db, `CREATE ONLY h8_run_fact:z_second SET recipe = h8_recipe:two_hours, stock_account = stock_account:overlap,
      input_quantity = 6dec, output_quantity = 0dec, planned_start = d'2026-07-02T08:00:00Z', status = 'scheduled';`,
    'overlapping reservations exceed available stock without a partial write', /H8_RESERVATION_CAPACITY/);
    await db.query(`CREATE ONLY h8_run_fact:z_first SET recipe = h8_recipe:two_hours, stock_account = stock_account:reverse,
      input_quantity = 6dec, output_quantity = 0dec, planned_start = d'2026-07-02T08:00:00Z', status = 'scheduled';`);
    await rejectsUnchanged(db, `CREATE ONLY h8_run_fact:a_second SET recipe = h8_recipe:two_hours, stock_account = stock_account:reverse,
      input_quantity = 6dec, output_quantity = 0dec, planned_start = d'2026-07-02T08:00:00Z', status = 'scheduled';`,
    'reverse-ID overlapping reservations exceed prior free stock', /H8_RESERVATION_CAPACITY/);

    // Scheduled completion changes physical stock at end; release and input
    // consumption share that exact complete timestamp in separate measures.
    await db.query(`CREATE ONLY h8_run_fact:completion SET recipe = h8_recipe:two_hours, stock_account = stock_account:complete,
      input_quantity = 6dec, output_quantity = 0dec, planned_start = d'2026-07-02T08:00:00Z', status = 'scheduled';`);
    await assertOracle(db);
    assert.deepEqual(await asOf(db, 'stock_account:complete', '2026-07-02T07:59:59Z'), { quantity: 10, available: 10 });
    assert.deepEqual(await asOf(db, 'stock_account:complete', '2026-07-02T08:00:00Z'), { quantity: 10, available: 4 },
      'during production physical stock stays unchanged and six units are reserved');
    assert.deepEqual(await asOf(db, 'stock_account:complete', '2026-07-02T10:00:00Z'), { quantity: 4, available: 4 },
      'at exact end physical input is consumed while reservation release coalesces to unchanged free stock');
    await rejectsUnchanged(db, `CREATE ONLY h8_stock_debit:reserved_use SET stock_account = stock_account:complete,
      quantity = 5dec, effective_at = d'2026-07-02T09:00:00Z';`,
    'ordinary debit cannot consume reserved availability even while physical stock remains', /H8_AVAILABLE_STOCK_CAPACITY/);

    // Same-account coproduct cannot self-fund a run with no opening stock.
    await rejectsUnchanged(db, `CREATE ONLY h8_run_fact:self_funding SET recipe = h8_recipe:two_hours, stock_account = stock_account:self,
      input_quantity = 1dec, output_quantity = 1dec, planned_start = d'2026-07-03T08:00:00Z', status = 'scheduled';`,
    'same-account output at end cannot fund the start reservation or gross input', /H8_RESERVATION_CAPACITY/);
    await db.query(`CREATE ONLY h8_run_fact:same_account SET recipe = h8_recipe:two_hours, stock_account = stock_account:same,
      input_quantity = 2dec, output_quantity = 2dec, planned_start = d'2026-07-03T08:00:00Z', status = 'scheduled';`);
    await assertOracle(db);
    assert.deepEqual(await asOf(db, 'stock_account:same', '2026-07-03T08:00:00Z'), { quantity: 2, available: 0 });
    assert.deepEqual(await asOf(db, 'stock_account:same', '2026-07-03T10:00:00Z'), { quantity: 2, available: 2 },
      'same-time input/output deltas coalesce to the source-row physical and free-stock totals');

    // Pre-start cancellation removes the future hold; post-start cancellation
    // releases it at cancellation without consuming physical stock or making output.
    await db.query(`CREATE ONLY h8_run_fact:cancel_before SET recipe = h8_recipe:two_hours, stock_account = stock_account:cancel_before,
      input_quantity = 4dec, output_quantity = 0dec, planned_start = d'2026-07-04T10:00:00Z', status = 'scheduled';`);
    await db.query(`UPDATE h8_run_fact:cancel_before SET status = 'cancelled', cancelled_at = d'2026-07-04T09:59:59Z';`);
    await assertOracle(db);
    assert.deepEqual(await asOf(db, 'stock_account:cancel_before', '2026-07-04T09:59:58Z'), { quantity: 10, available: 10 });
    assert.deepEqual(await asOf(db, 'stock_account:cancel_before', '2026-07-04T10:00:00Z'), { quantity: 10, available: 10 });
    assert.deepEqual(await asOf(db, 'stock_account:cancel_before', '2026-07-04T12:00:00Z'), { quantity: 10, available: 10 });
    await db.query(`UPDATE h8_run_fact:cancel_before SET cancelled_at = d'2026-07-04T10:00:00Z';`);
    await assertOracle(db);
    assert.deepEqual(await asOf(db, 'stock_account:cancel_before', '2026-07-04T12:00:00Z'), { quantity: 10, available: 10 },
      'cancellation at the exact start is treated as pre-start');

    await db.query(`CREATE ONLY h8_run_fact:cancel_after SET recipe = h8_recipe:two_hours, stock_account = stock_account:cancel_after,
      input_quantity = 4dec, output_quantity = 0dec, planned_start = d'2026-07-04T14:00:00Z', status = 'scheduled';`);
    await db.query(`UPDATE h8_run_fact:cancel_after SET status = 'cancelled', cancelled_at = d'2026-07-04T15:00:00Z';`);
    await assertOracle(db);
    assert.deepEqual(await asOf(db, 'stock_account:cancel_after', '2026-07-04T13:59:59Z'), { quantity: 10, available: 10 });
    assert.deepEqual(await asOf(db, 'stock_account:cancel_after', '2026-07-04T14:00:00Z'), { quantity: 10, available: 6 });
    assert.deepEqual(await asOf(db, 'stock_account:cancel_after', '2026-07-04T15:00:00Z'), { quantity: 10, available: 10 });
    assert.deepEqual(await asOf(db, 'stock_account:cancel_after', '2026-07-04T16:00:00Z'), { quantity: 10, available: 10 });
    await rejectsUnchanged(db, `UPDATE h8_run_fact:cancel_after SET cancelled_at = d'2026-07-04T16:00:00Z';`,
      'cancellation at the scheduled end cannot erase completed production', /H8_CANCEL_AFTER_END/);

    console.log('H8 feasibility passed: overlapping reservations, exact-end quantity/available, same-account self-funding rejection, cancellation as-of oracle');
  } finally {
    await db.close().catch(() => {});
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
