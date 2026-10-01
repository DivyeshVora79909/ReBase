#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');

const root = path.resolve(__dirname, '../..');
const number = (value) => Number(String(value ?? 0).replace(/dec$/i, ''));

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`SurrealDB exited with ${child.exitCode}`);
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
  throw new Error('Stock timestamp probe SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    accounts: (SELECT * FROM stock_account ORDER BY id),
    incoming: (SELECT * FROM stock_in ORDER BY id),
    outgoing: (SELECT * FROM stock_out ORDER BY id),
    transfers: (SELECT * FROM stock_transfer ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: source rows and every stock root roll back`);
}

const quantity = (row) => number(row?.z_history?.summary?.measures?.quantity?.sum ?? 0);
const instantMin = (row) => number(row?.z_history?.summary?.measures?.quantity?.instant_min ?? 0);
const strictPrefix = (row) => number(row?.z_history?.summary?.measures?.quantity?.min_prefix ?? 0);
const byId = (rows, id) => rows.find((row) => String(row.id) === id);

function reconstruct(state, accountId) {
  const incoming = state.incoming.filter((row) => String(row.to_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const outgoing = state.outgoing.filter((row) => String(row.from_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const transferredIn = state.transfers.filter((row) => String(row.to_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const transferredOut = state.transfers.filter((row) => String(row.from_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  return incoming - outgoing + transferredIn - transferredOut;
}

function assertOracle(state, accountId, expected) {
  const account = byId(state.accounts, accountId);
  assert.equal(reconstruct(state, accountId), expected, `${accountId}: source rows reconstruct expected quantity`);
  assert.equal(quantity(account), expected, `${accountId}: stock root equals independently reconstructed source quantity`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_stock_time_${Date.now().toString(36)}`;
  const child = spawn('surreal', ['start', 'memory', '--user', 'root', '--pass', 'root',
    '--bind', `127.0.0.1:${port}`, '--no-banner', '--log', 'error'],
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
      CREATE ONLY misc_account:opening_balance SET owned_by = rebase_group:root, label = 'Opening balance';
      CREATE ONLY misc_account:consumption SET owned_by = rebase_group:root, label = 'Consumption';
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', dimension = 'count', name = 'Each';
      CREATE ONLY item:widget SET owned_by = rebase_group:root, name = 'Widget', unit = measure_unit:each;
      CREATE ONLY operating_unit:out_first SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Outgoing first', code = 'out_first';
      CREATE ONLY operating_unit:in_first SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Incoming first', code = 'in_first';
      CREATE ONLY operating_unit:direct_io SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Direct stock in/out', code = 'direct_io';
      CREATE ONLY operating_unit:same_overdraw SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Same-time overdraw', code = 'same_overdraw';
      CREATE ONLY operating_unit:later_inflow SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Later inflow', code = 'later_inflow';
      CREATE ONLY operating_unit:donor1 SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Donor 1', code = 'donor1';
      CREATE ONLY operating_unit:donor2 SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Donor 2', code = 'donor2';
      CREATE ONLY operating_unit:donor3 SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Donor 3', code = 'donor3';
      CREATE ONLY operating_unit:donor4 SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Donor 4', code = 'donor4';
      CREATE ONLY operating_unit:donor5 SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Donor 5', code = 'donor5';
      CREATE ONLY operating_unit:donor6 SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Donor 6', code = 'donor6';
      CREATE ONLY stock_account:out_first SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:out_first, resource = item:widget;
      CREATE ONLY stock_account:in_first SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:in_first, resource = item:widget;
      CREATE ONLY stock_account:direct_io SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:direct_io, resource = item:widget;
      CREATE ONLY stock_account:same_overdraw SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:same_overdraw, resource = item:widget;
      CREATE ONLY stock_account:later_inflow SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:later_inflow, resource = item:widget;
      CREATE ONLY stock_account:donor1 SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:donor1, resource = item:widget, minimum_quantity = -100dec;
      CREATE ONLY stock_account:donor2 SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:donor2, resource = item:widget, minimum_quantity = -100dec;
      CREATE ONLY stock_account:donor3 SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:donor3, resource = item:widget, minimum_quantity = -100dec;
      CREATE ONLY stock_account:donor4 SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:donor4, resource = item:widget, minimum_quantity = -100dec;
      CREATE ONLY stock_account:donor5 SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:donor5, resource = item:widget, minimum_quantity = -100dec;
      CREATE ONLY stock_account:donor6 SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:donor6, resource = item:widget, minimum_quantity = -100dec;
      CREATE ONLY stock_in:donor1_open SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:donor1, quantity = 5dec, effective_at = d'2026-06-30T00:00:00Z';
      CREATE ONLY stock_in:donor2_open SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:donor2, quantity = 5dec, effective_at = d'2026-06-30T00:00:00Z';
      CREATE ONLY stock_in:donor3_open SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:donor3, quantity = 5dec, effective_at = d'2026-06-30T00:00:00Z';
      CREATE ONLY stock_in:donor4_open SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:donor4, quantity = 5dec, effective_at = d'2026-06-30T00:00:00Z';
      CREATE ONLY stock_in:donor5_open SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:donor5, quantity = 5dec, effective_at = d'2026-06-30T00:00:00Z';
      CREATE ONLY stock_in:donor6_open SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:donor6, quantity = 5dec, effective_at = d'2026-06-30T00:00:00Z';
      CREATE ONLY stock_transfer:z_in_out_first SET owned_by = rebase_group:root,
        from_account = stock_account:donor1, to_account = stock_account:out_first,
        quantity = 5dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_transfer:a_in_in_first SET owned_by = rebase_group:root,
        from_account = stock_account:donor3, to_account = stock_account:in_first,
        quantity = 5dec, effective_at = d'2026-07-02T00:00:00Z';
      CREATE ONLY stock_transfer:z_in_same_overdraw SET owned_by = rebase_group:root,
        from_account = stock_account:donor5, to_account = stock_account:same_overdraw,
        quantity = 5dec, effective_at = d'2026-07-03T00:00:00Z';
      CREATE ONLY stock_in:later_receipt SET owned_by = rebase_group:root, from_party = misc_account:opening_balance,
        to_account = stock_account:later_inflow, quantity = 5dec, effective_at = d'2026-07-05T00:00:00Z';
      CREATE ONLY stock_in:direct_receipt SET owned_by = rebase_group:root, from_party = misc_account:opening_balance,
        to_account = stock_account:direct_io, quantity = 5dec, effective_at = d'2026-07-01T00:00:00Z';
    `);

    // Table/record key ordering places stock_out before stock_transfer here.
    await db.query(`CREATE ONLY stock_transfer:a_out_out_first SET owned_by = rebase_group:root,
      from_account = stock_account:out_first, to_account = stock_account:donor2,
      quantity = 5dec, effective_at = d'2026-07-01T00:00:00Z';`);
    let state = await snapshot(db);
    const outFirst = byId(state.accounts, 'stock_account:out_first');
    assertOracle(state, 'stock_account:out_first', 0);
    assert.equal(instantMin(outFirst), 0, 'same-time outgoing-first transfer pair has zero complete-time minimum');
    assert.equal(strictPrefix(outFirst), -5,
      'strict record-order prefix would reject the outgoing-first same-time transfer pair');

    // The reverse ID order also coalesces to zero at the timestamp.
    await db.query(`CREATE ONLY stock_transfer:z_out_in_first SET owned_by = rebase_group:root,
      from_account = stock_account:in_first, to_account = stock_account:donor4,
      quantity = 5dec, effective_at = d'2026-07-02T00:00:00Z';`);
    state = await snapshot(db);
    const inFirst = byId(state.accounts, 'stock_account:in_first');
    assertOracle(state, 'stock_account:in_first', 0);
    assert.equal(instantMin(inFirst), 0);
    assert.equal(strictPrefix(inFirst), 0, 'incoming-first record order remains valid under strict prefixes too');

    // Direct stock_in and stock_out rows share one effective timestamp.
    await db.query(`CREATE ONLY stock_out:direct_dispatch SET owned_by = rebase_group:root,
      from_account = stock_account:direct_io, to_party = misc_account:consumption,
      quantity = 5dec, effective_at = d'2026-07-01T00:00:00Z';`);
    state = await snapshot(db);
    const direct = byId(state.accounts, 'stock_account:direct_io');
    assertOracle(state, 'stock_account:direct_io', 0);
    assert.equal(instantMin(direct), 0, 'same-time stock-in/out leaves zero available quantity');

    await rejectsUnchanged(db, `CREATE ONLY stock_out:same_time_overdraw SET owned_by = rebase_group:root,
      from_account = stock_account:same_overdraw, to_party = misc_account:consumption,
      quantity = 6dec, effective_at = d'2026-07-03T00:00:00Z';`,
    'same-time aggregate stock deficit rejects atomically');
    state = await snapshot(db);
    const overdraw = byId(state.accounts, 'stock_account:same_overdraw');
    assertOracle(state, 'stock_account:same_overdraw', 5);
    assert.equal(instantMin(overdraw), 0, 'failed same-time overdraw leaves the valid receipt intact');

    await rejectsUnchanged(db, `CREATE ONLY stock_out:before_later_receipt SET owned_by = rebase_group:root,
      from_account = stock_account:later_inflow, to_party = misc_account:consumption,
      quantity = 1dec, effective_at = d'2026-07-04T00:00:00Z';`,
    'outflow before a later receipt rejects despite a positive eventual balance');
    state = await snapshot(db);
    const later = byId(state.accounts, 'stock_account:later_inflow');
    assertOracle(state, 'stock_account:later_inflow', 5);
    assert.equal(instantMin(later), 0, 'rejected earlier outflow leaves later receipt intact');

    await rejectsUnchanged(db, 'UPDATE stock_in:direct_receipt SET quantity = 4dec;',
      'source edit that creates a same-time deficit rolls back');
    state = await snapshot(db);
    assertOracle(state, 'stock_account:direct_io', 0);

    console.log('H5a stock complete-timestamp floor, tie-order independence, source reconstruction, and rollback passed');
  } finally {
    await db.close().catch(() => {});
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
