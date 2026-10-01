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
  throw new Error('H5b stock return probe SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    accounts: (SELECT * FROM stock_account ORDER BY id),
    incoming: (SELECT * FROM stock_in ORDER BY id),
    outgoing: (SELECT * FROM stock_out ORDER BY id),
    transfers: (SELECT * FROM stock_transfer ORDER BY id),
    returns: (SELECT * FROM stock_return ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: source rows, return capacity, and stock roots roll back`);
}

const qty = (row) => number(row?.z_history?.summary?.measures?.quantity?.sum ?? 0);
const minimum = (row) => number(row?.z_returns?.summary?.measures?.quantity?.instant_min ?? 0);
const byId = (rows, id) => rows.find((row) => String(row.id) === id);

function oracle(state, accountId) {
  const incoming = state.incoming.filter((row) => String(row.to_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const outgoing = state.outgoing.filter((row) => String(row.from_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const transferredIn = state.transfers.filter((row) => String(row.to_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const transferredOut = state.transfers.filter((row) => String(row.from_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  const returned = state.returns.filter((row) => String(row.destination_account) === accountId)
    .reduce((sum, row) => sum + number(row.quantity), 0);
  return incoming - outgoing + transferredIn - transferredOut + returned;
}

function assertAccount(state, accountId, expected) {
  const account = byId(state.accounts, accountId);
  assert.equal(oracle(state, accountId), expected, `${accountId}: stock movement rows reconstruct the expected quantity`);
  assert.equal(qty(account), expected, `${accountId}: stock root matches the independent source-row oracle`);
}

function capacityOracle(state, sourceId) {
  const source = byId(state.outgoing, sourceId);
  const events = new Map();
  const add = (at, delta) => {
    const key = new Date(at).toISOString();
    events.set(key, (events.get(key) ?? 0) + delta);
  };
  add(source.effective_at, number(source.quantity));
  for (const row of state.returns.filter((candidate) => String(candidate.source) === sourceId)) {
    add(row.effective_at, -number(row.quantity));
  }
  let running = 0;
  let instantMin = 0;
  for (const at of [...events.keys()].sort()) {
    running += events.get(at);
    instantMin = Math.min(instantMin, running);
  }
  return { sum: running, instantMin };
}

function assertCapacity(state, sourceId) {
  const source = byId(state.outgoing, sourceId);
  const expected = capacityOracle(state, sourceId);
  const summary = source.z_returns.summary.measures.quantity;
  assert.equal(number(summary.sum), expected.sum, `${sourceId}: source rows reconstruct dated return-capacity sum`);
  assert.equal(number(summary.instant_min), expected.instantMin,
    `${sourceId}: source rows reconstruct complete-timestamp return-capacity minimum`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_stock_return_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY misc_account:opening SET owned_by = rebase_group:root, label = 'Opening stock';
      CREATE ONLY misc_account:recipient SET owned_by = rebase_group:root, label = 'Original recipient';
      CREATE ONLY misc_account:wrong_recipient SET owned_by = rebase_group:root, label = 'Wrong recipient';
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', dimension = 'count', name = 'Each';
      CREATE ONLY measure_unit:box SET owned_by = rebase_group:root, code = 'box', dimension = 'count', name = 'Box';
      CREATE ONLY item:widget SET owned_by = rebase_group:root, name = 'Widget', unit = measure_unit:each;
      CREATE ONLY item:gadget SET owned_by = rebase_group:root, name = 'Gadget', unit = measure_unit:each;
      CREATE ONLY item:boxed_widget SET owned_by = rebase_group:root, name = 'Boxed widget', unit = measure_unit:box;
      CREATE ONLY operating_unit:origin SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Origin', code = 'origin';
      CREATE ONLY operating_unit:alternate SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Alternate', code = 'alternate';
      CREATE ONLY operating_unit:wrong_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity, name = 'Wrong entity', code = 'wrong_entity';
      CREATE ONLY operating_unit:wrong_resource SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Wrong resource', code = 'wrong_resource';
      CREATE ONLY operating_unit:wrong_unit SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Wrong unit', code = 'wrong_unit';
      CREATE ONLY stock_account:origin SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:origin, resource = item:widget;
      CREATE ONLY stock_account:alternate SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:alternate, resource = item:widget;
      CREATE ONLY stock_account:wrong_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity, operating_unit = operating_unit:wrong_entity, resource = item:widget;
      CREATE ONLY stock_account:wrong_resource SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:wrong_resource, resource = item:gadget;
      CREATE ONLY stock_account:wrong_unit SET owned_by = rebase_group:root, economic_entity = organization:entity, operating_unit = operating_unit:wrong_unit, resource = item:boxed_widget;
      CREATE ONLY stock_in:opening SET owned_by = rebase_group:root, from_party = misc_account:opening, to_account = stock_account:origin, quantity = 10dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_out:main SET owned_by = rebase_group:root, from_account = stock_account:origin, to_party = misc_account:recipient, quantity = 8dec, effective_at = d'2026-07-02T00:00:00Z';
    `);

    let state = await snapshot(db);
    const out = byId(state.outgoing, 'stock_out:main');
    assert.equal(number(out.z_returns.summary.measures.quantity.sum), 8, 'self-seeded source pool grants exactly the original quantity');
    assert.equal(minimum(out), 0, 'source seed starts the dated return-capacity root at zero floor');
    assertAccount(state, 'stock_account:origin', 2);
    assertCapacity(state, 'stock_out:main');

    await rejectsUnchanged(db, `CREATE ONLY stock_return:before_source SET owned_by = rebase_group:root,
      source = stock_out:main, return_party = misc_account:recipient, destination_account = stock_account:origin,
      quantity = 1dec, effective_at = d'2026-07-01T12:00:00Z';`, 'return before source is rejected');

    await db.query(`CREATE ONLY stock_return:main_a SET owned_by = rebase_group:root,
      source = stock_out:main, return_party = misc_account:recipient, destination_account = stock_account:alternate,
      quantity = 3dec, effective_at = d'2026-07-02T00:00:00Z';`);
    state = await snapshot(db);
    assert.equal(number(byId(state.outgoing, 'stock_out:main').z_returns.summary.measures.quantity.sum), 5,
      'same-time correction return is accepted at source timestamp and leaves capacity 5');
    assert.equal(minimum(byId(state.outgoing, 'stock_out:main')), 0, 'the dated capacity root never goes below zero');
    assert.deepEqual(byId(state.outgoing, 'stock_out:main').z_returns.summary.first,
      [new Date('2026-07-02T00:00:00Z').toISOString(), 'stock_out:main', 'z_return_grant'],
      'the observed same-time source grant sorts before return children across these table names');
    assert.deepEqual(byId(state.outgoing, 'stock_out:main').z_returns.summary.last,
      [new Date('2026-07-02T00:00:00Z').toISOString(), 'stock_return:main_a', 'z_source_capacity']);
    assertAccount(state, 'stock_account:origin', 2);
    assertAccount(state, 'stock_account:alternate', 3);
    assertCapacity(state, 'stock_out:main');

    await db.query(`CREATE ONLY stock_return:main_equal_z SET owned_by = rebase_group:root,
      source = stock_out:main, return_party = misc_account:recipient, destination_account = stock_account:origin,
      quantity = 1dec, effective_at = d'2026-07-02T00:00:00Z';`);
    state = await snapshot(db);
    assert.equal(number(byId(state.outgoing, 'stock_out:main').z_returns.summary.measures.quantity.sum), 4,
      'same-time sibling return in the opposite record-ID order coexists with the first return');
    assert.equal(minimum(byId(state.outgoing, 'stock_out:main')), 0);
    assertAccount(state, 'stock_account:origin', 3);
    assertAccount(state, 'stock_account:alternate', 3);
    assertCapacity(state, 'stock_out:main');

    await db.query(`CREATE ONLY stock_return:main_b SET owned_by = rebase_group:root,
      source = stock_out:main, return_party = misc_account:recipient, destination_account = stock_account:origin,
      quantity = 1dec, effective_at = d'2026-07-04T00:00:00Z';`);
    state = await snapshot(db);
    assertAccount(state, 'stock_account:origin', 4);
    assertAccount(state, 'stock_account:alternate', 3);
    assert.equal(number(byId(state.outgoing, 'stock_out:main').z_returns.summary.measures.quantity.sum), 3,
      'capacity tracks original quantity minus dated returns');
    assertCapacity(state, 'stock_out:main');

    await rejectsUnchanged(db, `CREATE ONLY stock_return:competing_overreturn SET owned_by = rebase_group:root,
      source = stock_out:main, return_party = misc_account:recipient, destination_account = stock_account:alternate,
      quantity = 4dec, effective_at = d'2026-07-04T00:00:00Z';`, 'competing returns cannot exceed shared source capacity');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET quantity = 0dec;`, 'zero return quantity rejects atomically');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET quantity = 6dec;`, 'return amount edit beyond shared capacity rolls back');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET effective_at = d'2026-07-01T00:00:00Z';`, 'return date edit before source rolls back');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET destination_account = stock_account:wrong_entity;`, 'wrong-entity destination rejects');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET destination_account = stock_account:wrong_resource;`, 'wrong-resource destination rejects');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET destination_account = stock_account:wrong_unit;`, 'wrong-unit destination rejects');
    await rejectsUnchanged(db, `UPDATE stock_return:main_b SET return_party = misc_account:wrong_recipient;`, 'return party must match original recipient');

    await db.query('UPDATE stock_return:main_b SET quantity = 0.5dec;');
    state = await snapshot(db);
    assertAccount(state, 'stock_account:origin', 3.5);
    assertAccount(state, 'stock_account:alternate', 3);
    assert.equal(number(byId(state.outgoing, 'stock_out:main').z_returns.summary.measures.quantity.sum), 3.5,
      'successful return quantity edit refreshes shared source capacity');
    assertCapacity(state, 'stock_out:main');
    await db.query('UPDATE stock_return:main_b SET quantity = 1dec;');
    state = await snapshot(db);
    assertAccount(state, 'stock_account:origin', 4);
    assertAccount(state, 'stock_account:alternate', 3);

    // A source reduction or source-time move must refresh the self-grant and validate all returns atomically.
    await rejectsUnchanged(db, `UPDATE stock_out:main SET quantity = 4dec;`, 'source quantity reduction below returns rolls back');
    await rejectsUnchanged(db, `UPDATE stock_out:main SET effective_at = d'2026-07-05T00:00:00Z';`, 'source date move after a return rolls back');
    await rejectsUnchanged(db, `DELETE stock_out:main;`, 'source deletion with linked returns is protected');

    // Edit destination and date while preserving the source cap, then verify lifecycle cleanup and stable re-add.
    await db.query(`UPDATE stock_return:main_b SET destination_account = stock_account:alternate,
      effective_at = d'2026-07-03T00:00:00Z';`);
    state = await snapshot(db);
    assertAccount(state, 'stock_account:origin', 3);
    assertAccount(state, 'stock_account:alternate', 4);
    assertCapacity(state, 'stock_out:main');
    await db.query('DELETE stock_return:main_b;');
    state = await snapshot(db);
    assertAccount(state, 'stock_account:origin', 3);
    assertAccount(state, 'stock_account:alternate', 3);
    assert.equal(number(byId(state.outgoing, 'stock_out:main').z_returns.summary.measures.quantity.sum), 4);
    assertCapacity(state, 'stock_out:main');
    await db.query(`CREATE ONLY stock_return:main_b SET owned_by = rebase_group:root,
      source = stock_out:main, return_party = misc_account:recipient, destination_account = stock_account:origin,
      quantity = 1dec, effective_at = d'2026-07-04T00:00:00Z';`);
    state = await snapshot(db);
    assert.equal(String(byId(state.returns, 'stock_return:main_b').id), 'stock_return:main_b', 're-added return retains stable ID');
    assertAccount(state, 'stock_account:origin', 4);
    assertAccount(state, 'stock_account:alternate', 3);
    assertCapacity(state, 'stock_out:main');

    await rejectsUnchanged(db, 'DELETE stock_account:origin;', 'used source/destination account deletion is protected');
    await rejectsUnchanged(db, 'DELETE stock_account:alternate;', 'used alternate destination deletion is protected');

    // An independent oracle includes every authoritative stock source and each explicit return.
    state = await snapshot(db);
    assertAccount(state, 'stock_account:origin', 4);
    assertAccount(state, 'stock_account:alternate', 3);
    assertCapacity(state, 'stock_out:main');
    assert.equal(number(byId(state.outgoing, 'stock_out:main').z_returns.summary.measures.quantity.sum), 3,
      'dated capacity sums the source grant and both active return facts');
    console.log('H5b physical return, dated self-seeded capacity, lifecycle rollback, and source-row oracle passed');
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
