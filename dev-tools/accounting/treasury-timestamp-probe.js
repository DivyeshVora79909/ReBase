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
  throw new Error('Treasury timestamp probe SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    transfers: (SELECT * FROM cash_transfer ORDER BY id),
    accounts: (SELECT * FROM treasury_account ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: transfer rows and all affected account roots roll back`);
}

const balance = (row) => number(row?.z_history?.summary?.measures?.balance?.sum ?? 0);
const floor = (row) => number(row?.z_history?.summary?.measures?.balance?.instant_min ?? 0);
const strictPrefix = (row) => number(row?.z_history?.summary?.measures?.balance?.min_prefix ?? 0);

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_treasury_time_${Date.now().toString(36)}`;
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
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY treasury:tie_out_first SET owned_by = rebase_group:root, name = 'Outgoing-first tie target';
      CREATE ONLY treasury:tie_in_first SET owned_by = rebase_group:root, name = 'Incoming-first tie target';
      CREATE ONLY treasury:same_time_overdraw SET owned_by = rebase_group:root, name = 'Same-time overdraw target';
      CREATE ONLY treasury:earlier_outflow SET owned_by = rebase_group:root, name = 'Earlier-outflow target';
      CREATE ONLY treasury:donor1 SET owned_by = rebase_group:root, name = 'Transfer donor 1';
      CREATE ONLY treasury:donor2 SET owned_by = rebase_group:root, name = 'Transfer donor 2';
      CREATE ONLY treasury:donor3 SET owned_by = rebase_group:root, name = 'Transfer donor 3';
      CREATE ONLY treasury:donor4 SET owned_by = rebase_group:root, name = 'Transfer donor 4';
      CREATE ONLY treasury:donor5 SET owned_by = rebase_group:root, name = 'Transfer donor 5';
      CREATE ONLY treasury:donor6 SET owned_by = rebase_group:root, name = 'Transfer donor 6';
      CREATE ONLY treasury_account:tie_out_first SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:tie_out_first, currency = currency:usd;
      CREATE ONLY treasury_account:tie_in_first SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:tie_in_first, currency = currency:usd;
      CREATE ONLY treasury_account:same_time_overdraw SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:same_time_overdraw, currency = currency:usd;
      CREATE ONLY treasury_account:earlier_outflow SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:earlier_outflow, currency = currency:usd;
      CREATE ONLY treasury_account:donor1 SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:donor1, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY treasury_account:donor2 SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:donor2, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY treasury_account:donor3 SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:donor3, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY treasury_account:donor4 SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:donor4, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY treasury_account:donor5 SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:donor5, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY treasury_account:donor6 SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:donor6, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY cash_transfer:z_in_out_first SET owned_by = rebase_group:root,
        from_account = treasury_account:donor1, to_account = treasury_account:tie_out_first,
        amount = 5dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY cash_transfer:z_in_same_time_overdraw SET owned_by = rebase_group:root,
        from_account = treasury_account:donor3, to_account = treasury_account:same_time_overdraw,
        amount = 5dec, effective_at = d'2026-07-02T00:00:00Z';
      CREATE ONLY cash_transfer:z_in_later SET owned_by = rebase_group:root,
        from_account = treasury_account:donor5, to_account = treasury_account:earlier_outflow,
        amount = 5dec, effective_at = d'2026-07-04T00:00:00Z';
    `);

    // The incoming event is created first, but its ID sorts after the outgoing event.
    await db.query(`CREATE ONLY cash_transfer:a_out_out_first SET owned_by = rebase_group:root,
      from_account = treasury_account:tie_out_first, to_account = treasury_account:donor2,
      amount = 5dec, effective_at = d'2026-07-01T00:00:00Z';`);
    let state = await snapshot(db);
    const outFirst = state.accounts.find((row) => String(row.id) === 'treasury_account:tie_out_first');
    assert.equal(balance(outFirst), 0, 'same-time outgoing and incoming leave a zero balance');
    assert.equal(floor(outFirst), 0, 'complete-time minimum is zero despite outgoing ID sorting first');
    assert.equal(strictPrefix(outFirst), -5,
      'strict record-order prefix would reject this economically valid same-time pair');

    // Incoming ID sorts after the outgoing ID; an aggregate same-time deficit still rejects.
    await rejectsUnchanged(db, `CREATE ONLY cash_transfer:a_out_same_time_overdraw SET owned_by = rebase_group:root,
      from_account = treasury_account:same_time_overdraw, to_account = treasury_account:donor4,
      amount = 6dec, effective_at = d'2026-07-02T00:00:00Z';`,
    'same-time net outflow of 1 rejects atomically');
    state = await snapshot(db);
    const overdraw = state.accounts.find((row) => String(row.id) === 'treasury_account:same_time_overdraw');
    assert.equal(balance(overdraw), 5, 'failed same-time overdraw leaves its incoming transfer intact');
    assert.equal(floor(overdraw), 0, 'same-time overdraw rollback leaves the nonnegative floor intact');

    // A later credit cannot fund an earlier outflow.
    await rejectsUnchanged(db, `CREATE ONLY cash_transfer:a_out_earlier SET owned_by = rebase_group:root,
      from_account = treasury_account:earlier_outflow, to_account = treasury_account:donor6,
      amount = 1dec, effective_at = d'2026-07-03T00:00:00Z';`,
    'outflow before a later inflow rejects despite a positive final balance');
    state = await snapshot(db);
    const later = state.accounts.find((row) => String(row.id) === 'treasury_account:earlier_outflow');
    assert.equal(balance(later), 5, 'rejected earlier outflow leaves the later inflow unchanged');
    assert.equal(floor(later), 0, 'later inflow does not erase the earlier-time minimum');

    // Also exercise the opposite record-ID order; both signed positions remain valid.
    await db.query(`CREATE ONLY cash_transfer:a_in_in_first SET owned_by = rebase_group:root,
      from_account = treasury_account:donor1, to_account = treasury_account:tie_in_first,
      amount = 5dec, effective_at = d'2026-07-05T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_transfer:z_out_in_first SET owned_by = rebase_group:root,
      from_account = treasury_account:tie_in_first, to_account = treasury_account:donor2,
      amount = 5dec, effective_at = d'2026-07-05T00:00:00Z';`);
    state = await snapshot(db);
    const inFirst = state.accounts.find((row) => String(row.id) === 'treasury_account:tie_in_first');
    assert.equal(balance(inFirst), 0, 'opposite same-time ID order also leaves a zero balance');
    assert.equal(floor(inFirst), 0, 'opposite ID order has the same complete-time minimum');

    console.log('Treasury complete-timestamp floor, tie-order independence, and atomic overdraw controls passed');
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
