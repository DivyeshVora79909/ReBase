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
  throw new Error('H4b5a SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    offsets: (SELECT * FROM claim_offset_instruction ORDER BY id),
    receivables: (SELECT * FROM receivable ORDER BY id),
    payables: (SELECT * FROM payable ORDER BY id),
    main: (SELECT * FROM ONLY claim_account:main),
    receivable_cap: (SELECT * FROM ONLY claim_account:receivable_cap),
    payable_cap: (SELECT * FROM ONLY claim_account:payable_cap),
    simultaneous: (SELECT * FROM ONLY claim_account:simultaneous),
    cash: (SELECT * FROM ONLY treasury_account:cash)
  };`));
}

const measure = (row, tree, name) => number(row?.[tree]?.summary?.measures?.[name]?.sum ?? 0);

async function oracle(db, mainOffset, simultaneousOffset = 0) {
  const state = await snapshot(db);
  const received = state.receivables.filter((row) => String(row.claim_account) === 'claim_account:main')
    .reduce((sum, row) => sum + number(row.amount), 0);
  const paid = state.payables.filter((row) => String(row.claim_account) === 'claim_account:main')
    .reduce((sum, row) => sum + number(row.amount), 0);
  const offsetSum = state.offsets.filter((row) => String(row.claim_account) === 'claim_account:main')
    .reduce((sum, row) => sum + number(row.amount), 0);
  assert.equal(offsetSum, mainOffset, 'main offset rows independently reconstruct the expected amount');
  assert.equal(measure(state.main, 'z_history', 'receivable'), received - offsetSum,
    'receivable equals explicit openings less paired offsets');
  assert.equal(measure(state.main, 'z_history', 'payable'), paid - offsetSum,
    'payable equals explicit openings less paired offsets');
  assert.equal(measure(state.main, 'z_history', 'net'), received - paid,
    'paired offset contributes zero net delta');
  const simultaneousR = state.receivables.filter((row) => String(row.claim_account) === 'claim_account:simultaneous')
    .reduce((sum, row) => sum + number(row.amount), 0);
  const simultaneousP = state.payables.filter((row) => String(row.claim_account) === 'claim_account:simultaneous')
    .reduce((sum, row) => sum + number(row.amount), 0);
  const simultaneous = state.offsets.filter((row) => String(row.claim_account) === 'claim_account:simultaneous')
    .reduce((sum, row) => sum + number(row.amount), 0);
  assert.equal(simultaneous, simultaneousOffset, 'same-timestamp offset rows independently reconstruct');
  assert.equal(measure(state.simultaneous, 'z_history', 'receivable'), simultaneousR - simultaneous,
    'same-timestamp receivable is the complete-time aggregate');
  assert.equal(measure(state.simultaneous, 'z_history', 'payable'), simultaneousP - simultaneous,
    'same-timestamp payable is the complete-time aggregate');
  assert.equal(measure(state.cash, 'z_history', 'balance'), 0,
    'claim offset creates no treasury movement');
  return state;
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: instruction, source claims, cash and roots roll back`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h4b5a_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Authority';
      CREATE ONLY organization:authority_rcap SET owned_by = rebase_group:root, name = 'Receivable cap authority';
      CREATE ONLY organization:authority_pcap SET owned_by = rebase_group:root, name = 'Payable cap authority';
      CREATE ONLY organization:authority_sim SET owned_by = rebase_group:root, name = 'Same-time authority';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY tax_account:main SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Main tax claim';
      CREATE ONLY tax_account:rcap SET owned_by = rebase_group:root,
        authority = organization:authority_rcap, jurisdiction = organization:entity, label = 'Receivable cap';
      CREATE ONLY tax_account:pcap SET owned_by = rebase_group:root,
        authority = organization:authority_pcap, jurisdiction = organization:entity, label = 'Payable cap';
      CREATE ONLY tax_account:sim SET owned_by = rebase_group:root,
        authority = organization:authority_sim, jurisdiction = organization:entity, label = 'Same-time tax claim';
      CREATE ONLY treasury:main SET owned_by = rebase_group:root, name = 'Main';
      CREATE ONLY treasury_account:cash SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:main, currency = currency:usd;
      CREATE ONLY claim_account:main SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:main, currency = currency:usd;
      CREATE ONLY claim_account:receivable_cap SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:rcap, currency = currency:usd;
      CREATE ONLY claim_account:payable_cap SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:pcap, currency = currency:usd;
      CREATE ONLY claim_account:simultaneous SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:sim, currency = currency:usd;
      CREATE ONLY receivable:main_r SET owned_by = rebase_group:root, claim_account = claim_account:main,
        amount = 6dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY payable:main_p SET owned_by = rebase_group:root, claim_account = claim_account:main,
        amount = 18dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY receivable:rcap_r SET owned_by = rebase_group:root, claim_account = claim_account:receivable_cap,
        amount = 2dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY payable:rcap_p SET owned_by = rebase_group:root, claim_account = claim_account:receivable_cap,
        amount = 8dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY receivable:pcap_r SET owned_by = rebase_group:root, claim_account = claim_account:payable_cap,
        amount = 8dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY payable:pcap_p SET owned_by = rebase_group:root, claim_account = claim_account:payable_cap,
        amount = 2dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY payable:simultaneous_p SET owned_by = rebase_group:root, claim_account = claim_account:simultaneous,
        amount = 18dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY receivable:simultaneous_r SET owned_by = rebase_group:root, claim_account = claim_account:simultaneous,
        amount = 6dec, effective_at = d'2026-07-01T00:00:00Z';
    `);
    let state = await oracle(db, 0, 0);
    const mainNet = measure(state.main, 'z_history', 'net');
    const cashBefore = JSON.stringify(state.cash.z_history);

    await db.query(`CREATE ONLY claim_offset_instruction:main_offset SET owned_by = rebase_group:root,
      claim_account = claim_account:main, amount = 6dec, effective_at = d'2026-06-03T00:00:00Z';`);
    state = await oracle(db, 6, 0);
    assert.equal(measure(state.main, 'z_history', 'receivable'), 0, 'R6 with offset 6 leaves receivable zero');
    assert.equal(measure(state.main, 'z_history', 'payable'), 12, 'P18 with offset 6 leaves payable 12');
    assert.equal(measure(state.main, 'z_history', 'net'), mainNet, 'offset net delta remains zero');
    assert.equal(JSON.stringify(state.cash.z_history), cashBefore, 'offset leaves treasury unchanged');

    await rejectsUnchanged(db, "UPDATE claim_offset_instruction:main_offset SET effective_at = d'2026-05-31T00:00:00Z';",
      'moving offset before opening receivable/payable rejects and rolls back the full graph');
    await db.query("UPDATE claim_offset_instruction:main_offset SET effective_at = d'2026-06-02T00:00:00Z';");
    state = await oracle(db, 6, 0);
    assert.equal(measure(state.main, 'z_history', 'receivable'), 0,
      'offset at payable opening instant leaves receivable zero after complete-time aggregation');
    assert.equal(measure(state.main, 'z_history', 'payable'), 12,
      'offset at payable opening instant leaves payable 12 after complete-time aggregation');
    assert.equal(measure(state.main, 'z_history', 'net'), mainNet,
      'same-time date edit preserves net');
    await db.query("UPDATE claim_offset_instruction:main_offset SET effective_at = d'2026-06-03T00:00:00Z';");
    state = await oracle(db, 6, 0);
    assert.equal(measure(state.main, 'z_history', 'receivable'), 0);
    assert.equal(measure(state.main, 'z_history', 'payable'), 12);

    await rejectsUnchanged(db, `CREATE ONLY claim_offset_instruction:zero SET owned_by = rebase_group:root,
      claim_account = claim_account:main, amount = 0dec, effective_at = d'2026-06-03T00:00:00Z';`, 'zero amount rejects');
    await rejectsUnchanged(db, `CREATE ONLY claim_offset_instruction:negative SET owned_by = rebase_group:root,
      claim_account = claim_account:main, amount = -1dec, effective_at = d'2026-06-03T00:00:00Z';`, 'negative amount rejects');
    await rejectsUnchanged(db, `CREATE ONLY claim_offset_instruction:excess_precision SET owned_by = rebase_group:root,
      claim_account = claim_account:main, amount = 1.001dec, effective_at = d'2026-06-03T00:00:00Z';`,
    'currency-inexact amount rejects without changing the graph');
    await rejectsUnchanged(db, `CREATE ONLY claim_offset_instruction:receivable_overdraw SET owned_by = rebase_group:root,
      claim_account = claim_account:receivable_cap, amount = 3dec, effective_at = d'2026-06-03T00:00:00Z';`,
    'receivable capacity rejects overdraw independently');
    await rejectsUnchanged(db, `CREATE ONLY claim_offset_instruction:payable_overdraw SET owned_by = rebase_group:root,
      claim_account = claim_account:payable_cap, amount = 3dec, effective_at = d'2026-06-03T00:00:00Z';`,
    'payable capacity rejects overdraw independently');
    await rejectsUnchanged(db, 'UPDATE claim_offset_instruction:main_offset SET amount = 7dec;',
      'overdrawn amount edit rolls back the instruction and both root measures');

    await db.query('UPDATE claim_offset_instruction:main_offset SET amount = 5dec;');
    state = await oracle(db, 5, 0);
    const stableId = String(state.offsets.find((row) => String(row.id) === 'claim_offset_instruction:main_offset').id);
    assert.equal(measure(state.main, 'z_history', 'receivable'), 1);
    assert.equal(measure(state.main, 'z_history', 'payable'), 13);
    await db.query('DELETE claim_offset_instruction:main_offset;');
    state = await oracle(db, 0, 0);
    assert.equal(measure(state.main, 'z_history', 'receivable'), 6);
    assert.equal(measure(state.main, 'z_history', 'payable'), 18);
    await db.query(`CREATE ONLY claim_offset_instruction:main_offset SET owned_by = rebase_group:root,
      claim_account = claim_account:main, amount = 6dec, effective_at = d'2026-06-03T00:00:00Z';`);
    state = await oracle(db, 6, 0);
    assert.equal(String(state.offsets.find((row) => String(row.id) === 'claim_offset_instruction:main_offset').id), stableId,
      'deletion/re-addition reuses the stable instruction ID');
    await rejectsUnchanged(db, 'DELETE claim_account:main;', 'account deletion while offset instruction exists rejects');

    await db.query(`CREATE ONLY claim_offset_instruction:same_timestamp_first SET owned_by = rebase_group:root,
      claim_account = claim_account:simultaneous, amount = 6dec, effective_at = d'2026-07-01T00:00:00Z';`);
    state = await oracle(db, 6, 6);
    assert.equal(measure(state.simultaneous, 'z_history', 'receivable'), 0,
      'same-timestamp R6 with offset 6 is reduced atomically');
    assert.equal(measure(state.simultaneous, 'z_history', 'payable'), 12,
      'same-timestamp P18 with offset 6 is reduced atomically');
    assert.equal(measure(state.simultaneous, 'z_history', 'net'), -12,
      'same-timestamp offset contributes zero net delta');
    await rejectsUnchanged(db, `CREATE ONLY claim_offset_instruction:same_timestamp_overdraw SET owned_by = rebase_group:root,
      claim_account = claim_account:simultaneous, amount = 1dec, effective_at = d'2026-07-01T00:00:00Z';`,
    'same-timestamp overdraw rejects after complete-time grouping, regardless of source insert order');

    console.log('Accounting H4b5a paired tax claim offset, complete-timestamp capacity, lifecycle, and rollback passed');
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
