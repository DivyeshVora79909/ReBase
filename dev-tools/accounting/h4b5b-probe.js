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
  throw new Error('H4b5b SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    remittances: (SELECT * FROM tax_claim_remittance ORDER BY id),
    payables: (SELECT * FROM payable ORDER BY id),
    cashouts: (SELECT * FROM cash_out ORDER BY id),
    claims: (SELECT * FROM claim_account ORDER BY id),
    treasuries: (SELECT * FROM treasury_account ORDER BY id)
  };`));
}

const measure = (row, tree, name) => number(row?.[tree]?.summary?.measures?.[name]?.sum ?? 0);
const byId = (rows, id) => rows.find((row) => String(row.id) === id);

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: facts, cash sources, payable rows and roots roll back`);
}

async function assertClaimAndSource(db, claimId, cashoutId, expectedOpen, expectedRemitted) {
  const state = await snapshot(db);
  const claim = byId(state.claims, claimId);
  const cashout = byId(state.cashouts, cashoutId);
  const opening = state.payables.filter((row) => String(row.claim_account) === claimId)
    .reduce((sum, row) => sum + number(row.amount), 0);
  const remittances = state.remittances.filter((row) => String(row.claim_account) === claimId);
  const remitted = remittances.reduce((sum, row) => sum + number(row.amount), 0);
  const sourceAllocated = state.remittances.filter((row) => String(row.source) === cashoutId)
    .reduce((sum, row) => sum + number(row.amount), 0);
  assert.equal(opening, expectedOpen, `${claimId}: payable input reconstructs from explicit payable rows`);
  assert.equal(remitted, expectedRemitted, `${claimId}: remittance facts independently reconstruct their total`);
  assert.equal(measure(claim, 'z_history', 'payable'), expectedOpen - expectedRemitted,
    `${claimId}: direct tax payable equals openings less remittances`);
  assert.equal(measure(claim, 'z_history', 'net'), -expectedOpen + expectedRemitted,
    `${claimId}: remittance increases claim net by its amount`);
  assert.equal(number(cashout?.z_allocations?.summary?.measures?.allocated?.sum ?? 0), sourceAllocated,
    `${cashoutId}: allocation root equals actual remittance facts on that cash-out`);
  return state;
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h4b5b_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Tax authority';
      CREATE ONLY organization:other_authority SET owned_by = rebase_group:root, name = 'Other authority';
      CREATE ONLY organization:vendor SET owned_by = rebase_group:root, name = 'Vendor';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:jpy SET owned_by = rebase_group:root, code = 'JPY', name = 'JPY', precision = 0;
      CREATE ONLY tax_account:main SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Main tax authority';
      CREATE ONLY tax_account:cap SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Allocation cap';
      CREATE ONLY tax_account:paycap SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Payable cap';
      CREATE ONLY tax_account:other SET owned_by = rebase_group:root,
        authority = organization:other_authority, jurisdiction = organization:entity, label = 'Other tax authority';
      CREATE ONLY treasury:main SET owned_by = rebase_group:root, name = 'Main treasury';
      CREATE ONLY treasury:capacity SET owned_by = rebase_group:root, name = 'Allocation capacity treasury';
      CREATE ONLY treasury:payable_capacity SET owned_by = rebase_group:root, name = 'Payable capacity treasury';
      CREATE ONLY treasury:wrong_entity SET owned_by = rebase_group:root, name = 'Wrong entity treasury';
      CREATE ONLY treasury:wrong_currency SET owned_by = rebase_group:root, name = 'Wrong currency treasury';
      CREATE ONLY treasury:wrong_party SET owned_by = rebase_group:root, name = 'Wrong party treasury';
      CREATE ONLY treasury:wrong_type SET owned_by = rebase_group:root, name = 'Wrong type treasury';
      CREATE ONLY treasury:non_tax SET owned_by = rebase_group:root, name = 'Non tax treasury';
      CREATE ONLY treasury_account:main SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:main, currency = currency:usd, minimum_balance = -12dec;
      CREATE ONLY treasury_account:capacity SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:capacity, currency = currency:usd, minimum_balance = -10dec;
      CREATE ONLY treasury_account:payable_capacity SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:payable_capacity, currency = currency:usd, minimum_balance = -12dec;
      CREATE ONLY treasury_account:wrong_entity SET owned_by = rebase_group:root,
        economic_entity = organization:other_entity, treasury = treasury:wrong_entity, currency = currency:usd, minimum_balance = -2dec;
      CREATE ONLY treasury_account:wrong_currency SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:wrong_currency, currency = currency:jpy, minimum_balance = -2dec;
      CREATE ONLY treasury_account:wrong_party SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:wrong_party, currency = currency:usd, minimum_balance = -2dec;
      CREATE ONLY treasury_account:wrong_type SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:wrong_type, currency = currency:usd, minimum_balance = -2dec;
      CREATE ONLY treasury_account:non_tax SET owned_by = rebase_group:root,
        economic_entity = organization:entity, treasury = treasury:non_tax, currency = currency:usd, minimum_balance = -2dec;
      CREATE ONLY claim_account:main SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:main, currency = currency:usd;
      CREATE ONLY claim_account:capacity SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:cap, currency = currency:usd;
      CREATE ONLY claim_account:payable_capacity SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:paycap, currency = currency:usd;
      CREATE ONLY claim_account:wrong_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        opponent = tax_account:main, currency = currency:usd;
      CREATE ONLY claim_account:wrong_currency SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:main, currency = currency:jpy;
      CREATE ONLY claim_account:wrong_type SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:vendor, currency = currency:usd;
      CREATE ONLY payable:main_open SET owned_by = rebase_group:root, claim_account = claim_account:main,
        amount = 12dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY payable:capacity_open SET owned_by = rebase_group:root, claim_account = claim_account:capacity,
        amount = 20dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY payable:payable_capacity_open SET owned_by = rebase_group:root, claim_account = claim_account:payable_capacity,
        amount = 7dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY cash_out:main SET owned_by = rebase_group:root, from_account = treasury_account:main,
        to_party = tax_account:main, amount = 12dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:capacity SET owned_by = rebase_group:root, from_account = treasury_account:capacity,
        to_party = tax_account:cap, amount = 10dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:payable_capacity SET owned_by = rebase_group:root, from_account = treasury_account:payable_capacity,
        to_party = tax_account:paycap, amount = 12dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:wrong_entity SET owned_by = rebase_group:root, from_account = treasury_account:wrong_entity,
        to_party = tax_account:main, amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:wrong_currency SET owned_by = rebase_group:root, from_account = treasury_account:wrong_currency,
        to_party = tax_account:main, amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:wrong_party SET owned_by = rebase_group:root, from_account = treasury_account:wrong_party,
        to_party = tax_account:other, amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:wrong_type SET owned_by = rebase_group:root, from_account = treasury_account:wrong_type,
        to_party = organization:vendor, amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_out:non_tax SET owned_by = rebase_group:root, from_account = treasury_account:non_tax,
        to_party = organization:vendor, amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';
    `);

    const start = await snapshot(db);
    const mainTreasury = byId(start.treasuries, 'treasury_account:main');
    assert.equal(measure(mainTreasury, 'z_history', 'balance'), -12,
      'the actual cash_out debits treasury once by 12 before tax remittance');

    await db.query(`CREATE ONLY tax_claim_remittance:main SET owned_by = rebase_group:root,
      source = cash_out:main, claim_account = claim_account:main, amount = 12dec,
      effective_at = d'2026-06-02T00:00:00Z';`);
    let state = await assertClaimAndSource(db, 'claim_account:main', 'cash_out:main', 12, 12);
    assert.equal(measure(byId(state.treasuries, 'treasury_account:main'), 'z_history', 'balance'), -12,
      'remittance does not add a second treasury debit');
    assert.equal(state.cashouts.filter((row) => String(row.id) === 'cash_out:main').length, 1,
      'remittance does not create another cash_out row');

    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:zero SET owned_by = rebase_group:root,
      source = cash_out:main, claim_account = claim_account:main, amount = 0dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'zero remittance rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:negative SET owned_by = rebase_group:root,
      source = cash_out:main, claim_account = claim_account:main, amount = -1dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'negative remittance rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:precision SET owned_by = rebase_group:root,
      source = cash_out:main, claim_account = claim_account:main, amount = 1.001dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'currency-inexact remittance rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:before_cash_out SET owned_by = rebase_group:root,
      source = cash_out:main, claim_account = claim_account:main, amount = 1dec,
      effective_at = d'2026-06-01T00:00:00Z';`, 'remittance before cash-out rejects');

    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:wrong_entity SET owned_by = rebase_group:root,
      source = cash_out:wrong_entity, claim_account = claim_account:main, amount = 1dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'economic entity mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:wrong_currency SET owned_by = rebase_group:root,
      source = cash_out:wrong_currency, claim_account = claim_account:main, amount = 1dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'currency mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:wrong_party SET owned_by = rebase_group:root,
      source = cash_out:wrong_party, claim_account = claim_account:main, amount = 1dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'cash-out party and claim opponent mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:wrong_type SET owned_by = rebase_group:root,
      source = cash_out:wrong_type, claim_account = claim_account:wrong_type, amount = 1dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'non-tax claim opponent rejects');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:wrong_source_type SET owned_by = rebase_group:root,
      source = payable:main_open, claim_account = claim_account:main, amount = 1dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'source must be a typed cash_out');

    // Multiple facts share only the existing cash_out allocation root.
    await db.query(`CREATE ONLY tax_claim_remittance:capacity_first SET owned_by = rebase_group:root,
      source = cash_out:capacity, claim_account = claim_account:capacity, amount = 6dec,
      effective_at = d'2026-06-03T00:00:00Z';`);
    await db.query(`CREATE ONLY tax_claim_remittance:capacity_second SET owned_by = rebase_group:root,
      source = cash_out:capacity, claim_account = claim_account:capacity, amount = 4dec,
      effective_at = d'2026-06-03T00:00:00Z';`);
    state = await assertClaimAndSource(db, 'claim_account:capacity', 'cash_out:capacity', 20, 10);
    assert.equal(number(byId(state.cashouts, 'cash_out:capacity').z_allocations.summary.measures.allocated.sum), 10,
      'two remittances share the source allocation cap exactly once');
    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:capacity_overdraw SET owned_by = rebase_group:root,
      source = cash_out:capacity, claim_account = claim_account:capacity, amount = 0.01dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'cash-out allocation capacity rejects cumulative overdraw');

    await rejectsUnchanged(db, `CREATE ONLY tax_claim_remittance:payable_overdraw SET owned_by = rebase_group:root,
      source = cash_out:payable_capacity, claim_account = claim_account:payable_capacity, amount = 8dec,
      effective_at = d'2026-06-03T00:00:00Z';`, 'claim payable guard independently rejects overdraw');
    state = await snapshot(db);
    assert.equal(number(byId(state.cashouts, 'cash_out:payable_capacity')?.z_allocations?.summary?.measures?.allocated?.sum ?? 0), 0,
      'payable overdraw rejection leaves independent cash-out capacity unused');

    await rejectsUnchanged(db, 'UPDATE tax_claim_remittance:main SET amount = 13dec;',
      'amount edit beyond both payable and source capacity rolls back');
    await rejectsUnchanged(db, "UPDATE tax_claim_remittance:main SET effective_at = d'2026-06-01T00:00:00Z';",
      'rekey before cash-out rejects and rolls back');
    await rejectsUnchanged(db, "UPDATE cash_out:main SET effective_at = d'2026-06-04T00:00:00Z';",
      'moving the source after its dependent remittance rejects and restores the full graph');

    await db.query('UPDATE tax_claim_remittance:main SET amount = 11dec;');
    await rejectsUnchanged(db, 'UPDATE cash_out:main SET amount = 10dec;',
      'lowering cash-out below its 11 allocated amount rejects and rolls back');
    await db.query("UPDATE tax_claim_remittance:main SET effective_at = d'2026-06-04T00:00:00Z';");
    state = await assertClaimAndSource(db, 'claim_account:main', 'cash_out:main', 12, 11);
    assert.equal(measure(byId(state.treasuries, 'treasury_account:main'), 'z_history', 'balance'), -12,
      'valid amount and date edits do not duplicate or rekey treasury cash');
    const stableId = String(byId(state.remittances, 'tax_claim_remittance:main').id);
    await rejectsUnchanged(db, 'DELETE cash_out:main;', 'cash-out deletion while remittance exists rejects');
    await rejectsUnchanged(db, 'DELETE claim_account:main;', 'claim-account deletion while remittance exists rejects');

    await db.query('DELETE tax_claim_remittance:main;');
    state = await assertClaimAndSource(db, 'claim_account:main', 'cash_out:main', 12, 0);
    assert.equal(number(byId(state.treasuries, 'treasury_account:main').z_history.summary.measures.balance.sum), -12,
      'deleting remittance leaves the original cash-out only');
    await db.query(`CREATE ONLY tax_claim_remittance:main SET owned_by = rebase_group:root,
      source = cash_out:main, claim_account = claim_account:main, amount = 12dec,
      effective_at = d'2026-06-02T00:00:00Z';`);
    state = await assertClaimAndSource(db, 'claim_account:main', 'cash_out:main', 12, 12);
    assert.equal(String(byId(state.remittances, 'tax_claim_remittance:main').id), stableId,
      'deletion and re-addition preserve the stable remittance ID');
    assert.equal(measure(byId(state.treasuries, 'treasury_account:main'), 'z_history', 'balance'), -12,
      're-addition still records no second treasury debit');

    console.log('Accounting H4b5b tax payable remittance, shared capacities, lifecycle, rollback, and no-duplicate-cash passed');
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
