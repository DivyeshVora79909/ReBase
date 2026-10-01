#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');

const root = path.resolve(__dirname, '../..');
const n = (value) => Number(String(value ?? 0).replace(/dec$/i, ''));
const rid = (value) => String(value);
const id = (row) => String(row.id);
const row = (rows, key) => rows.find((item) => id(item) === key);
const measure = (record, tree, name, extremum = 'sum') => n(record?.[tree]?.summary?.measures?.[name]?.[extremum] ?? 0);
const near = (actual, expected, label) => assert.ok(Math.abs(actual - expected) < 1e-8, `${label}: ${actual} ~= ${expected}`);
const round = (value, precision) => Math.round(value * (10 ** precision)) / (10 ** precision);

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const until = Date.now() + 5000;
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`H6b SurrealDB exited with ${child.exitCode}`);
    const ready = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const done = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => done(false));
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
    });
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H6b SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    currencies: (SELECT * FROM currency ORDER BY id),
    pairs: (SELECT * FROM exchange_pair ORDER BY id),
    quotes: (SELECT * FROM currency_exchange ORDER BY id),
    transfers: (SELECT * FROM cash_fx_transfer ORDER BY id),
    reversals: (SELECT * FROM cash_fx_transfer_reversal ORDER BY id),
    treasuries: (SELECT * FROM treasury_account ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label, pattern) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), pattern, label);
  assert.deepEqual(await snapshot(db), before, `${label}: facts, quote use, pair history, and both treasury roots roll back`);
}

async function assertOracle(db) {
  const state = await snapshot(db);
  for (const account of state.treasuries) {
    const accountId = id(account);
    const deltas = new Map();
    let total = 0;
    const add = (at, delta) => deltas.set(String(at), (deltas.get(String(at)) ?? 0) + delta);
    for (const transfer of state.transfers) {
      if (rid(transfer.from_account) === accountId) { total -= n(transfer.from_amount); add(transfer.effective_at, -n(transfer.from_amount)); }
      if (rid(transfer.to_account) === accountId) { total += n(transfer.to_amount); add(transfer.effective_at, n(transfer.to_amount)); }
    }
    for (const reversal of state.reversals) {
      if (rid(reversal.from_account) === accountId) { total -= n(reversal.from_amount); add(reversal.effective_at, -n(reversal.from_amount)); }
      if (rid(reversal.to_account) === accountId) { total += n(reversal.to_amount); add(reversal.effective_at, n(reversal.to_amount)); }
    }
    near(measure(account, 'z_history', 'balance'), total, `${accountId}: treasury sum matches direct FX source rows`);
    let running = 0;
    let minimum = 0;
    for (const delta of [...deltas.entries()].sort(([a], [b]) => Date.parse(a) - Date.parse(b)).map(([, value]) => value)) {
      running += delta;
      minimum = Math.min(minimum, running);
    }
    near(measure(account, 'z_history', 'balance', 'instant_min'), minimum,
      `${accountId}: complete-time treasury floor matches grouped FX source rows`);
  }
  for (const pair of state.pairs) {
    const pairId = id(pair);
    let given = 0;
    let received = 0;
    for (const transfer of state.transfers.filter((item) => rid(item.pair) === pairId)) {
      const quote = row(state.quotes, rid(transfer.exchange));
      assert.ok(quote, `${id(transfer)} resolves its exact quote`);
      const sourceCurrency = row(state.currencies, rid(quote.from_currency));
      const destinationCurrency = row(state.currencies, rid(quote.to_currency));
      assert.ok(sourceCurrency && destinationCurrency, `${id(transfer)} quote resolves its currency records`);
      assert.equal(round(n(transfer.from_amount), Number(sourceCurrency.precision)), n(transfer.from_amount),
        `${id(transfer)} input precision comes from its source currency record`);
      const pairGiven = round(n(transfer.from_amount) * n(quote.rate), Number(destinationCurrency.precision));
      assert.equal(n(transfer.to_amount), pairGiven, `${id(transfer)} target amount independently rounds from its referenced quote`);
      assert.ok(Math.abs(n(transfer.rounding_residual) - (n(transfer.from_amount) * n(quote.rate) - pairGiven)) < 1e-9,
        `${id(transfer)} residual is source product less rounded target`);
      given += n(transfer.from_amount);
      received += n(transfer.to_amount);
    }
    for (const reversal of state.reversals.filter((item) => rid(item.pair) === pairId)) {
      const source = row(state.transfers, rid(reversal.source));
      assert.ok(source, `${id(reversal)} resolves its direct transfer source`);
      assert.equal(n(reversal.from_amount), n(source.to_amount), 'reversal debits the original received amount');
      assert.equal(n(reversal.to_amount), n(source.from_amount), 'reversal credits the original given amount');
      given -= n(source.from_amount);
      received -= n(source.to_amount);
    }
    near(measure(pair, 'z_history', 'quoted_given'), given, `${pairId}: quoted given totals match source facts`);
    near(measure(pair, 'z_history', 'quoted_received'), received, `${pairId}: quoted received totals match source facts`);
    assert.equal(measure(pair, 'z_history', 'executed_given'), 0, `${pairId}: quote-derived rows do not enter entered-execution totals`);
    assert.equal(measure(pair, 'z_history', 'executed_received'), 0, `${pairId}: quote-derived rows do not enter entered-execution totals`);
    const executionRate = await queryResult(await db.query(`SELECT id,
      IF ((z_history.summary.measures.executed_given.sum ?? 0dec) > 0dec)
      THEN <decimal>(z_history.summary.measures.executed_received.sum ?? 0dec)
        / (z_history.summary.measures.executed_given.sum ?? 0dec)
      ELSE NONE END AS reported_rate FROM exchange_pair WHERE id = ${pairId};`));
    assert.equal(executionRate[0]?.reported_rate ?? null, null,
      `${pairId}: quote-derived volumes do not appear in the entered-execution rate projection`);
  }
  for (const quote of state.quotes) {
    const uses = state.transfers.filter((transfer) => rid(transfer.exchange) === id(quote));
    near(measure(quote, 'z_usage', 'source'), uses.reduce((sum, transfer) => sum + n(transfer.from_amount), 0),
      `${id(quote)} historical source usage equals explicit transfer facts`);
    near(measure(quote, 'z_usage', 'target'), uses.reduce((sum, transfer) => sum + n(transfer.to_amount), 0),
      `${id(quote)} historical target usage equals explicit transfer facts`);
  }
  return state;
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h6b_${Date.now().toString(36)}`;
  const child = spawn('surreal', ['start', 'memory', '--user', 'root', '--pass', 'root', '--bind', `127.0.0.1:${port}`, '--no-banner', '--log', 'error'], { cwd: root, stdio: ['ignore', 'ignore', 'ignore'] });
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
      CREATE ONLY rebase_group:second SET name = 'Second owner', parents = [rebase_group:root];
      CREATE ONLY organization:entity SET owned_by = rebase_group:root, name = 'Entity';
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY currency:jpy SET owned_by = rebase_group:root, code = 'JPY', name = 'JPY', precision = 0;
      CREATE ONLY treasury:usd SET owned_by = rebase_group:root, name = 'USD';
      CREATE ONLY treasury:eur SET owned_by = rebase_group:root, name = 'EUR';
      CREATE ONLY treasury:jpy SET owned_by = rebase_group:root, name = 'JPY';
      CREATE ONLY treasury:usd_other SET owned_by = rebase_group:root, name = 'USD other entity';
      CREATE ONLY treasury:eur_owner SET owned_by = rebase_group:root, name = 'EUR other owner';
      CREATE ONLY treasury:floor SET owned_by = rebase_group:root, name = 'FX floor treasury';
      CREATE ONLY treasury_account:usd SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:usd, currency = currency:usd, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:eur, currency = currency:eur, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:jpy SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:jpy, currency = currency:jpy, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:usd_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        treasury = treasury:usd_other, currency = currency:usd, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:eur_owner SET owned_by = rebase_group:second, economic_entity = organization:entity,
        treasury = treasury:eur_owner, currency = currency:eur, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:floor SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:floor, currency = currency:usd, minimum_balance = 0dec;
      CREATE ONLY exchange_pair:usd_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:usd, received_resource = currency:eur;
      CREATE ONLY exchange_pair:eur_usd SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:eur, received_resource = currency:usd;
      CREATE ONLY exchange_pair:usd_jpy SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:usd, received_resource = currency:jpy;
      CREATE ONLY exchange_pair:jpy_usd SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:jpy, received_resource = currency:usd;
      CREATE ONLY exchange_pair:other_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        given_resource = currency:usd, received_resource = currency:eur;
      CREATE ONLY exchange_pair:other_owner SET owned_by = rebase_group:second, economic_entity = organization:entity,
        given_resource = currency:usd, received_resource = currency:eur;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:widget SET owned_by = rebase_group:root, name = 'Widget', unit = measure_unit:each;
      CREATE ONLY service:repair SET owned_by = rebase_group:root, name = 'Repair', unit = measure_unit:each;
      CREATE ONLY exchange_pair:identity_only SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = item:widget, received_resource = service:repair;
      CREATE ONLY currency_exchange:main SET owned_by = rebase_group:root, pair = exchange_pair:usd_eur,
        from_currency = currency:usd, to_currency = currency:eur, rate = 0.9dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY currency_exchange:later SET owned_by = rebase_group:root, pair = exchange_pair:usd_eur,
        from_currency = currency:usd, to_currency = currency:eur, rate = 0.5dec, effective_at = d'2026-06-05T00:00:00Z';
      CREATE ONLY currency_exchange:usd_jpy SET owned_by = rebase_group:root, pair = exchange_pair:usd_jpy,
        from_currency = currency:usd, to_currency = currency:jpy, rate = 0.1dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY currency_exchange:jpy_usd SET owned_by = rebase_group:root, pair = exchange_pair:jpy_usd,
        from_currency = currency:jpy, to_currency = currency:usd, rate = 0.01dec, effective_at = d'2026-06-01T00:00:00Z';
    `);
    await assertOracle(db);

    await rejectsUnchanged(db, `CREATE ONLY currency_exchange:unbound SET owned_by = rebase_group:root,
      from_currency = currency:usd, to_currency = currency:eur, rate = 1dec, effective_at = d'2026-06-01T00:00:00Z';`,
    'unbound quote rejects');
    await rejectsUnchanged(db, `CREATE ONLY currency_exchange:wrong_pair SET owned_by = rebase_group:root,
      pair = exchange_pair:eur_usd, from_currency = currency:usd, to_currency = currency:eur,
      rate = 1dec, effective_at = d'2026-06-01T00:00:00Z';`, 'quote currencies must match its explicit ordered pair');
    await rejectsUnchanged(db, `CREATE ONLY currency_exchange:wrong_owner SET owned_by = rebase_group:root,
      pair = exchange_pair:other_owner, from_currency = currency:usd, to_currency = currency:eur,
      rate = 1dec, effective_at = d'2026-06-01T00:00:00Z';`, 'quote owner must match the pair owner');
    await rejectsUnchanged(db, `CREATE ONLY currency_exchange:noncurrency SET owned_by = rebase_group:root,
      pair = exchange_pair:identity_only, from_currency = currency:usd, to_currency = currency:eur,
      rate = 1dec, effective_at = d'2026-06-01T00:00:00Z';`, 'quote pair must be currency-only');

    await db.query(`CREATE ONLY cash_fx_transfer:z_later_quote SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 2.01dec, effective_at = d'2026-06-06T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_fx_transfer:a_main SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 1.11dec, effective_at = d'2026-06-06T00:00:00Z';`);
    let state = await assertOracle(db);
    assert.equal(n(row(state.transfers, 'cash_fx_transfer:z_later_quote').to_amount), 1.81,
      'explicit older quote controls amount even when a newer quote exists');
    assert.equal(n(row(state.transfers, 'cash_fx_transfer:a_main').to_amount), 1,
      'quoted output is rounded to destination currency precision');
    assert.equal(measure(row(state.pairs, 'exchange_pair:usd_eur'), 'z_history', 'quoted_given'), 3.12,
      'quote-derived amounts enter quoted pair history');
    assert.equal(measure(row(state.pairs, 'exchange_pair:usd_eur'), 'z_history', 'executed_given'), 0,
      'quoted history does not mix with H6a entered quantities');
    await db.query(`CREATE ONLY cash_fx_transfer:b_rekeyable SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 0.5dec, effective_at = d'2026-06-06T00:00:00Z';`);
    state = await assertOracle(db);
    const stableTransfer = id(row(state.transfers, 'cash_fx_transfer:b_rekeyable'));
    await rejectsUnchanged(db, "UPDATE cash_fx_transfer:b_rekeyable SET effective_at = d'2026-05-31T00:00:00Z';",
      'valid unreversed transfer cannot move before its selected quote');
    await db.query('DELETE cash_fx_transfer:b_rekeyable;');
    state = await assertOracle(db);
    await db.query(`CREATE ONLY cash_fx_transfer:b_rekeyable SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 0.5dec, effective_at = d'2026-06-06T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(id(row(state.transfers, 'cash_fx_transfer:b_rekeyable')), stableTransfer,
      'unreversed transfer delete/re-add preserves its stable ID');
    await rejectsUnchanged(db, 'UPDATE currency_exchange:main SET rate = 0.8dec;',
      'selected quote rate is immutable after transfer selection');
    assert.equal(measure(row(state.quotes, 'currency_exchange:main'), 'z_usage', 'source'), 3.62,
      'selected quote records actual gross source usage');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:floor_guard SET owned_by = rebase_group:root,
      from_account = treasury_account:floor, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 1dec, effective_at = d'2026-06-06T00:00:00Z';`,
    'treasury guard rejects and rolls back both cash legs, quote use, and pair history');

    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:wrong_orientation SET owned_by = rebase_group:root,
      from_account = treasury_account:eur, to_account = treasury_account:usd, exchange = currency_exchange:main,
      from_amount = 1dec, effective_at = d'2026-06-06T00:00:00Z';`, 'transfer account currencies must follow quote pair');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:wrong_entity SET owned_by = rebase_group:root,
      from_account = treasury_account:usd_other, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 1dec, effective_at = d'2026-06-06T00:00:00Z';`, 'transfer accounts must use quote economic entity');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:wrong_owner SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur_owner, exchange = currency_exchange:main,
      from_amount = 1dec, effective_at = d'2026-06-06T00:00:00Z';`, 'transfer accounts must use quote authorization owner');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:before_quote SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 1dec, effective_at = d'2026-05-31T00:00:00Z';`, 'transfer before explicit quote effective date rejects');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:bad_source_precision SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:eur, exchange = currency_exchange:main,
      from_amount = 1.001dec, effective_at = d'2026-06-06T00:00:00Z';`, 'source amount must match its currency precision');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:rounded_zero SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:jpy, exchange = currency_exchange:usd_jpy,
      from_amount = 0.01dec, effective_at = d'2026-06-02T00:00:00Z';`, 'positive source rounding to zero JPY rejects atomically');
    await db.query(`CREATE ONLY cash_fx_transfer:jpy_valid SET owned_by = rebase_group:root,
      from_account = treasury_account:usd, to_account = treasury_account:jpy, exchange = currency_exchange:usd_jpy,
      from_amount = 10dec, effective_at = d'2026-06-02T00:00:00Z';`);
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer:jpy_source_fraction SET owned_by = rebase_group:root,
      from_account = treasury_account:jpy, to_account = treasury_account:usd, exchange = currency_exchange:jpy_usd,
      from_amount = 100.5dec, effective_at = d'2026-06-02T00:00:00Z';`,
    'zero-decimal source currency rejects fractional input');
    await db.query(`CREATE ONLY cash_fx_transfer:jpy_source_valid SET owned_by = rebase_group:root,
      from_account = treasury_account:jpy, to_account = treasury_account:usd, exchange = currency_exchange:jpy_usd,
      from_amount = 100dec, effective_at = d'2026-06-02T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(n(row(state.transfers, 'cash_fx_transfer:jpy_valid').to_amount), 1,
      'zero-decimal output is rounded with currency_round when positive');
    assert.equal(n(row(state.transfers, 'cash_fx_transfer:jpy_source_valid').to_amount), 1,
      'zero-decimal source currency accepts exact whole-unit input');

    await db.query(`CREATE ONLY cash_fx_transfer_reversal:z_reverse SET owned_by = rebase_group:root,
      source = cash_fx_transfer:z_later_quote, effective_at = d'2026-06-06T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:usd_eur'), 'z_history', 'quoted_given'), 1.61,
      'full reversal subtracts original quote-oriented source volume');
    assert.equal(measure(row(state.quotes, 'currency_exchange:main'), 'z_usage', 'source'), 3.62,
      'reversal leaves historical quote-use total unchanged');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer_reversal:z_duplicate SET owned_by = rebase_group:root,
      source = cash_fx_transfer:z_later_quote, effective_at = d'2026-06-06T00:00:00Z';`, 'one full reversal per transfer source');
    await rejectsUnchanged(db, `CREATE ONLY cash_fx_transfer_reversal:before SET owned_by = rebase_group:root,
      source = cash_fx_transfer:a_main, effective_at = d'2026-06-01T00:00:00Z';`, 'reversal before transfer rejects');
    await rejectsUnchanged(db, "UPDATE cash_fx_transfer:z_later_quote SET effective_at = d'2026-06-07T00:00:00Z';",
      'source date edit crossing a dependent reversal rejects atomically');
    await db.query('UPDATE cash_fx_transfer:z_later_quote SET from_amount = 2.22dec;');
    state = await assertOracle(db);
    assert.equal(n(row(state.reversals, 'cash_fx_transfer_reversal:z_reverse').from_amount), 2,
      'source amount edit refreshes the full-reversal treasury debit');
    assert.equal(n(row(state.reversals, 'cash_fx_transfer_reversal:z_reverse').to_amount), 2.22,
      'source amount edit refreshes the full-reversal treasury credit');
    assert.equal(measure(row(state.pairs, 'exchange_pair:usd_eur'), 'z_history', 'quoted_given'), 1.61,
      'edited source and full reversal net to the unreversed transfer');

    const stable = id(row(state.reversals, 'cash_fx_transfer_reversal:z_reverse'));
    await rejectsUnchanged(db, 'DELETE cash_fx_transfer:z_later_quote;', 'transfer source deletion while reversed rejects');
    await rejectsUnchanged(db, 'DELETE currency_exchange:main;', 'quote deletion while used rejects');
    await rejectsUnchanged(db, 'DELETE exchange_pair:usd_eur;', 'pair deletion while quote/transfer exist rejects');
    await db.query('DELETE cash_fx_transfer_reversal:z_reverse;');
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:usd_eur'), 'z_history', 'quoted_given'), 3.83,
      'deleting reversal restores all quote-derived volumes');
    await db.query(`CREATE ONLY cash_fx_transfer_reversal:z_reverse SET owned_by = rebase_group:root,
      source = cash_fx_transfer:z_later_quote, effective_at = d'2026-06-06T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(id(row(state.reversals, 'cash_fx_transfer_reversal:z_reverse')), stable, 'full reversal delete/re-add keeps stable ID');
    assert.equal(measure(row(state.pairs, 'exchange_pair:usd_eur'), 'z_history', 'quoted_given'), 1.61,
      're-added full reversal again excludes its source from net quote totals');

    const cutoff = Date.parse('2026-06-07T00:00:00Z');
    let expectedAsOf = 0;
    for (const transfer of state.transfers.filter((item) => rid(item.pair) === 'exchange_pair:usd_eur'
      && Date.parse(String(item.effective_at)) < cutoff)) expectedAsOf += n(transfer.from_amount);
    for (const reversal of state.reversals.filter((item) => rid(item.pair) === 'exchange_pair:usd_eur'
      && Date.parse(String(item.effective_at)) < cutoff)) {
      expectedAsOf -= n(row(state.transfers, rid(reversal.source)).from_amount);
    }
    const asOf = await queryResult(await db.query(`RETURN fn::tree::before(
      { rid: exchange_pair:usd_eur, slot: 'z_history' }, [d'2026-06-07T00:00:00Z']
    );`));
    near(n(asOf?.measures?.quoted_given?.sum), expectedAsOf,
      'pair as-of quote history matches direct transfer/reversal rows before the June 7 boundary');

    console.log('Accounting H6b explicit quote selection, currency-rounded transfers, separate pair history, historical quote usage, full reversals, and source-row oracles passed');
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
