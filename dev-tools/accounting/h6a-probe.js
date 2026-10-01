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
const id = (row) => String(row.id);
const ref = (value) => String(value);

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
    if (child.exitCode !== null) throw new Error(`H6a SurrealDB exited with ${child.exitCode}`);
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
  throw new Error('H6a SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    pairs: (SELECT * FROM exchange_pair ORDER BY id),
    exchanges: (SELECT * FROM cash_exchange ORDER BY id),
    reversals: (SELECT * FROM cash_exchange_reversal ORDER BY id),
    treasuries: (SELECT * FROM treasury_account ORDER BY id),
    quotes: (SELECT * FROM currency_exchange ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label, pattern) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), pattern, label);
  assert.deepEqual(await snapshot(db), before, `${label}: exchange graph and both treasury roots roll back`);
}

const row = (rows, key) => rows.find((item) => id(item) === key);
const measure = (record, name, extremum = 'sum') => n(record?.z_history?.summary?.measures?.[name]?.[extremum] ?? 0);

async function assertOracle(db) {
  const state = await snapshot(db);
  for (const account of state.treasuries) {
    const accountId = id(account);
    let expected = 0;
    const byTime = new Map();
    for (const exchange of state.exchanges) {
      if (ref(exchange.from_account) === accountId) {
        expected -= n(exchange.given_amount);
        const key = String(exchange.effective_at);
        byTime.set(key, (byTime.get(key) ?? 0) - n(exchange.given_amount));
      }
      if (ref(exchange.to_account) === accountId) {
        expected += n(exchange.received_amount);
        const key = String(exchange.effective_at);
        byTime.set(key, (byTime.get(key) ?? 0) + n(exchange.received_amount));
      }
    }
    for (const reversal of state.reversals) {
      if (ref(reversal.from_account) === accountId) {
        expected -= n(reversal.given_amount);
        const key = String(reversal.effective_at);
        byTime.set(key, (byTime.get(key) ?? 0) - n(reversal.given_amount));
      }
      if (ref(reversal.to_account) === accountId) {
        expected += n(reversal.received_amount);
        const key = String(reversal.effective_at);
        byTime.set(key, (byTime.get(key) ?? 0) + n(reversal.received_amount));
      }
    }
    assert.equal(measure(account, 'balance'), expected, `${accountId}: treasury history equals execution and reversal source rows`);
    let running = 0;
    let instantMin = 0;
    for (const delta of [...byTime.entries()].sort(([a], [b]) => Date.parse(a) - Date.parse(b)).map(([, value]) => value)) {
      running += delta;
      instantMin = Math.min(instantMin, running);
    }
    assert.equal(measure(account, 'balance', 'instant_min'), instantMin,
      `${accountId}: complete-time treasury floor equals grouped source-row effects`);
  }
  for (const pair of state.pairs) {
    const pairId = id(pair);
    let given = 0;
    let received = 0;
    for (const exchange of state.exchanges.filter((entry) => ref(entry.pair) === pairId)) {
      given += n(exchange.given_amount);
      received += n(exchange.received_amount);
    }
    for (const reversal of state.reversals.filter((entry) => ref(entry.pair) === pairId)) {
      const source = row(state.exchanges, ref(reversal.source));
      assert.ok(source, `${id(reversal)} resolves an existing direct source`);
      assert.equal(n(reversal.given_amount), n(source.received_amount), 'reversal treasury given leg is source received leg');
      assert.equal(n(reversal.received_amount), n(source.given_amount), 'reversal treasury received leg is source given leg');
      // Pair history is oriented like the original pair, not the swapped treasury legs.
      given -= n(source.given_amount);
      received -= n(source.received_amount);
    }
    assert.equal(measure(pair, 'executed_given'), given, `${pairId}: pair given sum matches source oracle`);
    assert.equal(measure(pair, 'executed_received'), received, `${pairId}: pair received sum matches source oracle`);
    const summary = await queryResult(await db.query(`SELECT id,
      IF ((z_history.summary.measures.executed_given.sum ?? 0dec) > 0dec)
      THEN <decimal>(z_history.summary.measures.executed_received.sum ?? 0dec)
        / (z_history.summary.measures.executed_given.sum ?? 0dec)
      ELSE NONE END AS reported_rate FROM exchange_pair WHERE id = ${pairId};`));
    const projection = summary[0]?.reported_rate ?? null;
    if (given > 0) assert.ok(Math.abs(n(projection) - received / given) < 1e-10, `${pairId}: read projection is ratio of net sums`);
    else assert.equal(projection, null, `${pairId}: zero denominator projects NONE`);
  }
  return state;
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h6a_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:entity SET owned_by = rebase_group:root, name = 'Entity';
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY rebase_group:second SET name = 'Second owner', parents = [rebase_group:root];
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY currency:jpy SET owned_by = rebase_group:root, code = 'JPY', name = 'JPY', precision = 0;
      CREATE ONLY treasury:usd SET owned_by = rebase_group:root, name = 'USD';
      CREATE ONLY treasury:eur SET owned_by = rebase_group:root, name = 'EUR';
      CREATE ONLY treasury:jpy SET owned_by = rebase_group:root, name = 'JPY';
      CREATE ONLY treasury:floor SET owned_by = rebase_group:root, name = 'Floor account';
      CREATE ONLY treasury:usd_other SET owned_by = rebase_group:root, name = 'USD other entity';
      CREATE ONLY treasury:eur_other SET owned_by = rebase_group:root, name = 'EUR other entity';
      CREATE ONLY treasury_account:usd SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:usd, currency = currency:usd, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:eur, currency = currency:eur, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:jpy SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:jpy, currency = currency:jpy, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:floor SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:floor, currency = currency:usd, minimum_balance = 0dec;
      CREATE ONLY treasury_account:usd_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        treasury = treasury:usd_other, currency = currency:usd, minimum_balance = -1000dec;
      CREATE ONLY treasury_account:eur_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        treasury = treasury:eur_other, currency = currency:eur, minimum_balance = -1000dec;
      CREATE ONLY exchange_pair:main SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:usd, received_resource = currency:eur;
      CREATE ONLY exchange_pair:inverse SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:eur, received_resource = currency:usd;
      CREATE ONLY exchange_pair:other_entity SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        given_resource = currency:usd, received_resource = currency:eur;
      CREATE ONLY exchange_pair:other_owner SET owned_by = rebase_group:second, economic_entity = organization:entity,
        given_resource = currency:usd, received_resource = currency:eur;
      CREATE ONLY exchange_pair:jpy_usd SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = currency:jpy, received_resource = currency:usd;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:widget SET owned_by = rebase_group:root, name = 'Widget', unit = measure_unit:each;
      CREATE ONLY service:repair SET owned_by = rebase_group:root, name = 'Repair', unit = measure_unit:each;
      CREATE ONLY exchange_pair:identity_only SET owned_by = rebase_group:root, economic_entity = organization:entity,
        given_resource = item:widget, received_resource = service:repair;
      CREATE ONLY currency_exchange:quote SET owned_by = rebase_group:root, pair = exchange_pair:main, from_currency = currency:usd,
        to_currency = currency:eur, rate = 0.5dec, effective_at = d'2026-01-01T00:00:00Z';
    `);
    await assertOracle(db);

    await rejectsUnchanged(db, `CREATE ONLY exchange_pair:duplicate SET owned_by = rebase_group:root,
      economic_entity = organization:entity, given_resource = currency:usd, received_resource = currency:eur;`,
    'same-owner/entity ordered pair duplicate rejects');
    await rejectsUnchanged(db, `CREATE ONLY exchange_pair:same SET owned_by = rebase_group:root,
      economic_entity = organization:entity, given_resource = currency:usd, received_resource = currency:usd;`,
    'same-resource pair rejects');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:identity_execution SET owned_by = rebase_group:root,
      pair = exchange_pair:identity_only, from_account = treasury_account:usd, to_account = treasury_account:eur,
      given_amount = 1dec, received_amount = 1dec, effective_at = d'2026-06-01T00:00:00Z';`,
    'item/service identity pair cannot be executed as a cash currency exchange');

    const raceClients = [new Surreal(), new Surreal()];
    let race;
    try {
      await Promise.all(raceClients.map(async (client) => {
        await client.connect(`ws://127.0.0.1:${port}/rpc`);
        await client.signin({ username: 'root', password: 'root' });
        await client.use({ namespace, database: 'probe' });
      }));
      race = await Promise.allSettled(raceClients.map((client, index) => client.query(
        `CREATE ONLY exchange_pair:race_${index} SET owned_by = rebase_group:root, economic_entity = organization:other_entity, given_resource = currency:eur, received_resource = currency:jpy;`
      )));
    } finally {
      await Promise.all(raceClients.map((client) => client.close().catch(() => {})));
    }
    assert.equal(race.filter((result) => result.status === 'fulfilled').length, 1, 'concurrent ordered-pair creation has one winner');
    assert.equal(race.filter((result) => result.status === 'rejected').length, 1, 'unique index rejects concurrent duplicate');

    await db.query(`CREATE ONLY cash_exchange:z_exec SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:usd, to_account = treasury_account:eur, given_amount = 100dec,
      received_amount = 90dec, effective_at = d'2026-06-01T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_exchange:a_exec SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:usd, to_account = treasury_account:eur, given_amount = 30dec,
      received_amount = 27dec, effective_at = d'2026-06-01T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_exchange:jpy_exec SET owned_by = rebase_group:root, pair = exchange_pair:jpy_usd,
      from_account = treasury_account:jpy, to_account = treasury_account:usd, given_amount = 7dec,
      received_amount = 6dec, effective_at = d'2026-06-01T00:00:00Z';`);
    let state = await assertOracle(db);
    assert.equal(measure(row(state.treasuries, 'treasury_account:usd'), 'balance'), -124, 'USD exchange debits and JPY exchange receipt post once');
    assert.equal(measure(row(state.treasuries, 'treasury_account:eur'), 'balance'), 117, 'both same-time inflows credit EUR once');
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 130, 'pair includes both same-time IDs independent of key order');
    const quote = row(state.quotes, 'currency_exchange:quote');
    assert.equal(quote.z_usage.summary.count, 0, 'entered exchange does not consume quote usage');

    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:bad_orientation SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:eur, to_account = treasury_account:usd, given_amount = 1dec,
      received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'wrong currency orientation rejects');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:bad_entity SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:usd_other, to_account = treasury_account:eur, given_amount = 1dec,
      received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'wrong economic entity rejects');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:bad_precision SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:usd, to_account = treasury_account:eur, given_amount = 1.001dec,
      received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'non-currency-precision amount rejects');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:bad_zero SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:usd, to_account = treasury_account:eur, given_amount = 0dec,
      received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'zero amount rejects');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:wrong_owner SET owned_by = rebase_group:root,
      pair = exchange_pair:other_owner, from_account = treasury_account:usd, to_account = treasury_account:eur,
      given_amount = 1dec, received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`,
    'root execution cannot use a same-entity pair owned by another group', /ACCOUNTING_CASH_EXCHANGE_OWNER_MISMATCH/);
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:jpy_bad_precision SET owned_by = rebase_group:root, pair = exchange_pair:jpy_usd,
      from_account = treasury_account:jpy, to_account = treasury_account:usd, given_amount = 1.5dec,
      received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'zero-decimal currency rejects fractional given amount');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange:floor_guard SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:floor, to_account = treasury_account:eur, given_amount = 1dec,
      received_amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`,
    'treasury floor rejects and rolls back the other treasury and pair roots');

    await db.query(`CREATE ONLY cash_exchange_reversal:z_reverse SET owned_by = rebase_group:root,
      source = cash_exchange:z_exec, effective_at = d'2026-06-01T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 30, 'asymmetric reversal subtracts source given volume');
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_received'), 27, 'asymmetric reversal subtracts source received volume');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange_reversal:z_duplicate SET owned_by = rebase_group:root,
      source = cash_exchange:z_exec, effective_at = d'2026-06-01T00:00:00Z';`, 'one reversal per source rejects duplicate');
    await rejectsUnchanged(db, `CREATE ONLY cash_exchange_reversal:before SET owned_by = rebase_group:root,
      source = cash_exchange:a_exec, effective_at = d'2026-05-31T00:00:00Z';`, 'reversal before source rejects');
    await rejectsUnchanged(db, "UPDATE cash_exchange:z_exec SET effective_at = d'2026-06-02T00:00:00Z';",
      'source date edit that would put dependent reversal before source rejects atomically');

    const originalReversal = row(state.reversals, 'cash_exchange_reversal:z_reverse');
    assert.equal(String(originalReversal.source_effective_at), String(row(state.exchanges, 'cash_exchange:z_exec').effective_at),
      'reversal maintains a typed reactive projection of its source date');
    await db.query("UPDATE cash_exchange_reversal:z_reverse SET effective_at = d'2026-06-03T00:00:00Z';");
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 30, 'rekeying a full reversal preserves net totals while changing its dated member');
    const asOf = await queryResult(await db.query(`RETURN fn::tree::before(
      { rid: exchange_pair:main, slot: 'z_history' }, [d'2026-06-02T00:00:00Z']
    );`));
    let beforeGiven = 0;
    let beforeReceived = 0;
    for (const exchange of state.exchanges.filter((entry) => ref(entry.pair) === 'exchange_pair:main' && Date.parse(String(entry.effective_at)) < Date.parse('2026-06-02T00:00:00Z'))) {
      beforeGiven += n(exchange.given_amount);
      beforeReceived += n(exchange.received_amount);
    }
    for (const reversal of state.reversals.filter((entry) => ref(entry.pair) === 'exchange_pair:main' && Date.parse(String(entry.effective_at)) < Date.parse('2026-06-02T00:00:00Z'))) {
      const source = row(state.exchanges, ref(reversal.source));
      beforeGiven -= n(source.given_amount);
      beforeReceived -= n(source.received_amount);
    }
    assert.equal(n(asOf?.measures?.executed_given?.sum), beforeGiven, 'pair as-of summary matches independent sources before the boundary');
    assert.equal(n(asOf?.measures?.executed_received?.sum), beforeReceived, 'pair as-of received summary matches independent sources before the boundary');
    await db.query('UPDATE cash_exchange:z_exec SET given_amount = 110dec, received_amount = 95dec;');
    state = await assertOracle(db);
    const refreshedReverse = row(state.reversals, 'cash_exchange_reversal:z_reverse');
    assert.equal(n(refreshedReverse.given_amount), 95, 'source edit refreshes the reversal treasury debit');
    assert.equal(n(refreshedReverse.received_amount), 110, 'source edit refreshes the reversal treasury credit');
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 30, 'source and full reversal net to the remaining execution');
    await rejectsUnchanged(db, 'UPDATE cash_exchange:a_exec SET received_amount = 24.001dec;',
      'inexact source amount edit rejects and restores both treasury roots and pair history');
    await db.query('UPDATE cash_exchange:a_exec SET received_amount = 24dec;');
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_received'), 24, 'valid unreversed source edit refreshes pair received amount');
    await rejectsUnchanged(db, 'DELETE cash_exchange:z_exec;', 'source deletion while reversal exists rejects');
    await rejectsUnchanged(db, 'DELETE treasury_account:usd;', 'used treasury account deletion rejects');
    await rejectsUnchanged(db, 'DELETE exchange_pair:main;', 'pair deletion while execution exists rejects');

    const stableReversal = id(row(state.reversals, 'cash_exchange_reversal:z_reverse'));
    await db.query('DELETE cash_exchange_reversal:z_reverse;');
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 140, 'reversal deletion restores all edited source amounts');
    await db.query(`CREATE ONLY cash_exchange_reversal:z_reverse SET owned_by = rebase_group:root,
      source = cash_exchange:z_exec, effective_at = d'2026-06-01T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(id(row(state.reversals, 'cash_exchange_reversal:z_reverse')), stableReversal, 'reversal re-add preserves stable ID');
    await db.query(`CREATE ONLY cash_exchange_reversal:a_reverse SET owned_by = rebase_group:root,
      source = cash_exchange:a_exec, effective_at = d'2026-06-01T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 0, 'full reversals empty the net given denominator');
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_received'), 0, 'full reversals empty the net received numerator');
    await db.query('DELETE cash_exchange_reversal:a_reverse;');
    await db.query('DELETE cash_exchange:a_exec;');
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 0, 'execution deletion removes its original and reversed contributions');
    await db.query(`CREATE ONLY cash_exchange:a_exec SET owned_by = rebase_group:root, pair = exchange_pair:main,
      from_account = treasury_account:usd, to_account = treasury_account:eur, given_amount = 30dec,
      received_amount = 24dec, effective_at = d'2026-06-01T00:00:00Z';`);
    state = await assertOracle(db);
    await db.query(`CREATE ONLY cash_exchange_reversal:a_reverse SET owned_by = rebase_group:root,
      source = cash_exchange:a_exec, effective_at = d'2026-06-01T00:00:00Z';`);
    state = await assertOracle(db);
    assert.equal(measure(row(state.pairs, 'exchange_pair:main'), 'executed_given'), 0, 'execution re-addition plus its one full reversal returns to zero');
    const rateRows = await queryResult(await db.query(`SELECT id,
      IF ($this.z_history.summary.measures.executed_given.sum > 0dec)
      THEN <decimal>($this.z_history.summary.measures.executed_received.sum) / ($this.z_history.summary.measures.executed_given.sum)
      ELSE NONE END AS reported_rate FROM exchange_pair WHERE id = exchange_pair:main;`));
    assert.equal(rateRows[0]?.reported_rate ?? null, null, 'reported rate projection is NONE at zero denominator');

    console.log('Accounting H6a ordered pairs, entered currency exchange, asymmetric full reversals, rate projection, atomicity, and source-row oracles passed');
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
