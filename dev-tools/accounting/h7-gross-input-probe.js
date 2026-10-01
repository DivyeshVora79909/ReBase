#!/usr/bin/env node

// Disposable feasibility probe for a gross-input capacity guard. All H7 tables
// and adapter extensions below exist only in this in-memory SurrealDB database.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');

const root = path.resolve(__dirname, '../..');
const value = (x) => Number(String(x ?? 0).replace(/dec$/i, ''));
const rid = (x) => String(x);
const rows = (x) => Array.isArray(x) ? x : [];

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', (e) => e ? reject(e) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const until = Date.now() + 5000;
  while (Date.now() < until) {
    if (child.exitCode !== null) throw new Error(`H7 SurrealDB exited with ${child.exitCode}`);
    const ok = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const done = (x) => { socket.destroy(); resolve(x); };
      socket.setTimeout(100, () => done(false));
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
    });
    if (ok) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H7 SurrealDB did not become ready');
}

function extendFunction(schema, name, edit) {
  const escaped = name.replaceAll(':', '\\:');
  const re = new RegExp(`DEFINE FUNCTION OVERWRITE ${escaped}\\([\\s\\S]*?\\} PERMISSIONS (?:FULL|NONE);`);
  const found = schema.match(re);
  assert.ok(found, `compiled profile contains ${name}`);
  return schema.replace(found[0], edit(found[0]));
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    accounts: (SELECT * FROM h7_account ORDER BY id),
    batches: (SELECT * FROM h7_batch ORDER BY id)
  };`));
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  let error;
  try { await db.query(statement); } catch (caught) { error = caught; }
  if (!error) throw new Error(`${label}: expected gross guard rejection; post-write state=${JSON.stringify(await snapshot(db))}`);
  assert.match(String(error), /H7_GROSS_INPUT_EXCEEDS_PRETIME_STOCK/, `${label}: expected the gross guard, got ${error}`);
  assert.deepEqual(await snapshot(db), before, `${label}: source and both temporal roots roll back`);
}

function reconstruct(state, accountId, beforeAt = undefined) {
  return rows(state.batches).filter((batch) => rid(batch.account) === accountId
    && (beforeAt === undefined || Date.parse(batch.effective_at) < Date.parse(beforeAt)))
    .reduce((sum, batch) => sum + value(batch.output_quantity) - value(batch.input_quantity), 0);
}

async function assertAccount(db, accountId) {
  const state = await snapshot(db);
  const account = rows(state.accounts).find((x) => rid(x.id) === accountId);
  const stock = value(account?.z_stock?.summary?.measures?.quantity?.sum);
  const gross = value(account?.z_gross_input?.summary?.measures?.gross_input?.sum);
  assert.equal(stock, reconstruct(state, accountId), `${accountId}: stock root matches source rows`);
  assert.equal(gross, rows(state.batches).filter((x) => rid(x.account) === accountId)
    .reduce((sum, x) => sum + value(x.input_quantity), 0), `${accountId}: gross root matches input source rows`);
  return { state, account, stock, gross };
}

async function main() {
  const original = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  let schema = original;
  schema = extendFunction(schema, 'fn::rebase::root_key_type', (body) => body.replace(
    "THROW 'TREE_UNKNOWN_ROOT'",
    "IF record::tb($link.rid) = 'h7_account' AND $link.slot IN ['z_stock', 'z_gross_input'] { RETURN 'datetime'; };\nTHROW 'TREE_UNKNOWN_ROOT'"));
  schema = extendFunction(schema, 'fn::rebase::membership_allowed', (body) => body.replace(
    'RETURN false;',
    "IF record::tb($link.rid) = 'h7_batch' AND $owner.rid = h7_account:zero AND $owner.slot IN ['z_stock', 'z_gross_input'] { RETURN $link.slot IN ['z_stock_member', 'z_gross_member']; };\nRETURN false;"));
  // The generic membership adapter needs account IDs other than :zero. Keep
  // the typed relationship limited to h7_batch -> h7_account roots.
  schema = schema.replaceAll("$owner.rid = h7_account:zero", "record::tb($owner.rid) = 'h7_account'");
  schema = extendFunction(schema, 'fn::rebase::slots', (body) => body.replace(
    'RETURN [];',
    "IF record::tb($rid) = 'h7_batch' { RETURN ['z_stock_member', 'z_gross_member']; };\nRETURN [];"));
  schema = extendFunction(schema, 'fn::rebase::members', (body) => body.replace(
    '\nRETURN []; } PERMISSIONS NONE;',
    "\nIF record::tb($row.id) = 'h7_batch' { RETURN fn::h7::batch_members($row); };\nRETURN []; } PERMISSIONS NONE;"));
  schema = extendFunction(schema, 'fn::rebase::validate', (body) => body.replace(
    '\n}',
    "\nIF record::tb($row.id) = 'h7_batch' { fn::h7::batch_validate($row); };\n}"));

  const port = await freePort();
  const namespace = `accounting_h7_gross_${Date.now().toString(36)}`;
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
      DEFINE TABLE h7_account SCHEMAFULL;
      DEFINE FIELD name ON h7_account TYPE string;
      DEFINE FIELD z_stock ON h7_account TYPE object FLEXIBLE DEFAULT { height: 0, revision: 0, refreshing: false, summary: fn::tree::empty() };
      DEFINE FIELD z_gross_input ON h7_account TYPE object FLEXIBLE DEFAULT { height: 0, revision: 0, refreshing: false, summary: fn::tree::empty() };
      DEFINE TABLE h7_batch SCHEMAFULL;
      DEFINE FIELD account ON h7_batch TYPE record<h7_account> REFERENCE ON DELETE REJECT;
      DEFINE FIELD effective_at ON h7_batch TYPE datetime;
      DEFINE FIELD input_quantity ON h7_batch TYPE decimal ASSERT $value >= 0dec;
      DEFINE FIELD output_quantity ON h7_batch TYPE decimal ASSERT $value >= 0dec;
      DEFINE FIELD z_stock_member ON h7_batch TYPE option<object> FLEXIBLE;
      DEFINE FIELD z_gross_member ON h7_batch TYPE option<object> FLEXIBLE;
      DEFINE FUNCTION OVERWRITE fn::h7::batch_members($row: object) {
        RETURN [
          fn::tree::member($row.id, 'z_stock_member', $row.account, 'z_stock', $row.effective_at,
            { quantity: $row.output_quantity - $row.input_quantity }, {}, {}, true),
          fn::tree::member($row.id, 'z_gross_member', $row.account, 'z_gross_input', $row.effective_at,
            { gross_input: $row.input_quantity }, {}, {}, false)
        ];
      } PERMISSIONS NONE;
      DEFINE FUNCTION OVERWRITE fn::h7::batch_validate($row: object) {
        LET $prior = fn::tree::before({ rid: $row.account, slot: 'z_stock' }, [$row.effective_at]);
        -- This foundation stores datetime ties at nanosecond precision, so the
        -- exclusive successor interval includes only the exact timestamp.
        LET $next = $row.effective_at + 1ns;
        LET $same_time = fn::tree::range({ rid: $row.account, slot: 'z_gross_input' }, [$row.effective_at], [$next]);
        IF ($same_time.measures.gross_input.sum ?? 0dec) > ($prior.measures.quantity.sum ?? 0dec) {
          THROW 'H7_GROSS_INPUT_EXCEEDS_PRETIME_STOCK';
        };
      } PERMISSIONS NONE;
      DEFINE EVENT h7_batch_refresh ON h7_batch
      WHEN $event != 'UPDATE' OR ($before.account != $after.account OR $before.effective_at != $after.effective_at
        OR $before.input_quantity != $after.input_quantity OR $before.output_quantity != $after.output_quantity) THEN {
        LET $image = IF $event = 'CREATE' THEN NONE ELSE $before END;
        fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $image, true));
      };
    `);
    await db.query(`CREATE ONLY h7_account:zero SET name = 'zero prior stock';
      CREATE ONLY h7_account:opening SET name = 'prior stock';
      CREATE ONLY h7_account:reverse SET name = 'reverse insertion order';
      CREATE ONLY h7_account:later SET name = 'later use';
      CREATE ONLY h7_account:range_exact SET name = 'sub-millisecond chronology';`);
    await db.query(`CREATE ONLY h7_batch:opening SET account = h7_account:opening,
      effective_at = d'2026-07-01T00:00:00Z', input_quantity = 0dec, output_quantity = 10dec;`);
    await db.query(`CREATE ONLY h7_batch:reverse_opening SET account = h7_account:reverse,
      effective_at = d'2026-07-01T00:00:00Z', input_quantity = 0dec, output_quantity = 10dec;`);
    await db.query(`CREATE ONLY h7_batch:later_opening SET account = h7_account:later,
      effective_at = d'2026-07-01T00:00:00Z', input_quantity = 0dec, output_quantity = 10dec;`);
    await db.query(`CREATE ONLY h7_batch:range_opening SET account = h7_account:range_exact,
      effective_at = d'2026-07-01T00:00:00Z', input_quantity = 0dec, output_quantity = 6dec;`);

    await rejectsUnchanged(db, `CREATE ONLY h7_batch:zero_self_funding SET account = h7_account:zero,
      effective_at = d'2026-07-02T00:00:00Z', input_quantity = 1dec, output_quantity = 1dec;`,
    'zero-prior same-time input 1/output 1');
    const zero = await assertAccount(db, 'h7_account:zero');
    assert.equal(zero.stock, 0, 'zero-prior rejected batch left net stock unchanged');
    assert.equal(zero.gross, 0, 'zero-prior rejected batch left gross demand unchanged');
    assert.equal(1 - 1, 0, 'hypothetical same-time batch net is zero and would pass a net floor');

    await db.query(`CREATE ONLY h7_batch:a_first SET account = h7_account:opening,
      effective_at = d'2026-07-02T00:00:00Z', input_quantity = 6dec, output_quantity = 0dec;`);
    await rejectsUnchanged(db, `CREATE ONLY h7_batch:z_second SET account = h7_account:opening,
      effective_at = d'2026-07-02T00:00:00Z', input_quantity = 6dec, output_quantity = 0dec;`,
    'same-time aggregate demand 12 exceeds pre-time stock 10');
    let opening = await assertAccount(db, 'h7_account:opening');
    assert.equal(opening.stock, 4);
    assert.equal(opening.gross, 6);
    await rejectsUnchanged(db, `UPDATE h7_batch:opening SET output_quantity = 5dec;`,
      'earlier opening reduction rechecks later gross input and rolls back');
    await rejectsUnchanged(db, `DELETE h7_batch:opening;`,
      'earlier opening deletion rechecks later gross input and rolls back');

    // Reverse both insertion and record-ID order on a separate identical account.
    await db.query(`CREATE ONLY h7_batch:z_first SET account = h7_account:reverse,
      effective_at = d'2026-07-02T00:00:00Z', input_quantity = 6dec, output_quantity = 0dec;`);
    await rejectsUnchanged(db, `CREATE ONLY h7_batch:a_second SET account = h7_account:reverse,
      effective_at = d'2026-07-02T00:00:00Z', input_quantity = 6dec, output_quantity = 0dec;`,
    'reverse-ID same-time aggregate demand 12 exceeds pre-time stock 10');
    const reversed = await assertAccount(db, 'h7_account:reverse');
    assert.equal(reversed.stock, 4);
    assert.equal(reversed.gross, 6);

    await db.query(`CREATE ONLY h7_batch:later_use SET account = h7_account:later,
      effective_at = d'2026-07-03T00:00:00Z', input_quantity = 6dec, output_quantity = 0dec;`);
    const later = await assertAccount(db, 'h7_account:later');
    const earlier = await queryResult(await db.query(`RETURN fn::tree::before(
      { rid: h7_account:later, slot: 'z_stock' }, [d'2026-07-03T00:00:00Z']
    ).measures.quantity.sum;`));
    assert.equal(value(earlier), 10, 'pre-event as-of stock at July 3 remains the prior-time grant of 10');
    assert.equal(later.stock, 4, 'prior-time stock grant is usable by later gross demand');
    assert.equal(later.gross, 6);

    // All three events fit inside one millisecond but are distinct supported
    // datetimes. A millisecond range would incorrectly combine their demand.
    await db.query(`CREATE ONLY h7_batch:range_replenish SET account = h7_account:range_exact,
      effective_at = d'2026-07-04T00:00:00.000500Z', input_quantity = 0dec, output_quantity = 6dec;`);
    await db.query(`CREATE ONLY h7_batch:range_later_demand SET account = h7_account:range_exact,
      effective_at = d'2026-07-04T00:00:00.000750Z', input_quantity = 6dec, output_quantity = 0dec;`);
    await db.query(`CREATE ONLY h7_batch:range_earlier_demand SET account = h7_account:range_exact,
      effective_at = d'2026-07-04T00:00:00.000000Z', input_quantity = 6dec, output_quantity = 0dec;`);
    const exact = await assertAccount(db, 'h7_account:range_exact');
    assert.equal(exact.stock, 0, 'distinct sub-millisecond events settle in chronological order');
    assert.equal(exact.gross, 12, 'total demand 12 is split across distinct valid timestamps');
    const nanos = await queryResult(await db.query(`LET $at = d'2026-07-04T00:00:00.000000000Z';
      LET $one_ns = $at + 1ns;
      RETURN {
        distinct: $at != $one_ns,
        exact: fn::tree::range({ rid: h7_account:range_exact, slot: 'z_gross_input' }, [$at], [$one_ns]).measures.gross_input.sum,
        one_ms: fn::tree::range({ rid: h7_account:range_exact, slot: 'z_gross_input' }, [$at], [$at + 1ms]).measures.gross_input.sum
      };`));
    assert.equal(nanos.distinct, true, 'SurrealDB preserves a one-nanosecond datetime distinction');
    assert.equal(value(nanos.exact), 6, 'the exclusive one-nanosecond successor interval contains only exact-time demand');
    assert.equal(value(nanos.one_ms), 12, 'the one-millisecond interval would incorrectly group a later demand');

    console.log('H7 gross-input feasibility probe passed on SurrealDB memory server.');
    console.log('The settled batch validator read gross demand from its schema-owned root and pre-time availability from fn::tree::before; equal-time outputs did not fund gross input.');
  } finally {
    await db.close().catch(() => {});
    child.kill('SIGTERM');
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
