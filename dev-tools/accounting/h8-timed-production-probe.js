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
const byId = (list, id) => rows(list).find((x) => rid(x.id) === id);
const keyTime = (x) => new Date(x).toISOString();

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
    if (child.exitCode !== null) throw new Error(`H8 production SurrealDB exited with ${child.exitCode}`);
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
  throw new Error('H8 production SurrealDB did not become ready');
}
async function state(db) {
  return queryResult(await db.query(`RETURN {
    accounts: (SELECT * FROM stock_account ORDER BY id),
    stockIn: (SELECT * FROM stock_in ORDER BY id), stockOut: (SELECT * FROM stock_out ORDER BY id),
    stockReturns: (SELECT * FROM stock_return ORDER BY id), stockTransfers: (SELECT * FROM stock_transfer ORDER BY id),
    recipes: (SELECT * FROM production_recipe_version ORDER BY id), runs: (SELECT * FROM production_run ORDER BY id),
    inputs: (SELECT * FROM production_input ORDER BY id), outputs: (SELECT * FROM production_output ORDER BY id)
  };`));
}
async function rejectsUnchanged(db, statement, label, pattern) {
  const before = await state(db);
  try { await assert.rejects(() => db.query(statement), pattern, label); }
  catch (error) { if (pattern) console.error(label, error.actual?.toString?.() ?? error); throw error; }
  assert.deepEqual(await state(db), before, `${label}: full source, managed-child, and root snapshot rolls back`);
}
function addEvent(events, at, q, a) {
  const k = keyTime(at); const x = events.get(k) ?? { quantity: 0, available: 0 };
  x.quantity += q; x.available += a; events.set(k, x);
}
function summarize(events) {
  let quantity = 0; let available = 0; let qmin = 0; let amin = 0;
  for (const k of [...events.keys()].sort()) {
    const e = events.get(k); quantity += e.quantity; available += e.available;
    qmin = Math.min(qmin, quantity); amin = Math.min(amin, available);
  }
  return { quantity, available, qmin, amin };
}
function durationMs(value) {
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(String(value));
  assert(match, `probe oracle supports the fixture's fixed duration format, got ${String(value)}`);
  const factor = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 }[match[2]];
  return Number(match[1]) * factor;
}
function runEnd(run, recipe) {
  return new Date(new Date(run.planned_start).getTime() + durationMs(recipe.duration)).toISOString();
}
function expectedRunRoles(data, run) {
  const recipe = byId(data.recipes, rid(run.recipe_version));
  assert(recipe, `${run.id}: selected immutable recipe exists`);
  const canceledBeforeStart = run.status === 'cancelled' && new Date(run.cancelled_at) <= new Date(run.planned_start);
  if (run.status === 'draft' || canceledBeforeStart) return [];
  const count = n(run.batch_count);
  const endAt = runEnd(run, recipe);
  const inputRows = ['input_a', 'input_b'].map((role) => ({
    table: 'production_input', role, run, recipe,
    stock_account: recipe[`${role}_account`],
    quantity: count * n(recipe[`${role}_quantity`]),
    planned_start: run.planned_start, end_at: endAt,
    status: run.status, cancelled_at: run.cancelled_at
  }));
  if (run.status === 'cancelled') return inputRows;
  return [...inputRows, ...['output_a', 'output_b'].map((role) => ({
    table: 'production_output', role, run, recipe,
    stock_account: recipe[`${role}_account`],
    quantity: count * n(recipe[`${role}_quantity`]),
    effective_at: endAt
  }))];
}
function assertManagedRoles(data) {
  const expected = rows(data.runs).flatMap((run) => expectedRunRoles(data, run));
  const actual = [
    ...rows(data.inputs).map((x) => ({ ...x, table: 'production_input' })),
    ...rows(data.outputs).map((x) => ({ ...x, table: 'production_output' }))
  ];
  assert.equal(actual.length, expected.length, 'required managed role rows exactly match source runs and immutable recipes');
  for (const role of expected) {
    const child = actual.find((x) => x.table === role.table
      && rid(x.rebase_managed_source) === rid(role.run.id)
      && x.rebase_managed_role === role.role);
    assert(child, `${role.run.id}/${role.role}: expected managed role exists`);
    assert.equal(rid(child.stock_account), rid(role.stock_account), `${child.id}: account derives from selected recipe role`);
    assert.equal(n(child.quantity), role.quantity, `${child.id}: quantity derives from batch count and immutable coefficient`);
    if (role.table === 'production_input') {
      assert.equal(keyTime(child.planned_start), keyTime(role.planned_start), `${child.id}: reservation start matches run`);
      assert.equal(keyTime(child.end_at), keyTime(role.end_at), `${child.id}: end matches start plus immutable recipe duration`);
      assert.equal(child.status, role.status, `${child.id}: lifecycle state follows source run`);
      assert.equal(child.cancelled_at == null ? null : keyTime(child.cancelled_at),
        role.cancelled_at == null ? null : keyTime(role.cancelled_at), `${child.id}: cancellation timestamp follows source run`);
    } else {
      assert.equal(keyTime(child.effective_at), keyTime(role.effective_at), `${child.id}: output date matches fixed run end`);
    }
  }
  for (const child of actual) {
    assert(expected.some((role) => role.table === child.table
      && rid(role.run.id) === rid(child.rebase_managed_source)
      && role.role === child.rebase_managed_role), `${child.id}: no extraneous managed role row`);
  }
}
function expectedAccount(data, accountId) {
  const events = new Map();
  for (const x of rows(data.stockIn)) if (rid(x.to_account) === accountId) addEvent(events, x.effective_at, n(x.quantity), n(x.quantity));
  for (const x of rows(data.stockOut)) if (rid(x.from_account) === accountId) addEvent(events, x.effective_at, -n(x.quantity), -n(x.quantity));
  for (const x of rows(data.stockReturns)) if (rid(x.destination_account) === accountId) addEvent(events, x.effective_at, n(x.quantity), n(x.quantity));
  for (const x of rows(data.stockTransfers)) {
    if (rid(x.from_account) === accountId) addEvent(events, x.effective_at, -n(x.quantity), -n(x.quantity));
    if (rid(x.to_account) === accountId) addEvent(events, x.effective_at, n(x.quantity), n(x.quantity));
  }
  for (const run of rows(data.runs)) for (const role of expectedRunRoles(data, run)) if (rid(role.stock_account) === accountId) {
    if (role.table === 'production_input' && role.status === 'scheduled') {
      addEvent(events, role.planned_start, 0, -role.quantity);
      addEvent(events, role.end_at, -role.quantity, 0);
    } else if (role.table === 'production_input' && role.status === 'cancelled') {
      addEvent(events, role.planned_start, 0, -role.quantity);
      addEvent(events, role.cancelled_at, 0, role.quantity);
    } else if (role.table === 'production_output') {
      addEvent(events, role.effective_at, role.quantity, role.quantity);
    }
  }
  return summarize(events);
}
function grossExpected(data, accountId) {
  return rows(data.runs).flatMap((run) => expectedRunRoles(data, run))
    .filter((x) => x.table === 'production_input' && x.status === 'scheduled' && rid(x.stock_account) === accountId)
    .reduce((s, x) => s + x.quantity, 0);
}
function outputCapacityExpected(data, outputId) {
  const events = new Map();
  for (const x of rows(data.stockOut).filter((r) => rid(r.production_output) === outputId)) {
    const k = keyTime(x.effective_at); events.set(k, (events.get(k) ?? 0) - n(x.quantity));
  }
  let sum = 0; let min = 0;
  for (const k of [...events.keys()].sort()) { sum += events.get(k); min = Math.min(min, sum); }
  return { sum, min };
}
function assertOracle(data) {
  assertManagedRoles(data);
  for (const a of rows(data.accounts)) {
    const expected = expectedAccount(data, rid(a.id));
    const q = a.z_history?.summary?.measures?.quantity ?? {};
    const av = a.z_history?.summary?.measures?.available ?? {};
    assert.equal(n(q.sum), expected.quantity, `${a.id}: physical source oracle matches quantity.sum`);
    assert.equal(n(q.instant_min), expected.qmin, `${a.id}: physical source oracle matches quantity.instant_min`);
    assert.equal(n(av.sum), expected.available, `${a.id}: free source oracle matches available.sum`);
    assert.equal(n(av.instant_min), expected.amin, `${a.id}: free source oracle matches available.instant_min`);
    assert.equal(n(a.z_gross_input?.summary?.measures?.gross_input?.sum ?? 0), grossExpected(data, rid(a.id)), `${a.id}: scheduled gross demand derives from input rows`);
  }
  for (const o of rows(data.outputs)) {
    const expected = outputCapacityExpected(data, rid(o.id));
    const q = o.z_capacity?.summary?.measures?.quantity ?? {};
    assert.equal(n(q.sum), expected.sum, `${o.id}: output use sum derives from linked stock_out rows`);
    assert.equal(n(q.instant_min), expected.min, `${o.id}: output use minimum derives from linked stock_out rows`);
    assert.ok(-expected.min <= n(o.quantity), `${o.id}: downstream draws do not exceed output quantity`);
  }
  return data;
}
async function assertAt(db) { return assertOracle(await state(db)); }

async function concurrentRuns(db, endpoint, namespace) {
  // Reverse the input traversal and change one output owner: the two writes
  // share roots but do not touch identical owner sets.
  await db.query(`CREATE ONLY production_recipe_version:reverse SET owned_by=rebase_group:root,
    recipe_key='reverse',version='1',economic_entity=organization:entity,duration=1h,
    input_a_account=stock_account:input_b,input_a_quantity=1,
    input_b_account=stock_account:input_a,input_b_quantity=1,
    output_a_account=stock_account:output_b,output_a_quantity=1,
    output_b_account=stock_account:shared,output_b_quantity=1;`);
  const peer = new Surreal();
  const commands = ['split', 'reverse'].map((recipe, index) =>
    `CREATE ONLY production_run:concurrent_${index} SET owned_by=rebase_group:root,
      recipe_version=production_recipe_version:${recipe},batch_count=1,
      planned_start=d'2026-07-08T00:00:00Z',status='scheduled';`);
  try {
    await peer.connect(endpoint);
    await peer.signin({ username: 'root', password: 'root' });
    await peer.use({ namespace, database: 'probe' });
    // Keep both transactions open briefly to exercise commit contention.
    // Correctness does not require a particular client to win the race.
    const attempts = await Promise.allSettled([db, peer].map(async (client, index) => {
      // collect()/await may throw an earlier NotExecuted wrapper instead of
      // the commit conflict. Inspect all responses before classifying a retry.
      const responses = await client.query(`BEGIN TRANSACTION; ${commands[index]} SLEEP 250ms; COMMIT TRANSACTION;`).responses();
      const errors = responses.filter((response) => !response.success).map((response) => response.error);
      // SurrealDB 3.2.0 also labels the final COMMIT conflict NotExecuted;
      // retain that final cause when every response has the wrapper kind.
      if (errors.length) throw errors.find((error) => !error.isNotExecuted) ?? errors.at(-1);
    }));
    const committed = attempts.filter((attempt) => attempt.status === 'fulfilled').length;
    assert(committed >= 1, 'at least one competing production transaction commits');
    const afterRace = await assertAt(db);
    for (const [index, attempt] of attempts.entries()) {
      const source = byId(afterRace.runs, `production_run:concurrent_${index}`);
      assert.equal(!!source, attempt.status === 'fulfilled', 'failed competing write leaves no source or managed effects');
      if (attempt.status === 'rejected') {
        assert.match(String(attempt.reason), /conflict|retry/i, 'only a transaction conflict may be retried');
        await db.query(commands[index]);
        await assertAt(db);
      }
    }
    const afterRetry = await assertAt(db);
    for (const index of [0, 1]) {
      const id = `production_run:concurrent_${index}`;
      assert.equal(afterRetry.runs.filter((run) => rid(run.id) === id).length, 1, 'retry preserves one business source');
      assert.equal([...afterRetry.inputs, ...afterRetry.outputs].filter((row) => rid(row.rebase_managed_source) === id).length,
        4, 'each committed business source has exactly four managed effects');
      await rejectsUnchanged(db, commands[index], 'replaying a committed business identity cannot duplicate effects');
    }
    console.log(`H8 concurrent writes: ${committed} initial commits, ${2 - committed} conflict retries; both independent owner/role oracles passed`);
    return afterRetry;
  } finally {
    await peer.close().catch(() => {});
  }
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort(); const namespace = `accounting_h8_${Date.now().toString(36)}`;
  const child = spawn('surreal', ['start', 'memory', '--user', 'root', '--pass', 'root', '--bind', `127.0.0.1:${port}`, '--no-banner', '--log', 'error'], { cwd: root, stdio: ['ignore', 'ignore', 'ignore'] });
  const db = new Surreal();
  try {
    await waitForPort(port, child);
    await db.connect(`ws://127.0.0.1:${port}/rpc`); await db.signin({ username: 'root', password: 'root' });
    await db.query(`DEFINE NAMESPACE ${namespace};`); await db.use({ namespace }); await db.query('DEFINE DATABASE probe;'); await db.use({ namespace, database: 'probe' });
    await db.query(schema);
    await db.query(`
      CREATE ONLY organization:entity SET owned_by=rebase_group:root, name='Entity';
      CREATE ONLY misc_account:opening SET owned_by=rebase_group:root, label='Opening';
      CREATE ONLY misc_account:customer SET owned_by=rebase_group:root, label='Customer';
      CREATE ONLY measure_unit:each SET owned_by=rebase_group:root, code='each', dimension='count', name='Each';
      CREATE ONLY item:shared SET owned_by=rebase_group:root, name='Shared', unit=measure_unit:each;
      CREATE ONLY item:input_a SET owned_by=rebase_group:root, name='Input A', unit=measure_unit:each;
      CREATE ONLY item:input_b SET owned_by=rebase_group:root, name='Input B', unit=measure_unit:each;
      CREATE ONLY item:output_a SET owned_by=rebase_group:root, name='Output A', unit=measure_unit:each;
      CREATE ONLY item:output_b SET owned_by=rebase_group:root, name='Output B', unit=measure_unit:each;
      CREATE ONLY operating_unit:shared SET owned_by=rebase_group:root, economic_entity=organization:entity, name='Shared', code='shared';
      CREATE ONLY operating_unit:input_a SET owned_by=rebase_group:root, economic_entity=organization:entity, name='Input A', code='input_a';
      CREATE ONLY operating_unit:input_b SET owned_by=rebase_group:root, economic_entity=organization:entity, name='Input B', code='input_b';
      CREATE ONLY operating_unit:output_a SET owned_by=rebase_group:root, economic_entity=organization:entity, name='Output A', code='output_a';
      CREATE ONLY operating_unit:output_b SET owned_by=rebase_group:root, economic_entity=organization:entity, name='Output B', code='output_b';
      CREATE ONLY stock_account:shared SET owned_by=rebase_group:root, economic_entity=organization:entity, operating_unit=operating_unit:shared, resource=item:shared, minimum_quantity=0dec;
      CREATE ONLY stock_account:input_a SET owned_by=rebase_group:root, economic_entity=organization:entity, operating_unit=operating_unit:input_a, resource=item:input_a, minimum_quantity=0dec;
      CREATE ONLY stock_account:input_b SET owned_by=rebase_group:root, economic_entity=organization:entity, operating_unit=operating_unit:input_b, resource=item:input_b, minimum_quantity=0dec;
      CREATE ONLY stock_account:output_a SET owned_by=rebase_group:root, economic_entity=organization:entity, operating_unit=operating_unit:output_a, resource=item:output_a, minimum_quantity=0dec;
      CREATE ONLY stock_account:output_b SET owned_by=rebase_group:root, economic_entity=organization:entity, operating_unit=operating_unit:output_b, resource=item:output_b, minimum_quantity=0dec;
      CREATE ONLY stock_in:open_shared SET owned_by=rebase_group:root, from_party=misc_account:opening, to_account=stock_account:shared, quantity=10dec, effective_at=d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_input_a SET owned_by=rebase_group:root, from_party=misc_account:opening, to_account=stock_account:input_a, quantity=20dec, effective_at=d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_in:open_input_b SET owned_by=rebase_group:root, from_party=misc_account:opening, to_account=stock_account:input_b, quantity=20dec, effective_at=d'2026-07-01T00:00:00Z';
      CREATE ONLY production_recipe_version:shared SET owned_by=rebase_group:root, recipe_key='shared', version='1', economic_entity=organization:entity, duration=1h,
        input_a_account=stock_account:shared,input_a_quantity=3,input_b_account=stock_account:shared,input_b_quantity=3,
        output_a_account=stock_account:shared,output_a_quantity=1,output_b_account=stock_account:shared,output_b_quantity=1;
      CREATE ONLY production_recipe_version:split SET owned_by=rebase_group:root, recipe_key='split', version='1', economic_entity=organization:entity, duration=1h,
        input_a_account=stock_account:input_a,input_a_quantity=1,input_b_account=stock_account:input_b,input_b_quantity=1,
        output_a_account=stock_account:output_a,output_a_quantity=2,output_b_account=stock_account:output_b,output_b_quantity=1;
      CREATE ONLY production_recipe_version:zero SET owned_by=rebase_group:root, recipe_key='zero', version='1', economic_entity=organization:entity, duration=1h,
        input_a_account=stock_account:output_a,input_a_quantity=1,input_b_account=stock_account:output_b,input_b_quantity=1,
        output_a_account=stock_account:output_a,output_a_quantity=1,output_b_account=stock_account:output_b,output_b_quantity=1;
      CREATE ONLY production_recipe_version:capacity SET owned_by=rebase_group:root, recipe_key='capacity', version='1', economic_entity=organization:entity, duration=1h,
        input_a_account=stock_account:input_a,input_a_quantity=1,input_b_account=stock_account:input_b,input_b_quantity=1,
        output_a_account=stock_account:output_a,output_a_quantity=2,output_b_account=stock_account:output_b,output_b_quantity=1;
    `);
    await assertAt(db);
    const beforeDraft = await state(db);
    await db.query(`CREATE ONLY production_run:draft SET owned_by=rebase_group:root,recipe_version=production_recipe_version:split,batch_count=1,planned_start=d'2026-07-02T00:00:00Z',status='draft';`);
    let draftState = await assertAt(db);
    assert.equal(draftState.inputs.length,0,'draft has no input role rows');
    assert.equal(draftState.outputs.length,0,'draft has no output role rows');
    assert.deepEqual(draftState.accounts,beforeDraft.accounts,'draft has no stock, reservation, or gross-demand effect');

    // Scheduled inputs reserve free stock at start. Ordinary stock_out sees the
    // shared available floor and cannot spend the held units.
    await db.query(`CREATE ONLY production_run:shared SET owned_by=rebase_group:root,recipe_version=production_recipe_version:shared,batch_count=1,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`);
    let s = await assertAt(db);
    await rejectsUnchanged(db,`CREATE ONLY production_run:shared SET owned_by=rebase_group:root,recipe_version=production_recipe_version:shared,batch_count=1,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`,'duplicate run retry rejects with unchanged required outputs and roots');
    const repeatedSchedule = await state(db);
    await db.query(`UPDATE production_run:shared SET status='scheduled';`);
    assert.deepEqual(await state(db),repeatedSchedule,'repeating scheduled state preserves stable role IDs and roots');
    const shared = byId(s.accounts,'stock_account:shared');
    assert.equal(n(shared.z_history.summary.measures.quantity.sum),6,'whole-history physical net includes the planned end effects');
    assert.equal(n(shared.z_history.summary.measures.available.sum),6,'whole-history free net includes end output availability');
    await rejectsUnchanged(db,`UPDATE production_run:shared SET end_at=d'2026-07-02T09:00:00Z';`,
      'conflicting fixed end time cannot override planned_start plus immutable duration');
    const mid = queryResult(await db.query(`RETURN fn::tree::before({rid:stock_account:shared,slot:'z_history'},[d'2026-07-02T01:00:00Z']);`));
    assert.equal(n(mid.measures.quantity.sum),10,'physical quantity remains 10 before the exact end');
    assert.equal(n(mid.measures.available.sum),4,'mid-run available as-of excludes the six reserved units');
    await rejectsUnchanged(db,`CREATE ONLY stock_out:spend_hold SET owned_by=rebase_group:root,from_account=stock_account:shared,to_party=misc_account:customer,quantity=5dec,effective_at=d'2026-07-02T00:30:00Z';`,'ordinary stock_out cannot spend a live reservation');
    await rejectsUnchanged(db,`CREATE ONLY production_run:self_fund SET owned_by=rebase_group:root,recipe_version=production_recipe_version:zero,batch_count=1,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`,'same-account output at end cannot self-fund gross input');
    await db.query(`UPDATE production_run:shared SET planned_start=d'2026-07-02T01:00:00Z';`);
    s = await assertAt(db); assert.equal(keyTime(s.inputs.find((x) => rid(x.rebase_managed_source)==='production_run:shared').end_at), '2026-07-02T02:00:00.000Z','date shift refreshes stable child end from immutable duration');
    await rejectsUnchanged(db,`UPDATE production_run:shared SET end_at=d'2026-07-02T09:00:00Z';`,
      'run has no writable end field; end is derived from start and immutable duration');
    await db.query(`UPDATE production_run:shared SET planned_start=d'2026-07-02T00:00:00Z';`);
    await db.query(`UPDATE production_run:shared SET status='cancelled',cancelled_at=d'2026-07-02T00:00:00Z';`);
    s = await assertAt(db); assert.equal(s.inputs.length,0,'cancellation at start removes reservation and all future effects');
    await db.query(`UPDATE production_run:shared SET status='scheduled',cancelled_at=NONE;`);
    await db.query(`UPDATE production_run:shared SET status='cancelled',cancelled_at=d'2026-07-02T00:30:00Z';`);
    s = await assertAt(db);
    assert.equal(n(byId(s.accounts,'stock_account:shared').z_history.summary.measures.quantity.sum),10,'post-start cancellation has no physical consumption');
    assert.equal(n(byId(s.accounts,'stock_account:shared').z_history.summary.measures.available.sum),10,'post-start cancellation releases the hold');
    await rejectsUnchanged(db,`UPDATE production_run:shared SET cancelled_at=d'2026-07-02T01:00:00Z';`,'cancellation at/after fixed end rejects');
    await db.query(`UPDATE production_run:shared SET status='scheduled',cancelled_at=NONE;`);

    // Exact end timestamp coalesces input consumption and output grant while
    // physical and free stock remain independently reconstructable.
    await db.query(`UPDATE production_run:shared SET status='cancelled',cancelled_at=d'2026-07-02T00:30:00Z';`);
    await db.query(`DELETE production_run:shared;`);
    await db.query(`CREATE ONLY production_run:shared SET owned_by=rebase_group:root,recipe_version=production_recipe_version:shared,batch_count=1,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`);
    s = await assertAt(db);
    const endSnap = await queryResult(await db.query(`RETURN { before: fn::tree::before({rid:stock_account:shared,slot:'z_history'},[d'2026-07-02T01:00:00Z']), after: stock_account:shared.z_history.summary };`));
    assert.equal(n(endSnap.before.measures.quantity.sum),10,'physical stock before exact end remains 10');
    assert.equal(n(endSnap.before.measures.available.sum),4,'reserved free stock before exact end is 4');
    assert.equal(n(byId(s.accounts,'stock_account:shared').z_history.summary.measures.quantity.sum),6,'end consumes six and produces two physical units');
    assert.equal(n(byId(s.accounts,'stock_account:shared').z_history.summary.measures.available.sum),6,'end releases held inputs and grants two output units');
    const outputARef = rid(s.outputs.find((x) => x.rebase_managed_role === 'output_a' && rid(x.rebase_managed_source) === 'production_run:shared').id);
    await db.query(`CREATE ONLY stock_out:use_output SET owned_by=rebase_group:root,from_account=stock_account:shared,to_party=misc_account:customer,quantity=1dec,effective_at=d'2026-07-02T01:00:00Z',production_output=${outputARef};`);
    s = await assertAt(db);
    await rejectsUnchanged(db,`UPDATE production_run:shared SET batch_count=0;`,'invalid output reduction attempt rolls back');
    await rejectsUnchanged(db,`UPDATE production_run:shared SET planned_start=d'2026-07-02T01:00:00Z';`,'moving output after its consumer rejects atomically');
    await rejectsUnchanged(db,`DELETE production_run:shared;`,'deleting a run with a used output rejects atomically');
    await rejectsUnchanged(db,`UPDATE stock_out:use_output SET production_output=NONE;`,'linked output cannot be unlinked to evade capacity');
    await db.query(`DELETE stock_out:use_output;`);
    await db.query(`DELETE production_run:shared;`);
    s = await assertAt(db); assert.equal(s.inputs.length,0); assert.equal(s.outputs.length,0,'deleting scheduled run prunes every required output');

    // Split-account planned inputs support overlapping capacity and date shifts.
    await db.query(`CREATE ONLY production_recipe_version:pair6 SET owned_by=rebase_group:root,recipe_key='pair6',version='1',economic_entity=organization:entity,duration=1h,
      input_a_account=stock_account:input_a,input_a_quantity=6,input_b_account=stock_account:input_b,input_b_quantity=1,
      output_a_account=stock_account:output_a,output_a_quantity=1,output_b_account=stock_account:output_b,output_b_quantity=1;`);
    await db.query(`CREATE ONLY production_run:overlap_a SET owned_by=rebase_group:root,recipe_version=production_recipe_version:pair6,batch_count=1,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`);
    await rejectsUnchanged(db,`CREATE ONLY production_run:overlap_b SET owned_by=rebase_group:root,recipe_version=production_recipe_version:pair6,batch_count=3,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`,'overlapping holds reject aggregate excess in second ID order');
    await rejectsUnchanged(db,`CREATE ONLY production_run:0overlap SET owned_by=rebase_group:root,recipe_version=production_recipe_version:pair6,batch_count=3,planned_start=d'2026-07-02T00:00:00Z',status='scheduled';`,'overlapping holds reject aggregate excess in reverse ID order');
    await db.query(`UPDATE production_run:overlap_a SET planned_start=d'2026-07-03T00:00:00Z';`);
    s = await assertAt(db); assert.equal(n(byId(s.accounts,'stock_account:input_a').z_history.summary.measures.available.sum),14,'later non-overlapping reservation leaves fourteen free units');
    await rejectsUnchanged(db,`UPDATE stock_in:open_input_a SET quantity=1dec;`,'earlier grant edit revalidates and rejects a later scheduled input');
    await rejectsUnchanged(db,`DELETE stock_in:open_input_a;`,'earlier grant deletion revalidates and rejects a later scheduled input');

    // Cancellation removes future output. Cancellation after the start keeps a
    // dated hold until cancellation, without physical use or output.
    await db.query(`CREATE ONLY production_run:cancel_before SET owned_by=rebase_group:root,recipe_version=production_recipe_version:split,batch_count=1,planned_start=d'2026-07-04T00:00:00Z',status='scheduled';`);
    await db.query(`UPDATE production_run:cancel_before SET status='cancelled',cancelled_at=d'2026-07-03T23:00:00Z';`);
    await assertAt(db);
    await db.query(`CREATE ONLY production_run:cancel_after SET owned_by=rebase_group:root,recipe_version=production_recipe_version:split,batch_count=1,planned_start=d'2026-07-04T00:00:00Z',status='scheduled';`);
    await db.query(`UPDATE production_run:cancel_after SET status='cancelled',cancelled_at=d'2026-07-04T00:30:00Z';`);
    s = await assertAt(db);
    assert.equal(rows(s.outputs).some((x) => rid(x.rebase_managed_source)==='production_run:cancel_after'),false,'cancel after start removes future output roles');
    await rejectsUnchanged(db,`UPDATE production_run:cancel_after SET cancelled_at=d'2026-07-04T01:00:00Z';`,'cancellation at end is rejected');
    await db.query(`CREATE ONLY production_run:capacity SET owned_by=rebase_group:root,recipe_version=production_recipe_version:capacity,batch_count=2,planned_start=d'2026-07-05T00:00:00Z',status='scheduled';`);
    s = await assertAt(db);
    const capacityOutput = s.outputs.find((x) => x.rebase_managed_role === 'output_a' && rid(x.rebase_managed_source) === 'production_run:capacity');
    const capacityOutputRef = rid(capacityOutput.id);
    await db.query(`CREATE ONLY stock_out:capacity_use SET owned_by=rebase_group:root,from_account=stock_account:output_a,to_party=misc_account:customer,quantity=3dec,effective_at=d'2026-07-05T01:00:00Z',production_output=${capacityOutputRef};`);
    s = await assertAt(db);
    await rejectsUnchanged(db,`UPDATE production_run:capacity SET batch_count=1;`,'used output quantity cannot be reduced below an existing stock_out');
    await rejectsUnchanged(db,`UPDATE production_run:capacity SET status='cancelled',cancelled_at=d'2026-07-05T00:30:00Z';`,'used output run cannot be cancelled and removed');
    await rejectsUnchanged(db,`DELETE production_run:capacity;`,'used output run cannot be deleted');
    await db.query(`DELETE stock_out:capacity_use;`);
    await db.query(`DELETE production_run:capacity;`);
    await assertAt(db);
    await db.query(`UPDATE production_run:overlap_a SET planned_start=d'2026-07-02T00:00:00Z';`);
    await rejectsUnchanged(db,`UPDATE production_run:overlap_a SET batch_count=4;`,'increasing existing run inputs beyond opening stock rejects atomically');
    await assertAt(db);
    s = await concurrentRuns(db, `ws://127.0.0.1:${port}/rpc`, namespace);
    const concurrentOutput = s.outputs.find((row) => rid(row.rebase_managed_source) === 'production_run:concurrent_0'
      && row.rebase_managed_role === 'output_a');
    await db.query(`CREATE ONLY stock_out:reapply_use SET owned_by=rebase_group:root,from_account=stock_account:output_a,
      to_party=misc_account:customer,quantity=1dec,effective_at=d'2026-07-08T01:00:00Z',production_output=${rid(concurrentOutput.id)};`);
    const beforeReapply = await assertAt(db);
    await db.query(schema);
    assert.deepEqual(await assertAt(db), beforeReapply,
      'populated schema reapplication preserves runs, immutable recipes, managed roles, used-output capacity, and stock roots');
    await rejectsUnchanged(db, `UPDATE production_run:concurrent_0 SET planned_start=d'2026-07-08T02:00:00Z';`,
      'output date dependency still guards an existing consumer after schema reapplication');
    console.log('H8 timed production probe passed: reservations, exact-end stock, gross input, cancellation, output use, date shifts, source-row oracles, concurrent retries, and populated reapplication');
  } finally {
    await db.close().catch(() => {}); child.kill('SIGTERM');
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
