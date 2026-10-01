#!/usr/bin/env node
'use strict';

// A bounded, disposable H8 observation. A returned row diff and a disk file
// footprint are observations of different things; neither is an engine write count.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { start, client, applySchema } = require('../temporal-tree/harness');

const root = path.resolve(__dirname, '../..');
const schemaPath = path.join(root, 'build/all-in-accounting/schema.surql');
const schema = fs.readFileSync(schemaPath, 'utf8');
const sizes = [2, 8];
const repeats = 3;
const stockIds = ['input_a', 'input_b', 'output_a', 'output_b'];
const numeric = (value) => Number(String(value ?? 0).replace(/dec$/i, ''));
const id = (value) => String(value ?? '');
const elapsed = (startAt) => Math.round((performance.now() - startAt) * 1000) / 1000;

function directoryBytes(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).reduce((sum, entry) => {
    const target = path.join(directory, entry.name);
    return sum + (entry.isDirectory() ? directoryBytes(target) : fs.statSync(target).size);
  }, 0);
}

async function snapshot(q) {
  return q(`RETURN {
    accounts: (SELECT * FROM stock_account ORDER BY id),
    stockIn: (SELECT * FROM stock_in ORDER BY id),
    recipes: (SELECT * FROM production_recipe_version ORDER BY id),
    runs: (SELECT * FROM production_run ORDER BY id),
    inputs: (SELECT * FROM production_input ORDER BY id),
    outputs: (SELECT * FROM production_output ORDER BY id)
  };`);
}

function counts(state) {
  const roots = state.accounts.flatMap((account) => [account.z_history, account.z_gross_input]);
  const nodeSlots = [
    ...state.stockIn.map((row) => row.z_to),
    ...state.inputs.flatMap((row) => [row.z_reserve, row.z_cancel_release, row.z_consume, row.z_gross_input]),
    ...state.outputs.map((row) => row.z_stock),
  ];
  return {
    sourceRows: state.runs.length,
    managedRows: state.inputs.length + state.outputs.length,
    activeNodeSlots: nodeSlots.filter((slot) => slot != null).length,
    rootSummaryCounts: roots.map((root) => numeric(root?.summary?.count)),
    rootSummaryJsonBytes: roots.map((root) => Buffer.byteLength(JSON.stringify(root?.summary ?? null))),
  };
}

function changedRows(before, after) {
  const changed = {};
  for (const key of ['accounts', 'stockIn', 'recipes', 'runs', 'inputs', 'outputs']) {
    const oldRows = new Map(before[key].map((row) => [id(row.id), JSON.stringify(row)]));
    changed[key] = after[key].filter((row) => oldRows.get(id(row.id)) !== JSON.stringify(row)).length;
  }
  return changed;
}

function assertSourceOracle(state, expectedRuns) {
  assert.equal(state.runs.length, expectedRuns);
  assert.equal(state.inputs.length, expectedRuns * 2);
  assert.equal(state.outputs.length, expectedRuns * 2);
  const recipes = new Map(state.recipes.map((row) => [id(row.id), row]));
  const events = Object.fromEntries(stockIds.map((name) => [`stock_account:${name}`, []]));
  for (const row of state.stockIn) {
    const account = id(row.to_account);
    events[account].push({ at: String(row.effective_at), physical: numeric(row.quantity), free: numeric(row.quantity) });
  }
  for (const run of state.runs) {
    const recipe = recipes.get(id(run.recipe_version));
    assert(recipe, 'selected recipe exists');
    assert.equal(run.status, 'scheduled');
    const startAt = new Date(run.planned_start).getTime();
    const endAt = new Date(startAt + 3600000).toISOString();
    const roles = [...state.inputs, ...state.outputs].filter((row) => id(row.rebase_managed_source) === id(run.id));
    assert.equal(roles.length, 4, 'one source owns four distinct managed roles');
    for (const role of ['input_a', 'input_b', 'output_a', 'output_b']) {
      const child = roles.find((row) => row.rebase_managed_role === role);
      assert(child, `missing ${role}`);
      const account = id(recipe[`${role}_account`]);
      const quantity = numeric(run.batch_count) * numeric(recipe[`${role}_quantity`]);
      assert.equal(id(child.stock_account), account);
      assert.equal(numeric(child.quantity), quantity);
      if (role.startsWith('input')) {
        assert.equal(new Date(child.planned_start).toISOString(), new Date(startAt).toISOString());
        assert.equal(new Date(child.end_at).toISOString(), endAt);
        events[account].push({ at: new Date(startAt).toISOString(), physical: 0, free: -quantity });
        events[account].push({ at: endAt, physical: -quantity, free: 0 });
      } else {
        assert.equal(new Date(child.effective_at).toISOString(), endAt);
        events[account].push({ at: endAt, physical: quantity, free: quantity });
      }
    }
  }
  for (const account of state.accounts) {
    const accountId = id(account.id);
    let physical = 0; let free = 0; let physicalMin = 0; let freeMin = 0;
    for (const event of events[accountId].sort((a, b) => a.at.localeCompare(b.at))) {
      physical += event.physical; free += event.free;
      physicalMin = Math.min(physicalMin, physical);
      freeMin = Math.min(freeMin, free);
    }
    assert.equal(numeric(account.z_history.summary.measures.quantity.sum), physical, `${accountId} physical conservation`);
    assert.equal(numeric(account.z_history.summary.measures.available.sum), free, `${accountId} free conservation`);
    assert.equal(numeric(account.z_history.summary.measures.quantity.instant_min), physicalMin, `${accountId} physical floor`);
    assert.equal(numeric(account.z_history.summary.measures.available.instant_min), freeMin, `${accountId} free floor`);
    const gross = state.inputs.filter((row) => id(row.stock_account) === accountId)
      .reduce((sum, row) => sum + numeric(row.quantity), 0);
    assert.equal(numeric(account.z_gross_input?.summary?.measures?.gross_input?.sum), gross,
      `${accountId} gross input derives from managed source facts`);
  }
}

function foundationSql() {
  return `
    CREATE ONLY organization:entity SET owned_by=rebase_group:root,name='Entity';
    CREATE ONLY misc_account:opening SET owned_by=rebase_group:root,label='Opening';
    CREATE ONLY measure_unit:each SET owned_by=rebase_group:root,code='each',dimension='count',name='Each';
    ${stockIds.map((name) => `CREATE ONLY item:${name} SET owned_by=rebase_group:root,name='${name}',unit=measure_unit:each;`).join('\n')}
    ${stockIds.map((name) => `CREATE ONLY operating_unit:${name} SET owned_by=rebase_group:root,economic_entity=organization:entity,name='${name}',code='${name}';`).join('\n')}
    ${stockIds.map((name) => `CREATE ONLY stock_account:${name} SET owned_by=rebase_group:root,economic_entity=organization:entity,operating_unit=operating_unit:${name},resource=item:${name},minimum_quantity=0dec;`).join('\n')}
    CREATE ONLY stock_in:open_a SET owned_by=rebase_group:root,from_party=misc_account:opening,to_account=stock_account:input_a,quantity=100dec,effective_at=d'2026-07-01T00:00:00Z';
    CREATE ONLY stock_in:open_b SET owned_by=rebase_group:root,from_party=misc_account:opening,to_account=stock_account:input_b,quantity=100dec,effective_at=d'2026-07-01T00:00:00Z';
    CREATE ONLY production_recipe_version:split SET owned_by=rebase_group:root,recipe_key='split',version='1',economic_entity=organization:entity,duration=1h,
      input_a_account=stock_account:input_a,input_a_quantity=1,input_b_account=stock_account:input_b,input_b_quantity=1,
      output_a_account=stock_account:output_a,output_a_quantity=2,output_b_account=stock_account:output_b,output_b_quantity=1;
  `;
}

function runSql(name, batch, day) {
  return `CREATE ONLY production_run:${name} SET owned_by=rebase_group:root,recipe_version=production_recipe_version:split,batch_count=${batch},planned_start=d'2026-07-${String(day).padStart(2, '0')}T00:00:00Z',status='scheduled';`;
}

async function oneRun(priorRuns, repeat) {
  const startedAt = performance.now();
  const server = await start({ engine: 'surrealkv' });
  const serverStartMs = elapsed(startedAt);
  const q = client(server.url, `h8_measure_${priorRuns}_${repeat}`);
  let closed = false;
  try {
    const importStarted = performance.now();
    await q('DEFINE NAMESPACE temporal_probe; DEFINE DATABASE h8_measure;');
    await applySchema(q, schema);
    const schemaImportMs = elapsed(importStarted);
    const fixtureStarted = performance.now();
    await q(foundationSql());
    for (let index = 0; index < priorRuns; index += 1) await q(runSql(`prior_${index}`, 1, 2 + index));
    const fixtureMs = elapsed(fixtureStarted);
    const before = await snapshot(q);
    assertSourceOracle(before, priorRuns);

    const operationStarted = performance.now();
    await q(runSql('target', 1, 20));
    const successMs = elapsed(operationStarted);
    const after = await snapshot(q);
    assertSourceOracle(after, priorRuns + 1);
    const beforeCounts = counts(before);
    const afterCounts = counts(after);
    assert.equal(afterCounts.managedRows - beforeCounts.managedRows, 4);
    assert.equal(afterCounts.activeNodeSlots - beforeCounts.activeNodeSlots, 8);
    const rejectStarted = performance.now();
    let rejection = null;
    try { await q(runSql('rejected', 200, 20)); }
    catch (error) { rejection = String(error.message); }
    const rejectedMs = elapsed(rejectStarted);
    assert(rejection, 'over-capacity run rejects');
    const afterReject = await snapshot(q);
    assert.deepEqual(afterReject, after, 'rejected source and all managed/root effects roll back');
    assert.match(rejection, /available|minimum|capacity|insufficient|stock/i,
      'rejected create must fail a stock capacity guard');
    const changed = changedRows(before, after);
    assert.equal(changed.accounts, 4, 'each distinct stock owner root changes');
    assert.equal(changed.runs, 1, 'only the new source row changes');
    assert.equal(changed.recipes, 0);
    assert(changed.inputs >= 2 && changed.outputs >= 2, 'new managed rows are present');
    await server.close({ keepData: true });
    closed = true;
    return {
      priorRuns, repeat, serverStartMs, schemaImportMs, fixtureMs,
      successfulCreateMs: successMs, rejectedCreateMs: rejectedMs,
      rejectionClass: 'stock capacity guard',
      rejectionMessage: rejection.slice(0, 240),
      changedRows: changed, before: beforeCounts, after: afterCounts,
      rejectedSnapshotUnchanged: true, observedConflictRetries: 0,
      databaseDirectoryBytesAfterShutdown: directoryBytes(server.directory),
    };
  } finally {
    if (!closed) await server.close({ keepData: true });
    fs.rmSync(server.directory, { recursive: true, force: true });
  }
}

async function main() {
  const observations = [];
  for (const priorRuns of sizes) for (let repeat = 1; repeat <= repeats; repeat += 1)
    observations.push(await oneRun(priorRuns, repeat));
  console.log(JSON.stringify({
    id: 'h8-bounded-measurement-2026-09-30', recordedAt: new Date().toISOString(),
    environment: { node: process.version, surrealdb: 'local executable, version captured by command record', engine: 'SurrealKV' },
    schemaSha256: crypto.createHash('sha256').update(schema).digest('hex'),
    contract: 'CREATE ONLY one scheduled split-recipe production_run, batch_count=1, four distinct stock owners, two managed inputs and two managed outputs; rejected variant batch_count=200 at the same date',
    sizes: sizes.map((priorRuns) => ({ priorRuns, repeats })), observations,
    metricScope: {
      durations: 'client-observed milliseconds; setup, schema import, fixture, successful and rejected SQL separately',
      activeNodeSlots: 'non-null live tree-node fields on selected stock and H8 managed rows',
      rootSummaryCounts: 'four stock history and four gross-input root summary counts in account ID order',
      rootSummaryJsonBytes: 'UTF-8 JSON representation of each returned summary, not persisted bytes',
      changedRows: 'rows whose returned JSON changed, including inserts; not internal storage writes',
      databaseDirectoryBytesAfterShutdown: 'total local SurrealKV files for entire schema and fixture; not per-operation bytes or write amplification',
      retries: 'serial run observed zero transaction-conflict retries; contention variance unmeasured',
      dependencyVisits: 'unmeasured: no direct visit counter exposed by this probe',
      internalWrites: 'unmeasured: SQL and directory footprint do not expose engine write count',
      operationBytes: 'unmeasured: no isolated persisted-byte delta or engine write-byte counter',
    },
  }, null, 2));
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
