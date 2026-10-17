#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { Surreal, RecordId, Decimal, escapeIdent } = require("surrealdb");
const { createModel, plan, populate } = require("../fixtures");
const { accountingOptions, money } = require("../fixtures/examples/accounting");
const { loadClientSchemas } = require("../client-schemas");
const { compile } = require("../accounting/acceptance");
const { exact, snapshot } = require("../accounting/source-oracle");
const { prepare } = require("../prepare");
const { start, client } = require("../temporal-tree/harness");

async function main() {
  const built = compile();
  const model = createModel({ schema: built.bundle,
    schemas: loadClientSchemas(path.resolve(__dirname, "../../designs/all-in-accounting/schemas")) });
  const tenant = new RecordId("rebase_tenant", "fixture_owner");
  const foreignTenant = new RecordId("rebase_tenant", "fixture_foreign");
  const defaults = { model, tenant, balanceCents: 12345n, reserveCents: 2345n, count: 3 };
  const preview = await plan(accountingOptions({ ...defaults, seed: "preview" }));
  const previewAgain = await plan(accountingOptions({ ...defaults, seed: "preview" }));
  assert.deepEqual(preview, previewAgain, "offline preview is deterministic");
  assert(preview.rows.every(row => row.id instanceof RecordId));
  assert(preview.rows.filter(row => row.table === "account_entry").every(row => row.content.real instanceof Decimal));
  assert.equal(preview.space.cash[0].minimum_real, "0.00");
  console.log("PASS offline deterministic accounting preview with native bindings and exact-cent solver allocation");

  const server = await start({ engine: "surrealkv" });
  const db = new Surreal();
  let readsInTransaction = 0;
  try {
    await db.connect(`${server.url.replace(/^http/, "ws")}/rpc`);
    await db.signin({ username: "root", password: "root" });
    await db.query("DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;");
    await db.use({ namespace: "temporal_probe", database: "fixture" });
    console.log("CHECK installing accounting schema in disposable SurrealKV over WebSocket");
    const installation = await prepare(db, { schema: built.bundle, onProgress: progress => {
      if (progress.phase === "commit") console.log(`CHECK accounting DDL finished after ${Math.round(progress.elapsedMs)}ms; committing`);
    } });
    console.log(`PASS accounting schema installation: ${JSON.stringify(installation)}`);
    console.log("CHECK accounting schema installed; running fixture transactions");
    for (const id of [tenant, foreignTenant]) await db.query("CREATE $id CONTENT $content;", {
      id, content: { name: "Explicit fixture tenant" },
    });

    const readSpace = owner => async transaction => {
      assert.notEqual(transaction, db, "existing space is read using the SDK transaction");
      readsInTransaction++;
      const [tenants] = await transaction.query("SELECT * FROM $owner;", { owner });
      return { tenants };
    };
    const valid = await populate(db, { ...accountingOptions({ ...defaults, seed: "valid",
      space: readSpace(tenant) }), batchSize: 2 });
    assert.equal(valid.created.length, 4 + defaults.count * 2);
    const treasury = valid.rows.find(row => row.table === "treasury").id;
    const [summary] = await db.query("RETURN $account.z_history.summary;", { account: treasury });
    assert.equal(summary.count, 1 + defaults.count * 2);
    exact(summary.measures.real.sum, money(defaults.reserveCents), "treasury exact remaining balance");
    assert(summary.measures.real.sum instanceof Decimal, "tree balances retain native SDK decimals");
    exact(summary.measures.real.instant_min, "0", "treasury never drops below its floor");
    const [source] = await db.query("SELECT * FROM account_entry WHERE account=$account ORDER BY effective_at;", { account: treasury });
    assert.equal(source[0].description, "Opening funding");
    let expected = defaults.balanceCents;
    for (const row of source.slice(1)) {
      const planned = [...valid.space.withdrawals, ...valid.space.fees].find(item => item.id === String(row.id));
      const match = /^-(\d+)\.(\d\d)$/.exec(planned.real);
      expected -= BigInt(match[1]) * 100n + BigInt(match[2]);
      const [prefix] = await db.query("RETURN fn::tree::read($account,'z_history','before',[$until]).measures.real.sum;", {
        account: treasury, until: new Date(Date.parse(row.effective_at.toISOString()) + 1),
      });
      exact(prefix, money(expected), "each chronological tree prefix matches the source allocation");
    }
    assert.equal(expected, defaults.reserveCents);
    console.log("PASS native SDK transactional population, existing tenant reads, funding order and exact tree prefixes");

    const foreign = await populate(db, { ...accountingOptions({ model, tenant: foreignTenant,
      seed: "foreign", count: 2, space: readSpace(foreignTenant) }), batchSize: 2 });
    const foreignCash = foreign.rows.find(row => row.table === "treasury").id;
    const q = client(server.url);
    const snapshotAll = () => snapshot(q, [...built.schema.tables.keys()]);
    const rejected = async (variant, mutate, pattern) => {
      const before = await snapshotAll();
      const options = accountingOptions({ ...defaults, seed: variant, space: async transaction => ({
        ...await readSpace(tenant)(transaction),
        foreignAccounts: (await transaction.query("SELECT * FROM $account;", { account: foreignCash }))[0],
      }) });
      const recipe = options.recipe;
      options.recipe = async context => mutate(await recipe(context), context);
      // Deliberately bypass the recipe's independent business preflight to
      // prove the database rejects invalid JSON-valid records after writes.
      delete options.assert;
      await assert.rejects(populate(db, { ...options, batchSize: 2 }), pattern);
      assert.deepEqual(await snapshotAll(), before,
        `${variant}: rollback restores every compiled table, tree, dependency, audit row and earlier batch`);
      console.log(`PASS ${variant} rejection and complete transaction rollback across earlier insert batches`);
    };
    const changeFees = update => steps => steps.map(step => step.name !== "fees" ? step : {
      ...step, values: async context => ({ ...await step.values(context), ...update(context) }),
    });
    await rejected("overdraw", changeFees(({ index }) => index === defaults.count - 1
      ? { real: money(-defaults.balanceCents) } : {}), /ACCOUNT_BALANCE_FLOOR/);
    await rejected("backdated", changeFees(({ index }) => index === defaults.count - 1
      ? { effective_at: "2027-01-01T00:00:00.500Z" } : {}), /ACCOUNT_BALANCE_FLOOR/);
    await rejected("cross-tenant", changeFees(({ index }) => index === defaults.count - 1
      ? { account: String(foreignCash) } : {}), /REBASE_DEPENDENCY_TENANT|REBASE_TENANT_REFERENCE_MISMATCH/);
    assert.equal(readsInTransaction, 5, "valid, foreign, and every rejected population read their space inside a transaction");
    const report = { created: valid.created.length, exactRemaining: money(defaults.reserveCents),
      rejectedTransactions: 3, transactionSpaceReads: readsInTransaction, storage: "SurrealKV" };
    const [catalog] = await db.query("INFO FOR DB;");
    const tableNames = Object.keys(catalog.tables).sort();
    const metadataSql = tableNames.map(table => `RETURN crypto::sha256(<string>(INFO FOR TABLE ${escapeIdent(table)} STRUCTURE));`).join("\n");
    const definitionsBefore = await db.query(metadataSql);
    const cleared = await prepare(db, { clear: true });
    assert.deepEqual(cleared.tables, tableNames, "clear includes every public and compiler-generated table");
    assert.deepEqual(await db.query("INFO FOR DB;"), [catalog], "database definitions survive clear");
    assert.deepEqual(await db.query(metadataSql), definitionsBefore, "all fields, events and indexes survive clear");
    const remaining = await db.query(tableNames.map(table => `SELECT id FROM ${escapeIdent(table)} LIMIT 1;`).join("\n"));
    assert(remaining.every(rows => rows.length === 0), "all accounting, helper, principal, tree, dependency and audit records are empty");
    await db.query("CREATE $tenant CONTENT $content;", { tenant, content: { name: "Recreated fixture tenant" } });
    const replay = await populate(db, { ...accountingOptions({ ...defaults, seed: "valid", space: readSpace(tenant) }), batchSize: 2 });
    assert.equal(replay.created.length, valid.created.length, "same deterministic IDs and native indexes work after clear");
    exact((await db.query("RETURN $account.z_history.summary;", { account: treasury }))[0].measures.real.sum,
      money(defaults.reserveCents), "reactive tree rebuilt after clear");
    report.installMs = Math.round(installation.durationMs);
    report.clearMs = Math.round(cleared.durationMs);
    report.clearedTables = cleared.tables.length;
    console.log(`PASS accounting schema-preserving clear and reactive fixture replay: ${JSON.stringify(cleared)}`);
    console.log(`PASS fixtures: ${JSON.stringify(report)}`);
    return report;
  } finally {
    try { await db.close(); } finally { await server.close(); }
  }
}

if (require.main === module) main().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
module.exports = { main };
