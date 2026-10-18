#!/usr/bin/env node
"use strict";

// Opt-in integration check. Always starts its own disposable server; never reads
// the application's environment profile or connects to its development data.
const assert = require("node:assert/strict");
const { Surreal, RecordId } = require("surrealdb");
const { plan, insert, populate } = require("..");
const { prepare } = require("../..");
const { start, client } = require("../../temporal-tree/harness");
const { compile, acceptance } = require("../../accounting/acceptance");
const { verify, compare, D } = require("../../accounting/source-oracle");
const { createCompleteModel, completeOptions, populateComplete } = require("./accounting-complete");

async function check(db, compiled, q) {
  const model = createCompleteModel();
  const options = completeOptions({ model });
  const preview = await plan(options);
  assert.equal(preview.rows.length, 109);
  assert.deepEqual(preview, await plan(completeOptions({ model })), "same config produces the same typed plan");
  assert.deepEqual(new Set(preview.rows.map(row => row.table)), new Set(model.tables.keys()), "every public input table covered");
  assert.equal((await plan(completeOptions({ model, salesCount: 20 }))).rows.length, 194);
  for (const seed of ["another-scenario", "incomplete", "must-rollback", "one", "two"]) {
    const varied = await plan(completeOptions({ model, seed, salesCount: 1 }));
    for (const name of ["cashOpening", "dollarOpening", "foreignOpening", "stockOpening", "laborOpening", "foreignStockOpening"]) {
      assert.equal(varied.space[name][0].receivable, "0", `${seed}/${name}: no invented claim`);
      assert.equal(varied.space[name][0].payable, "0", `${seed}/${name}: no invented liability`);
    }
    assert.equal(varied.space.taxOpening[0].real, "0");
    assert.equal(varied.space.purchaseCredit[0].price_delta, "0");
    assert.equal(varied.space.secondCredit[0].quantity_delta, "0");
  }
  assert.throws(() => completeOptions({ model, salesCount: 21 }), /salesCount/);
  assert.throws(() => completeOptions({ model, startAt: "invalid" }), /startAt/);
  console.log("PASS offline determinism, all-table coverage and configuration validation");

  // First use bootstraps the tenant; second seed later tests an existing tenant.
  const first = await populateComplete(db, { model });
  assert.equal(first.reused, false);
  assert.equal(first.created.length, 109);
  const id = first.ids;
  const h = acceptance(q, compiled);
  const checkIntegrity = async () => {
    const data = await h.snapshot();
    // The accounting oracle has no authentication membership formulas. Verify
    // that separate tree from contact source fields, then check accounting with
    // only the already-checked authentication slots removed from the snapshot.
    const owners = data.rebase_tenant.map(row => ({ id: row.id, z_auth_identifiers: row.z_auth_identifiers }));
    const contacts = [...data.authentication_email, ...data.authentication_phone];
    const entries = contacts.map(row => ({ link: { rid: row.id, slot: "z_auth_identifier" },
      owner: { rid: row.tenant, slot: "z_auth_identifiers" },
      key: [...(row.address ? ["email", row.address] : ["phone", row.number]), row.id, "z_auth_identifier"], measures: {}, tags: {} }));
    const nodes = contacts.map(row => ({ id: row.id, z_auth_identifier: row.z_auth_identifier }));
    require("../../temporal-tree/oracle").verify(owners, nodes, entries, compare);
    require("../../temporal-tree/exact-oracle").verify(owners, nodes, entries, compare, D);
    const accounting = structuredClone(data);
    for (const rows of Object.values(accounting)) for (const row of rows) {
      delete row.z_auth_identifier; delete row.z_auth_identifiers;
    }
    const roots = compiled.temporal.trees.roots.filter(root => root.slot !== "z_auth_identifiers");
    verify(accounting, h.slots, roots, compiled.temporalModel.dependencyModel);
    return data;
  };
  const data = await checkIntegrity();
  assert(data.audit_mutation.length > 0, "audit events produced their own records");
  for (const [table, count] of Object.entries(first.counts)) assert.equal(data[table].length, count, table);
  const value = async (name, field, expected) => h.value(`${id[name]}.${field}`, expected);
  await value("saleNetTax1", "amount", "11");
  await value("firstCredit", "amount_delta", "-1");
  await value("firstCreditTax", "amount_delta", "-0.1");
  await value("firstCreditNetTax", "amount_delta", "-0.11");
  await value("secondCredit", "amount_delta", "-9");
  await value("manualCompoundCredit", "amount_delta", "-0.1");
  await value("salePayment1", "fee_amount", "0.3");
  await value("salePayment1", "fee_tax_amount", "0.05");
  await value("purchasePayment", "invoice_amount", "5");
  await value("fxTrade", "to_amount", "1200");
  await value("foreignTransfer", "to_amount", "11");
  await value("rentClaim", "z_capacity.summary.measures.remaining.sum", "25");
  await value("taxPool", "z_history.summary.measures.credit_available.sum", "70");
  await value("taxPool", "z_history.summary.measures.liability_available.sum", "30");
  await value("productionCost", "fee_amount", "1.5");
  await value("finishedStock", "z_history.summary.measures.real.sum", "2");
  assert.equal(await q(`RETURN ${id.contact}.login_access;`), false);
  assert.equal(await q(`RETURN ${id.email}.verified_at;`), null);
  assert.equal(await q(`RETURN ${id.phone}.verified_at;`), null);
  for (const table of ["authentication_challenge", "authentication_delivery_task", "authentication_passkey",
    "authentication_passkey_challenge", "authentication_passkey_exchange"]) {
    assert.equal(data[table].length, 0, `${table} belongs to a real authentication workflow`);
  }
  console.log("PASS 109 records, automatic audit, inert contacts, dated FX, compound adjustments and full tree/formula oracle");

  await db.query("UPDATE $id SET name = 'Developer edit';", { id: new RecordId("organization", id.customer.split(":")[1]) });
  const beforeReuse = await h.snapshot();
  const repeated = await populateComplete(db, { model, tenantName: "Do not overwrite" });
  assert.equal(repeated.reused, true);
  assert.equal(repeated.created.length, 0);
  assert.deepEqual(repeated.ids, id);
  assert.deepEqual(await h.snapshot(), beforeReuse, "repeat neither overwrites edits nor adds audit/history rows");

  const second = await populateComplete(db, { model, seed: "another-scenario", salesCount: 1 });
  assert.equal(second.created.length, 99);
  assert.notEqual(second.ids.inr, id.inr);
  const both = await checkIntegrity();
  for (const [table, count] of Object.entries(first.counts)) assert.equal(both[table].length, count + second.counts[table], table);
  console.log("PASS same-seed no-op and different-seed coexistence within the default tenant");

  const partialConfig = { model, seed: "incomplete", tenant: "rebase_tenant:incomplete" };
  const partialOptions = completeOptions(partialConfig);
  const partial = await plan(partialOptions);
  // Simulate a conflicting partial dataset without provisioning its new tenant.
  partial.rows[0].content.owned_by = new RecordId("rebase_tenant", "default");
  const tx = await db.beginTransaction();
  try { await insert(tx, { rows: partial.rows.slice(0, 1) }); await tx.commit(); }
  catch (error) { await tx.cancel(); throw error; }
  const beforePartial = await h.snapshot();
  await assert.rejects(populateComplete(db, partialConfig), /is incomplete/);
  assert.deepEqual(await h.snapshot(), beforePartial, "partial history is not silently repaired and new tenant creation rolls back");

  // Compose a small extension with the existing dataset. Avoid generating a
  // third full scenario just to verify the same native rollback boundary.
  const bad = { model, seed: "must-rollback", space: { existing: [{ id: first.tenant }, { id: id.cash }] },
    recipe: ["topup", "overdraw"].map((name, index) => ({ name, table: "account_entry", after: index ? ["topup"] : [],
      values: { owned_by: first.tenant, account: id.cash, real: index ? "-999999" : "1", receivable: "0", payable: "0",
        effective_at: `2027-02-0${index + 1}T00:00:00Z` } })) };
  const beforeFailure = await h.snapshot();
  await assert.rejects(populate(db, bad), /ACCOUNT_BALANCE_FLOOR/);
  assert.deepEqual(await h.snapshot(), beforeFailure, "the extension's source rows, parent events and audits all roll back");
  console.log("PASS incomplete-run detection and native aggregate-failure rollback");
  return { recordsPerScenario: first.created.length, tables: Object.keys(first.counts).length, formulaChecks: h.result.valueChecks };
}

async function main() {
  const compiled = compile();
  const server = await start({ engine: "surrealkv" });
  const db = new Surreal();
  try {
    await db.connect(`${server.url.replace(/^http/, "ws")}/rpc`);
    await db.signin({ username: "root", password: "root" });
    await db.query("DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;");
    await db.use({ namespace: "temporal_probe", database: "fixture" });
    console.log("Installing accounting schema in disposable SurrealKV database...");
    await prepare(db, { schema: compiled.bundle });
    console.log(JSON.stringify(await check(db, compiled, client(server.url))));
  } finally {
    try { await db.close(); } finally { await server.close(); }
  }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { check, main };
