#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { queryResult } = require("../../gateway/utils");
const { preflightH1 } = require("./h1-migration-preflight");

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", (error) => error ? reject(error) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`SurrealDB exited with ${child.exitCode}`);
    const connected = await new Promise((resolve) => {
      const socket = net.connect(port, "127.0.0.1");
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("SurrealDB did not become ready");
}

async function rejects(operation, label) {
  await assert.rejects(operation, undefined, label);
}

function numeric(value) {
  return Number(String(value).replace(/dec$/i, ""));
}

async function rows(db, table) {
  const result = queryResult(await db.query(`SELECT * FROM ${table};`));
  return Array.isArray(result) ? result : [];
}

async function rowsBefore(db, table, cutoff) {
  const result = queryResult(await db.query(`SELECT * FROM ${table} WHERE effective_at < d'${cutoff}';`));
  return Array.isArray(result) ? result : [];
}

async function treeSum(db, id, measure) {
  return numeric(queryResult(await db.query(
    `RETURN ${id}.z_history.summary.measures.${measure}.sum ?? 0dec;`,
  )));
}

async function treeBefore(db, id, measure, cutoff) {
  return numeric(queryResult(await db.query(
    `RETURN fn::tree::read(${id}, 'z_history', 'before', [d'${cutoff}']).measures.${measure}.sum ?? 0dec;`,
  )));
}

async function cashOracle(db, accountId, cutoff = null) {
  let total = 0;
  for (const row of await (cutoff ? rowsBefore(db, "cash_in", cutoff) : rows(db, "cash_in"))) {
    if (String(row.to_account) === accountId) total += Math.round(numeric(row.amount) * 100);
  }
  for (const row of await (cutoff ? rowsBefore(db, "cash_out", cutoff) : rows(db, "cash_out"))) {
    if (String(row.from_account) === accountId) total -= Math.round(numeric(row.amount) * 100);
  }
  for (const row of await (cutoff ? rowsBefore(db, "cash_transfer", cutoff) : rows(db, "cash_transfer"))) {
    if (String(row.from_account) === accountId) total -= Math.round(numeric(row.amount) * 100);
    if (String(row.to_account) === accountId) total += Math.round(numeric(row.amount) * 100);
  }
  for (const row of await (cutoff ? rowsBefore(db, "cash_fx_transfer", cutoff) : rows(db, "cash_fx_transfer"))) {
    if (String(row.from_account) === accountId) total -= Math.round(numeric(row.from_amount) * 100);
    if (String(row.to_account) === accountId) total += Math.round(numeric(row.to_amount) * 100);
  }
  return total / 100;
}

async function stockOracle(db, accountId, cutoff = null) {
  let total = 0;
  for (const row of await (cutoff ? rowsBefore(db, "stock_in", cutoff) : rows(db, "stock_in"))) {
    if (String(row.to_account) === accountId) total += numeric(row.quantity);
  }
  for (const row of await (cutoff ? rowsBefore(db, "stock_out", cutoff) : rows(db, "stock_out"))) {
    if (String(row.from_account) === accountId) total -= numeric(row.quantity);
  }
  for (const row of await (cutoff ? rowsBefore(db, "stock_transfer", cutoff) : rows(db, "stock_transfer"))) {
    if (String(row.from_account) === accountId) total -= numeric(row.quantity);
    if (String(row.to_account) === accountId) total += numeric(row.quantity);
  }
  return total;
}

async function claimOracle(db, table, accountId, cutoff = null) {
  const adjustmentTable = table === "receivable" ? "receivable_adjustment" : "payable_adjustment";
  const allocationTable = table === "receivable" ? "receivable_cash_allocation" : "payable_cash_allocation";
  const invoiceLineTable = table === "receivable" ? "sales_invoice_line" : "purchase_invoice_line";
  const invoiceAllocationTable = table === "receivable"
    ? "sales_invoice_cash_allocation" : "purchase_invoice_cash_allocation";
  const base = cutoff ? await rowsBefore(db, table, cutoff) : await rows(db, table);
  const adjustments = cutoff ? await rowsBefore(db, adjustmentTable, cutoff) : await rows(db, adjustmentTable);
  const invoiceLines = cutoff ? await rowsBefore(db, invoiceLineTable, cutoff) : await rows(db, invoiceLineTable);
  const where = cutoff ? ` WHERE effective_at < d'${cutoff}'` : "";
  const allocations = [];
  for (const allocationKind of [allocationTable, invoiceAllocationTable]) {
    const claimAccount = allocationKind === invoiceAllocationTable ? "target.invoice.claim_account" : "target.claim_account";
    const result = queryResult(await db.query(
      `SELECT VALUE { claim_account: ${claimAccount}, amount: amount } FROM ${allocationKind}${where};`,
    ));
    if (Array.isArray(result)) allocations.push(...result);
  }
  const postings = [...base, ...adjustments, ...invoiceLines].reduce((sum, row) => (
    String(row.claim_account) === accountId ? sum + numeric(row.amount ?? row.delta) : sum
  ), 0);
  const reductions = allocations.reduce((sum, row) => (
    String(row.claim_account) === accountId ? sum + numeric(row.amount) : sum
  ), 0);
  return Math.round((postings - reductions) * 100) / 100;
}

async function ownerTreeSum(db, id, slot, measure) {
  return numeric(queryResult(await db.query(
    `RETURN ${id}.${slot}.summary.measures.${measure}.sum ?? 0dec;`,
  )));
}

async function allocationOracle(db, table, ownerField, ownerId) {
  return (await rows(db, table)).reduce((sum, row) => (
    String(row[ownerField]) === ownerId ? sum + numeric(row.amount) : sum
  ), 0);
}

async function assertSettlementOracles(db) {
  for (const id of ["cash_in:ar_receipt", "cash_in:ar_second_receipt"]) {
    assert.equal(await ownerTreeSum(db, id, "z_allocations", "allocated"),
      await allocationOracle(db, "receivable_cash_allocation", "source", id),
      `receivable source pool mismatch for ${id}`);
  }
  for (const id of ["cash_out:tax_payment", "cash_out:tax_second_payment"]) {
    assert.equal(await ownerTreeSum(db, id, "z_allocations", "allocated"),
      await allocationOracle(db, "payable_cash_allocation", "source", id),
      `payable source pool mismatch for ${id}`);
  }
  for (const id of ["receivable:ar_open", "receivable:ar_open2", "receivable:ar_open3"]) {
    assert.equal(await ownerTreeSum(db, id, "z_settlement", "settled"),
      await allocationOracle(db, "receivable_cash_allocation", "target", id),
      `receivable target capacity mismatch for ${id}`);
  }
  assert.equal(await ownerTreeSum(db, "payable:tax_open", "z_settlement", "settled"),
    await allocationOracle(db, "payable_cash_allocation", "target", "payable:tax_open"),
    "payable target capacity mismatch");
}

async function assertClaimOracles(db) {
  for (const account of await rows(db, "claim_account")) {
    const id = String(account.id);
    const receivable = await claimOracle(db, "receivable", id);
    const payable = await claimOracle(db, "payable", id);
    assert.equal(numeric(queryResult(await db.query(
      `RETURN ${id}.z_history.summary.measures.receivable.sum ?? 0dec;`,
    ))), receivable, `receivable history mismatch for ${id}`);
    assert.equal(numeric(queryResult(await db.query(
      `RETURN ${id}.z_history.summary.measures.payable.sum ?? 0dec;`,
    ))), payable, `payable history mismatch for ${id}`);
    assert.equal(numeric(queryResult(await db.query(
      `RETURN ${id}.z_history.summary.measures.net.sum ?? 0dec;`,
    ))), Math.round((receivable - payable) * 100) / 100,
      `derived net history mismatch for ${id}`);
  }
}

async function assertOpeningMovementSnapshots(db) {
  const prior = "2025-12-30T00:00:00Z";
  const cutoff = "2026-01-01T00:00:00Z";
  for (const [id, measure, oracle] of [
    ["treasury_account:cash_a", "balance", cashOracle],
    ["stock_account:stock_a", "quantity", stockOracle],
  ]) {
    assert.equal(await treeBefore(db, id, measure, prior), await oracle(db, id, prior));
    assert.equal(await treeBefore(db, id, measure, cutoff), await oracle(db, id, cutoff));
  }
  assert.equal(await treeBefore(db, "treasury_account:cash_a", "balance", cutoff), 100,
    "ordinary dated cash-in postings represent the opening cash fact");
  assert.equal(await treeBefore(db, "stock_account:stock_a", "quantity", cutoff), 20,
    "ordinary dated stock-in postings represent the opening stock fact");
}

async function assertOpeningClaimSnapshots(db) {
  const prior = "2025-12-30T00:00:00Z";
  const cutoff = "2026-01-01T00:00:00Z";
  for (const family of ["receivable", "payable"]) {
    assert.equal(await treeBefore(db, "claim_account:claim_a", family, prior),
      await claimOracle(db, family, "claim_account:claim_a", prior));
    assert.equal(await treeBefore(db, "claim_account:claim_a", family, cutoff),
      await claimOracle(db, family, "claim_account:claim_a", cutoff));
  }
  assert.equal(await treeBefore(db, "claim_account:claim_a", "receivable", cutoff), 12);
  assert.equal(await treeBefore(db, "claim_account:claim_a", "payable", cutoff), 7);
}

async function probeStandaloneClaims(db) {
  await db.query(`
    CREATE ONLY receivable:ar_opening SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, amount = 12dec, effective_at = d'2025-12-31T00:00:00Z';
    CREATE ONLY payable:ap_opening SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, amount = 7dec, effective_at = d'2025-12-31T00:00:00Z';
    CREATE ONLY receivable:ar_open SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, amount = 80dec, effective_at = d'2026-03-01T00:00:00Z';
    CREATE ONLY payable:ap_open SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, amount = 20dec, effective_at = d'2026-03-02T00:00:00Z';
    CREATE ONLY payable:tax_open SET owned_by = rebase_group:root, claim_account = claim_account:claim_tax, amount = 50dec, effective_at = d'2026-03-03T00:00:00Z';
  `);
  await assertClaimOracles(db);
  await assertOpeningClaimSnapshots(db);
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.receivable.sum - claim_account:claim_a.z_history.summary.measures.payable.sum;",
  ))), 65, "net outstanding claims are read-time receivable minus payable");
  await db.query("UPDATE receivable:ar_open SET amount = 75dec;");
  await assertClaimOracles(db);
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.receivable.sum - claim_account:claim_a.z_history.summary.measures.payable.sum;",
  ))), 60);
}

async function probeClaimSettlements(db) {
  await db.query(`
    CREATE ONLY organization:org_c SET owned_by = rebase_group:root, name = 'Book owner C';
    CREATE ONLY claim_account:claim_foreign SET owned_by = rebase_group:root, economic_entity = organization:org_a,
      opponent = organization:org_c, currency = currency:usd;
    CREATE ONLY receivable:ar_open2 SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, amount = 50dec, effective_at = d'2026-03-01T00:00:00Z';
    CREATE ONLY receivable:ar_open3 SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, amount = 50dec, effective_at = d'2026-03-01T00:00:00Z';
    CREATE ONLY receivable:ar_misc_scope SET owned_by = rebase_group:root, claim_account = claim_account:claim_misc, amount = 10dec, effective_at = d'2026-03-01T00:00:00Z';
    CREATE ONLY receivable:ar_foreign SET owned_by = rebase_group:root, claim_account = claim_account:claim_foreign, amount = 20dec, effective_at = d'2026-03-01T00:00:00Z';
    CREATE ONLY payable:ap_foreign SET owned_by = rebase_group:root, claim_account = claim_account:claim_foreign, amount = 20dec, effective_at = d'2026-03-01T00:00:00Z';
    CREATE ONLY treasury_account:cash_b SET owned_by = rebase_group:root, economic_entity = organization:org_b,
      treasury = treasury:bank_b, currency = currency:usd;
    CREATE ONLY cash_in:ar_receipt SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = treasury_account:cash_a,
      amount = 100dec, effective_at = d'2026-03-02T00:00:00Z';
    CREATE ONLY cash_in:ar_second_receipt SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = treasury_account:cash_a,
      amount = 50dec, effective_at = d'2026-03-03T00:00:00Z';
    CREATE ONLY cash_in:eur_receipt SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = treasury_account:cash_eur,
      amount = 10dec, effective_at = d'2026-03-02T00:00:00Z';
    CREATE ONLY cash_in:entity_b_receipt SET owned_by = rebase_group:root, from_party = organization:org_c, to_account = treasury_account:cash_b,
      amount = 20dec, effective_at = d'2026-03-02T00:00:00Z';
    CREATE ONLY cash_out:eur_payment SET owned_by = rebase_group:root, from_account = treasury_account:cash_eur, to_party = tax_account:tax_a,
      amount = 5dec, effective_at = d'2026-03-03T00:00:00Z';
    CREATE ONLY cash_out:entity_b_payment SET owned_by = rebase_group:root, from_account = treasury_account:cash_b, to_party = organization:org_c,
      amount = 10dec, effective_at = d'2026-03-03T00:00:00Z';
    CREATE ONLY cash_out:tax_payment SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_party = tax_account:tax_a,
      amount = 30dec, effective_at = d'2026-03-04T00:00:00Z';
    CREATE ONLY cash_out:tax_second_payment SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_party = tax_account:tax_a,
      amount = 50dec, effective_at = d'2026-03-04T00:00:00Z';
  `);
  await assertMovementOracles(db);
  assert.equal(await treeSum(db, "treasury_account:cash_b", "balance"), await cashOracle(db, "treasury_account:cash_b"));
  await assertClaimOracles(db);

  await db.query(`
    CREATE ONLY receivable_cash_allocation:ar_payment_one SET owned_by = rebase_group:root,
      source = cash_in:ar_receipt, target = receivable:ar_open, amount = 60dec,
      effective_at = d'2026-03-03T00:00:00Z';
    CREATE ONLY receivable_cash_allocation:ar_payment_split SET owned_by = rebase_group:root,
      source = cash_in:ar_receipt, target = receivable:ar_open2, amount = 40dec,
      effective_at = d'2026-03-03T00:00:00Z';
    CREATE ONLY receivable_cash_allocation:ar_second_payment SET owned_by = rebase_group:root,
      source = cash_in:ar_second_receipt, target = receivable:ar_open, amount = 10dec,
      effective_at = d'2026-03-04T00:00:00Z';
    CREATE ONLY payable_cash_allocation:ap_payment_one SET owned_by = rebase_group:root,
      source = cash_out:tax_payment, target = payable:tax_open, amount = 20dec,
      effective_at = d'2026-03-05T00:00:00Z';
    CREATE ONLY payable_cash_allocation:ap_payment_two SET owned_by = rebase_group:root,
      source = cash_out:tax_second_payment, target = payable:tax_open, amount = 10dec,
      effective_at = d'2026-03-05T00:00:00Z';
  `);
  await assertSettlementOracles(db);
  await assertClaimOracles(db);
  await assertMovementOracles(db);
  assert.equal(await ownerTreeSum(db, "cash_in:ar_receipt", "z_allocations", "allocated"), 100);
  assert.equal(await ownerTreeSum(db, "receivable:ar_open", "z_settlement", "settled"), 70);
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.receivable.sum;",
  ))), 77, "receivable cash allocations reduce only the receivable family");
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_tax.z_history.summary.measures.payable.sum;",
  ))), 20, "cash payments reduce only the payable family");

  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_over_source SET owned_by = rebase_group:root,
    source = cash_in:ar_receipt, target = receivable:ar_open3, amount = 1dec,
    effective_at = d'2026-03-04T00:00:00Z';`),
  "one receipt cannot be allocated beyond its source amount");
  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_over_target SET owned_by = rebase_group:root,
    source = cash_in:ar_second_receipt, target = receivable:ar_open, amount = 11dec,
    effective_at = d'2026-03-04T00:00:00Z';`),
  "several receipts cannot settle one claim beyond its amount");
  await rejects(() => db.query("UPDATE cash_in:ar_receipt SET amount = 99dec;"),
    "a source cash amount cannot be edited below its allocated amount");
  await rejects(() => db.query("UPDATE receivable:ar_open SET amount = 69dec;"),
    "a claim amount cannot be edited below its settled amount");
  await rejects(() => db.query("UPDATE cash_in:ar_receipt SET effective_at = d'2026-03-04T00:00:00Z';"),
    "a source cash date cannot move past its allocation dates");
  await rejects(() => db.query("UPDATE receivable:ar_open SET effective_at = d'2026-03-06T00:00:00Z';"),
    "a claim date cannot move past its settlement dates");
  await rejects(() => db.query(`CREATE ONLY payable_cash_allocation:ap_over_source SET owned_by = rebase_group:root,
    source = cash_out:tax_payment, target = payable:tax_open, amount = 11dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "one payment cannot be allocated beyond its source amount");
  await rejects(() => db.query(`CREATE ONLY payable_cash_allocation:ap_over_target SET owned_by = rebase_group:root,
    source = cash_out:tax_second_payment, target = payable:tax_open, amount = 21dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "several payments cannot settle one payable beyond its amount");
  await rejects(() => db.query("UPDATE cash_out:tax_payment SET amount = 19dec;"),
    "a cash payment amount cannot be edited below its allocated amount");
  await rejects(() => db.query("UPDATE payable:tax_open SET amount = 29dec;"),
    "a payable amount cannot be edited below its settled amount");
  await rejects(() => db.query("UPDATE cash_out:tax_payment SET effective_at = d'2026-03-06T00:00:00Z';"),
    "a payment date cannot move past its allocation dates");
  await rejects(() => db.query("UPDATE payable:tax_open SET effective_at = d'2026-03-06T00:00:00Z';"),
    "a payable date cannot move past its settlement dates");

  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_zero SET owned_by = rebase_group:root,
    source = cash_in:ar_receipt, target = receivable:ar_open, amount = 0dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "settlement allocations must be positive");
  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_before_source SET owned_by = rebase_group:root,
    source = cash_in:ar_second_receipt, target = receivable:ar_open, amount = 1dec,
    effective_at = d'2026-03-02T00:00:00Z';`),
  "a receivable cannot settle before cash is received");
  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_wrong_party SET owned_by = rebase_group:root,
    source = cash_in:ar_receipt, target = receivable:ar_misc_scope, amount = 1dec,
    effective_at = d'2026-03-04T00:00:00Z';`),
  "cash and claim counterparties must match");
  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_wrong_currency SET owned_by = rebase_group:root,
    source = cash_in:eur_receipt, target = receivable:ar_open, amount = 1dec,
    effective_at = d'2026-03-04T00:00:00Z';`),
  "cash and claim currencies must match");
  await rejects(() => db.query(`CREATE ONLY receivable_cash_allocation:ar_wrong_entity SET owned_by = rebase_group:root,
    source = cash_in:entity_b_receipt, target = receivable:ar_foreign, amount = 1dec,
    effective_at = d'2026-03-04T00:00:00Z';`),
  "cash and claim entities must match");
  await rejects(() => db.query(`CREATE ONLY payable_cash_allocation:ap_wrong_party SET owned_by = rebase_group:root,
    source = cash_out:tax_payment, target = payable:ap_open, amount = 1dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "payment and payable counterparties must match");
  await rejects(() => db.query(`CREATE ONLY payable_cash_allocation:ap_wrong_currency SET owned_by = rebase_group:root,
    source = cash_out:eur_payment, target = payable:tax_open, amount = 1dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "payment and payable currencies must match");
  await rejects(() => db.query(`CREATE ONLY payable_cash_allocation:ap_wrong_entity SET owned_by = rebase_group:root,
    source = cash_out:entity_b_payment, target = payable:ap_foreign, amount = 1dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "payment and payable entities must match");
  await rejects(() => db.query(`CREATE ONLY payable_cash_allocation:ap_before_source SET owned_by = rebase_group:root,
    source = cash_out:tax_second_payment, target = payable:tax_open, amount = 1dec,
    effective_at = d'2026-03-03T12:00:00Z';`),
  "a payable cannot settle before cash is paid");

  await assertSettlementOracles(db);
  await assertClaimOracles(db);
  await assertMovementOracles(db);
  assert.equal(await treeSum(db, "treasury_account:cash_b", "balance"), await cashOracle(db, "treasury_account:cash_b"));
  assert.equal(queryResult(await db.query("RETURN cash_in:ar_receipt.effective_at = d'2026-03-02T00:00:00Z';")), true);
  assert.equal(numeric(queryResult(await db.query("RETURN cash_in:ar_receipt.amount;"))), 100);
  assert.equal(numeric(queryResult(await db.query("RETURN receivable:ar_open.amount;"))), 75);
  assert.equal(queryResult(await db.query("RETURN receivable:ar_open.effective_at = d'2026-03-01T00:00:00Z';")), true);
}

async function probeClaimAdjustments(db) {
  await rejects(() => db.query(`CREATE ONLY receivable_adjustment:ar_zero SET owned_by = rebase_group:root,
    claim_account = claim_account:claim_a, delta = 0dec,
    effective_at = d'2026-03-04T00:00:00Z';`),
  "claim adjustments must have a nonzero signed delta");
  await db.query(`
    CREATE ONLY receivable_adjustment:ar_credit SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, delta = -5dec, effective_at = d'2026-03-04T00:00:00Z';
    CREATE ONLY payable_adjustment:ap_correction SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, delta = 3dec, effective_at = d'2026-03-05T00:00:00Z';
  `);
  await assertClaimOracles(db);
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.receivable.sum;",
  ))), 72, "a signed receivable correction stays in the receivable family");
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.payable.sum;",
  ))), 30, "a signed payable correction stays in the payable family");

  const beforeOverCorrection = await treeSum(db, "claim_account:claim_a", "receivable");
  await rejects(() => db.query(`CREATE ONLY receivable_adjustment:ar_overcorrect SET owned_by = rebase_group:root,
    claim_account = claim_account:claim_a, delta = -100dec,
    effective_at = d'2026-03-06T00:00:00Z';`),
  "a correction cannot reduce outstanding receivables below zero");
  assert.equal(await treeSum(db, "claim_account:claim_a", "receivable"), beforeOverCorrection,
    "a rejected correction restores the complete claim history");
  await assertClaimOracles(db);

  await db.query("DELETE payable:ap_open;");
  await assertClaimOracles(db);
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.payable.sum ?? 0dec;",
  ))), 10, "deleting a standalone payable removes only its own claim effect");
  assert.equal(numeric(queryResult(await db.query(
    "RETURN claim_account:claim_a.z_history.summary.measures.receivable.sum - claim_account:claim_a.z_history.summary.measures.payable.sum;",
  ))), 62);
}

async function assertInvoiceOracles(db) {
  for (const [id, lineTable, allocationTable] of [
    ["sales_invoice:invoice_one", "sales_invoice_line", "sales_invoice_cash_allocation"],
    ["sales_invoice:invoice_two", "sales_invoice_line", "sales_invoice_cash_allocation"],
    ["purchase_invoice:bill_one", "purchase_invoice_line", "purchase_invoice_cash_allocation"],
  ]) {
    let posted = 0;
    for (const line of await rows(db, lineTable)) {
      if (String(line.invoice) !== id) continue;
      const calculated = Math.round(numeric(line.billed_quantity) * numeric(line.unit_price) * 100) / 100;
      assert.equal(numeric(line.amount), calculated, `priced amount mismatch for ${line.id}`);
      posted += calculated;
    }
    const allocations = queryResult(await db.query(
      `SELECT VALUE amount FROM ${allocationTable} WHERE target.invoice = ${id};`,
    ));
    const allocated = (Array.isArray(allocations) ? allocations : []).reduce((sum, amount) => sum + numeric(amount), 0);
    assert.equal(await ownerTreeSum(db, id, "z_outstanding", "outstanding"),
      Math.round((posted - allocated) * 100) / 100, `invoice history mismatch for ${id}`);
  }
  for (const [id, lineTable] of [
    ["stock_out:invoiced_delivery", "sales_invoice_line"],
    ["stock_out:invoiced_delivery2", "sales_invoice_line"],
    ["stock_in:invoiced_receipt", "purchase_invoice_line"],
  ]) {
    const billed = (await rows(db, lineTable)).reduce((sum, row) => (
      String(row.source) === id ? sum + numeric(row.billed_quantity) : sum
    ), 0);
    assert.equal(await ownerTreeSum(db, id, "z_billing", "billed"), billed,
      `shared billed quantity mismatch for ${id}`);
  }
  assert.equal(await ownerTreeSum(db, "cash_in:invoice_receipt", "z_allocations", "allocated"),
    await allocationOracle(db, "receivable_cash_allocation", "source", "cash_in:invoice_receipt")
      + await allocationOracle(db, "sales_invoice_cash_allocation", "source", "cash_in:invoice_receipt"));
  assert.equal(await ownerTreeSum(db, "cash_out:invoice_payment", "z_allocations", "allocated"),
    await allocationOracle(db, "purchase_invoice_cash_allocation", "source", "cash_out:invoice_payment"));
  await assertClaimOracles(db);
  await assertMovementOracles(db);
}

async function probeInvoices(db) {
  await db.query(`
    CREATE ONLY stock_in:invoiced_receipt SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = stock_account:stock_a,
      quantity = 3dec, effective_at = d'2026-03-06T00:00:00Z';
    CREATE ONLY stock_out:invoiced_delivery SET owned_by = rebase_group:root, from_account = stock_account:stock_a, to_party = organization:org_b,
      quantity = 5dec, effective_at = d'2026-03-06T00:00:00Z';
    CREATE ONLY stock_out:invoiced_delivery2 SET owned_by = rebase_group:root, from_account = stock_account:stock_a, to_party = organization:org_b,
      quantity = 2dec, effective_at = d'2026-03-06T00:00:00Z';
    CREATE ONLY sales_invoice:invoice_one SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, number = 'S-1';
    CREATE ONLY sales_invoice:invoice_two SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, number = 'S-2';
    CREATE ONLY purchase_invoice:bill_one SET owned_by = rebase_group:root, claim_account = claim_account:claim_a, number = 'P-1';
  `);
  await rejects(() => db.query(`CREATE ONLY sales_invoice_issue:empty_issue SET owned_by = rebase_group:root,
    invoice = sales_invoice:invoice_two, issued_at = d'2026-03-07T00:00:00Z', lines = [];`),
  "an issued invoice requires at least one line");
  await rejects(() => db.query(`CREATE ONLY sales_invoice_issue:duplicate_keys SET owned_by = rebase_group:root,
    invoice = sales_invoice:invoice_two, issued_at = d'2026-03-07T00:00:00Z', lines = [
      { line_key: 'same', source: stock_out:invoiced_delivery, billed_quantity: 1dec, unit_price: 1dec },
      { line_key: 'same', source: stock_out:invoiced_delivery2, billed_quantity: 1dec, unit_price: 1dec }
    ];`), "issued line keys are unique");
  await db.query(`
    CREATE ONLY sales_invoice_issue:sale_issue_one SET owned_by = rebase_group:root,
      invoice = sales_invoice:invoice_one, issued_at = d'2026-03-07T00:00:00Z', lines = [
        { line_key: 'sale_a', source: stock_out:invoiced_delivery, billed_quantity: 4dec, unit_price: 2.50dec },
        { line_key: 'sale_b', source: stock_out:invoiced_delivery2, billed_quantity: 2dec, unit_price: 1.755dec }
      ];
    CREATE ONLY sales_invoice_issue:sale_issue_two SET owned_by = rebase_group:root,
      invoice = sales_invoice:invoice_two, issued_at = d'2026-03-07T00:00:00Z', lines = [
        { line_key: 'sale_c', source: stock_out:invoiced_delivery, billed_quantity: 1dec, unit_price: 2.50dec }
      ];
    CREATE ONLY purchase_invoice_issue:purchase_issue_one SET owned_by = rebase_group:root,
      invoice = purchase_invoice:bill_one, issued_at = d'2026-03-07T00:00:00Z', lines = [
        { line_key: 'purchase_a', source: stock_in:invoiced_receipt, billed_quantity: 3dec, unit_price: 4dec }
      ];
    CREATE ONLY cash_in:invoice_funding SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = treasury_account:cash_a,
      amount = 40dec, effective_at = d'2026-03-08T00:00:00Z';
    CREATE ONLY cash_in:invoice_receipt SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = treasury_account:cash_a,
      amount = 12dec, effective_at = d'2026-03-08T00:00:00Z';
    CREATE ONLY cash_out:invoice_payment SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_party = organization:org_b,
      amount = 20dec, effective_at = d'2026-03-08T00:00:00Z';
    CREATE ONLY sales_invoice_cash_allocation:sale_payment SET owned_by = rebase_group:root,
      source = cash_in:invoice_receipt, target = sales_invoice_issue:sale_issue_one,
      amount = 8dec, effective_at = d'2026-03-09T00:00:00Z';
    CREATE ONLY receivable_cash_allocation:shared_invoice_source SET owned_by = rebase_group:root,
      source = cash_in:invoice_receipt, target = receivable:ar_open3,
      amount = 4dec, effective_at = d'2026-03-09T00:00:00Z';
    CREATE ONLY purchase_invoice_cash_allocation:purchase_payment SET owned_by = rebase_group:root,
      source = cash_out:invoice_payment, target = purchase_invoice_issue:purchase_issue_one,
      amount = 7dec, effective_at = d'2026-03-09T00:00:00Z';
  `);
  await assertInvoiceOracles(db);
  assert.equal(await ownerTreeSum(db, "sales_invoice:invoice_one", "z_outstanding", "outstanding"), 5.51);
  assert.equal(await ownerTreeSum(db, "purchase_invoice:bill_one", "z_outstanding", "outstanding"), 5);
  const originalIds = (await rows(db, "sales_invoice_line")).map(row => String(row.id)).sort();

  await rejects(() => db.query(`UPDATE sales_invoice_issue:sale_issue_one SET lines = [
    { line_key: 'sale_a', source: stock_out:invoiced_delivery, billed_quantity: 4.1dec, unit_price: 2.50dec },
    { line_key: 'sale_b', source: stock_out:invoiced_delivery2, billed_quantity: 2dec, unit_price: 1.755dec }
  ];`), "a delivery cannot be billed beyond its shared quantity");
  await rejects(() => db.query("UPDATE stock_out:invoiced_delivery SET quantity = 4.9dec;"),
    "a billed source cannot be reduced below shared billed quantity");
  await rejects(() => db.query(`UPDATE purchase_invoice_issue:purchase_issue_one SET lines = [
    { line_key: 'purchase_a', source: stock_in:invoiced_receipt, billed_quantity: 3.1dec, unit_price: 4dec }
  ];`), "a receipt cannot be billed beyond its quantity");
  await rejects(() => db.query("UPDATE stock_in:invoiced_receipt SET quantity = 2.9dec;"),
    "a billed receipt cannot be reduced below shared billed quantity");
  await rejects(() => db.query(`CREATE ONLY sales_invoice_cash_allocation:over_source SET owned_by = rebase_group:root,
    source = cash_in:invoice_receipt, target = sales_invoice_issue:sale_issue_one,
    amount = 1dec, effective_at = d'2026-03-09T00:00:00Z';`),
  "standalone and invoice allocations share one receipt's capacity");
  await rejects(() => db.query(`CREATE ONLY purchase_invoice_cash_allocation:over_target SET owned_by = rebase_group:root,
    source = cash_out:invoice_payment, target = purchase_invoice_issue:purchase_issue_one,
    amount = 6dec, effective_at = d'2026-03-09T00:00:00Z';`),
  "several allocations cannot exceed invoice claim capacity");
  await rejects(() => db.query(`CREATE ONLY sales_invoice:duplicate_number SET owned_by = rebase_group:root,
    claim_account = claim_account:claim_a, number = 'S-1';`), "invoice numbers are unique per entity");
  await db.query(`
    CREATE ONLY sales_invoice:foreign_party SET owned_by = rebase_group:root,
      claim_account = claim_account:claim_foreign, number = 'S-3';
    CREATE ONLY purchase_invoice:foreign_party SET owned_by = rebase_group:root,
      claim_account = claim_account:claim_foreign, number = 'P-2';
  `);
  await rejects(() => db.query(`CREATE ONLY sales_invoice_issue:wrong_party SET owned_by = rebase_group:root,
    invoice = sales_invoice:foreign_party, issued_at = d'2026-03-07T00:00:00Z', lines = [
      { line_key: 'wrong', source: stock_out:stock_out_org, billed_quantity: 0.1dec, unit_price: 1dec }
    ];`), "invoice line party must match its delivery");
  await rejects(() => db.query(`CREATE ONLY purchase_invoice_issue:wrong_party SET owned_by = rebase_group:root,
    invoice = purchase_invoice:foreign_party, issued_at = d'2026-03-07T00:00:00Z', lines = [
      { line_key: 'wrong', source: stock_in:stock_in_org, billed_quantity: 0.1dec, unit_price: 1dec }
    ];`), "purchase line party must match its receipt");
  assert.equal((await rows(db, "sales_invoice_issue")).some(row => String(row.id) === "sales_invoice_issue:wrong_party"), false,
    "invalid output creation leaves no partial issue source");
  assert.equal((await rows(db, "sales_invoice_line")).some(row => String(row.invoice) === "sales_invoice:foreign_party"), false,
    "invalid output creation leaves no partial invoice lines");
  await rejects(() => db.query(`CREATE ONLY sales_invoice_cash_allocation:wrong_currency SET owned_by = rebase_group:root,
    source = cash_in:eur_receipt, target = sales_invoice_issue:sale_issue_one,
    amount = 1dec, effective_at = d'2026-03-09T00:00:00Z';`), "invoice allocation currency must agree");
  await rejects(() => db.query("UPDATE stock_out:invoiced_delivery SET effective_at = d'2026-03-10T00:00:00Z';"),
    "moving delivery after its invoice must roll back");
  await rejects(() => db.query("UPDATE sales_invoice_issue:sale_issue_one SET issued_at = d'2026-03-05T00:00:00Z';"),
    "moving issue before delivery must roll back");
  await rejects(() => db.query("UPDATE sales_invoice_issue:sale_issue_one SET issued_at = d'2026-03-10T00:00:00Z';"),
    "moving issue after allocation must roll back");
  await rejects(() => db.query("UPDATE cash_in:invoice_receipt SET effective_at = d'2026-03-10T00:00:00Z';"),
    "moving cash source after allocation must roll back");
  assert.equal(queryResult(await db.query("RETURN sales_invoice_issue:sale_issue_one.issued_at = d'2026-03-07T00:00:00Z';")), true);
  assert.equal(numeric(queryResult(await db.query("RETURN stock_out:invoiced_delivery.quantity;"))), 5);
  await assertInvoiceOracles(db);

  await db.query("UPDATE sales_invoice_issue:sale_issue_one SET issued_at = d'2026-03-08T00:00:00Z';");
  await assertInvoiceOracles(db);
  assert.equal(await treeBefore(db, "claim_account:claim_a", "receivable", "2026-03-08T00:00:00Z"),
    await claimOracle(db, "receivable", "claim_account:claim_a", "2026-03-08T00:00:00Z"));
  await db.query(`UPDATE sales_invoice_issue:sale_issue_one SET lines = [
    { line_key: 'sale_a', source: stock_out:invoiced_delivery, billed_quantity: 3.5dec, unit_price: 2.50dec },
    { line_key: 'sale_b', source: stock_out:invoiced_delivery2, billed_quantity: 2dec, unit_price: 2.005dec }
  ];`);
  await assertInvoiceOracles(db);
  assert.equal(await ownerTreeSum(db, "stock_out:invoiced_delivery", "z_billing", "billed"), 4.5);
  assert.deepEqual((await rows(db, "sales_invoice_line")).map(row => String(row.id)).sort(), originalIds,
    "stable line keys preserve managed output identities");
  await rejects(() => db.query(`UPDATE sales_invoice_issue:sale_issue_one SET lines = [
    { line_key: 'sale_b', source: stock_out:invoiced_delivery2, billed_quantity: 2dec, unit_price: 2.005dec }
  ];`), "removing a line cannot leave its allocations unsupported");
  await assertInvoiceOracles(db);
  await db.query("DELETE sales_invoice_issue:sale_issue_two;");
  assert.equal((await rows(db, "sales_invoice_line")).some(row => String(row.invoice) === "sales_invoice:invoice_two"), false,
    "deleting an unallocated issue removes its managed invoice lines");
  assert.equal(await ownerTreeSum(db, "sales_invoice:invoice_two", "z_outstanding", "outstanding"), 0,
    "issue deletion removes its invoice and claim postings");
}

async function assertMovementOracles(db) {
  for (const id of ["treasury_account:cash_a", "treasury_account:cash_overdraft", "treasury_account:cash_eur"]) {
    assert.equal(await treeSum(db, id, "balance"), await cashOracle(db, id), `cash history mismatch for ${id}`);
  }
  for (const id of ["stock_account:stock_a", "stock_account:stock_b"]) {
    assert.equal(await treeSum(db, id, "quantity"), await stockOracle(db, id), `stock history mismatch for ${id}`);
  }
}

async function probeMovements(db) {
  await db.query(`
    CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'Euro', precision = 2;
    CREATE ONLY misc_account:opening_balance SET owned_by = rebase_group:root, label = 'Opening balance', purpose = 'opening_balance';
    CREATE ONLY treasury:bank_eur SET owned_by = rebase_group:root, name = 'Euro bank';
    CREATE ONLY treasury_account:cash_eur SET owned_by = rebase_group:root, economic_entity = organization:org_a,
      treasury = treasury:bank_eur, currency = currency:eur;
    CREATE ONLY operating_unit:unit_a2 SET owned_by = rebase_group:root, economic_entity = organization:org_a, name = 'A second warehouse';
    CREATE ONLY stock_account:stock_b SET owned_by = rebase_group:root, economic_entity = organization:org_a,
      operating_unit = operating_unit:unit_a2, resource = item:grain;
    CREATE ONLY item:copper SET owned_by = rebase_group:root, name = 'Copper', unit = measure_unit:kg;
    CREATE ONLY stock_account:stock_copper SET owned_by = rebase_group:root, economic_entity = organization:org_a,
      operating_unit = operating_unit:unit_a, resource = item:copper;
    CREATE ONLY exchange_pair:usd_eur SET owned_by = rebase_group:root, economic_entity = organization:org_a,
      given_resource = currency:usd, received_resource = currency:eur;
    CREATE ONLY currency_exchange:usd_eur SET owned_by = rebase_group:root, pair = exchange_pair:usd_eur,
      from_currency = currency:usd, to_currency = currency:eur, rate = 0.9dec,
      effective_at = d'2026-01-07T00:00:00Z';
  `);

  await db.query(`
    CREATE ONLY cash_in:cash_opening SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = treasury_account:cash_a,
      amount = 100dec, effective_at = d'2025-12-31T00:00:00Z';
    CREATE ONLY cash_in:in_org SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = treasury_account:cash_a, amount = 10dec, effective_at = d'2026-01-01T00:00:00Z';
    CREATE ONLY cash_in:in_tax SET owned_by = rebase_group:root, from_party = tax_account:tax_a, to_account = treasury_account:cash_a, amount = 10dec, effective_at = d'2026-01-02T00:00:00Z';
    CREATE ONLY cash_in:in_misc SET owned_by = rebase_group:root, from_party = misc_account:purpose_a, to_account = treasury_account:cash_a, amount = 10dec, effective_at = d'2026-01-03T00:00:00Z';
    CREATE ONLY cash_out:out_org SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_party = organization:org_b, amount = 1dec, effective_at = d'2026-01-04T00:00:00Z';
    CREATE ONLY cash_out:out_tax SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_party = tax_account:tax_a, amount = 1dec, effective_at = d'2026-01-05T00:00:00Z';
    CREATE ONLY cash_out:out_misc SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_party = misc_account:purpose_a, amount = 1dec, effective_at = d'2026-01-06T00:00:00Z';
    CREATE ONLY cash_transfer:cash_move SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_account = treasury_account:cash_overdraft,
      amount = 5dec, effective_at = d'2026-01-07T00:00:00Z';
    CREATE ONLY stock_in:stock_opening SET owned_by = rebase_group:root, from_party = misc_account:opening_balance, to_account = stock_account:stock_a,
      quantity = 20dec, effective_at = d'2025-12-31T00:00:00Z';
    CREATE ONLY stock_in:stock_in_org SET owned_by = rebase_group:root, from_party = organization:org_b, to_account = stock_account:stock_a, quantity = 10dec, effective_at = d'2026-01-01T00:00:00Z';
    CREATE ONLY stock_in:stock_in_misc SET owned_by = rebase_group:root, from_party = misc_account:purpose_a, to_account = stock_account:stock_a, quantity = 10dec, effective_at = d'2026-01-02T00:00:00Z';
    CREATE ONLY stock_out:stock_out_org SET owned_by = rebase_group:root, from_account = stock_account:stock_a, to_party = organization:org_b, quantity = 1dec, effective_at = d'2026-01-03T00:00:00Z';
    CREATE ONLY stock_out:stock_out_misc SET owned_by = rebase_group:root, from_account = stock_account:stock_a, to_party = misc_account:purpose_a, quantity = 1dec, effective_at = d'2026-01-04T00:00:00Z';
    CREATE ONLY stock_transfer:stock_move SET owned_by = rebase_group:root, from_account = stock_account:stock_a, to_account = stock_account:stock_b,
      quantity = 3dec, effective_at = d'2026-01-05T00:00:00Z';
    CREATE ONLY cash_fx_transfer:fx_move SET owned_by = rebase_group:root, from_account = treasury_account:cash_a, to_account = treasury_account:cash_eur,
      exchange = currency_exchange:usd_eur, from_amount = 2.01dec,
      effective_at = d'2026-02-06T00:00:00Z';
  `);
  await assertMovementOracles(db);
  await assertOpeningMovementSnapshots(db);
  assert.equal(await treeSum(db, "treasury_account:cash_a", "balance"), 119.99);
  assert.equal(await treeSum(db, "treasury_account:cash_overdraft", "balance"), 5);
  assert.equal(await treeSum(db, "treasury_account:cash_eur", "balance"), 1.81);
  assert.equal(await treeSum(db, "stock_account:stock_a", "quantity"), 35);
  assert.equal(await treeSum(db, "stock_account:stock_b", "quantity"), 3);
  assert.equal((await rows(db, "cash_in")).length, 4);
  assert.equal((await rows(db, "cash_out")).length, 3);
  assert.equal((await rows(db, "cash_transfer")).length, 1);
  assert.equal((await rows(db, "cash_fx_transfer")).length, 1);
  assert.equal((await rows(db, "stock_in")).length, 3);
  assert.equal((await rows(db, "stock_out")).length, 2);
  assert.equal((await rows(db, "stock_transfer")).length, 1);
  const fx = queryResult(await db.query(`RETURN {
    to_amount: cash_fx_transfer:fx_move.to_amount,
    residual: cash_fx_transfer:fx_move.rounding_residual,
    used_source: currency_exchange:usd_eur.z_usage.summary.measures.source.sum,
    used_target: currency_exchange:usd_eur.z_usage.summary.measures.target.sum
  };`));
  assert.equal(numeric(fx.to_amount), 1.81);
  assert.equal(numeric(fx.residual), -0.001);
  assert.equal(numeric(fx.used_source), 2.01);
  assert.equal(numeric(fx.used_target), 1.81);

  await db.query("UPDATE cash_in:in_org SET amount = 12dec;");
  await assertMovementOracles(db);
  await db.query("DELETE cash_out:out_tax;");
  await assertMovementOracles(db);
  const beforeRejectedCash = await treeSum(db, "treasury_account:cash_a", "balance");
  await rejects(() => db.query(`CREATE ONLY cash_out:overdraw SET owned_by = rebase_group:root,
    from_account = treasury_account:cash_a, to_party = misc_account:purpose_a,
    amount = 1000dec, effective_at = d'2026-02-01T00:00:00Z';`),
  "cash history cannot fall below the account's configured minimum");
  assert.equal(await treeSum(db, "treasury_account:cash_a", "balance"), beforeRejectedCash,
    "rejected cash movement must restore the complete source tree");
  await assertMovementOracles(db);
  await rejects(() => db.query(`CREATE ONLY cash_transfer:cross_currency SET owned_by = rebase_group:root,
    from_account = treasury_account:cash_a, to_account = treasury_account:cash_eur,
    amount = 1dec, effective_at = d'2026-02-02T00:00:00Z';`),
  "cash transfers cannot combine currencies");
  const cashAfterFx = await treeSum(db, "treasury_account:cash_a", "balance");
  await rejects(() => db.query(`CREATE ONLY cash_fx_transfer:before_quote SET owned_by = rebase_group:root,
    from_account = treasury_account:cash_a, to_account = treasury_account:cash_eur,
    exchange = currency_exchange:usd_eur, from_amount = 1dec,
    effective_at = d'2026-01-06T00:00:00Z';`),
  "an FX quote cannot be used before its effective time");
  assert.equal(await treeSum(db, "treasury_account:cash_a", "balance"), cashAfterFx,
    "rejected early FX use must roll back all treasury positions");
  await assertMovementOracles(db);
  await rejects(() => db.query(`CREATE ONLY stock_transfer:cross_resource SET owned_by = rebase_group:root,
    from_account = stock_account:stock_a, to_account = stock_account:stock_copper,
    quantity = 1dec, effective_at = d'2026-02-03T00:00:00Z';`),
  "stock transfers cannot convert one resource into another");
  await rejects(() => db.query(`CREATE ONLY stock_out:overdraw SET owned_by = rebase_group:root,
    from_account = stock_account:stock_a, to_party = misc_account:purpose_a,
    quantity = 1000dec, effective_at = d'2026-02-04T00:00:00Z';`),
  "stock history cannot fall below its configured minimum");
  await rejects(() => db.query(`CREATE ONLY cash_transfer:external_to_external SET owned_by = rebase_group:root,
    from_account = organization:org_a, to_account = organization:org_b,
    amount = 1dec, effective_at = d'2026-02-05T00:00:00Z';`),
  "real money cannot move between unmodeled external endpoints");
}

async function probeH1Identity(db) {
  await db.query(`
    CREATE ONLY rebase_user:personal SET name = 'Personal entity', parents = [rebase_group:root];
    CREATE ONLY rebase_user:counterparty SET name = 'User counterparty', parents = [rebase_group:root];
    CREATE ONLY organization:managed SET owned_by = rebase_group:root, name = 'Managed organization';
    CREATE ONLY treasury:shared SET owned_by = rebase_group:root, name = 'Reusable treasury';
    CREATE ONLY operating_unit:personal_unit SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, name = 'Personal store';
    CREATE ONLY treasury_account:personal_usd SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, treasury = treasury:shared, currency = currency:usd;
    CREATE ONLY treasury_account:managed_usd SET owned_by = rebase_group:root,
      economic_entity = organization:managed, treasury = treasury:shared, currency = currency:usd;
    CREATE ONLY treasury_account:personal_eur SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, treasury = treasury:shared, currency = currency:eur;
    CREATE ONLY stock_account:personal_stock SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, operating_unit = operating_unit:personal_unit, resource = item:grain;
    CREATE ONLY claim_account:personal_claim SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, opponent = rebase_user:counterparty, currency = currency:usd;
    CREATE ONLY cash_in:personal_opening SET owned_by = rebase_group:root,
      from_party = rebase_user:counterparty, to_account = treasury_account:personal_usd,
      amount = 10dec, effective_at = d'2026-04-01T00:00:00Z';
    CREATE ONLY receivable:personal_receivable SET owned_by = rebase_group:root,
      claim_account = claim_account:personal_claim, amount = 2dec,
      effective_at = d'2026-04-01T00:00:00Z';
  `);
  assert.equal(String(queryResult(await db.query('RETURN treasury_account:personal_usd.economic_entity;'))),
    'rebase_user:personal', 'personal account directly references its user');
  assert.equal(String(queryResult(await db.query('RETURN cash_in:personal_opening.economic_entity;'))),
    'rebase_user:personal', 'movement inherits the account entity');
  assert.equal(String(queryResult(await db.query('RETURN receivable:personal_receivable.economic_entity;'))),
    'rebase_user:personal', 'claim source inherits the account entity');
  assert.equal(String(queryResult(await db.query('RETURN treasury_account:personal_usd.owned_by;'))),
    'rebase_group:root', 'authorization ownership is independent of economic entity');
  assert.equal(await treeSum(db, 'treasury_account:personal_usd', 'balance'), 10);
  await rejects(() => db.query(`CREATE ONLY treasury_account:duplicate_personal SET owned_by = rebase_group:root,
    economic_entity = rebase_user:personal, treasury = treasury:shared, currency = currency:usd;`),
  'multi-currency profile forbids duplicate entity, treasury and currency');
  await rejects(() => db.query(`CREATE ONLY stock_account:cross_unit SET owned_by = rebase_group:root,
    economic_entity = organization:managed, operating_unit = operating_unit:personal_unit, resource = item:grain;`),
  'stock account cannot borrow an operating unit from another entity');
  await rejects(() => db.query(`CREATE ONLY cash_transfer:cross_entity SET owned_by = rebase_group:root,
    from_account = treasury_account:personal_usd, to_account = treasury_account:managed_usd,
    amount = 1dec, effective_at = d'2026-04-02T00:00:00Z';`),
  'treasury endpoints must agree on entity');
  assert.equal(await treeSum(db, 'treasury_account:personal_usd', 'balance'), 10,
    'cross-entity rejection leaves history intact');
  await rejects(() => db.query(`CREATE ONLY stock_transfer:cross_entity SET owned_by = rebase_group:root,
    from_account = stock_account:personal_stock, to_account = stock_account:stock_a,
    quantity = 1dec, effective_at = d'2026-04-02T00:00:00Z';`),
  'stock endpoints must agree on entity');
  await rejects(() => db.query('UPDATE treasury_account:personal_usd SET economic_entity = organization:managed;'),
    'economic identity is immutable');
  await rejects(() => db.query('UPDATE operating_unit:personal_unit SET economic_entity = organization:managed;'),
    'operating unit identity is immutable');
  await rejects(() => db.query('UPDATE item:grain SET unit = measure_unit:each;'),
    'resource unit is immutable');
  await rejects(() => db.query('UPDATE claim_account:personal_claim SET currency = currency:eur;'),
    'claim currency is immutable');
}

async function probeH1Authorization(db, endpoint, namespace) {
  await db.query(`
    CREATE ONLY rebase_group:h1_actor SET name = 'H1 actor', parents = [rebase_group:root],
      role = ['cash_in_create', 'cash_in_select', 'treasury_account_select', 'treasury_account_update'];
    CREATE ONLY rebase_user:h1_actor SET name = 'H1 actor', parents = [rebase_group:h1_actor];
    DEFINE ACCESS h1_probe_actor ON DATABASE TYPE RECORD SIGNIN rebase_user:h1_actor;
  `);
  const actor = new Surreal();
  try {
    await actor.connect(endpoint);
    await actor.signin({ namespace, database: 'probe', access: 'h1_probe_actor' });
    const visible = queryResult(await actor.query('SELECT VALUE id FROM treasury_account:personal_usd;'));
    assert.deepEqual(visible, [], 'a record actor cannot read an account owned by another principal');
    const before = (await rows(db, 'cash_in')).length;
    try {
      await actor.query(`CREATE ONLY cash_in:unauthorized_personal SET owned_by = rebase_user:h1_actor,
        from_party = rebase_user:counterparty, to_account = treasury_account:personal_usd,
        amount = 1dec, effective_at = d'2026-04-03T00:00:00Z';`);
    } catch { /* The engine may reject at the reference or tree update boundary. */ }
    assert.equal((await rows(db, 'cash_in')).length, before,
      'a principal with source-create permission cannot post into another owner\'s account');
    assert.equal(await treeSum(db, 'treasury_account:personal_usd', 'balance'), 10,
      'unauthorized use leaves account history unchanged');
  } finally {
    await actor.close().catch(() => {});
  }
}

async function probeSingleCurrencyVariant(db, namespace, schema) {
  const index = 'DEFINE INDEX OVERWRITE treasury_account_dimensions ON treasury_account FIELDS economic_entity, treasury, currency UNIQUE;';
  assert(schema.includes(index), 'multi-currency index must have an exact replacement point');
  const singleSchema = schema.replace(index,
    'DEFINE INDEX OVERWRITE treasury_account_dimensions ON treasury_account FIELDS economic_entity, treasury UNIQUE;');
  await db.use({ namespace, database: 'single_currency_variant' });
  await db.query(singleSchema);
  await db.query(`
    CREATE ONLY rebase_user:personal SET name = 'Personal entity', parents = [rebase_group:root];
    CREATE ONLY treasury:shared SET owned_by = rebase_group:root, name = 'Shared';
    CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'US dollar';
    CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'Euro';
    CREATE ONLY treasury_account:usd SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, treasury = treasury:shared, currency = currency:usd;
  `);
  await rejects(() => db.query(`CREATE ONLY treasury_account:eur SET owned_by = rebase_group:root,
    economic_entity = rebase_user:personal, treasury = treasury:shared, currency = currency:eur;`),
  'single-currency variant forbids a second currency for the same entity and treasury');
  await db.use({ namespace, database: 'probe' });
}

async function probeH1MigrationPreflight(db, namespace) {
  const snapshot = {
    books: [{ id: 'book:personal' }, { id: 'book:company' }],
    legacy: {
      treasury_account: [
        { id: 'treasury_account:personal', book: 'book:personal', treasury: 'treasury:shared', currency: 'currency:usd' },
        { id: 'treasury_account:company', book: 'book:company', treasury: 'treasury:shared', currency: 'currency:usd' },
      ],
      claim_account: [], stock_account: [], sales_invoice: [
        { id: 'sales_invoice:personal', book: 'book:personal', number: 'S-1' },
        { id: 'sales_invoice:company', book: 'book:company', number: 'S-1' },
      ], purchase_invoice: [],
    },
    existing: {},
  };
  const mapping = [
    { book: 'book:personal', economic_entity: 'rebase_user:personal' },
    { book: 'book:company', economic_entity: 'organization:managed' },
  ];
  const plan = preflightH1(snapshot, mapping);
  assert.equal(plan.treasury_account.length, 2);
  assert.equal(plan.sales_invoice.length, 2);
  await db.use({ namespace, database: 'h1_migration_fixture' });
  await db.query(`
    DEFINE TABLE legacy_account SCHEMAFULL;
    DEFINE FIELD book ON legacy_account TYPE record<book>;
    DEFINE FIELD treasury ON legacy_account TYPE record<treasury>;
    DEFINE FIELD currency ON legacy_account TYPE record<currency>;
    DEFINE TABLE migrated_account SCHEMAFULL;
    DEFINE FIELD economic_entity ON migrated_account TYPE record<rebase_user | organization>;
    DEFINE FIELD treasury ON migrated_account TYPE record<treasury>;
    DEFINE FIELD currency ON migrated_account TYPE record<currency>;
    DEFINE INDEX migrated_account_key ON migrated_account FIELDS economic_entity, treasury, currency UNIQUE;
    DEFINE TABLE migrated_invoice SCHEMAFULL;
    DEFINE FIELD economic_entity ON migrated_invoice TYPE record<rebase_user | organization>;
    DEFINE FIELD number ON migrated_invoice TYPE string;
    DEFINE INDEX migrated_invoice_key ON migrated_invoice FIELDS economic_entity, number UNIQUE;
    CREATE ONLY legacy_account:personal SET book = book:personal, treasury = treasury:shared, currency = currency:usd;
    CREATE ONLY legacy_account:company SET book = book:company, treasury = treasury:shared, currency = currency:usd;
  `);
  await db.query(`BEGIN TRANSACTION;
    CREATE ONLY migrated_account:personal SET economic_entity = rebase_user:personal,
      treasury = treasury:shared, currency = currency:usd;
    CREATE ONLY migrated_account:company SET economic_entity = organization:managed,
      treasury = treasury:shared, currency = currency:usd;
    CREATE ONLY migrated_invoice:personal SET economic_entity = rebase_user:personal, number = 'S-1';
    CREATE ONLY migrated_invoice:company SET economic_entity = organization:managed, number = 'S-1';
    COMMIT TRANSACTION;`);
  assert.equal((await rows(db, 'migrated_account')).length, 2);
  assert.equal((await rows(db, 'legacy_account')).length, 2, 'legacy rows remain available until cutover');
  snapshot.existing = {
    treasury_account: snapshot.legacy.treasury_account.map((row, i) => ({
      ...row, book: undefined, economic_entity: mapping[i].economic_entity,
    })),
    sales_invoice: snapshot.legacy.sales_invoice.map((row, i) => ({
      ...row, book: undefined, economic_entity: mapping[i].economic_entity,
    })),
  };
  const reapply = preflightH1(snapshot, mapping);
  assert.equal(reapply.treasury_account.length, 0, 'reapplication has no account writes');
  assert.equal(reapply.sales_invoice.length, 0, 'reapplication has no invoice writes');
  assert.throws(() => preflightH1(snapshot, [mapping[0], mapping[0], mapping[1]]),
    /H1_AMBIGUOUS_MAPPING/, 'duplicate mapping is rejected');
  assert.throws(() => preflightH1(snapshot, [mapping[0]]),
    /H1_MISSING_MAPPING/, 'every legacy book needs an explicit mapping');
  assert.throws(() => preflightH1({ ...snapshot, existing: {} }, [mapping[0],
    { book: 'book:company', economic_entity: 'rebase_user:personal' }]),
  /H1_DESTINATION_COLLISION/, 'destination account and invoice keys cannot merge');
  assert.equal((await rows(db, 'migrated_account')).length, 2, 'failed preflight makes no writes');
  await rejects(() => db.query(`BEGIN TRANSACTION;
    CREATE ONLY migrated_account:transient SET economic_entity = organization:managed,
      treasury = treasury:other, currency = currency:usd;
    CREATE ONLY migrated_account:collision SET economic_entity = rebase_user:personal,
      treasury = treasury:shared, currency = currency:usd;
    COMMIT TRANSACTION;`), 'unexpected destination collision rolls back the whole transaction');
  assert.equal((await rows(db, 'migrated_account')).length, 2, 'transaction rollback removes partial writes');
  const ambiguousUnit = {
    ...snapshot, existing: {}, legacy: { ...snapshot.legacy,
      stock_account: [
        { id: 'stock_account:one', book: 'book:personal', operating_unit: 'operating_unit:shared', resource: 'item:grain' },
        { id: 'stock_account:two', book: 'book:company', operating_unit: 'operating_unit:shared', resource: 'item:grain' },
      ], operating_unit: [{ id: 'operating_unit:shared' }],
    },
  };
  assert.throws(() => preflightH1(ambiguousUnit, mapping), /H1_AMBIGUOUS_OPERATING_UNIT/,
    'an operating unit shared across new entities cannot be silently split');
  await db.use({ namespace, database: 'probe' });
}

async function h2RootSnapshot(db) {
  return queryResult(await db.query(`RETURN {
    stock: stock_account:h2_stock.z_history.summary,
    supplier: claim_account:h2_supplier.z_history.summary,
    tax: claim_account:h2_tax_claim.z_history.summary,
    invoice: purchase_invoice:h2_invoice.z_outstanding.summary
  };`));
}

async function assertH2ReceiptOracle(db) {
  const receipts = (await rows(db, 'purchase_receipt')).filter((row) =>
    String(row.invoice) === 'purchase_invoice:h2_invoice');
  let quantity = 0, base = 0, tax = 0;
  for (const row of receipts) {
    quantity += numeric(row.quantity);
    base += Math.round(numeric(row.quantity) * numeric(row.unit_price) * 100) / 100;
    tax += numeric(row.tax_amount);
  }
  const gross = Math.round((base + tax) * 100) / 100;
  const snapshot = await h2RootSnapshot(db);
  const measure = (root, name) => numeric(snapshot[root]?.measures?.[name]?.sum ?? 0);
  assert.equal(measure('stock', 'quantity'), quantity, 'stock oracle uses received quantity');
  assert.equal(measure('supplier', 'payable'), gross, 'supplier oracle uses calculated base plus entered tax');
  assert.equal(measure('supplier', 'net'), gross === 0 ? 0 : -gross,
    'supplier net is the negative payable');
  assert.equal(measure('tax', 'receivable'), tax, 'tax credit uses the entered invoice fact');
  assert.equal(measure('tax', 'net'), tax, 'tax credit net is positive');
  assert.equal(measure('invoice', 'outstanding'), gross, 'invoice oracle uses calculated gross');
  for (const root of ['stock', 'supplier', 'tax', 'invoice']) {
    assert.equal(snapshot[root]?.count ?? 0, receipts.length,
      `${root} has one active position per receipt despite same-root slots`);
  }
  return snapshot;
}

async function probeH2Receipt(db) {
  await db.query(`
    CREATE ONLY organization:h2_vendor SET owned_by = rebase_group:root, name = 'H2 vendor';
    CREATE ONLY tax_account:h2_tax SET owned_by = rebase_group:root,
      authority = organization:org_b, jurisdiction = organization:org_a, label = 'Input tax';
    CREATE ONLY operating_unit:h2_unit SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, name = 'H2 warehouse';
    CREATE ONLY stock_account:h2_stock SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, operating_unit = operating_unit:h2_unit, resource = item:grain;
    CREATE ONLY claim_account:h2_supplier SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = organization:h2_vendor, currency = currency:usd;
    CREATE ONLY claim_account:h2_tax_claim SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h2_tax, currency = currency:usd;
    CREATE ONLY claim_account:h2_tax_eur SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h2_tax, currency = currency:eur;
    CREATE ONLY claim_account:h2_tax_other_entity SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, opponent = tax_account:h2_tax, currency = currency:usd;
    CREATE ONLY purchase_invoice:h2_invoice SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_supplier, number = 'H2-1';
  `);
  const beforeStockIn = (await rows(db, 'stock_in')).length;
  const beforeIssues = (await rows(db, 'purchase_invoice_issue')).length;
  const beforeLines = (await rows(db, 'purchase_invoice_line')).length;
  const common = `invoice = purchase_invoice:h2_invoice,
    stock_account = stock_account:h2_stock,
    tax_claim_account = claim_account:h2_tax_claim, quantity = 3dec, unit_price = 7.33dec,
    tax_amount = 2.01dec, effective_at = d'2026-05-01T00:00:00Z'`;
  await db.query(`CREATE ONLY purchase_receipt:h2 SET owned_by = rebase_group:root, ${common};`);
  let snapshot = await assertH2ReceiptOracle(db);
  assert.equal(numeric(queryResult(await db.query('RETURN purchase_receipt:h2.base_amount;'))), 21.99);
  assert.equal(numeric(queryResult(await db.query('RETURN purchase_receipt:h2.gross_amount;'))), 24);
  const derived = queryResult(await db.query(`RETURN {
    from_party: purchase_receipt:h2.from_party,
    resource: purchase_receipt:h2.resource,
    unit: purchase_receipt:h2.unit,
    economic_entity: purchase_receipt:h2.economic_entity
  };`));
  assert.equal(String(derived.from_party), 'organization:h2_vendor');
  assert.equal(String(derived.resource), 'item:grain');
  assert.equal(String(derived.unit), 'measure_unit:kg');
  assert.equal(String(derived.economic_entity), 'organization:org_a');
  assert.equal((await rows(db, 'stock_in')).length, beforeStockIn, 'receipt adds no old stock source');
  assert.equal((await rows(db, 'purchase_invoice_issue')).length, beforeIssues, 'receipt adds no invoice issue');
  assert.equal((await rows(db, 'purchase_invoice_line')).length, beforeLines, 'receipt adds no invoice line');
  await rejects(() => db.query(`CREATE ONLY purchase_receipt:h2_wrong_entity SET owned_by = rebase_group:root,
    ${common.replace('stock_account:h2_stock', 'stock_account:personal_stock')};`), 'stock endpoint must share entity');
  await rejects(() => db.query(`CREATE ONLY purchase_receipt:h2_wrong_tax_entity SET owned_by = rebase_group:root,
    ${common.replace('claim_account:h2_tax_claim', 'claim_account:h2_tax_other_entity')};`), 'tax claim must share entity');
  await rejects(() => db.query(`CREATE ONLY purchase_receipt:h2_wrong_currency SET owned_by = rebase_group:root,
    ${common.replace('claim_account:h2_tax_claim', 'claim_account:h2_tax_eur')};`), 'tax claim must use invoice currency');
  await rejects(() => db.query(`CREATE ONLY purchase_receipt:h2_wrong_tax_opponent SET owned_by = rebase_group:root,
    ${common.replace('claim_account:h2_tax_claim', 'claim_account:claim_misc')};`), 'tax claim opponent must be a tax account');
  await rejects(() => db.query('UPDATE purchase_receipt:h2 SET from_party = organization:org_b;'),
    'supplier is protected by the invoice claim');
  await rejects(() => db.query('UPDATE purchase_receipt:h2 SET resource = item:copper;'),
    'resource is protected by the stock account');
  await rejects(() => db.query('UPDATE purchase_receipt:h2 SET unit = measure_unit:each;'),
    'unit is protected by the stock account');
  assert.deepEqual(await h2RootSnapshot(db), snapshot, 'rejected endpoint changes leave every root unchanged');
  await db.query('UPDATE purchase_receipt:h2 SET tax_amount = 3dec;');
  snapshot = await assertH2ReceiptOracle(db);
  assert.equal(numeric(queryResult(await db.query('RETURN purchase_receipt:h2.gross_amount;'))), 24.99);
  await db.query('UPDATE purchase_receipt:h2 SET quantity = 4dec;');
  snapshot = await assertH2ReceiptOracle(db);
  assert.equal(numeric(queryResult(await db.query('RETURN purchase_receipt:h2.base_amount;'))), 29.32);
  await db.query("UPDATE purchase_receipt:h2 SET effective_at = d'2027-01-01T00:00:00Z';");
  await assertH2ReceiptOracle(db);
  assert.equal(numeric(queryResult(await db.query(`RETURN fn::tree::read(stock_account:h2_stock,
    'z_history', 'before', [d'2026-12-31T00:00:00Z']).measures.quantity.sum ?? 0dec;`))), 0,
  'future-effective receipt has no earlier stock position');
  await db.query("UPDATE purchase_receipt:h2 SET effective_at = d'2026-05-03T00:00:00Z';");
  snapshot = await assertH2ReceiptOracle(db);
  assert.equal(numeric(queryResult(await db.query(`RETURN fn::tree::read(stock_account:h2_stock,
    'z_history', 'before', [d'2026-05-02T00:00:00Z']).measures.quantity.sum ?? 0dec;`))), 0,
  'date move removes the old dated position');
  await db.query('UPDATE claim_account:h2_supplier SET net_floor = -33dec;');
  await rejects(() => db.query('UPDATE purchase_receipt:h2 SET unit_price = 8.50dec;'),
    'supplier net floor rejects a larger historical payable');
  assert.deepEqual(await h2RootSnapshot(db), snapshot, 'failed net guard rolls back all four roots');
  assert.equal(numeric(queryResult(await db.query('RETURN purchase_receipt:h2.unit_price;'))), 7.33,
    'failed price edit rolls back the source');
  await rejects(() => db.query('UPDATE claim_account:h2_tax_claim SET net_ceiling = 2dec;'),
    'lowering a tax-credit ceiling below history fails');
  assert.deepEqual(await h2RootSnapshot(db), snapshot, 'failed limit change preserves tax and other roots');
  await db.query('DELETE purchase_receipt:h2;');
  await assertH2ReceiptOracle(db);
  assert.equal((await rows(db, 'stock_in')).length, beforeStockIn);
  assert.equal((await rows(db, 'purchase_invoice_issue')).length, beforeIssues);
  assert.equal((await rows(db, 'purchase_invoice_line')).length, beforeLines);
}

async function assertH2NetOracle(db, accountId) {
  const changes = new Map();
  let positions = 0;
  for (const [table, sign] of [['receivable', 1], ['payable', -1]]) {
    for (const row of await rows(db, table)) {
      if (String(row.claim_account) !== accountId) continue;
      const at = String(row.effective_at);
      changes.set(at, (changes.get(at) || 0) + sign * numeric(row.amount));
      positions++;
    }
  }
  let net = 0, low = 0, high = 0;
  for (const at of [...changes.keys()].sort()) {
    net = Math.round((net + changes.get(at)) * 100) / 100;
    low = Math.min(low, net);
    high = Math.max(high, net);
  }
  const summary = queryResult(await db.query(`RETURN ${accountId}.z_history.summary;`));
  assert.equal(numeric(summary.measures.net.sum), net, `${accountId} net sum`);
  assert.equal(numeric(summary.measures.net.instant_min), low, `${accountId} complete-time minimum`);
  assert.equal(numeric(summary.measures.net.instant_max), high, `${accountId} complete-time maximum`);
  assert.equal(summary.count, positions, `${accountId} active root positions`);
  return summary;
}

async function probeH2NetBounds(db) {
  await db.query(`
    CREATE ONLY misc_account:h2_net_a SET owned_by = rebase_group:root, label = 'Net order A';
    CREATE ONLY misc_account:h2_net_b SET owned_by = rebase_group:root, label = 'Net order B';
    CREATE ONLY misc_account:h2_peak SET owned_by = rebase_group:root, label = 'Net peak';
    CREATE ONLY misc_account:h2_trough SET owned_by = rebase_group:root, label = 'Net trough';
    CREATE ONLY misc_account:h2_unbounded SET owned_by = rebase_group:root, label = 'No net bound';
    CREATE ONLY claim_account:h2_net_a SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = misc_account:h2_net_a, currency = currency:usd;
    CREATE ONLY claim_account:h2_net_b SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = misc_account:h2_net_b, currency = currency:usd;
    CREATE ONLY claim_account:h2_peak SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = misc_account:h2_peak, currency = currency:usd;
    CREATE ONLY claim_account:h2_trough SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = misc_account:h2_trough, currency = currency:usd;
    CREATE ONLY claim_account:h2_unbounded SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = misc_account:h2_unbounded, currency = currency:usd;
    CREATE ONLY receivable:h2_a_r SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_net_a, amount = 100dec, effective_at = d'2026-06-01T00:00:00Z';
    CREATE ONLY payable:h2_z_p SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_net_a, amount = 100dec, effective_at = d'2026-06-01T00:00:00Z';
    CREATE ONLY payable:h2_a_p SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_net_b, amount = 100dec, effective_at = d'2026-06-01T00:00:00Z';
    CREATE ONLY receivable:h2_z_r SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_net_b, amount = 100dec, effective_at = d'2026-06-01T00:00:00Z';
    CREATE ONLY receivable:h2_peak_r SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_peak, amount = 100dec, effective_at = d'2026-06-01T00:00:00Z';
    CREATE ONLY payable:h2_peak_p SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_peak, amount = 100dec, effective_at = d'2026-06-02T00:00:00Z';
    CREATE ONLY payable:h2_trough_p SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_trough, amount = 100dec, effective_at = d'2026-06-01T00:00:00Z';
    CREATE ONLY receivable:h2_trough_r SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_trough, amount = 100dec, effective_at = d'2026-06-02T00:00:00Z';
    CREATE ONLY payable:h2_unbounded_p SET owned_by = rebase_group:root,
      claim_account = claim_account:h2_unbounded, amount = 50dec, effective_at = d'2026-06-03T00:00:00Z';
  `);
  const a = await assertH2NetOracle(db, 'claim_account:h2_net_a');
  const b = await assertH2NetOracle(db, 'claim_account:h2_net_b');
  assert.equal(numeric(a.measures.net.instant_max), 0);
  assert.equal(numeric(b.measures.net.instant_min), 0);
  await db.query(`
    UPDATE claim_account:h2_net_a SET net_floor = 0dec, net_ceiling = 0dec;
    UPDATE claim_account:h2_net_b SET net_floor = 0dec, net_ceiling = 0dec;
  `);
  const beforeMove = queryResult(await db.query('RETURN claim_account:h2_net_a.z_history.summary;'));
  await rejects(() => db.query("UPDATE payable:h2_z_p SET effective_at = d'2026-06-02T00:00:00Z';"),
    'moving one same-time side later exposes a forbidden historical peak');
  assert.deepEqual(queryResult(await db.query('RETURN claim_account:h2_net_a.z_history.summary;')),
    beforeMove, 'failed date move restores the entire claim root');
  await assertH2NetOracle(db, 'claim_account:h2_net_a');
  await assertH2NetOracle(db, 'claim_account:h2_net_b');

  const peak = await assertH2NetOracle(db, 'claim_account:h2_peak');
  assert.equal(numeric(peak.measures.net.sum), 0, 'final net is zero');
  assert.equal(numeric(peak.measures.net.instant_max), 100, 'earlier complete-time peak is retained');
  const beforeLimit = queryResult(await db.query('RETURN claim_account:h2_peak.z_history.summary;'));
  await rejects(() => db.query('UPDATE claim_account:h2_peak SET net_ceiling = 99dec;'),
    'final zero does not erase a historical peak');
  assert.deepEqual(queryResult(await db.query('RETURN claim_account:h2_peak.z_history.summary;')),
    beforeLimit, 'failed ceiling change preserves the root');
  await db.query('UPDATE claim_account:h2_peak SET net_ceiling = 100dec;');
  await rejects(() => db.query('UPDATE claim_account:h2_peak SET net_ceiling = 99dec;'),
    'lowering an existing ceiling must revalidate history');
  await assertH2NetOracle(db, 'claim_account:h2_peak');
  const trough = await assertH2NetOracle(db, 'claim_account:h2_trough');
  assert.equal(numeric(trough.measures.net.instant_min), -100);
  await rejects(() => db.query('UPDATE claim_account:h2_trough SET net_floor = -99dec;'),
    'complete-time historical trough enforces optional floor');
  await db.query('UPDATE claim_account:h2_trough SET net_floor = -100dec;');
  const unbounded = await assertH2NetOracle(db, 'claim_account:h2_unbounded');
  assert.equal(numeric(unbounded.measures.net.sum), -50,
    'account without a net bound still maintains the net measure');
  await assertClaimOracles(db);
}

async function h3bGraph(db) {
  return queryResult(await db.query(`RETURN {
    receipt: (SELECT * FROM ONLY purchase_receipt:h3b_receipt),
    allocations: (SELECT * FROM purchase_receipt_cash_allocation
      WHERE target = purchase_receipt:h3b_receipt ORDER BY id),
    shared_due: (SELECT * FROM ONLY payable:h3b_shared_due),
    shared_allocation: (SELECT * FROM ONLY payable_cash_allocation:h3b_shared),
    source_a: (SELECT * FROM ONLY cash_out:h3b_pay_a),
    source_b: (SELECT * FROM ONLY cash_out:h3b_pay_b),
    source_c: (SELECT * FROM ONLY cash_out:h3b_pay_c),
    wrong_party: (SELECT * FROM ONLY cash_out:h3b_wrong_party),
    wrong_currency: (SELECT * FROM ONLY cash_out:h3b_wrong_currency),
    wrong_entity: (SELECT * FROM ONLY cash_out:h3b_wrong_entity),
    stock: (SELECT * FROM ONLY stock_account:h3b_stock),
    supplier: (SELECT * FROM ONLY claim_account:h3b_supplier),
    tax: (SELECT * FROM ONLY claim_account:h3b_tax_claim),
    invoice: (SELECT * FROM ONLY purchase_invoice:h3b_invoice),
    cash: (SELECT * FROM ONLY treasury_account:h3b_cash),
    other_currency_cash: (SELECT * FROM ONLY treasury_account:cash_eur),
    other_entity_cash: (SELECT * FROM ONLY treasury_account:personal_usd)
  };`));
}

async function assertH3bOracle(db) {
  const graph = await h3bGraph(db);
  const receipt = graph.receipt;
  const allocations = graph.allocations || [];
  const base = receipt ? Math.round(numeric(receipt.quantity) * numeric(receipt.unit_price) * 100) / 100 : 0;
  const tax = receipt ? numeric(receipt.tax_amount) : 0;
  const gross = Math.round((base + tax) * 100) / 100;
  const paid = Math.round(allocations.reduce((sum, row) => sum + numeric(row.amount), 0) * 100) / 100;
  const sharedDue = graph.shared_due ? numeric(graph.shared_due.amount) : 0;
  const sharedPaid = graph.shared_allocation ? numeric(graph.shared_allocation.amount) : 0;
  const supplierBalance = Math.round((gross + sharedDue - paid - sharedPaid) * 100) / 100;
  const measure = (owner, root, name) => numeric(owner?.[root]?.summary?.measures?.[name]?.sum ?? 0);
  assert.equal(measure(graph.stock, 'z_history', 'quantity'), receipt ? numeric(receipt.quantity) : 0,
    'receipt alone publishes physical stock');
  assert.equal(measure(graph.tax, 'z_history', 'receivable'), tax,
    'payment does not duplicate or consume input tax credit');
  assert.equal(measure(graph.tax, 'z_history', 'net'), tax, 'tax-credit net remains independent');
  assert.equal(measure(graph.supplier, 'z_history', 'payable'), supplierBalance,
    'supplier payable reconstructs from receipt and payment sources');
  assert.equal(measure(graph.supplier, 'z_history', 'net'), supplierBalance === 0 ? 0 : -supplierBalance,
    'supplier net reconstructs from authoritative sources');
  assert.equal(measure(graph.invoice, 'z_outstanding', 'outstanding'), Math.round((gross - paid) * 100) / 100,
    'invoice outstanding reconstructs from receipt and payment sources');
  for (const [owner, root, expected, label] of [
    [graph.stock, 'z_history', receipt ? 1 : 0, 'stock'],
    [graph.tax, 'z_history', receipt ? 1 : 0, 'tax claim'],
    [graph.supplier, 'z_history', (receipt ? 1 : 0) + allocations.length
      + (graph.shared_due ? 1 : 0) + (graph.shared_allocation ? 1 : 0), 'supplier claim'],
    [graph.invoice, 'z_outstanding', (receipt ? 1 : 0) + allocations.length, 'invoice'],
  ]) {
    assert.equal(owner?.[root]?.summary?.count ?? 0, expected, `${label} active positions`);
  }
  for (const [id, source, other] of [
    ['cash_out:h3b_pay_a', graph.source_a, sharedPaid],
    ['cash_out:h3b_pay_b', graph.source_b, 0],
    ['cash_out:h3b_pay_c', graph.source_c, 0],
  ]) {
    const matching = allocations.filter((row) => String(row.source) === id);
    const expected = other + matching.reduce((sum, row) => sum + numeric(row.amount), 0);
    assert.equal(measure(source, 'z_allocations', 'allocated'), expected,
      `${id} shared cash allocation capacity`);
    assert.equal(source?.z_allocations?.summary?.count ?? 0,
      (other ? 1 : 0) + matching.length, `${id} active allocation positions`);
  }
  for (const source of [graph.wrong_party, graph.wrong_currency, graph.wrong_entity]) {
    assert.equal(source?.z_allocations?.summary?.count ?? 0, 0,
      'incompatible cash sources cannot acquire receipt allocations');
  }
  assert.equal(measure(graph.cash, 'z_history', 'balance'), await cashOracle(db, 'treasury_account:h3b_cash'),
    'cash asset comes only from cash movement sources');
  assert.equal(measure(graph.other_currency_cash, 'z_history', 'balance'),
    await cashOracle(db, 'treasury_account:cash_eur'), 'wrong-currency cash root retains its own source history');
  assert.equal(measure(graph.other_entity_cash, 'z_history', 'balance'),
    await cashOracle(db, 'treasury_account:personal_usd'), 'wrong-entity cash root retains its own source history');
  return graph;
}

async function probeH3bReceiptSettlement(db) {
  const oldSources = {
    stockIn: (await rows(db, 'stock_in')).length,
    issues: (await rows(db, 'purchase_invoice_issue')).length,
    lines: (await rows(db, 'purchase_invoice_line')).length,
  };
  await db.query(`
    CREATE ONLY organization:h3b_vendor SET owned_by = rebase_group:root, name = 'H3b vendor';
    CREATE ONLY tax_account:h3b_tax SET owned_by = rebase_group:root,
      authority = organization:org_b, jurisdiction = organization:org_a, label = 'H3b input tax';
    CREATE ONLY operating_unit:h3b_unit SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, name = 'H3b warehouse';
    CREATE ONLY stock_account:h3b_stock SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, operating_unit = operating_unit:h3b_unit, resource = item:grain;
    CREATE ONLY claim_account:h3b_supplier SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = organization:h3b_vendor, currency = currency:usd;
    CREATE ONLY claim_account:h3b_tax_claim SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h3b_tax, currency = currency:usd;
    CREATE ONLY purchase_invoice:h3b_invoice SET owned_by = rebase_group:root,
      claim_account = claim_account:h3b_supplier, number = 'H3b-1';
    CREATE ONLY purchase_receipt:h3b_receipt SET owned_by = rebase_group:root,
      invoice = purchase_invoice:h3b_invoice, stock_account = stock_account:h3b_stock,
      tax_claim_account = claim_account:h3b_tax_claim, quantity = 3dec, unit_price = 7.33dec,
      tax_amount = 2.01dec, effective_at = d'2026-08-01T00:00:00Z';
    CREATE ONLY treasury:h3b_bank SET owned_by = rebase_group:root, name = 'H3b bank';
    CREATE ONLY treasury_account:h3b_cash SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, treasury = treasury:h3b_bank, currency = currency:usd;
    CREATE ONLY cash_in:h3b_funding SET owned_by = rebase_group:root,
      from_party = misc_account:opening_balance, to_account = treasury_account:h3b_cash,
      amount = 50dec, effective_at = d'2026-07-31T00:00:00Z';
    CREATE ONLY cash_out:h3b_pay_a SET owned_by = rebase_group:root,
      from_account = treasury_account:h3b_cash, to_party = organization:h3b_vendor,
      amount = 13dec, effective_at = d'2026-08-02T00:00:00Z';
    CREATE ONLY cash_out:h3b_pay_b SET owned_by = rebase_group:root,
      from_account = treasury_account:h3b_cash, to_party = organization:h3b_vendor,
      amount = 14dec, effective_at = d'2026-08-03T00:00:00Z';
    CREATE ONLY cash_out:h3b_pay_c SET owned_by = rebase_group:root,
      from_account = treasury_account:h3b_cash, to_party = organization:h3b_vendor,
      amount = 1dec, effective_at = d'2026-08-03T00:00:00Z';
    CREATE ONLY payable:h3b_shared_due SET owned_by = rebase_group:root,
      claim_account = claim_account:h3b_supplier, amount = 3dec,
      effective_at = d'2026-08-01T00:00:00Z';
    CREATE ONLY payable_cash_allocation:h3b_shared SET owned_by = rebase_group:root,
      source = cash_out:h3b_pay_a, target = payable:h3b_shared_due,
      amount = 3dec, effective_at = d'2026-08-03T00:00:00Z';
  `);
  let graph = await assertH3bOracle(db);
  assert.equal(numeric(graph.invoice.z_outstanding.summary.measures.outstanding.sum), 24);
  await db.query(`
    CREATE ONLY cash_out:h3b_wrong_party SET owned_by = rebase_group:root,
      from_account = treasury_account:h3b_cash, to_party = organization:org_b,
      amount = 1dec, effective_at = d'2026-08-03T00:00:00Z';
    CREATE ONLY cash_out:h3b_wrong_currency SET owned_by = rebase_group:root,
      from_account = treasury_account:cash_eur, to_party = organization:h3b_vendor,
      amount = 0.50dec, effective_at = d'2026-08-03T00:00:00Z';
    CREATE ONLY cash_out:h3b_wrong_entity SET owned_by = rebase_group:root,
      from_account = treasury_account:personal_usd, to_party = organization:h3b_vendor,
      amount = 0.50dec, effective_at = d'2026-08-03T00:00:00Z';
  `);
  const beforeWrongSource = await h3bGraph(db);
  for (const [id, source] of [
    ['party', 'cash_out:h3b_wrong_party'],
    ['currency', 'cash_out:h3b_wrong_currency'],
    ['entity', 'cash_out:h3b_wrong_entity'],
  ]) {
    await rejects(() => db.query(`CREATE ONLY purchase_receipt_cash_allocation:h3b_wrong_${id} SET
      owned_by = rebase_group:root, source = ${source}, target = purchase_receipt:h3b_receipt,
      amount = 0.50dec, effective_at = d'2026-08-04T00:00:00Z';`),
    `receipt settlement rejects a cash source with mismatched ${id}`);
  }
  assert.deepEqual(await h3bGraph(db), beforeWrongSource,
    'rejected cash endpoints restore receipt, claim, invoice, source and cash roots');
  await db.query(`CREATE ONLY purchase_receipt_cash_allocation:h3b_a SET owned_by = rebase_group:root,
    source = cash_out:h3b_pay_a, target = purchase_receipt:h3b_receipt,
    amount = 10dec, effective_at = d'2026-08-04T00:00:00Z';`);
  graph = await assertH3bOracle(db);
  assert.equal(numeric(graph.invoice.z_outstanding.summary.measures.outstanding.sum), 14,
    'first independently dated payment leaves a partial invoice balance');
  await db.query(`CREATE ONLY purchase_receipt_cash_allocation:h3b_b SET owned_by = rebase_group:root,
    source = cash_out:h3b_pay_b, target = purchase_receipt:h3b_receipt,
    amount = 14dec, effective_at = d'2026-08-05T00:00:00Z';`);
  graph = await assertH3bOracle(db);
  assert.equal(numeric(graph.invoice.z_outstanding.summary.measures.outstanding.sum), 0,
    'second independently dated payment fully settles the receipt invoice');
  assert.equal((await rows(db, 'stock_in')).length, oldSources.stockIn, 'settlement creates no old stock source');
  assert.equal((await rows(db, 'purchase_invoice_issue')).length, oldSources.issues,
    'settlement creates no invented invoice issue');
  assert.equal((await rows(db, 'purchase_invoice_line')).length, oldSources.lines,
    'settlement creates no invoice line');

  let before = await h3bGraph(db);
  await rejects(() => db.query(`CREATE ONLY purchase_receipt_cash_allocation:h3b_over_invoice SET
    owned_by = rebase_group:root, source = cash_out:h3b_pay_c, target = purchase_receipt:h3b_receipt,
    amount = 1dec, effective_at = d'2026-08-06T00:00:00Z';`),
  'invoice outstanding guard rejects payment beyond the receipt gross');
  await rejects(() => db.query('UPDATE cash_out:h3b_pay_a SET amount = 12.99dec;'),
    'lowering cash below combined allocation capacity fails');
  assert.deepEqual(await h3bGraph(db), before, 'cash and invoice guard failures restore the full graph');

  await db.query('UPDATE cash_out:h3b_pay_a SET amount = 14dec;');
  await assertH3bOracle(db);
  await db.query("UPDATE cash_out:h3b_pay_a SET effective_at = d'2026-08-03T00:00:00Z';");
  await assertH3bOracle(db);
  before = await h3bGraph(db);
  await rejects(() => db.query("UPDATE cash_out:h3b_pay_a SET effective_at = d'2026-08-05T00:00:00Z';"),
    'cash source cannot move after its independently dated allocations');
  assert.deepEqual(await h3bGraph(db), before, 'failed cash date move restores every source and root');
  await db.query('UPDATE cash_out:h3b_pay_a SET amount = 13dec;');
  await assertH3bOracle(db);

  await db.query('DELETE purchase_receipt_cash_allocation:h3b_b;');
  graph = await assertH3bOracle(db);
  assert.equal(numeric(graph.invoice.z_outstanding.summary.measures.outstanding.sum), 14,
    'payment deletion reopens the invoice');
  before = await h3bGraph(db);
  await rejects(() => db.query('UPDATE purchase_receipt_cash_allocation:h3b_a SET amount = 10.01dec;'),
    'receipt route and standalone payable allocation share the cash source capacity');
  assert.deepEqual(await h3bGraph(db), before, 'over-cash allocation restores every source and root');
  await db.query('DELETE cash_out:h3b_pay_b;');
  graph = await assertH3bOracle(db);
  assert.equal(graph.source_b == null, true,
    'unallocated payment source can be deleted after allocation cleanup');
  await db.query('UPDATE purchase_receipt:h3b_receipt SET unit_price = 8dec;');
  graph = await assertH3bOracle(db);
  assert.equal(numeric(graph.invoice.z_outstanding.summary.measures.outstanding.sum), 16.01,
    'receipt price edit reprices the unpaid balance once');
  await db.query("UPDATE purchase_receipt:h3b_receipt SET effective_at = d'2026-08-03T00:00:00Z';");
  await assertH3bOracle(db);
  assert.equal(numeric(queryResult(await db.query(`RETURN fn::tree::read(purchase_invoice:h3b_invoice,
    'z_outstanding', 'before', [d'2026-08-02T00:00:00Z']).measures.outstanding.sum ?? 0dec;`))), 0,
  'receipt date move removes its old invoice posting');
  before = await h3bGraph(db);
  await rejects(() => db.query("UPDATE purchase_receipt:h3b_receipt SET effective_at = d'2026-08-05T00:00:00Z';"),
    'receipt cannot move after the first payment');
  await rejects(() => db.query('UPDATE purchase_receipt:h3b_receipt SET unit_price = 2dec;'),
    'receipt amount cannot be reduced below already settled value');
  assert.deepEqual(await h3bGraph(db), before, 'failed receipt changes restore stock, tax, claim, cash, invoice and sources');
  await db.query('UPDATE purchase_receipt_cash_allocation:h3b_a SET amount = 9dec;');
  await assertH3bOracle(db);
  await db.query("UPDATE purchase_receipt_cash_allocation:h3b_a SET effective_at = d'2026-08-06T00:00:00Z';");
  await assertH3bOracle(db);
  before = await h3bGraph(db);
  await rejects(() => db.query("UPDATE purchase_receipt_cash_allocation:h3b_a SET effective_at = d'2026-08-02T00:00:00Z';"),
    'allocation cannot move before receipt and cash source');
  assert.deepEqual(await h3bGraph(db), before, 'failed allocation date move restores every root');
}

async function h3Graph(db) {
  return queryResult(await db.query(`RETURN {
    customer: (SELECT * FROM ONLY claim_account:h3_customer),
    tax_a: (SELECT * FROM ONLY claim_account:h3_tax_a),
    tax_b: (SELECT * FROM ONLY claim_account:h3_tax_b),
    tax_c: (SELECT * FROM ONLY claim_account:h3_tax_c),
    invoice_a: (SELECT * FROM ONLY sales_invoice:h3_invoice_a),
    invoice_b: (SELECT * FROM ONLY sales_invoice:h3_invoice_b),
    invoice_wrong_party: (SELECT * FROM ONLY sales_invoice:h3_invoice_wrong_party),
    invoice_wrong_currency: (SELECT * FROM ONLY sales_invoice:h3_invoice_wrong_currency),
    invoice_wrong_entity: (SELECT * FROM ONLY sales_invoice:h3_invoice_wrong_entity),
    claim_wrong_party: (SELECT * FROM ONLY claim_account:claim_a),
    claim_wrong_currency: (SELECT * FROM ONLY claim_account:h3_customer_eur),
    claim_wrong_entity: (SELECT * FROM ONLY claim_account:personal_claim),
    issue: (SELECT * FROM ONLY sales_invoice_issue:h3_issue),
    lines: (SELECT * FROM sales_invoice_line WHERE rebase_managed_source = 'sales_invoice_issue:h3_issue' ORDER BY id),
    taxes: (SELECT * FROM sales_invoice_tax_component WHERE rebase_managed_source = 'sales_invoice_issue:h3_issue' ORDER BY id),
    dispatch: (SELECT * FROM ONLY stock_out:h3_dispatch),
    unbilled: (SELECT * FROM ONLY stock_out:h3_unbilled),
    stock: stock_account:stock_a.z_history.summary
  };`));
}

async function assertH3Oracle(db) {
  const graph = await h3Graph(db);
  const issue = graph.issue;
  const lines = issue?.lines || [];
  const components = issue?.tax_components || [];
  const base = Math.round(lines.reduce((sum, line) => sum
    + Math.round(numeric(line.billed_quantity) * numeric(line.unit_price) * 100) / 100, 0) * 100) / 100;
  const tax = Math.round(components.reduce((sum, component) => sum + numeric(component.amount), 0) * 100) / 100;
  const gross = Math.round((base + tax) * 100) / 100;
  const measure = (owner, name) => numeric(owner?.z_history?.summary?.measures?.[name]?.sum ?? 0);
  const invoiceMeasure = (owner) => numeric(owner?.z_outstanding?.summary?.measures?.outstanding?.sum ?? 0);
  assert.equal(graph.lines.length, lines.length, 'one managed base output per authoritative line');
  assert.equal(graph.taxes.length, components.length, 'one managed tax output per authoritative component');
  assert.equal(measure(graph.customer, 'receivable'), gross, 'customer claim reconstructs base plus tax');
  assert.equal(measure(graph.customer, 'net'), gross, 'customer net reconstructs base plus tax');
  assert.equal(graph.customer.z_history?.summary?.count ?? 0, lines.length + components.length,
    'customer active positions count every distinct managed output');
  for (const [invoiceId, owner] of [
    ['sales_invoice:h3_invoice_a', graph.invoice_a], ['sales_invoice:h3_invoice_b', graph.invoice_b],
  ]) {
    const expected = issue && String(issue.invoice) === invoiceId ? gross : 0;
    assert.equal(invoiceMeasure(owner), expected, `${invoiceId} outstanding source oracle`);
    assert.equal(owner.z_outstanding?.summary?.count ?? 0,
      issue && String(issue.invoice) === invoiceId ? lines.length + components.length : 0,
      `${invoiceId} active positions`);
  }
  for (const [id, owner] of [
    ['claim_account:h3_tax_a', graph.tax_a], ['claim_account:h3_tax_b', graph.tax_b],
    ['claim_account:h3_tax_c', graph.tax_c],
  ]) {
    const matching = components.filter((component) => String(component.tax_claim_account) === id);
    const expected = Math.round(matching.reduce((sum, component) => sum + numeric(component.amount), 0) * 100) / 100;
    assert.equal(measure(owner, 'payable'), expected, `${id} payable source oracle`);
    assert.equal(measure(owner, 'net'), expected === 0 ? 0 : -expected, `${id} net source oracle`);
    assert.equal(owner.z_history?.summary?.count ?? 0, matching.length, `${id} active positions`);
  }
  assert.equal(await ownerTreeSum(db, 'stock_out:h3_dispatch', 'z_billing', 'billed'),
    lines.reduce((sum, line) => sum + numeric(line.billed_quantity), 0),
  'base line alone owns billed stock capacity');
  assert.equal(await ownerTreeSum(db, 'stock_out:h3_unbilled', 'z_billing', 'billed'), 0,
    'unbilled stock-out has no invoice child');
  assert.equal(await treeSum(db, 'stock_account:stock_a', 'quantity'),
    await stockOracle(db, 'stock_account:stock_a'),
  'stock quantity comes only from real stock sources');
  return graph;
}

async function probeH3SalesTax(db, endpoint, namespace) {
  await db.query(`
    CREATE ONLY organization:h3_customer SET owned_by = rebase_group:root, name = 'H3 customer';
    CREATE ONLY tax_account:h3_tax_identity_a SET owned_by = rebase_group:root,
      authority = organization:org_b, jurisdiction = organization:org_a, label = 'H3 tax A';
    CREATE ONLY tax_account:h3_tax_identity_b SET owned_by = rebase_group:root,
      authority = organization:org_b, jurisdiction = organization:org_a, label = 'H3 tax B';
    CREATE ONLY tax_account:h3_tax_identity_c SET owned_by = rebase_group:root,
      authority = organization:org_b, jurisdiction = organization:org_a, label = 'H3 tax C';
    CREATE ONLY claim_account:h3_customer SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = organization:h3_customer, currency = currency:usd;
    CREATE ONLY claim_account:h3_tax_a SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h3_tax_identity_a, currency = currency:usd;
    CREATE ONLY claim_account:h3_tax_b SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h3_tax_identity_b, currency = currency:usd;
    CREATE ONLY claim_account:h3_tax_c SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h3_tax_identity_c, currency = currency:usd;
    CREATE ONLY claim_account:h3_tax_wrong_currency SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = tax_account:h3_tax_identity_a, currency = currency:eur;
    CREATE ONLY claim_account:h3_tax_wrong_entity SET owned_by = rebase_group:root,
      economic_entity = rebase_user:personal, opponent = tax_account:h3_tax_identity_a, currency = currency:usd;
    CREATE ONLY claim_account:h3_customer_eur SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = organization:h3_customer, currency = currency:eur;
    CREATE ONLY sales_invoice:h3_invoice_a SET owned_by = rebase_group:root,
      claim_account = claim_account:h3_customer, number = 'H3-A';
    CREATE ONLY sales_invoice:h3_invoice_b SET owned_by = rebase_group:root,
      claim_account = claim_account:h3_customer, number = 'H3-B';
    CREATE ONLY sales_invoice:h3_invoice_wrong_party SET owned_by = rebase_group:root,
      claim_account = claim_account:claim_a, number = 'H3-WP';
    CREATE ONLY sales_invoice:h3_invoice_wrong_currency SET owned_by = rebase_group:root,
      claim_account = claim_account:h3_customer_eur, number = 'H3-WC';
    CREATE ONLY sales_invoice:h3_invoice_wrong_entity SET owned_by = rebase_group:root,
      claim_account = claim_account:personal_claim, number = 'H3-WE';
    CREATE ONLY stock_out:h3_dispatch SET owned_by = rebase_group:root,
      from_account = stock_account:stock_a, to_party = organization:h3_customer,
      quantity = 2dec, effective_at = d'2026-07-01T00:00:00Z';
    CREATE ONLY stock_out:h3_unbilled SET owned_by = rebase_group:root,
      from_account = stock_account:stock_a, to_party = organization:h3_customer,
      quantity = 1dec, effective_at = d'2026-07-01T00:00:00Z';
  `);
  await assertH3Oracle(db);
  const baseLines = `[{ line_key: 'dispatch', source: stock_out:h3_dispatch,
    billed_quantity: 2dec, unit_price: 5dec }]`;
  await rejects(() => db.query(`CREATE ONLY sales_invoice_issue:h3_duplicate_tax_keys SET owned_by = rebase_group:root,
    invoice = sales_invoice:h3_invoice_a, issued_at = d'2026-07-02T00:00:00Z', lines = ${baseLines},
    tax_components = [
      { tax_key: 'same', tax_claim_account: claim_account:h3_tax_a, amount: 1dec },
      { tax_key: 'same', tax_claim_account: claim_account:h3_tax_b, amount: 1dec }
    ];`), 'tax component keys must be distinct');
  await rejects(() => db.query(`CREATE ONLY sales_invoice_issue:h3_zero_tax SET owned_by = rebase_group:root,
    invoice = sales_invoice:h3_invoice_a, issued_at = d'2026-07-02T00:00:00Z', lines = ${baseLines},
    tax_components = [{ tax_key: 'zero', tax_claim_account: claim_account:h3_tax_a, amount: 0dec }];`),
  'entered tax components must be positive');
  await db.query(`CREATE ONLY sales_invoice_issue:h3_issue SET owned_by = rebase_group:root,
    invoice = sales_invoice:h3_invoice_a, issued_at = d'2026-07-02T00:00:00Z', lines = ${baseLines},
    tax_components = [
      { tax_key: 'vat', tax_claim_account: claim_account:h3_tax_a, amount: 2dec },
      { tax_key: 'cess', tax_claim_account: claim_account:h3_tax_b, amount: 1dec }
    ];`);
  let graph = await assertH3Oracle(db);
  assert.equal(await ownerTreeSum(db, 'sales_invoice:h3_invoice_a', 'z_outstanding', 'outstanding'), 13);
  assert.equal(graph.taxes.length, 2);
  const stableVat = String(graph.taxes.find((row) => row.rebase_managed_role === 'tax:vat').id);
  const stableLine = String(graph.lines[0].id);

  await db.query(`UPDATE sales_invoice_issue:h3_issue SET lines = [{
    line_key: 'dispatch', source: stock_out:h3_dispatch,
    billed_quantity: 1.5dec, unit_price: 5dec
  }];`);
  graph = await assertH3Oracle(db);
  assert.equal(numeric(graph.customer.z_history.summary.measures.receivable.sum), 10.5,
    'quantity edit updates customer receivable while preserving tax components');
  assert.equal(numeric(graph.invoice_a.z_outstanding.summary.measures.outstanding.sum), 10.5,
    'quantity edit updates the invoice root');
  assert.equal(await ownerTreeSum(db, 'stock_out:h3_dispatch', 'z_billing', 'billed'), 1.5,
    'quantity edit updates the linked dispatch billing position');
  assert.equal(graph.dispatch.z_billing.summary.count, 1,
    'quantity edit retains one active billing position');
  assert.equal(String(graph.lines[0].id), stableLine, 'quantity edit preserves the base output ID');
  const beforeExcessBilling = await h3Graph(db);
  await rejects(() => db.query(`UPDATE sales_invoice_issue:h3_issue SET lines = [{
    line_key: 'dispatch', source: stock_out:h3_dispatch,
    billed_quantity: 2.01dec, unit_price: 5dec
  }];`), 'billed quantity cannot exceed linked physical dispatch');
  assert.deepEqual(await h3Graph(db), beforeExcessBilling,
    'excess billed quantity restores issue, managed children, and every affected root');

  await rejects(() => db.query(`CREATE ONLY sales_invoice_issue:h3_duplicate_issue SET owned_by = rebase_group:root,
    invoice = sales_invoice:h3_invoice_a, issued_at = d'2026-07-02T00:00:00Z', lines = ${baseLines};`),
  'one issue per invoice remains unique');
  const beforeMismatch = await h3Graph(db);
  await rejects(() => db.query(`UPDATE sales_invoice_issue:h3_issue SET tax_components = [
    { tax_key: 'vat', tax_claim_account: claim_account:h3_tax_wrong_currency, amount: 2dec }
  ];`), 'tax claim currency must match invoice');
  await rejects(() => db.query(`UPDATE sales_invoice_issue:h3_issue SET tax_components = [
    { tax_key: 'vat', tax_claim_account: claim_account:h3_tax_wrong_entity, amount: 2dec }
  ];`), 'tax claim entity must match invoice');
  await rejects(() => db.query(`UPDATE sales_invoice_issue:h3_issue SET tax_components = [
    { tax_key: 'vat', tax_claim_account: claim_account:claim_misc, amount: 2dec }
  ];`), 'tax claim opponent must be tax account');
  assert.deepEqual(await h3Graph(db), beforeMismatch, 'failed tax child rejects restore whole graph');

  await db.query(`UPDATE sales_invoice_issue:h3_issue SET tax_components = [
    { tax_key: 'vat', tax_claim_account: claim_account:h3_tax_a, amount: 3dec },
    { tax_key: 'cess', tax_claim_account: claim_account:h3_tax_b, amount: 1dec },
    { tax_key: 'levy', tax_claim_account: claim_account:h3_tax_c, amount: 0.50dec }
  ];`);
  graph = await assertH3Oracle(db);
  assert.equal(String(graph.taxes.find((row) => row.rebase_managed_role === 'tax:vat').id), stableVat,
    'amount edit preserves stable tax child identity');
  assert.equal(String(graph.lines[0].id), stableLine, 'tax role edits preserve base line identity');
  await db.query(`UPDATE sales_invoice_issue:h3_issue SET tax_components = [
    { tax_key: 'vat', tax_claim_account: claim_account:h3_tax_a, amount: 3dec },
    { tax_key: 'levy', tax_claim_account: claim_account:h3_tax_c, amount: 0.50dec }
  ];`);
  graph = await assertH3Oracle(db);
  assert.equal(graph.taxes.some((row) => row.rebase_managed_role === 'tax:cess'), false,
    'removed tax role deletes its required child');

  await db.query("UPDATE sales_invoice_issue:h3_issue SET issued_at = d'2026-07-03T00:00:00Z';");
  graph = await assertH3Oracle(db);
  assert.equal(await treeBefore(db, 'claim_account:h3_customer', 'receivable', '2026-07-03T00:00:00Z'), 0,
    'issue date move rekeys base and tax after physical dispatch');
  const beforeEarlyIssue = await h3Graph(db);
  await rejects(() => db.query("UPDATE sales_invoice_issue:h3_issue SET issued_at = d'2026-06-30T00:00:00Z';"),
    'issue before dispatch fails');
  assert.deepEqual(await h3Graph(db), beforeEarlyIssue, 'failed issue date move restores all roots and children');

  await db.query('UPDATE sales_invoice_issue:h3_issue SET invoice = sales_invoice:h3_invoice_b;');
  graph = await assertH3Oracle(db);
  assert.equal(String(graph.lines[0].id), stableLine, 'compatible reparent preserves line ID');
  assert.equal(String(graph.taxes.find((row) => row.rebase_managed_role === 'tax:vat').id), stableVat,
    'compatible reparent preserves tax child ID');
  assert.equal(graph.invoice_a.z_outstanding.summary.count, 0, 'old invoice tree is cleared');
  const beforeBadReparent = await h3Graph(db);
  await rejects(() => db.query('UPDATE sales_invoice_issue:h3_issue SET invoice = sales_invoice:h3_invoice_wrong_party;'),
    'reparent to a different customer must fail');
  await rejects(() => db.query('UPDATE sales_invoice_issue:h3_issue SET invoice = sales_invoice:h3_invoice_wrong_currency;'),
    'reparent to a different currency must fail');
  await rejects(() => db.query('UPDATE sales_invoice_issue:h3_issue SET invoice = sales_invoice:h3_invoice_wrong_entity;'),
    'reparent to another economic entity must fail');
  assert.deepEqual(await h3Graph(db), beforeBadReparent, 'failed reparent restores old and candidate roots');

  await db.query(`
    CREATE ONLY rebase_group:h3_tax_actor SET name = 'H3 managed-output actor', parents = [rebase_group:root],
      role = ['sales_invoice_tax_component_select', 'sales_invoice_tax_component_create',
        'sales_invoice_tax_component_update', 'sales_invoice_tax_component_delete'];
    CREATE ONLY rebase_user:h3_tax_actor SET name = 'H3 managed-output actor',
      parents = [rebase_group:h3_tax_actor, rebase_group:root];
    DEFINE ACCESS h3_tax_actor ON DATABASE TYPE RECORD SIGNIN rebase_user:h3_tax_actor;
  `);
  const actor = new Surreal();
  try {
    await actor.connect(endpoint);
    await actor.signin({ namespace, database: 'probe', access: 'h3_tax_actor' });
    const beforeDirect = await h3Graph(db);
    assert.deepEqual(queryResult(await actor.query('SELECT * FROM sales_invoice_tax_component;')), [],
      'managed tax child is not selectable by a record user');
    assert.deepEqual(queryResult(await actor.query(`CREATE sales_invoice_tax_component:forged SET
      owned_by = rebase_user:h3_tax_actor,
      invoice = sales_invoice:h3_invoice_b, tax_claim_account = claim_account:h3_tax_a,
      amount = 99dec, effective_at = d'2026-07-03T00:00:00Z';`)), [],
    'record user cannot create managed tax child');
    assert.deepEqual(queryResult(await actor.query(`UPDATE ${stableVat} SET amount = 99dec;`)), [],
      'record user cannot edit managed tax child');
    assert.deepEqual(queryResult(await actor.query(`DELETE ${stableVat};`)), [],
      'record user cannot delete managed tax child');
    assert.deepEqual(await h3Graph(db), beforeDirect, 'direct managed-output attempts leave whole graph intact');
  } finally { await actor.close().catch(() => {}); }

  await db.query('DELETE sales_invoice_issue:h3_issue;');
  graph = await assertH3Oracle(db);
  assert.equal(graph.lines.length, 0);
  assert.equal(graph.taxes.length, 0);
  assert.equal(graph.dispatch != null, true, 'source deletion leaves the physical stock-out fact');
  assert.equal(graph.unbilled != null, true, 'unbilled stock-out remains independent');
}

async function main() {
  const root = path.resolve(__dirname, "../..");
  const compile = spawnSync(process.execPath, [
    "dev-tools/compiler/cli.js",
    "--project", "designs/all-in-accounting",
    "--output", "build/all-in-accounting",
  ], { cwd: root, encoding: "utf8" });
  if (compile.status !== 0) throw new Error(compile.stderr || compile.stdout || "Accounting compilation failed");
  const schema = fs.readFileSync(path.join(root, "build/all-in-accounting/schema.surql"), "utf8");

  const port = await freePort();
  const namespace = `accounting_core_${Date.now().toString(36)}`;
  const database = "probe";
  const child = spawn("surreal", [
    "start", "memory", "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--no-banner", "--log", "error",
  ], { cwd: root, stdio: ["ignore", "ignore", "ignore"] });
  const db = new Surreal();
  try {
    await waitForPort(port, child);
    await db.connect(`ws://127.0.0.1:${port}/rpc`);
    await db.signin({ username: "root", password: "root" });
    await db.query(`DEFINE NAMESPACE ${namespace};`);
    await db.use({ namespace });
    await db.query(`DEFINE DATABASE ${database};`);
    await db.use({ namespace, database });
    await db.query(schema);
    await db.query(`
      CREATE ONLY organization:org_a SET owned_by = rebase_group:root, name = 'Book owner A';
      CREATE ONLY organization:org_b SET owned_by = rebase_group:root, name = 'Book owner B';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'US dollar', precision = 2;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY measure_unit:kg SET owned_by = rebase_group:root, code = 'kg', name = 'Kilogram', dimension = 'mass';
      CREATE ONLY treasury:bank_a SET owned_by = rebase_group:root, name = 'Bank A';
      CREATE ONLY treasury:bank_b SET owned_by = rebase_group:root, name = 'Bank B';
      CREATE ONLY treasury:overdraft SET owned_by = rebase_group:root, name = 'Overdraft facility';
      CREATE ONLY operating_unit:unit_a SET owned_by = rebase_group:root, economic_entity = organization:org_a, name = 'A warehouse';
      CREATE ONLY operating_unit:unit_b SET owned_by = rebase_group:root, economic_entity = organization:org_b, name = 'B warehouse';
      CREATE ONLY item:grain SET owned_by = rebase_group:root, name = 'Grain', unit = measure_unit:kg;
      CREATE ONLY tax_account:tax_a SET owned_by = rebase_group:root, authority = organization:org_b, jurisdiction = organization:org_b, label = 'Tax A';
      CREATE ONLY misc_account:purpose_a SET owned_by = rebase_group:root, label = 'Purpose A';
      CREATE ONLY treasury_account:cash_a SET owned_by = rebase_group:root, economic_entity = organization:org_a,
        treasury = treasury:bank_a, currency = currency:usd, minimum_balance = 0dec;
      CREATE ONLY treasury_account:cash_overdraft SET owned_by = rebase_group:root, economic_entity = organization:org_a,
        treasury = treasury:overdraft, currency = currency:usd, minimum_balance = -500dec;
      CREATE ONLY claim_account:claim_a SET owned_by = rebase_group:root, economic_entity = organization:org_a,
        opponent = organization:org_b, currency = currency:usd;
      CREATE ONLY claim_account:claim_misc SET owned_by = rebase_group:root, economic_entity = organization:org_a,
        opponent = misc_account:purpose_a, currency = currency:usd;
      CREATE ONLY claim_account:claim_tax SET owned_by = rebase_group:root, economic_entity = organization:org_a,
        opponent = tax_account:tax_a, currency = currency:usd;
      CREATE ONLY stock_account:stock_a SET owned_by = rebase_group:root, economic_entity = organization:org_a,
        operating_unit = operating_unit:unit_a, resource = item:grain;
    `);

    const stockUnit = queryResult(await db.query("RETURN (SELECT VALUE unit FROM stock_account:stock_a)[0];"));
    assert.equal(String(stockUnit), "measure_unit:kg", "stock-account unit must follow its resource's immutable unit");
    await rejects(() => db.query(`CREATE ONLY treasury_account:duplicate SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, treasury = treasury:bank_a, currency = currency:usd, minimum_balance = 0dec;`),
    "treasury account dimensions must be unique");
    await rejects(() => db.query(`CREATE ONLY stock_account:wrong_entity SET owned_by = rebase_group:root,
      economic_entity = organization:org_b, operating_unit = operating_unit:unit_a, resource = item:grain;`),
    "a stock account cannot cross economic entities");
    await rejects(() => db.query(`CREATE ONLY claim_account:wrong_opponent SET owned_by = rebase_group:root,
      economic_entity = organization:org_a, opponent = treasury:bank_a, currency = currency:usd;`),
    "claim opponents must use the declared user/organization/tax/misc union");
    await rejects(() => db.query("UPDATE currency:usd SET precision = 3;"),
      "currency precision must remain immutable after use");
    await rejects(() => db.query("DELETE currency:usd;"),
      "referenced currencies cannot be deleted");

    await probeMovements(db);
    await probeStandaloneClaims(db);
    await probeClaimSettlements(db);
    await probeClaimAdjustments(db);
    await probeInvoices(db);

    const dimensions = queryResult(await db.query(`
      RETURN {
        organizations: (SELECT VALUE id FROM organization).len(),
        treasury_accounts: (SELECT VALUE id FROM treasury_account).len(),
        claim_accounts: (SELECT VALUE id FROM claim_account).len(),
        stock_accounts: (SELECT VALUE id FROM stock_account).len()
      };
    `));
    assert.deepEqual(dimensions, {
      organizations: 3,
      treasury_accounts: 4,
      claim_accounts: 4,
      stock_accounts: 3,
    });
    await probeH1Identity(db);
    await probeH1Authorization(db, `ws://127.0.0.1:${port}/rpc`, namespace);
    await probeH2Receipt(db);
    await probeH2NetBounds(db);
    await probeH3bReceiptSettlement(db);
    await probeH3SalesTax(db, `ws://127.0.0.1:${port}/rpc`, namespace);
    await probeSingleCurrencyVariant(db, namespace, schema);
    await probeH1MigrationPreflight(db, namespace);
    process.stdout.write("Accounting H3b receipt settlement, H3a sales tax, H2 receipt and net bounds, H1 fixtures, and A1/A2 oracles passed\n");
  } finally {
    await db.close().catch(() => {});
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await new Promise((resolve) => child.once("exit", resolve));
    }
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`Accounting core: FAIL: ${error.stack || error}`);
  process.exitCode = 1;
});

module.exports = { main };
