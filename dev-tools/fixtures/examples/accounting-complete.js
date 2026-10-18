#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { createHash } = require("node:crypto");
const { parseArgs } = require("node:util");
const { createModel, populate } = require("..");
const { recordId } = require("../model");
const { build, connect } = require("../..");
const { resolveConfiguration } = require("../../../config/environment");
const { loadClientSchemas } = require("../../client-schemas");

// These are public inputs, not forged authentication ceremony/verification state.
// Accounting's 48 input schemas already live in designs/all-in-accounting/schemas.
const contactSchemas = {
  rebase_user: {
    type: "object", additionalProperties: false, required: ["name", "parents", "login_access"],
    properties: { name: { type: "string", minLength: 1 }, login_access: { type: "boolean" },
      parents: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 1 } },
  },
  authentication_email: {
    type: "object", additionalProperties: false, required: ["owned_by", "address"],
    properties: { owned_by: { type: "string" }, address: { type: "string", format: "email" } },
  },
  authentication_phone: {
    type: "object", additionalProperties: false, required: ["owned_by", "number"],
    properties: { owned_by: { type: "string" }, number: { type: "string", pattern: "^\\+[1-9][0-9]{7,14}$" } },
  },
};

function createCompleteModel() {
  // Explain compiles metadata in memory: no build files, deployment or connection.
  const schema = build({ project: "all-in-accounting", explain: "*",
    configuration: resolveConfiguration({ NODE_ENV: "test" }) });
  const catalog = loadClientSchemas(path.resolve(__dirname, "../../../designs/all-in-accounting/schemas"));
  return createModel({ schema, schemas: {
    ...Object.fromEntries([...catalog.schemas].map(([table, entry]) => [table, entry.schema])),
    ...contactSchemas,
  } });
}

/** Pure configuration. Pass this straight to fixtures.plan() for an offline preview. */
function completeOptions({ model, tenant = "rebase_tenant:default", seed = "complete-demo",
  startAt = "2027-01-01T00:00:00Z", salesCount = 3 } = {}) {
  const owner = String(recordId(tenant));
  if (recordId(owner).table.name !== "rebase_tenant") throw new Error("tenant must be a rebase_tenant record id");
  if (typeof seed !== "string" || !seed.trim()) throw new Error("seed must be a nonempty string");
  if (!Number.isSafeInteger(salesCount) || salesCount < 1 || salesCount > 20) throw new Error("salesCount must be from 1 to 20");
  const start = Date.parse(startAt);
  if (!Number.isFinite(start) || !Number.isFinite(start + 30 * 86400000)) throw new Error("startAt must be a valid date");
  const at = (day, seconds = 0) => new Date(start + (day - 1) * 86400000 + seconds * 1000).toISOString();
  // Version the scenario when changing its recipe. Include all configuration in
  // the identity so different datasets can coexist even within the same tenant.
  const digest = createHash("sha256").update(JSON.stringify([1, owner, seed, at(1), salesCount])).digest("hex").slice(0, 16);
  const scenario = `demo_${digest}`, ids = {}, recipe = [];
  const add = (table, name, values, owned = true) => {
    ids[name] = `${table}:${scenario}_${name}`;
    recipe.push({ name, table, id: ids[name],
      // Explicit ordering also covers prerequisites that are aggregate effects,
      // e.g. funding before a withdrawal, not merely foreign-key dependencies.
      after: recipe.length ? [recipe.at(-1).name] : [],
      values: context => ({ ...(owned ? { owned_by: owner } : {}),
        ...(typeof values === "function" ? values(context) : values) }),
    });
    return ids[name];
  };
  const dated = { effective_at: at(1) };

  // 1. Dimensions. Codes are scenario-scoped too: the tenant enforces uniqueness.
  add("currency", "inr", { code: `${scenario}_INR`, name: "Demo Indian rupee", precision: 2 });
  add("currency", "usd", { code: `${scenario}_USD`, name: "Demo US dollar", precision: 2 });
  add("measure_unit", "each", { code: `${scenario}_each`, name: "Each / work unit" });
  add("item", "widget", { name: "Raw widgets", unit: ids.each });
  add("item", "finished", { name: "Finished widgets", unit: ids.each });
  add("service", "labor", { name: "Workshop labor", unit: ids.each,
    available_from: at(1), available_until: at(31), minimum_duration: "1h", maximum_duration: "2d" });
  add("subsidiary", "home", ({ faker }) => ({ name: `${faker.company.name()} / INR`, currency: ids.inr, ...dated }));
  add("subsidiary", "overseas", ({ faker }) => ({ name: `${faker.company.name()} / USD`, currency: ids.usd, ...dated }));
  add("operating_unit", "store", { name: "Home workshop", subsidiary: ids.home, capacity: "2" });
  add("operating_unit", "annex", { name: "Overseas store", subsidiary: ids.overseas, capacity: "2" });
  for (const [name, subsidiary, currency] of [["customer", ids.home, ids.inr], ["supplier", ids.home, ids.usd], ["foreign", ids.overseas, ids.usd]]) {
    add("organization", name, ({ faker }) => ({ name: `${name}: ${faker.company.name()}`, subsidiary, currency, ...dated }));
  }
  for (const [name, given_resource, received_resource, initial_rate] of [
    ["usdInr", ids.usd, ids.inr, "10"], ["inrUsd", ids.inr, ids.usd, "0.1"],
    ["widgetInr", ids.widget, ids.inr, "10"], ["widgetUsd", ids.widget, ids.usd, "1"],
    ["finishedInr", ids.finished, ids.inr, "20"], ["laborInr", ids.labor, ids.inr, "5"],
  ]) add("exchange_pair", name, { given_resource, received_resource, initial_rate, ...dated });

  // 2. Accounts in both subsidiary and counterparty currencies.
  add("organization_currency_account", "customerMoney", { name: "Customer INR", organization: ids.customer, currency: ids.inr, ...dated });
  add("organization_currency_account", "customerUsd", { name: "Customer USD", organization: ids.customer, currency: ids.usd,
    valuation_pair: ids.usdInr, organization_pair: ids.usdInr, ...dated });
  add("organization_currency_account", "supplierMoney", { name: "Supplier USD", organization: ids.supplier, currency: ids.usd, valuation_pair: ids.usdInr, ...dated });
  add("organization_currency_account", "foreignMoney", { name: "Foreign USD", organization: ids.foreign, currency: ids.usd, ...dated });
  for (const [name, organization, valuation_pair, organization_pair] of [
    ["customerGoods", ids.customer, ids.widgetInr, ids.widgetInr],
    ["supplierGoods", ids.supplier, ids.widgetInr, ids.widgetUsd],
    ["foreignGoods", ids.foreign, ids.widgetUsd, ids.widgetUsd],
  ]) add("organization_resource_account", name, { name, organization, resource: ids.widget, valuation_pair, organization_pair, ...dated });
  for (const [table, name, subsidiary, currency, valuation_pair] of [
    ["treasury", "cash", ids.home, ids.inr], ["treasury", "dollars", ids.home, ids.usd, ids.usdInr],
    ["treasury", "foreignCash", ids.overseas, ids.usd],
    ["misc_currency_account", "fees", ids.home, ids.inr], ["misc_currency_account", "dollarFees", ids.home, ids.usd, ids.usdInr],
    ["indirect_tax_account", "vat", ids.home, ids.inr], ["indirect_tax_account", "dollarVat", ids.home, ids.usd, ids.usdInr],
    ["indirect_tax_account", "taxPool", ids.home, ids.inr], ["direct_tax_account", "withheld", ids.home, ids.inr],
  ]) add(table, name, { name, subsidiary, currency, ...(valuation_pair ? { valuation_pair } : {}), ...dated });
  for (const [table, name, resource, subsidiary, operating_unit, valuation_pair] of [
    ["stock_account", "stock", ids.widget, ids.home, ids.store, ids.widgetInr],
    ["stock_account", "finishedStock", ids.finished, ids.home, ids.store, ids.finishedInr],
    ["stock_account", "laborStock", ids.labor, ids.home, ids.store, ids.laborInr],
    ["stock_account", "foreignStock", ids.widget, ids.overseas, ids.annex, ids.widgetUsd],
    ["misc_stock_account", "damage", ids.widget, ids.home, ids.store, ids.widgetInr],
  ]) add(table, name, { name, resource, subsidiary, operating_unit, valuation_pair, ...dated });

  // 3. Opening balances precede every consuming posting (including reservations).
  // Pin all three legs: JSON Schema's anyOf can otherwise cause the faker to
  // supply another nonzero leg, which is structurally valid but not valid cash/stock.
  for (const [name, account, real] of [["cashOpening", ids.cash, "10000"], ["dollarOpening", ids.dollars, "1000"], ["foreignOpening", ids.foreignCash, "1000"]]) {
    add("account_entry", name, { account, real, receivable: "0", payable: "0", description: "Opening funding", ...dated });
  }
  for (const [name, account, real] of [["stockOpening", ids.stock, "1000"], ["laborOpening", ids.laborStock, "10"], ["foreignStockOpening", ids.foreignStock, "100"]]) {
    add("stock_entry", name, { account, real, receivable: "0", payable: "0", ...dated });
  }
  add("account_entry", "taxOpening", { account: ids.taxPool, real: "0", receivable: "100", payable: "100", effective_at: at(2) });

  // 4. Sales: 100 principal + 10 tax + 11 compound tax. Each retains capacity
  // for later credits. Invoice time is the invoice's cut-off, not insertion time.
  const fee = { fee_account: ids.fees, fee_rate: "1", fee_tax_rate: "18", fee_tax_creditable: true, fee_tax_account: ids.vat };
  for (let i = 1; i <= salesCount; i++) {
    add("sales_invoice", `sale${i}`, { account: ids.customerMoney, invoice_date: at(10), description: `Sale ${i}` });
    add("sales_issue", `saleIssue${i}`, { invoice: ids[`sale${i}`], stock_account: ids.stock, counterparty_stock: ids.customerGoods,
      quantity: "10", price: "10", effective_at: at(5) });
    add("issue_tax", `saleTax${i}`, { source: ids[`saleIssue${i}`], tax_account: ids.vat, rate: "10", effective_at: at(6) });
    add("issue_net_tax", `saleNetTax${i}`, { source: ids[`saleIssue${i}`], tax_account: ids.vat, rate: "10", effective_at: at(7) });
    add("invoice_settlement", `salePayment${i}`, { invoice: ids[`sale${i}`], treasury: ids.cash, amount: "30", effective_at: at(9), ...fee });
  }

  // 5. A USD purchase, paid out of INR using the explicit reverse exchange pair.
  add("purchase_invoice", "purchase", { account: ids.supplierMoney, invoice_date: at(10) });
  add("purchase_issue", "purchaseIssue", { invoice: ids.purchase, stock_account: ids.stock, counterparty_stock: ids.supplierGoods,
    quantity: "4", price: "2", effective_at: at(5) });
  add("issue_tax", "purchaseTax", { source: ids.purchaseIssue, tax_account: ids.dollarVat, rate: "10", effective_at: at(6) });
  add("issue_net_tax", "purchaseNetTax", { source: ids.purchaseIssue, tax_account: ids.dollarVat, rate: "10", effective_at: at(7) });
  add("invoice_settlement", "purchasePayment", { invoice: ids.purchase, treasury: ids.cash, exchange_pair: ids.inrUsd, amount: "50", effective_at: at(9) });

  // 6. Repeated and interleaved adjustments. Linked tax rows are explicit public
  // records; their amounts are calculated by the database, never copied in here.
  add("sales_adjustment_note", "creditNote", { account: ids.customerMoney });
  add("sales_adjustment_note", "refundNote", { account: ids.customerMoney });
  add("purchase_adjustment_note", "purchaseNote", { account: ids.supplierMoney });
  add("issue_adjustment", "firstCredit", { source: ids.saleIssue1, adjustment_note: ids.creditNote,
    quantity_delta: "-1", price_delta: "1", effective_at: at(11) });
  add("issue_adjustment_tax", "firstCreditTax", { source_tax: ids.saleTax1, adjustment: ids.firstCredit, effective_at: at(11, 1) });
  add("issue_adjustment_net_tax", "firstCreditNetTax", { source_tax: ids.saleNetTax1, adjustment: ids.firstCredit, effective_at: at(11, 2) });
  add("issue_adjustment", "purchaseCredit", { source: ids.purchaseIssue, adjustment_note: ids.purchaseNote,
    quantity_delta: "-1", price_delta: "0", effective_at: at(11) });
  add("issue_adjustment_tax", "purchaseCreditTax", { source_tax: ids.purchaseTax, adjustment: ids.purchaseCredit, effective_at: at(11, 1) });
  add("issue_adjustment_net_tax", "purchaseCreditNetTax", { source_tax: ids.purchaseNetTax, adjustment: ids.purchaseCredit, effective_at: at(11, 2) });
  add("issue_adjustment", "secondCredit", { source: ids.saleIssue1, adjustment_note: ids.creditNote,
    quantity_delta: "0", price_delta: "-1", effective_at: at(12) });
  add("issue_adjustment_tax", "secondCreditTax", { source_tax: ids.saleTax1, adjustment: ids.secondCredit, effective_at: at(12, 1) });
  add("issue_adjustment_net_tax", "secondCreditNetTax", { source_tax: ids.saleNetTax1, adjustment: ids.secondCredit, effective_at: at(12, 2) });
  add("payment_withholding", "withholding", { source: ids.salePayment1, tax_account: ids.withheld, amount: "10", effective_at: at(12, 3) });
  add("payment_adjustment", "refund", { source: ids.salePayment1, adjustment_note: ids.refundNote,
    amount_delta: "-10", effective_at: at(13), fee_account: ids.fees, fee_lower_bound: "1" });
  add("tax_adjustment", "manualTaxCredit", { source_tax: ids.saleTax1, adjustment_note: ids.creditNote, amount_delta: "-1", effective_at: at(14) });
  add("net_tax_adjustment", "manualNetCredit", { source_tax: ids.saleNetTax1, adjustment_note: ids.creditNote, amount_delta: "-1", effective_at: at(14, 1) });
  add("tax_adjustment_net_tax", "manualCompoundCredit", { source_tax: ids.saleNetTax1, adjustment: ids.manualTaxCredit, effective_at: at(14, 2) });

  // 7. Monetary and resource claims, tax payment/deposit/refund/offset.
  add("account_claim", "rentClaim", { account: ids.customerMoney, claim_kind: "payable", amount: "40", effective_at: at(15) });
  add("claim_settlement", "rentPayment", { source: ids.rentClaim, paid_account: ids.cash, amount: "15", effective_at: at(16) });
  add("account_claim", "goodsClaim", { account: ids.customerGoods, claim_kind: "receivable", amount: "3", effective_at: at(15) });
  add("claim_settlement", "goodsPayment", { source: ids.goodsClaim, paid_account: ids.stock, amount: "1.5", effective_at: at(16) });
  add("tax_settlement", "taxPayment", { tax_account: ids.taxPool, treasury: ids.cash, amount: "30", effective_at: at(15) });
  add("tax_deposit", "taxDeposit", { tax_account: ids.taxPool, treasury: ids.cash, amount: "20", effective_at: at(16) });
  add("tax_refund", "taxRefund", { tax_account: ids.taxPool, treasury: ids.cash, amount: "10", effective_at: at(17) });
  add("tax_offset", "taxOffset", { credit_account: ids.taxPool, liability_account: ids.taxPool, amount: "40", effective_at: at(18) });

  // 8. Same-resource movement, cross-subsidiary transfer and FX with fees.
  add("resource_exchange", "damagedGoods", { from_account: ids.stock, to_account: ids.damage, from_amount: "2", effective_at: at(18) });
  add("resource_exchange", "foreignTransfer", { from_account: ids.cash, to_account: ids.foreignCash,
    exchange_pair: ids.inrUsd, from_amount: "100", effective_at: at(18) });
  add("resource_exchange", "goodsTransfer", { from_account: ids.foreignStock, to_account: ids.stock, from_amount: "1", effective_at: at(19) });
  add("resource_exchange", "fxTrade", { from_account: ids.dollars, to_account: ids.cash,
    exchange_pair: ids.usdInr, from_amount: "100", effective_at: at(18), fee_account: ids.dollarFees, fee_rate: "1" });

  // 9. A real production reservation, inputs, output, capacity and later sale.
  add("production", "production", { name: "Widget assembly", subsidiary: ids.home, starts_at: at(20), ends_at: at(21) });
  add("production_input", "productionMaterial", { production: ids.production, stock_account: ids.stock, quantity: "3" });
  add("production_input", "productionLabor", { production: ids.production, stock_account: ids.laborStock, quantity: "1" });
  add("production_output", "productionOutput", { production: ids.production, stock_account: ids.finishedStock, quantity: "4" });
  add("production_cost", "productionCost", { production: ids.production, treasury: ids.cash, amount: "30", fee_account: ids.fees, fee_rate: "5", fee_tax_rate: "20" });
  add("production_capacity", "productionCapacity", { production: ids.production, operating_unit: ids.store, resource: ids.labor, quantity: "2" });
  add("resource_exchange", "outputSale", { from_account: ids.finishedStock, to_account: ids.cash,
    exchange_pair: ids.finishedInr, from_amount: "2", production_output: ids.productionOutput, effective_at: at(22) });

  // 10. Insert sparse dated rates AFTER their dependants: events must revalue
  // affected history. USD->INR becomes 11 on day 4, then 12 on day 9. Reverse
  // quotes are independently authoritative, not assumed to be reciprocal.
  add("exchange_rate", "earlyQuote", { pair: ids.usdInr, rate: "11", effective_at: at(4) });
  add("exchange_rate", "laterQuote", { pair: ids.usdInr, rate: "12", effective_at: at(9) });
  add("exchange_rate", "reverseQuote", { pair: ids.inrUsd, rate: "0.11", effective_at: at(15) });

  // 11. Inert contact examples: login disabled, no credentials or verification.
  add("rebase_user", "contact", ({ faker }) => ({ name: faker.person.fullName(), parents: [owner], login_access: false }), false);
  add("authentication_email", "email", { owned_by: ids.contact, address: `${scenario}@example.test` }, false);
  // +999 is unassigned. This is deliberately not a routable person's number.
  add("authentication_phone", "phone", { owned_by: ids.contact,
    number: `+999${(BigInt(`0x${digest}`) % 1000000000000n).toString().padStart(12, "0")}` }, false);

  return { model, seed, scenario, tenant: owner, ids, recipe, space: { tenants: [{ id: owner }] } };
}

/** One transaction, including tenant creation. Existing complete runs are reused. */
async function populateComplete(db, { model = createCompleteModel(), tenantName = "Default Tenant", ...config } = {}) {
  const options = completeOptions({ ...config, model });
  const tenant = recordId(options.tenant), intended = Object.values(options.ids).map(recordId);
  let reused = false;
  const result = await populate(db, { ...options,
    space: async tx => {
      await tx.query("IF !record::exists($tenant) { CREATE $tenant SET name = $name; };", { tenant, name: tenantName });
      const [existing] = await tx.query("SELECT id, tenant FROM $ids;", { ids: intended });
      if (existing.length && existing.length !== intended.length) {
        throw new Error(`Scenario ${options.scenario} is incomplete (${existing.length}/${intended.length} records). Use a new seed, or explicitly clear your development database before rerunning.`);
      }
      if (existing.some(row => String(row.tenant) !== String(tenant))) throw new Error("Existing scenario has a different tenant");
      reused = existing.length === intended.length;
      return { tenants: [{ id: String(tenant) }] };
    },
    recipe: () => reused ? [] : options.recipe,
  });
  const counts = {};
  for (const step of options.recipe) counts[step.table] = (counts[step.table] || 0) + 1;
  return { ...result, scenario: options.scenario, tenant: options.tenant, ids: options.ids, counts, reused };
}

async function main() {
  const { values } = parseArgs({ options: {
    seed: { type: "string" }, tenant: { type: "string" }, start: { type: "string" },
    sales: { type: "string" }, help: { type: "boolean", short: "h" },
  } });
  if (values.help) {
    console.log("Usage: node --env-file=<profile> dev-tools/fixtures/examples/accounting-complete.js [--seed NAME] [--tenant rebase_tenant:default] [--start ISO_DATE] [--sales 1..20]\nUses the configured, already-deployed development database. Same config reuses records; a new seed adds a separate scenario.");
    return;
  }
  const config = { ...(values.seed !== undefined ? { seed: values.seed } : {}),
    ...(values.tenant !== undefined ? { tenant: values.tenant } : {}),
    ...(values.start !== undefined ? { startAt: values.start } : {}),
    ...(values.sales !== undefined ? { salesCount: Number(values.sales) } : {}) };
  const model = createCompleteModel();
  completeOptions({ ...config, model }); // Validate before opening a connection.
  const c = await connect();
  try {
    const result = await populateComplete(c.db, { ...config, model });
    console.log(JSON.stringify({ scenario: result.scenario, tenant: result.tenant, reused: result.reused,
      inserted: result.created.length, counts: result.counts, ids: result.ids }, null, 2));
  } finally { await c.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { createCompleteModel, completeOptions, populateComplete };
