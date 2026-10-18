#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { build, connect, fixtures, prepare } = require("../../index");
const { loadClientSchemas } = require("../../client-schemas");

function enterpriseOptions({ model, tenant = "rebase_tenant:default" }) {
  const at = (day, hour = 0, minute = 0) =>
    new Date(Date.UTC(2026, 0, day, hour, minute, 0)).toISOString();

  const owned = { owned_by: "tenants" };

  return {
    model,
    seed: "full-enterprise-fixture-v1",
    space: { tenants: [{ id: tenant }] },
    recipe: [
      // ==========================================
      // 1. CURRENCIES & MEASUREMENT UNITS
      // ==========================================
      {
        name: "curr_usd",
        table: "currency",
        refs: owned,
        values: { code: "USD", name: "US Dollar", precision: 2 },
      },
      {
        name: "curr_eur",
        table: "currency",
        refs: owned,
        values: { code: "EUR", name: "Euro", precision: 2 },
      },
      {
        name: "unit_pcs",
        table: "measure_unit",
        refs: owned,
        values: { code: "PCS", name: "Pieces" },
      },
      {
        name: "unit_hr",
        table: "measure_unit",
        refs: owned,
        values: { code: "HR", name: "Hours" },
      },

      // ==========================================
      // 2. ITEMS & SERVICES
      // ==========================================
      {
        name: "item_laptop",
        table: "item",
        refs: { unit: "unit_pcs" },
        values: { name: "Pro Laptop 16" },
      },
      {
        name: "item_parts",
        table: "item",
        refs: { unit: "unit_pcs" },
        values: { name: "Raw Aluminum Chassis" },
      },
      {
        name: "svc_assembly",
        table: "service",
        refs: { unit: "unit_hr" },
        values: { name: "Assembly Machine Labor" },
      },

      // ==========================================
      // 3. EXCHANGE PAIRS & RATES
      // ==========================================
      {
        name: "pair_usd_eur",
        table: "exchange_pair",
        refs: {
          ...owned,
          given_resource: "curr_usd",
          received_resource: "curr_eur",
        },
        values: { initial_rate: "0.92", effective_at: at(1) },
      },
      {
        name: "pair_eur_usd",
        table: "exchange_pair",
        refs: {
          ...owned,
          given_resource: "curr_eur",
          received_resource: "curr_usd",
        },
        values: { initial_rate: "1.08", effective_at: at(1) },
      },
      {
        name: "fx_rate_update",
        table: "exchange_rate",
        refs: { pair: "pair_usd_eur" },
        values: { effective_at: at(2), rate: "0.93" },
      },

      // ==========================================
      // 4. ENTITIES (Subsidiary, Organizations, Operating Units)
      // ==========================================
      {
        name: "sub_us",
        table: "subsidiary",
        refs: { ...owned, currency: "curr_usd" },
        values: { name: "Global Tech US Inc", effective_at: at(1) },
      },
      {
        name: "wh_main",
        table: "operating_unit",
        refs: { ...owned, subsidiary: "sub_us" },
        values: { name: "Nevada Mega Warehouse", capacity: "10000.00" },
      },
      {
        name: "org_acme",
        table: "organization",
        refs: { ...owned, subsidiary: "sub_us", currency: "curr_usd" },
        values: { name: "Acme Customer Corp", effective_at: at(1) },
      },
      {
        name: "org_supplier",
        table: "organization",
        refs: { ...owned, subsidiary: "sub_us", currency: "curr_usd" },
        values: { name: "Direct Tech Supplier LLC", effective_at: at(1) },
      },

      // ==========================================
      // 5. ACCOUNTS (Treasury, Stock, Tax, Misc, AR/AP)
      // ==========================================
      {
        name: "bank_usd",
        table: "treasury",
        refs: { ...owned, subsidiary: "sub_us", currency: "curr_usd" },
        values: {
          name: "JPMorgan Main Operating USD",
          minimum_real: "0.00",
          effective_at: at(1),
        },
      },
      {
        name: "bank_eur",
        table: "treasury",
        refs: {
          ...owned,
          subsidiary: "sub_us",
          currency: "curr_eur",
          valuation_pair: "pair_eur_usd",
        },
        values: {
          name: "Deutsche Bank EUR Reserve",
          minimum_real: "0.00",
          effective_at: at(1),
        },
      },
      {
        name: "acct_tax_direct",
        table: "direct_tax_account",
        refs: { ...owned, subsidiary: "sub_us", currency: "curr_usd" },
        values: { name: "Federal Income Tax Withholding", effective_at: at(1) },
      },
      {
        name: "acct_tax_indirect",
        table: "indirect_tax_account",
        refs: { ...owned, subsidiary: "sub_us", currency: "curr_usd" },
        values: { name: "State Sales Tax Account", effective_at: at(1) },
      },
      {
        name: "acct_misc_fee",
        table: "misc_currency_account",
        refs: { ...owned, subsidiary: "sub_us", currency: "curr_usd" },
        values: {
          name: "Payment Processing Fees Expense",
          effective_at: at(1),
        },
      },
      {
        name: "acct_stock_laptops",
        table: "stock_account",
        refs: {
          ...owned,
          subsidiary: "sub_us",
          resource: "item_laptop",
          operating_unit: "wh_main",
        },
        values: {
          name: "Finished Laptops Stock",
          minimum_real: "0",
          effective_at: at(1),
        },
      },
      {
        name: "acct_stock_parts",
        table: "stock_account",
        refs: {
          ...owned,
          subsidiary: "sub_us",
          resource: "item_parts",
          operating_unit: "wh_main",
        },
        values: {
          name: "Raw Parts Stock",
          minimum_real: "0",
          effective_at: at(1),
        },
      },
      {
        name: "ar_acme",
        table: "organization_currency_account",
        refs: { ...owned, organization: "org_acme", currency: "curr_usd" },
        values: { name: "Acme USD Receivables", effective_at: at(1) },
      },
      {
        name: "ap_supplier",
        table: "organization_currency_account",
        refs: { ...owned, organization: "org_supplier", currency: "curr_usd" },
        values: { name: "Supplier USD Payables", effective_at: at(1) },
      },
      {
        name: "acme_delivered_stock",
        table: "organization_resource_account",
        refs: { ...owned, organization: "org_acme", resource: "item_laptop" },
        values: { name: "Acme Possessed Laptops", effective_at: at(1) },
      },
      {
        name: "supplier_shipped_parts",
        table: "organization_resource_account",
        refs: {
          ...owned,
          organization: "org_supplier",
          resource: "item_parts",
        },
        values: { name: "Supplier Sourced Parts", effective_at: at(1) },
      },

      // ==========================================
      // 6. INITIAL SEEDING (Cash & Stock Intake)
      // ==========================================
      {
        name: "init_cash",
        table: "account_entry",
        refs: { ...owned, account: "bank_usd" },
        values: {
          description: "Opening Equity Investment",
          real: "250000.00",
          effective_at: at(2),
        },
      },
      {
        name: "init_parts_stock",
        table: "stock_entry",
        refs: { ...owned, account: "acct_stock_parts" },
        values: {
          description: "Warehouse Opening Raw Materials",
          real: "500",
          effective_at: at(2),
        },
      },

      // ==========================================
      // 7. PRODUCTION CYCLE (Consume raw parts -> Output finished laptops)
      // ==========================================
      {
        name: "prod_batch_1",
        table: "production",
        refs: { ...owned, subsidiary: "sub_us" },
        values: {
          name: "Batch #101 Laptops Assembly",
          starts_at: at(3, 8),
          ends_at: at(3, 17),
        },
      },
      {
        name: "prod_in_parts",
        table: "production_input",
        refs: { production: "prod_batch_1", stock_account: "acct_stock_parts" },
        values: { quantity: "100" },
      },
      {
        name: "prod_out_laptops",
        table: "production_output",
        refs: {
          production: "prod_batch_1",
          stock_account: "acct_stock_laptops",
        },
        values: { quantity: "100" },
      },
      {
        name: "prod_labor_cap",
        table: "production_capacity",
        refs: {
          production: "prod_batch_1",
          operating_unit: "wh_main",
          resource: "svc_assembly",
        },
        values: { quantity: "9.00" },
      },
      {
        name: "prod_assembly_cost",
        table: "production_cost",
        refs: { production: "prod_batch_1", treasury: "bank_usd" },
        values: { amount: "1500.00" },
      },

      // ==========================================
      // 8. COMMERCIAL SALES CYCLE (Invoice, Issue, Tax, Payment with Fee)
      // ==========================================
      {
        name: "inv_sales_1",
        table: "sales_invoice",
        refs: { ...owned, account: "ar_acme" },
        values: { number: "INV-2026-001", invoice_date: at(5) },
      },
      {
        name: "issue_sales_1",
        table: "sales_issue",
        refs: {
          ...owned,
          invoice: "inv_sales_1",
          stock_account: "acct_stock_laptops",
          counterparty_stock: "acme_delivered_stock",
        },
        values: { quantity: "20", price: "1500.00", effective_at: at(4) },
      },
      {
        name: "tax_sales_1",
        table: "issue_tax",
        refs: {
          ...owned,
          source: "issue_sales_1",
          tax_account: "acct_tax_indirect",
        },
        values: { rate: "8.00", effective_at: at(4, 1) }, // 8% sales tax = $2,400.00
      },
      {
        name: "settle_sales_1",
        table: "invoice_settlement",
        refs: {
          ...owned,
          invoice: "inv_sales_1",
          treasury: "bank_usd",
          fee_account: "acct_misc_fee",
        },
        values: {
          amount: "32400.00",
          effective_at: at(6),
          fee_rate: "1.5", // 1.5% payment gateway fee
        },
      },

      // ==========================================
      // 9. ADJUSTMENTS & CREDIT NOTES
      // ==========================================
      {
        name: "note_sales_adj",
        table: "sales_adjustment_note",
        refs: { ...owned, account: "ar_acme" },
        values: { number: "CN-2026-001" },
      },
      {
        name: "adj_issue_1",
        table: "issue_adjustment",
        refs: {
          ...owned,
          source: "issue_sales_1",
          adjustment_note: "note_sales_adj",
        },
        values: {
          quantity_delta: "-2", // Returned 2 laptops
          price_delta: "0.00",
          effective_at: at(7),
        },
      },
      {
        name: "adj_tax_1",
        table: "issue_adjustment_tax",
        refs: {
          ...owned,
          source_tax: "tax_sales_1",
          adjustment: "adj_issue_1",
        },
        values: { effective_at: at(7, 1) },
      },

      // ==========================================
      // 10. CLAIMS & DIRECT SETTLEMENTS
      // ==========================================
      {
        name: "claim_rebate",
        table: "account_claim",
        refs: { ...owned, account: "ar_acme" },
        values: {
          claim_kind: "payable",
          amount: "500.00",
          effective_at: at(8),
          description: "Annual Customer Volume Rebate",
        },
      },
      {
        name: "claim_payout",
        table: "claim_settlement",
        refs: {
          ...owned,
          source: "claim_rebate",
          paid_account: "bank_usd",
        },
        values: { amount: "500.00", effective_at: at(9) },
      },

      // ==========================================
      // 11. TREASURY FOREX & TRANSFERS
      // ==========================================
      {
        name: "forex_conversion",
        table: "resource_exchange",
        refs: {
          ...owned,
          from_account: "bank_usd",
          to_account: "bank_eur",
          exchange_pair: "pair_usd_eur",
        },
        values: {
          from_amount: "50000.00",
          effective_at: at(10),
          description: "USD to EUR Liquidity Rebalance",
        },
      },

      // ==========================================
      // 12. TAX CASH OPERATIONS (Remittance & Offsets)
      // ==========================================
      {
        name: "tax_remit_state",
        table: "tax_settlement",
        refs: {
          ...owned,
          tax_account: "acct_tax_indirect",
          treasury: "bank_usd",
        },
        values: { amount: "2000.00", effective_at: at(11) },
      },

      // ==========================================
      // 13. FRAMEWORK SECURITY & USERS
      // ==========================================
      {
        name: "usr_auditor",
        table: "rebase_user",
        values: { name: "Chief Financial Officer" },
      },
      {
        name: "usr_email",
        table: "authentication_email",
        refs: { owned_by: "usr_auditor" },
        values: { address: "cfo@globaltech.com" },
      },
      {
        name: "usr_phone",
        table: "authentication_phone",
        refs: { owned_by: "usr_auditor" },
        values: { number: "+14155552671" },
      },
    ],
  };
}

async function run() {
  console.log("Compiling ReBase design...");
  const built = build({ project: "all-in-accounting" });
  const model = fixtures.createModel({
    schema: built.bundle,
    schemas: loadClientSchemas(
      path.resolve(__dirname, "../../../designs/all-in-accounting/schemas"),
    ),
  });

  console.log("Connecting and clearing previous data...");
  const admin = await connect();
  await prepare(admin.db, { clear: true });

  // Ensure default tenant exists
  await admin.db.query(
    "IF !record::exists(rebase_tenant:default) { CREATE rebase_tenant:default SET name = 'Primary Corporation'; };",
  );

  console.log("Populating complete enterprise fixture graph...");
  const result = await fixtures.populate(
    admin.db,
    enterpriseOptions({ model }),
  );

  console.log(
    `\nSuccessfully populated ${result.created.length} business and ledger records!`,
  );
  await admin.close();
}

if (require.main === module) {
  run().catch((err) => {
    console.error("Population failed:", err);
    process.exitCode = 1;
  });
}

module.exports = { enterpriseOptions, run };
