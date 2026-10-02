#!/usr/bin/env node

"use strict";

const path = require("node:path");
const { Decimal } = require("surrealdb");
const { assertClientInput, loadClientSchemas } = require("../client-schemas");
const { recordId } = require("../populate");

const schemaDirectory = path.resolve(__dirname, "../../designs/all-in-accounting/schemas");

// Edit these JSON-native input values. This preview reads authored schemas so
// it works before the first build; the compiler copies those schemas unchanged
// to build/all-in-accounting/client/schemas for applications to consume.
const fixture = [
  {
    table: "organization",
    id: "organization:demo_owner",
    content: {
      owned_by: "rebase_group:root",
      name: "Northwind Supply",
      code: "NORTHWIND",
    },
  },
  {
    table: "organization",
    id: "organization:demo_customer",
    content: {
      owned_by: "rebase_group:root",
      name: "Harbor Market",
    },
  },
  {
    table: "currency",
    id: "currency:demo_usd",
    content: {
      owned_by: "rebase_group:root",
      code: "USD",
      name: "US dollar",
      precision: 2,
    },
  },
  {
    table: "treasury",
    id: "treasury:demo_bank",
    content: {
      owned_by: "rebase_group:root",
      name: "Operating bank",
    },
  },
  {
    table: "treasury_account",
    id: "treasury_account:demo_cash",
    content: {
      owned_by: "rebase_group:root",
      economic_entity: "organization:demo_owner",
      treasury: "treasury:demo_bank",
      currency: "currency:demo_usd",
      minimum_balance: "0.00",
    },
  },
  {
    table: "cash_in",
    id: "cash_in:demo_receipt",
    content: {
      owned_by: "rebase_group:root",
      from_party: "organization:demo_customer",
      to_account: "treasury_account:demo_cash",
      amount: "42.50",
      effective_at: "2026-10-01T00:00:00Z",
    },
  },
];

const recordFields = {
  organization: ["owned_by"],
  currency: ["owned_by"],
  treasury: ["owned_by"],
  treasury_account: ["owned_by", "economic_entity", "treasury", "currency"],
  cash_in: ["owned_by", "from_party", "to_account"],
};

const decimalFields = {
  treasury_account: ["minimum_balance"],
  cash_in: ["amount"],
};

function bindValues(table, input) {
  const bound = { ...input };
  for (const field of recordFields[table] || []) {
    if (bound[field] !== undefined) bound[field] = recordId(bound[field]);
  }
  for (const field of decimalFields[table] || []) {
    if (bound[field] !== undefined) bound[field] = new Decimal(bound[field]);
  }
  if (table === "cash_in") bound.effective_at = new Date(bound.effective_at);
  return bound;
}

function prepareFixture(rows = fixture) {
  const catalog = loadClientSchemas(schemaDirectory);
  return rows.map(({ table, id, content }) => {
    assertClientInput(catalog, table, content);
    return {
      table,
      id: recordId(id),
      content: bindValues(table, content),
    };
  });
}

if (require.main === module) {
  const rows = prepareFixture();
  console.log(`Validated ${rows.length} explicit all-in-accounting fixture rows.`);
  console.log("SDK RecordId, Decimal, and Date values are ready for bound client writes.");
  console.log("No database connection is opened by this example.");
}

module.exports = { bindValues, fixture, prepareFixture };
