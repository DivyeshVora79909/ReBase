#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

const root = process.cwd();
const projectRequire = createRequire(path.join(root, "package.json"));
const { RecordId, Uuid, Decimal } = projectRequire("surrealdb");
const { connectDatabase } = projectRequire("./gateway/connection");
const { fixture, prepareFixture } = projectRequire("./dev-tools/accounting/fixture-example");
const { recordId } = projectRequire("./dev-tools/populate");
const { start, client, applySchema } = projectRequire("./dev-tools/temporal-tree/harness");

const uuid4Text = "550e8400-e29b-41d4-a716-446655440000";
const uuid7Text = "0198f92c-8a8a-7abc-8def-0123456789ab";
const customTreasuryKey = `fixture-prefix-${uuid7Text}-suffix`;

async function main() {
  const schemaPath = process.argv[2];
  if (!schemaPath) throw new Error("Usage: node designs/rebase-system/evidence/2026-10-02-fixture-sdk-smoke.cjs <all-in-accounting-schema.surql>");
  const schemaSource = fs.readFileSync(path.resolve(schemaPath), "utf8");

  let server;
  let session;
  let transaction;
  let committed = false;
  try {
    server = await start({ engine: "memory" });
    const q = client(server.url);
    await q("DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;");
    await applySchema(q, schemaSource);

    session = await connectDatabase({
      endpoint: server.url,
      username: "root",
      password: "root",
      namespace: "temporal_probe",
      database: "fixture",
    });
    const db = session.db;

    const rootGroupId = new RecordId("rebase_group", "root");
    const rootGroup = await db.select(rootGroupId);
    if (!rootGroup) {
      await db.query("CREATE $id CONTENT $content RETURN AFTER;", {
        id: rootGroupId,
        content: { name: "System Admins" },
      });
    }

    const rows = structuredClone(fixture);
    const customerId = `organization:u"${uuid4Text}"`;
    const customTreasuryId = `treasury:${customTreasuryKey}`;
    const customer = rows.find((row) => row.table === "organization" && row.content.name === "Harbor Market");
    const treasury = rows.find((row) => row.table === "treasury");
    const treasuryAccount = rows.find((row) => row.table === "treasury_account");
    const cashIn = rows.find((row) => row.table === "cash_in");
    assert(customer && treasury && treasuryAccount && cashIn, "fixture has customer, treasury, treasury account, and cash-in rows");
    customer.id = customerId;
    cashIn.content.from_party = customerId;
    treasury.id = customTreasuryId;
    treasuryAccount.content.treasury = customTreasuryId;
    assert.equal(rows.length, 6, "fixture contains exactly six explicit rows");
    const sdkRows = prepareFixture(rows);

    transaction = await db.beginTransaction();
    for (const row of sdkRows) {
      await transaction.query("CREATE $id CONTENT $content RETURN AFTER;", {
        id: row.id,
        content: row.content,
      });
    }
    await transaction.commit();
    committed = true;

    const readTable = async (table) => {
      const [result] = await db.query(`SELECT * FROM ${table};`);
      assert(Array.isArray(result), `${table} query returns rows`);
      return result;
    };
    const organizations = await readTable("organization");
    const currencies = await readTable("currency");
    const treasuries = await readTable("treasury");
    const treasuryAccounts = await readTable("treasury_account");
    const cashIns = await readTable("cash_in");
    const tableCounts = {
      organization: organizations.length,
      currency: currencies.length,
      treasury: treasuries.length,
      treasury_account: treasuryAccounts.length,
      cash_in: cashIns.length,
    };
    assert.deepEqual(tableCounts, {
      organization: 2,
      currency: 1,
      treasury: 1,
      treasury_account: 1,
      cash_in: 1,
    }, "exactly six fixture input rows were inserted");
    const explicitRowsInserted = Object.values(tableCounts).reduce((total, count) => total + count, 0);
    assert.equal(explicitRowsInserted, 6);

    const returnedCustomer = organizations.find((row) => row.name === "Harbor Market");
    assert(returnedCustomer, "customer row returned by native SDK");
    assert(returnedCustomer.id instanceof RecordId, "customer id remains a RecordId");
    assert(returnedCustomer.id.id instanceof Uuid, "canonical UUIDv4 key remains a typed Uuid");
    assert.equal(returnedCustomer.id.id.toString(), uuid4Text);
    assert(recordId(returnedCustomer.id.toString()).equals(returnedCustomer.id), "populate recordId round-trips canonical UUIDv4 IDs");
    assert(cashIns[0].from_party instanceof RecordId, "cash_in.from_party remains a RecordId");
    assert(cashIns[0].from_party.id instanceof Uuid, "cash_in.from_party key remains a typed Uuid");
    assert(cashIns[0].from_party.equals(returnedCustomer.id), "cash_in.from_party refers to the returned customer id");

    assert(treasuries[0].id instanceof RecordId, "treasury id returned by native SDK");
    assert.equal(treasuries[0].id.id, customTreasuryKey, "UUIDv7-looking custom key remains the full string");
    assert(recordId(treasuries[0].id.toString()).equals(treasuries[0].id), "populate recordId round-trips the SDK-serialized custom ID");
    assert(treasuryAccounts[0].treasury instanceof RecordId, "treasury reference returned by native SDK");
    assert.equal(treasuryAccounts[0].treasury.id, customTreasuryKey, "treasury reference keeps its full custom key");
    assert(treasuryAccounts[0].treasury.equals(treasuries[0].id), "treasury reference matches returned treasury id");

    const databaseIdStrings = {};
    for (const [table, nativeRows] of [["organization", organizations], ["treasury", treasuries]]) {
      const [serializedIds] = await db.query(`SELECT VALUE <string>id FROM ${table};`);
      databaseIdStrings[table] = serializedIds;
      assert.equal(serializedIds.length, nativeRows.length);
      for (const text of serializedIds) {
        const restored = recordId(text);
        assert(nativeRows.some(row => row.id.equals(restored)), "populate converts actual DB ID strings without changing identity");
      }
    }

    const balance = treasuryAccounts[0].z_history?.summary?.measures?.balance?.sum;
    assert(balance instanceof Decimal, "treasury history balance is returned as an SDK Decimal");
    assert.equal(balance.toString(), "42.5", "treasury balance equals Decimal 42.5");

    console.log(JSON.stringify({
      serverEngine: server.engine,
      explicitRowsInserted,
      tableCounts,
      rootGroup: rootGroup ? "already present" : "created because absent",
      uuid4CustomerId: returnedCustomer.id.toString(),
      uuid4CustomerIdValueType: returnedCustomer.id.id.constructor.name,
      uuid4CashInReference: cashIns[0].from_party.toString(),
      customUuid7TreasuryId: treasuries[0].id.toString(),
      customTreasuryReference: treasuryAccounts[0].treasury.toString(),
      databaseIdStrings,
      treasuryBalanceType: balance.constructor.name,
      treasuryBalance: balance.toString(),
    }, null, 2));
  } finally {
    if (transaction && !committed) await transaction.cancel().catch(() => {});
    if (session) await session.close().catch(() => {});
    if (server) await server.close().catch(() => {});
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
