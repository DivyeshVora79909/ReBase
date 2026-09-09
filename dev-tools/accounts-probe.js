#!/usr/bin/env node

/*
 * Disposable on-disk smoke/integrity probe for the all-in-one Accounts kernel.
 * It deliberately uses SurrealKV (never mem://), a generated bundle, explicit
 * IDs, and final-statement extraction.  The fixture is small by design: this
 * is a deterministic regression probe, not a capacity benchmark.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { isRetryableConflict } = require("surrealdb");

const WS = globalThis.WebSocket || (() => {
  try {
    return require("ws");
  } catch {
    throw new Error("Accounts probe requires a native WebSocket or the ws package");
  }
})();
const ROOT = path.resolve(__dirname, "..");

function surrealBinary() {
  if (process.env.REBASE_ACCOUNTS_SURREAL_BIN) return process.env.REBASE_ACCOUNTS_SURREAL_BIN;
  return fs.existsSync("/tmp/surreal") ? "/tmp/surreal" : "surreal";
}

function finalResult(response) {
  const last = Array.isArray(response) ? response.at(-1) : response;
  if (last && typeof last === "object" && Object.hasOwn(last, "result")) {
    if (last.status === "ERR") throw new Error(last.detail || "SurrealQL query failed");
    return last.result;
  }
  return last;
}

function rows(response) {
  const value = finalResult(response);
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) break;
    const connected = await new Promise((resolve) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  throw new Error("Disposable SurrealDB did not start");
}

async function startServer() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-accounts-probe-"));
  const port = await freePort();
  const child = spawn(surrealBinary(), [
    "start", `surrealkv://${directory}`,
    "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`,
    "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.once("error", (error) => { stderr = `${stderr}${error.message}`; });
  try {
    await waitForPort(port, child);
  } catch (error) {
    child.kill("SIGTERM");
    throw new Error(`${error.message}${stderr.trim() ? `: ${stderr.trim()}` : ""}`);
  }
  return { directory, child, endpoint: `ws://127.0.0.1:${port}/rpc` };
}

async function stopServer(server) {
  if (!server?.child || server.child.exitCode !== null) return;
  const exited = new Promise((resolve) => server.child.once("exit", resolve));
  server.child.kill("SIGTERM");
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 2000))]);
  if (server.child.exitCode === null) server.child.kill("SIGKILL");
  fs.rmSync(server.directory, { recursive: true, force: true });
}

async function connect(server, namespace, database) {
  const db = new Surreal({ websocketImpl: WS });
  await db.connect(server.endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.query(`DEFINE NAMESPACE IF NOT EXISTS ${namespace}; USE NS ${namespace}; DEFINE DATABASE ${database}; USE DB ${database};`);
  await db.use({ namespace, database });
  return db;
}

async function openSession(server, namespace, database) {
  const db = new Surreal({ websocketImpl: WS });
  await db.connect(server.endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.use({ namespace, database });
  return db;
}

async function queryWithConflictRetry(db, query, attempts = 50) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await db.query(query);
    } catch (error) {
      const retryable = isRetryableConflict(error) || /transaction conflict|conflict/i.test(error.message || "");
      if (!retryable || attempt === attempts - 1) throw error;
      await new Promise((resolve) => setTimeout(resolve, Math.min(40, 2 ** Math.min(attempt, 5))));
    }
  }
  throw new Error("unreachable");
}

function compileBundle(namespace, database) {
  const output = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "rebase-accounts-build-")), "build");
  const result = require("./compiler/cli").compileFromArgs({
    projectDir: "designs/all-in-one",
    frameworkDir: "framework",
    outputDir: output,
    namespace,
    database,
  }, ROOT);
  return { output, bundle: result.bundle };
}

async function main() {
  const namespace = `rebase_accounts_probe_${Date.now().toString(36)}`;
  const database = "accounts";
  const compiled = compileBundle(namespace, database);
  const server = await startServer();
  const db = await connect(server, namespace, database);
  try {
    await db.query(compiled.bundle);
    await db.query(`
      CREATE currency:inr SET owned_by = groups:root, a_code = 'INR', a_name = 'Indian Rupee';
      CREATE currency:usd SET owned_by = groups:root, a_code = 'USD', a_name = 'US Dollar';
      CREATE currency:eur SET owned_by = groups:root, a_code = 'EUR', a_name = 'Euro';
      CREATE organization:vendor SET owned_by = groups:root, a_name = 'Vendor';
      CREATE organization:other SET owned_by = groups:root, a_name = 'Other';
      CREATE organization:context SET owned_by = groups:root, a_name = 'Context Only';
      CREATE organization:no_code_1 SET owned_by = groups:root, a_name = 'No Code 1';
      CREATE organization:no_code_2 SET owned_by = groups:root, a_name = 'No Code 2';
      CREATE treasury_account:cash SET owned_by = groups:root, a_name = 'Cash', a_currency = currency:inr;
      CREATE misc_account:permissive SET owned_by = groups:root, a_name = 'Permissive Misc', a_currency = currency:inr;
      CREATE misc_account:guarded SET owned_by = groups:root, a_name = 'Guarded Misc', a_currency = currency:inr, a_guard_non_negative = true;
      CREATE item:widget SET owned_by = groups:root, a_name = 'Widget';
      CREATE item:no_sku_1 SET owned_by = groups:root, a_name = 'No SKU 1';
      CREATE item:no_sku_2 SET owned_by = groups:root, a_name = 'No SKU 2';
      CREATE operating_unit:warehouse SET owned_by = groups:root, a_name = 'Warehouse', a_kind = 'warehouse';
      CREATE operating_unit:warehouse_2 SET owned_by = groups:root, a_name = 'Warehouse 2', a_kind = 'warehouse';
      CREATE operating_unit:opening_probe SET owned_by = groups:root, a_name = 'Opening Probe Unit', a_kind = 'warehouse';
      CREATE misc_inventory_node:external_stock SET owned_by = groups:root, a_name = 'External Stock';
      CREATE service:consulting SET owned_by = groups:root, a_name = 'Consulting';
      CREATE service:no_code_1 SET owned_by = groups:root, a_name = 'No Service Code 1';
      CREATE service:no_code_2 SET owned_by = groups:root, a_name = 'No Service Code 2';
      CREATE tax_rule:gst SET owned_by = groups:root, a_name = 'GST', a_code = 'GST', a_default_rate = 18dec;
      CREATE tax_rule:no_code_1 SET owned_by = groups:root, a_name = 'No Tax Code 1';
      CREATE tax_rule:no_code_2 SET owned_by = groups:root, a_name = 'No Tax Code 2';
      CREATE organization_finance_profile:vendor SET owned_by = groups:root,
        a_organization = organization:vendor, a_functional_currency = currency:inr,
        a_reporting_currency = currency:usd;
    `);
    await db.query(`CREATE money_opening_balance:permissive SET owned_by = groups:root,
        a_endpoint = misc_account:permissive, a_currency = currency:inr,
        a_amount = 10dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'permissive-opening';
      CREATE money_movement:permissive_out SET owned_by = groups:root,
        a_from = misc_account:permissive, a_to = organization:vendor,
        a_currency = currency:inr, a_amount = 20dec,
        a_effective_at = d'2026-01-02T00:00:00Z', a_idempotency_key = 'permissive-out';`);
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = misc_account:permissive;"))[0].balance), "-10");
    await db.query(`CREATE money_opening_balance:guarded SET owned_by = groups:root,
        a_endpoint = misc_account:guarded, a_currency = currency:inr,
        a_amount = 10dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'guarded-opening';`);
    await assert.rejects(
      db.query(`CREATE money_movement:guarded_out SET owned_by = groups:root,
        a_from = misc_account:guarded, a_to = organization:vendor,
        a_currency = currency:inr, a_amount = 20dec,
        a_effective_at = d'2026-01-02T00:00:00Z', a_idempotency_key = 'guarded-out';`),
      /NEGATIVE_MONEY_POSITION|HISTORICAL_NEGATIVE_PREFIX|negative/i,
    );
    await assert.rejects(
      db.query(`CREATE organization_finance_profile:vendor_duplicate SET owned_by = groups:root,
        a_organization = organization:vendor, a_functional_currency = currency:usd;`),
      /unique|duplicate|index/i,
    );
    await db.query(`CREATE money_opening_balance:cash SET owned_by = groups:root,
        a_endpoint = treasury_account:cash, a_currency = currency:inr,
        a_amount = 100dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'opening-cash';`);
    await db.query(`CREATE treasury_account:opening_probe SET owned_by = groups:root,
        a_name = 'Opening Probe', a_currency = currency:inr;
      CREATE money_opening_balance:opening_probe SET owned_by = groups:root,
        a_endpoint = treasury_account:opening_probe, a_currency = currency:inr,
        a_amount = 20dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'opening-probe';`);
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:opening_probe;"))[0].balance), "20");
    await db.query("UPDATE money_opening_balance:opening_probe SET a_amount = 30dec;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:opening_probe;"))[0].balance), "30");
    await db.query("DELETE money_opening_balance:opening_probe;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:opening_probe;"))[0].balance), "0");
    await db.query(`CREATE money_movement:pay_1 SET owned_by = groups:root,
        a_from = treasury_account:cash, a_to = organization:vendor,
        a_currency = currency:inr, a_amount = 30dec,
        a_effective_at = d'2026-01-02T00:00:00Z', a_idempotency_key = 'pay-1';`);
    const position = rows(await db.query("SELECT * FROM money_position WHERE endpoint = treasury_account:cash;"))[0];
    assert.equal(String(position.balance), "70");
    assert.equal(String(position.total_out), "30");

    await db.query("UPDATE money_movement:pay_1 SET a_amount = 20dec;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:cash;"))[0].balance), "80");
    await db.query("UPDATE money_movement:pay_1 SET a_amount = 30dec;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:cash;"))[0].balance), "70");

    await assert.rejects(
      db.query(`CREATE money_movement:pay_over SET owned_by = groups:root,
        a_from = treasury_account:cash, a_to = organization:vendor,
        a_currency = currency:inr, a_amount = 80dec,
        a_effective_at = d'2026-01-03T00:00:00Z', a_idempotency_key = 'pay-over';`),
      /NEGATIVE_MONEY_POSITION|negative/i,
    );
    assert.equal(rows(await db.query("SELECT id FROM money_movement WHERE id = money_movement:pay_over;")).length, 0);

    // A current total can remain positive while an earlier effective-time
    // prefix becomes negative. Replay must reject the edit atomically.
    await db.query(`CREATE treasury_account:historical_cash SET owned_by = groups:root,
        a_name = 'Historical Cash', a_currency = currency:inr;
      CREATE money_opening_balance:historical_opening SET owned_by = groups:root,
        a_endpoint = treasury_account:historical_cash, a_currency = currency:inr,
        a_amount = 100dec, a_effective_at = d'2026-01-10T00:00:00Z',
        a_idempotency_key = 'historical-opening';
      CREATE money_movement:historical_out SET owned_by = groups:root,
        a_from = treasury_account:historical_cash, a_to = organization:vendor,
        a_currency = currency:inr, a_amount = 80dec,
        a_effective_at = d'2026-01-11T00:00:00Z',
        a_idempotency_key = 'historical-out';
      CREATE money_movement:historical_in SET owned_by = groups:root,
        a_from = organization:vendor, a_to = treasury_account:historical_cash,
        a_currency = currency:inr, a_amount = 100dec,
        a_effective_at = d'2026-01-12T00:00:00Z',
        a_idempotency_key = 'historical-in';`);
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:historical_cash;"))[0].balance), "120");
    await assert.rejects(
      db.query("UPDATE money_movement:historical_out SET a_amount = 150dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_amount FROM money_movement:historical_out;"))[0].a_amount), "80");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:historical_cash;"))[0].balance), "120");
    await assert.rejects(
      db.query("UPDATE money_opening_balance:historical_opening SET a_amount = 50dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    await assert.rejects(
      db.query("DELETE money_opening_balance:historical_opening;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    await db.query("DELETE money_movement:historical_in;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:historical_cash;"))[0].balance), "20");
    await db.query(`CREATE money_movement:historical_in SET owned_by = groups:root,
        a_from = organization:vendor, a_to = treasury_account:historical_cash,
        a_currency = currency:inr, a_amount = 100dec,
        a_effective_at = d'2026-01-12T00:00:00Z',
        a_idempotency_key = 'historical-in';`);
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:historical_cash;"))[0].balance), "120");

    await assert.rejects(
      db.query("UPDATE money_movement:pay_1 SET a_effective_at = d'2026-01-04T00:00:00Z';"),
      /READONLY|immutable|cannot/i,
    );

    await assert.rejects(
      db.query(`CREATE fx_rate:bad_same SET owned_by = groups:root,
        a_base_currency = currency:inr, a_quote_currency = currency:inr,
        a_rate = 1dec, a_effective_at = d'2026-01-02T00:00:00Z';`),
      /FX_SAME_CURRENCY|same.currency|same currency/i,
    );
    await db.query(`CREATE fx_rate:inr_usd SET owned_by = groups:root,
      a_base_currency = currency:inr, a_quote_currency = currency:usd,
      a_rate = 0.012dec, a_effective_at = d'2026-01-02T00:00:00Z';
      CREATE fx_rate:usd_eur SET owned_by = groups:root,
        a_base_currency = currency:usd, a_quote_currency = currency:eur,
        a_rate = 0.92dec, a_effective_at = d'2026-01-02T00:00:00Z';
      CREATE treasury_account:fx_cash SET owned_by = groups:root,
        a_name = 'FX Cash', a_currency = currency:inr;
      CREATE treasury_account:usd_cash SET owned_by = groups:root,
        a_name = 'USD Cash', a_currency = currency:usd;
      CREATE money_opening_balance:fx_cash SET owned_by = groups:root,
        a_endpoint = treasury_account:fx_cash, a_currency = currency:inr,
        a_amount = 100dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'opening-fx-cash';`);
    await db.query(`CREATE money_exchange:fx_1 SET owned_by = groups:root,
      a_from = treasury_account:fx_cash, a_to = treasury_account:usd_cash,
      a_from_currency = currency:inr, a_to_currency = currency:usd,
      a_from_amount = 10dec, a_to_amount = 0.12dec, a_fx_rate = fx_rate:inr_usd,
      a_effective_at = d'2026-01-03T00:00:00Z', a_idempotency_key = 'fx-1';`);
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:fx_cash;"))[0].balance), "90");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:usd_cash;"))[0].balance), "0.12");
    await db.query("UPDATE money_exchange:fx_1 SET a_from_amount = 12dec, a_to_amount = 0.14dec;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:fx_cash;"))[0].balance), "88");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:usd_cash;"))[0].balance), "0.14");
    await assert.rejects(
      db.query(`CREATE money_movement:bad_fx SET owned_by = groups:root,
        a_from = treasury_account:fx_cash, a_to = organization:vendor,
        a_currency = currency:usd, a_amount = 1dec,
        a_effective_at = d'2026-01-04T00:00:00Z', a_idempotency_key = 'bad-fx';`),
      /MONEY_FROM_CURRENCY|currency/i,
    );
    await assert.rejects(
      db.query(`UPDATE money_exchange:fx_1 SET a_from_amount = 1000dec;`),
      /NEGATIVE_MONEY_POSITION|negative/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_from_amount FROM money_exchange:fx_1;"))[0].a_from_amount), "12");
    await assert.rejects(
      db.query(`CREATE money_exchange:fx_bad_pair SET owned_by = groups:root,
        a_from = treasury_account:fx_cash, a_to = treasury_account:usd_cash,
        a_from_currency = currency:inr, a_to_currency = currency:usd,
        a_from_amount = 1dec, a_to_amount = 1dec, a_fx_rate = fx_rate:usd_eur,
        a_effective_at = d'2026-01-04T00:00:00Z', a_idempotency_key = 'fx-bad-pair';`),
      /FX_PAIR|pair/i,
    );
    await db.query("DELETE money_exchange:fx_1;");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:fx_cash;"))[0].balance), "100");
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:usd_cash;"))[0].balance), "0");

    await db.query(`CREATE treasury_account:historical_fx_inr SET owned_by = groups:root,
        a_name = 'Historical FX INR', a_currency = currency:inr;
      CREATE treasury_account:historical_fx_usd SET owned_by = groups:root,
        a_name = 'Historical FX USD', a_currency = currency:usd;
      CREATE money_opening_balance:historical_fx_opening SET owned_by = groups:root,
        a_endpoint = treasury_account:historical_fx_inr, a_currency = currency:inr,
        a_amount = 100dec, a_effective_at = d'2026-01-10T00:00:00Z',
        a_idempotency_key = 'historical-fx-opening';
      CREATE money_exchange:historical_fx_exchange SET owned_by = groups:root,
        a_from = treasury_account:historical_fx_inr, a_to = treasury_account:historical_fx_usd,
        a_from_currency = currency:inr, a_to_currency = currency:usd,
        a_from_amount = 80dec, a_to_amount = 0.96dec, a_fx_rate = fx_rate:inr_usd,
        a_effective_at = d'2026-01-11T00:00:00Z',
        a_idempotency_key = 'historical-fx-exchange';
      CREATE money_movement:historical_fx_in SET owned_by = groups:root,
        a_from = organization:vendor, a_to = treasury_account:historical_fx_inr,
        a_currency = currency:inr, a_amount = 100dec,
        a_effective_at = d'2026-01-12T00:00:00Z',
        a_idempotency_key = 'historical-fx-in';`);
    assert.equal(String(rows(await db.query("SELECT balance FROM money_position WHERE endpoint = treasury_account:historical_fx_inr;"))[0].balance), "120");
    await assert.rejects(
      db.query("UPDATE money_exchange:historical_fx_exchange SET a_from_amount = 150dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_from_amount FROM money_exchange:historical_fx_exchange;"))[0].a_from_amount), "80");

    await db.query(`
      CREATE service_capacity:cap_1 SET owned_by = groups:root,
        a_operating_unit = operating_unit:warehouse, a_service = service:consulting,
        a_quantity = 2dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'cap-1';
    `);
    await db.query(`CREATE service_delivery:delivery_1 SET owned_by = groups:root,
        a_operating_unit = operating_unit:warehouse, a_service = service:consulting,
        a_organization = organization:vendor, a_quantity = 1dec,
        a_effective_at = d'2026-01-02T00:00:00Z', a_idempotency_key = 'delivery-1';`);
    const servicePosition = rows(await db.query("SELECT * FROM service_position;"))[0];
    assert.equal(String(servicePosition.remaining), "1");
    await assert.rejects(
      db.query(`CREATE service_delivery:delivery_over SET owned_by = groups:root,
        a_operating_unit = operating_unit:warehouse, a_service = service:consulting,
        a_quantity = 2dec, a_effective_at = d'2026-01-03T00:00:00Z',
        a_idempotency_key = 'delivery-over';`),
      /SERVICE_CAPACITY_EXCEEDED|HISTORICAL_NEGATIVE_PREFIX|capacity/i,
    );
    await db.query("UPDATE service_capacity:cap_1 SET a_quantity = 3dec;");
    assert.equal(String(rows(await db.query("SELECT * FROM service_position;"))[0].remaining), "2");
    await db.query("UPDATE service_delivery:delivery_1 SET a_quantity = 2dec;");
    assert.equal(String(rows(await db.query("SELECT * FROM service_position;"))[0].remaining), "1");
    await db.query("UPDATE service_delivery:delivery_1 SET a_quantity = 3dec;");
    assert.equal(String(rows(await db.query("SELECT * FROM service_position;"))[0].remaining), "0");
    await assert.rejects(
      db.query("UPDATE service_delivery:delivery_1 SET a_quantity = 4dec;"),
      /SERVICE_CAPACITY_EXCEEDED|HISTORICAL_NEGATIVE_PREFIX|capacity/i,
    );
    assert.equal(String(rows(await db.query("SELECT * FROM service_position;"))[0].remaining), "0");

    await db.query(`CREATE operating_unit:historical_unit SET owned_by = groups:root,
        a_name = 'Historical Unit', a_kind = 'warehouse';
      CREATE inventory_opening_balance:historical_opening SET owned_by = groups:root,
        a_operating_unit = operating_unit:historical_unit, a_item = item:widget,
        a_quantity = 5dec, a_effective_at = d'2026-01-10T00:00:00Z',
        a_idempotency_key = 'historical-inventory-opening';
      CREATE inventory_movement:historical_inventory_out SET owned_by = groups:root,
        a_from = operating_unit:historical_unit, a_to = organization:vendor,
        a_item = item:widget, a_quantity = 3dec,
        a_effective_at = d'2026-01-11T00:00:00Z',
        a_idempotency_key = 'historical-inventory-out';
      CREATE inventory_movement:historical_inventory_in SET owned_by = groups:root,
        a_from = organization:vendor, a_to = operating_unit:historical_unit,
        a_item = item:widget, a_quantity = 10dec,
        a_effective_at = d'2026-01-12T00:00:00Z',
        a_idempotency_key = 'historical-inventory-in';`);
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:historical_unit;"))[0].quantity), "12");
    await assert.rejects(
      db.query("UPDATE inventory_movement:historical_inventory_out SET a_quantity = 8dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    await assert.rejects(
      db.query("UPDATE inventory_opening_balance:historical_opening SET a_quantity = 2dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    await assert.rejects(
      db.query("DELETE inventory_opening_balance:historical_opening;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative/i,
    );
    await db.query("DELETE inventory_movement:historical_inventory_in;");
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:historical_unit;"))[0].quantity), "2");
    await db.query(`CREATE inventory_movement:historical_inventory_in SET owned_by = groups:root,
        a_from = organization:vendor, a_to = operating_unit:historical_unit,
        a_item = item:widget, a_quantity = 10dec,
        a_effective_at = d'2026-01-12T00:00:00Z',
        a_idempotency_key = 'historical-inventory-in';`);

    await db.query(`CREATE service:historical_service SET owned_by = groups:root, a_name = 'Historical Service';
      CREATE service_capacity:historical_capacity SET owned_by = groups:root,
        a_operating_unit = operating_unit:historical_unit, a_service = service:historical_service,
        a_quantity = 5dec, a_effective_at = d'2026-01-10T00:00:00Z',
        a_idempotency_key = 'historical-service-capacity';
      CREATE service_delivery:historical_delivery SET owned_by = groups:root,
        a_operating_unit = operating_unit:historical_unit, a_service = service:historical_service,
        a_organization = organization:vendor, a_quantity = 3dec,
        a_effective_at = d'2026-01-11T00:00:00Z',
        a_idempotency_key = 'historical-service-delivery';
      CREATE service_capacity:historical_capacity_later SET owned_by = groups:root,
        a_operating_unit = operating_unit:historical_unit, a_service = service:historical_service,
        a_quantity = 4dec, a_effective_at = d'2026-01-12T00:00:00Z',
        a_idempotency_key = 'historical-service-capacity-later';`);
    assert.equal(String(rows(await db.query("SELECT remaining FROM service_position WHERE operating_unit = operating_unit:historical_unit;"))[0].remaining), "6");
    await assert.rejects(
      db.query("UPDATE service_capacity:historical_capacity SET a_quantity = 2dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative|capacity/i,
    );
    await assert.rejects(
      db.query("UPDATE service_delivery:historical_delivery SET a_quantity = 7dec;"),
      /ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX|historical|negative|capacity/i,
    );

    await db.query(`CREATE inventory_opening_balance:opening_probe SET owned_by = groups:root,
      a_operating_unit = operating_unit:opening_probe, a_item = item:widget,
      a_quantity = 5dec, a_effective_at = d'2026-01-01T00:00:00Z',
      a_idempotency_key = 'opening-inventory-probe';`);
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:opening_probe;"))[0].quantity), "5");
    await db.query("UPDATE inventory_opening_balance:opening_probe SET a_quantity = 7dec;");
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:opening_probe;"))[0].quantity), "7");
    await db.query("DELETE inventory_opening_balance:opening_probe;");
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:opening_probe;"))[0].quantity), "0");

    await db.query(`CREATE inventory_opening_balance:widget SET owned_by = groups:root,
      a_operating_unit = operating_unit:warehouse, a_item = item:widget,
      a_quantity = 10dec, a_effective_at = d'2026-01-01T00:00:00Z',
      a_idempotency_key = 'opening-widget';`);
    await db.query(`CREATE inventory_movement:stock_out SET owned_by = groups:root,
      a_from = operating_unit:warehouse, a_to = organization:vendor,
      a_item = item:widget, a_quantity = 4dec,
      a_effective_at = d'2026-01-02T00:00:00Z', a_idempotency_key = 'stock-out';`);
    assert.equal(String(rows(await db.query("SELECT * FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "6");
    await db.query("UPDATE inventory_movement:stock_out SET a_quantity = 3dec;");
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "7");
    await db.query("UPDATE inventory_movement:stock_out SET a_quantity = 4dec;");
    assert.equal(String(rows(await db.query("SELECT quantity FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "6");
    await assert.rejects(
      db.query(`CREATE inventory_movement:stock_over SET owned_by = groups:root,
        a_from = operating_unit:warehouse, a_to = organization:vendor,
        a_item = item:widget, a_quantity = 7dec,
        a_effective_at = d'2026-01-03T00:00:00Z', a_idempotency_key = 'stock-over';`),
      /NEGATIVE_INVENTORY|negative/i,
    );
    await db.query(`CREATE inventory_movement:stock_transfer SET owned_by = groups:root,
      a_from = operating_unit:warehouse, a_to = operating_unit:warehouse_2,
      a_item = item:widget, a_quantity = 2dec,
      a_effective_at = d'2026-01-04T00:00:00Z', a_idempotency_key = 'stock-transfer';`);
    const inventoryPositions = rows(await db.query("SELECT * FROM inventory_position ORDER BY operating_unit;"));
    assert.equal(String(inventoryPositions.find((row) => String(row.operating_unit) === "operating_unit:warehouse").quantity), "4");
    assert.equal(String(inventoryPositions.find((row) => String(row.operating_unit) === "operating_unit:warehouse_2").quantity), "2");

    await db.query(`CREATE invoice:inv_1 SET owned_by = groups:root,
      a_organization = organization:vendor, a_currency = currency:inr,
      a_direction = 'receivable', a_number = 'INV-1',
      a_effective_at = d'2026-01-01T00:00:00Z';
      CREATE invoice:other_number SET owned_by = groups:root,
        a_organization = organization:other, a_currency = currency:inr,
        a_direction = 'receivable', a_number = 'INV-1',
        a_effective_at = d'2026-01-01T00:00:00Z';`);
    await assert.rejects(
      db.query(`CREATE invoice:duplicate_number SET owned_by = groups:root,
        a_organization = organization:vendor, a_currency = currency:inr,
        a_direction = 'receivable', a_number = 'INV-1',
        a_effective_at = d'2026-01-01T00:00:00Z';`),
      /index|unique|duplicate/i,
    );
    await db.query(`CREATE invoice_line:line_1 SET owned_by = groups:root,
      a_invoice = invoice:inv_1, a_subject = item:widget,
      a_quantity = 1dec, a_unit_price = 50dec;`);
    await db.query(`CREATE tax_output:tax_1 SET owned_by = groups:root,
      a_invoice_line = invoice_line:line_1, a_rule = tax_rule:gst, a_rate = 18dec;`);
    const taxedLine = rows(await db.query("SELECT * FROM invoice_line:line_1;"))[0];
    assert.equal(String(taxedLine.d4_base_amount), "50");
    assert.equal(String(taxedLine.d5_tax_amount), "9");
    assert.equal(String(taxedLine.d6_gross_amount), "59");
    await db.query(`CREATE money_movement:pay_2 SET owned_by = groups:root,
      a_from = organization:vendor, a_to = treasury_account:cash,
      a_currency = currency:inr, a_amount = 50dec,
      a_effective_at = d'2026-01-05T00:00:00Z', a_idempotency_key = 'pay-2';`);
    await db.query(`CREATE payment_application:app_1 SET owned_by = groups:root,
      a_payment = money_movement:pay_2, a_invoice = invoice:inv_1,
      a_amount = 50dec, a_idempotency_key = 'application-1';`);
    await assert.rejects(
      db.query("UPDATE money_movement:pay_2 SET a_amount = 49dec;"),
      /OVER_APPLIED|applied|payment/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_amount FROM money_movement:pay_2;"))[0].a_amount), "50");
    await assert.rejects(
      db.query("CREATE payment_application:app_over SET owned_by = groups:root, a_payment = money_movement:pay_2, a_invoice = invoice:inv_1, a_amount = 1dec, a_idempotency_key = 'application-over';"),
      /OVER_APPLIED|OVER_SETTLED|settled|applied/i,
    );

    await db.query(`CREATE money_refund:refund_1 SET owned_by = groups:root,
      a_original_payment = money_movement:pay_1, a_amount = 10dec,
      a_effective_at = d'2026-01-06T00:00:00Z', a_idempotency_key = 'refund-1';`);
    assert.equal(String(rows(await db.query("SELECT * FROM money_position WHERE endpoint = treasury_account:cash;"))[0].balance), "130");

    await db.query(`CREATE inventory_return:return_1 SET owned_by = groups:root,
      a_original_movement = inventory_movement:stock_out, a_quantity = 1dec,
      a_effective_at = d'2026-01-06T00:00:00Z', a_idempotency_key = 'return-1';`);
    assert.equal(String(rows(await db.query("SELECT * FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "5");
    await assert.rejects(
      db.query(`CREATE inventory_return:return_internal SET owned_by = groups:root,
        a_original_movement = inventory_movement:stock_transfer, a_quantity = 1dec,
        a_effective_at = d'2026-01-06T00:00:00Z', a_idempotency_key = 'return-internal';`),
      /RETURN_REQUIRES_DELIVERY|delivery|organization/i,
    );

    await db.query(`CREATE adjustment_note:note_1 SET owned_by = groups:root,
      a_organization = organization:vendor, a_name = 'Correction';
      CREATE money_adjustment_line:money_adj_1 SET owned_by = groups:root,
        a_note = adjustment_note:note_1, a_target = money_movement:pay_1, a_delta = -5dec;
      CREATE inventory_adjustment_line:inventory_adj_1 SET owned_by = groups:root,
        a_note = adjustment_note:note_1, a_target = inventory_movement:stock_out, a_delta = -1dec;`);
    assert.equal(String(rows(await db.query("SELECT d4_net_amount FROM money_movement:pay_1;"))[0].d4_net_amount), "25");
    assert.equal(String(rows(await db.query("SELECT d4_net_quantity FROM inventory_movement:stock_out;"))[0].d4_net_quantity), "3");
    assert.equal(String(rows(await db.query("SELECT * FROM money_position WHERE endpoint = treasury_account:cash;"))[0].balance), "135");
    assert.equal(String(rows(await db.query("SELECT * FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "6");

    await db.query("UPDATE money_refund:refund_1 SET a_amount = 15dec;");
    assert.equal(String(rows(await db.query("SELECT * FROM money_position WHERE endpoint = treasury_account:cash;"))[0].balance), "140");
    await assert.rejects(
      db.query(`CREATE money_refund:refund_over SET owned_by = groups:root,
        a_original_payment = money_movement:pay_1, a_amount = 11dec,
        a_effective_at = d'2026-01-07T00:00:00Z', a_idempotency_key = 'refund-over';`),
      /REFUND_EXCEEDS_PAYMENT|refund/i,
    );
    await db.query("DELETE money_refund:refund_1;");
    assert.equal(String(rows(await db.query("SELECT * FROM money_position WHERE endpoint = treasury_account:cash;"))[0].balance), "125");

    await db.query("UPDATE inventory_return:return_1 SET a_quantity = 2dec;");
    assert.equal(String(rows(await db.query("SELECT * FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "7");
    await assert.rejects(
      db.query("UPDATE inventory_movement:stock_out SET a_quantity = 1dec;"),
      /RETURN_EXCEEDS_MOVEMENT|return|quantity/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_quantity FROM inventory_movement:stock_out;"))[0].a_quantity), "4");
    await assert.rejects(
      db.query(`CREATE inventory_return:return_over SET owned_by = groups:root,
        a_original_movement = inventory_movement:stock_out, a_quantity = 2dec,
        a_effective_at = d'2026-01-07T00:00:00Z', a_idempotency_key = 'return-over';`),
      /RETURN_EXCEEDS_MOVEMENT|return/i,
    );
    await db.query("DELETE inventory_return:return_1;");
    assert.equal(String(rows(await db.query("SELECT * FROM inventory_position WHERE operating_unit = operating_unit:warehouse;"))[0].quantity), "5");

    await db.query(`CREATE tax_adjustment_line:tax_adj_1 SET owned_by = groups:root,
      a_note = adjustment_note:note_1, a_target = tax_output:tax_1, a_delta = -1dec;`);
    const adjustedTaxLine = rows(await db.query("SELECT * FROM invoice_line:line_1;"))[0];
    assert.equal(String(adjustedTaxLine.d5_tax_amount), "8");
    assert.equal(String(adjustedTaxLine.d6_gross_amount), "58");
    await assert.rejects(
      db.query("UPDATE invoice_line:line_1 SET a_unit_price = 40dec;"),
      /OVER_SETTLED|settled|claim/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_unit_price FROM invoice_line:line_1;"))[0].a_unit_price), "50");
    await assert.rejects(
      db.query(`CREATE adjustment_note:wrong_org SET owned_by = groups:root,
        a_organization = organization:other, a_name = 'Wrong Org';
        CREATE tax_adjustment_line:tax_adj_wrong_org SET owned_by = groups:root,
          a_note = adjustment_note:wrong_org, a_target = tax_output:tax_1, a_delta = -1dec;`),
      /ADJUSTMENT_ORGANIZATION|organization/i,
    );

    await db.query(`CREATE money_refund:refund_revalidate SET owned_by = groups:root,
      a_original_payment = money_movement:pay_1, a_amount = 10dec,
      a_effective_at = d'2026-01-09T00:00:00Z', a_idempotency_key = 'refund-revalidate';`);
    await db.query("UPDATE money_adjustment_line:money_adj_1 SET a_delta = -20dec;");
    assert.equal(String(rows(await db.query("SELECT d4_net_amount FROM money_movement:pay_1;"))[0].d4_net_amount), "10");
    await assert.rejects(
      db.query("UPDATE money_adjustment_line:money_adj_1 SET a_delta = -25dec;"),
      /REFUND_EXCEEDS_PAYMENT|NET|refund|total_out|negative/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_delta FROM money_adjustment_line:money_adj_1;"))[0].a_delta), "-20");
    await db.query("DELETE money_refund:refund_revalidate; UPDATE money_adjustment_line:money_adj_1 SET a_delta = -5dec;");

    await db.query(`CREATE invoice:refund_invoice SET owned_by = groups:root,
      a_organization = organization:vendor, a_currency = currency:inr,
      a_direction = 'receivable', a_effective_at = d'2026-01-10T00:00:00Z';
      CREATE invoice_line:refund_line SET owned_by = groups:root,
        a_invoice = invoice:refund_invoice, a_subject = item:widget,
        a_quantity = 1dec, a_unit_price = 20dec;
      CREATE money_movement:pay_alloc SET owned_by = groups:root,
        a_from = organization:vendor, a_to = treasury_account:cash,
        a_currency = currency:inr, a_amount = 20dec,
        a_effective_at = d'2026-01-10T00:00:00Z', a_idempotency_key = 'pay-alloc';
      CREATE payment_application:app_alloc SET owned_by = groups:root,
        a_payment = money_movement:pay_alloc, a_invoice = invoice:refund_invoice,
        a_amount = 15dec, a_idempotency_key = 'application-alloc';
      CREATE money_refund:refund_alloc SET owned_by = groups:root,
        a_original_payment = money_movement:pay_alloc, a_amount = 5dec,
      a_effective_at = d'2026-01-11T00:00:00Z', a_idempotency_key = 'refund-alloc';`);
    await assert.rejects(
      db.query("UPDATE money_refund:refund_alloc SET a_amount = 6dec;"),
      /OVER_APPLIED|applied|refund|payment/i,
    );
    assert.equal(String(rows(await db.query("SELECT a_amount FROM money_refund:refund_alloc;"))[0].a_amount), "5");
    await assert.rejects(
      db.query(`CREATE payment_application:app_alloc_over SET owned_by = groups:root,
        a_payment = money_movement:pay_alloc, a_invoice = invoice:refund_invoice,
        a_amount = 6dec, a_idempotency_key = 'application-alloc-over';`),
      /OVER_APPLIED|OVER_SETTLED|applied|settled|refund/i,
    );

    await db.query(`CREATE service_capacity:context_cap SET owned_by = groups:root,
      a_operating_unit = operating_unit:warehouse, a_service = service:consulting,
      a_quantity = 1dec, a_effective_at = d'2026-01-08T00:00:00Z',
      a_idempotency_key = 'context-cap';
      CREATE service_delivery:context_delivery SET owned_by = groups:root,
        a_operating_unit = operating_unit:warehouse, a_service = service:consulting,
        a_quantity = 1dec, a_effective_at = d'2026-01-08T00:00:00Z',
        a_contexts = [organization:context], a_idempotency_key = 'context-delivery';`);
    await db.query("DELETE organization:context;");
    const contextDelivery = rows(await db.query("SELECT a_contexts FROM service_delivery:context_delivery;"))[0];
    assert.equal((contextDelivery.a_contexts || []).length, 0);
    await db.query("DELETE service_delivery:context_delivery; DELETE service_capacity:context_cap;");

    await assert.rejects(
      db.query("DELETE item:widget;"),
      /REFERENCE|referenced|REJECT|cannot delete/i,
    );

    await db.query(`CREATE adjustment_note:note_cascade SET owned_by = groups:root, a_name = 'Cascade';
      CREATE money_adjustment_line:money_adj_cascade SET owned_by = groups:root,
        a_note = adjustment_note:note_cascade, a_target = money_movement:pay_1, a_delta = 1dec;`);
    assert.equal(String(rows(await db.query("SELECT d4_net_amount FROM money_movement:pay_1;"))[0].d4_net_amount), "26");
    await db.query("DELETE adjustment_note:note_cascade;");
    assert.equal(rows(await db.query("SELECT id FROM money_adjustment_line WHERE id = money_adjustment_line:money_adj_cascade;"))[0], undefined);
    assert.equal(String(rows(await db.query("SELECT d4_net_amount FROM money_movement:pay_1;"))[0].d4_net_amount), "25");

    await db.query("CREATE invoice:locked SET owned_by = groups:root, a_organization = organization:vendor, a_currency = currency:inr, a_direction = 'receivable', a_effective_at = d'2026-01-08T00:00:00Z', a_locked = true;");
    await assert.rejects(
      db.query("CREATE invoice_line:locked_line SET owned_by = groups:root, a_invoice = invoice:locked, a_subject = item:widget, a_quantity = 1dec, a_unit_price = 1dec;"),
      /INVOICE_LOCKED|locked/i,
    );
    await db.query("CREATE adjustment_note:locked_note SET owned_by = groups:root, a_name = 'Locked', a_locked = true;");
    await assert.rejects(
      db.query("CREATE money_adjustment_line:locked_line SET owned_by = groups:root, a_note = adjustment_note:locked_note, a_target = money_movement:pay_1, a_delta = 1dec;"),
      /ADJUSTMENT_LOCKED|locked/i,
    );

    await db.query(`CREATE treasury_account:concurrent_cash SET owned_by = groups:root,
      a_name = 'Concurrent Cash', a_currency = currency:inr;
      CREATE money_opening_balance:concurrent_opening SET owned_by = groups:root,
        a_endpoint = treasury_account:concurrent_cash, a_currency = currency:inr,
        a_amount = 1000dec, a_effective_at = d'2026-01-01T00:00:00Z',
        a_idempotency_key = 'concurrent-opening';`);
    const sessions = await Promise.all(
      Array.from({ length: 8 }, () => openSession(server, namespace, database)),
    );
    try {
      await Promise.all(Array.from({ length: 24 }, (_, index) => {
        const id = `concurrent_${index + 1}`;
        return queryWithConflictRetry(
          sessions[index % sessions.length],
          `CREATE money_movement:${id} SET owned_by = groups:root,
            a_from = treasury_account:concurrent_cash, a_to = organization:vendor,
            a_currency = currency:inr, a_amount = 1dec,
            a_effective_at = d'2026-02-01T00:00:00Z',
            a_idempotency_key = '${id}';`,
        );
      }));
    } finally {
      await Promise.all(sessions.map((session) => session.close().catch(() => {})));
    }
    const concurrentPosition = rows(await db.query("SELECT * FROM money_position WHERE endpoint = treasury_account:concurrent_cash;"))[0];
    assert.equal(String(concurrentPosition.balance), "976");
    const concurrentRows = rows(await db.query("SELECT a_idempotency_key FROM money_movement;"))
      .filter((row) => String(row.a_idempotency_key).startsWith("concurrent_"));
    assert.equal(concurrentRows.length, 24);

    const info = finalResult(await db.query("INFO FOR DB;"));
    assert(Object.hasOwn(info.tables, "money_position"));
    assert(Object.hasOwn(info.tables, "invoice_line"));
    console.log("accounts: all-in-one schema, same-currency movements, FX exchanges, mutable deltas, position guards, service capacity, and settlement caps passed");
  } finally {
    await db.close().catch(() => {});
    fs.rmSync(compiled.output, { recursive: true, force: true });
    await stopServer(server);
  }
}

if (require.main === module) {
  main().then(() => process.exit(0), (error) => {
    console.error(`accounts: FAIL: ${error.stack || error.message}`);
    process.exit(1);
  });
}

module.exports = { main };
