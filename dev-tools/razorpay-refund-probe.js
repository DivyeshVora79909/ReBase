#!/usr/bin/env node

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const net = require("node:net");
const { spawn } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { queryResult } = require("../gateway/utils");
const handler = require("../designs/test/webhook-handlers/razorpay");

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

async function main() {
  const port = await freePort();
  const namespace = `refund_probe_${Date.now().toString(36)}`;
  const database = "probe";
  const child = spawn("surreal", [
    "start", "memory", "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--async-event-interval", "25ms", "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "ignore"] });
  const db = new Surreal();
  try {
    await waitForPort(port, child);
    await db.connect(`ws://127.0.0.1:${port}/rpc`);
    await db.signin({ username: "root", password: "root" });
    await db.query(`DEFINE NAMESPACE ${namespace};`);
    await db.use({ namespace });
    await db.query(`DEFINE DATABASE ${database};`);
    await db.use({ namespace, database });
    for (const table of ["razorpay_order", "razorpay_payment", "rebase_webhook_receipt"]) {
      await db.query(`DEFINE TABLE ${table} SCHEMALESS;`);
    }

    const paymentId = "pay_refund_probe";
    const orderId = "razorpay_order:order";
    const record = {
      id: orderId,
      provider_order_id: "order_provider_probe",
      owned_by: "rebase_group:root",
      amount_paise: 100,
      currency: "INR",
    };
    const store = { execute: (statement, variables) => db.query(statement, variables).then(queryResult) };
    const apply = async ({ event, status, eventAt, refundAmount = null, amountRefunded = 0, refundId = null }) => {
      const eventId = crypto.randomUUID();
      const receipt = {
        id: `rebase_webhook_receipt:${crypto.randomUUID()}`,
        provider_account_id: "razorpay:razorpay_config:probe",
        event_id: eventId,
        payload_hash: crypto.randomUUID(),
        rebase_lease_token: crypto.randomUUID(),
        rebase_lease_until: new Date(Date.now() + 60000).toISOString(),
        execution_id: crypto.randomUUID(),
        revision: crypto.randomUUID(),
      };
      await db.query(`CREATE ONLY type::record($id) SET
        provider_account_id = $account, event_id = $event, payload_hash = $hash,
        rebase_lease_token = type::uuid($lease), rebase_lease_until = type::datetime($until),
        execution_id = type::uuid($execution), revision = type::uuid($revision);`, {
        id: receipt.id,
        account: receipt.provider_account_id,
        event: receipt.event_id,
        hash: receipt.payload_hash,
        lease: receipt.rebase_lease_token,
        until: receipt.rebase_lease_until,
        execution: receipt.execution_id,
        revision: receipt.revision,
      });
      const verified = {
        event,
        createdAt: eventAt,
        payment: {
          id: paymentId,
          orderId: "order_provider_probe",
          amount: 100,
          currency: "INR",
          status,
          method: "card",
          createdAt: eventAt,
          amountRefunded,
          errorCode: null,
          errorDescription: null,
        },
        refund: refundId ? {
          id: refundId,
          paymentId,
          amount: refundAmount,
          currency: "INR",
          status: "processed",
          createdAt: eventAt,
        } : null,
      };
      const input = {
        route: { id: orderId, namespace, database, config: "razorpay_config:probe" },
        record,
        verified,
        receipt,
        store,
      };
      if (event === "refund.processed") handler.validate(input);
      const applyEvent = event === "refund.processed" ? "refund.processed" : "payment.captured";
      await handler.on[applyEvent]({ ...input, orderPaid: false });
      return queryResult(await db.query(
        "SELECT status, amount_refunded_paise FROM razorpay_payment WHERE provider_payment_id = $id;",
        { id: paymentId },
      ))[0];
    };

    const now = Date.now();
    assert.deepEqual(await apply({
      event: "payment.captured", status: "captured", eventAt: new Date(now).toISOString(),
    }), { status: "captured", amount_refunded_paise: 0 });
    assert.deepEqual(await apply({
      event: "refund.processed", status: "captured", eventAt: new Date(now + 2000).toISOString(),
      refundAmount: 40, amountRefunded: 40, refundId: "rfnd_partial_probe",
    }), { status: "captured", amount_refunded_paise: 40 });
    assert.deepEqual(await apply({
      event: "refund.processed", status: "captured", eventAt: new Date(now + 1000).toISOString(),
      refundAmount: 20, amountRefunded: 20, refundId: "rfnd_stale_probe",
    }), { status: "captured", amount_refunded_paise: 40 }, "older cumulative refund snapshots cannot lower totals");
    assert.deepEqual(await apply({
      event: "refund.processed", status: "captured", eventAt: new Date(now + 3000).toISOString(),
      refundAmount: 60, amountRefunded: 100, refundId: "rfnd_final_probe",
    }), { status: "refunded", amount_refunded_paise: 100 });
    assert.deepEqual(await apply({
      event: "payment.captured", status: "captured", eventAt: new Date(now + 1500).toISOString(),
    }), { status: "refunded", amount_refunded_paise: 100 }, "delayed captures cannot reverse a full refund");
    process.stdout.write("Razorpay refund SQL: partial, cumulative, stale-snapshot, and full-refund guards passed\n");
  } finally {
    await db.close().catch(() => {});
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await new Promise((resolve) => child.once("exit", resolve));
    }
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`Razorpay refund SQL: FAIL: ${error.stack || error}`);
  process.exitCode = 1;
});

module.exports = { main };
