const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createRuntime } = require("../gateway/runtime");
const { createWebhookRouteCodec } = require("../gateway/webhook-routes");

function createHarness({ failCommit = false, loseCommitResponse = false, queueDown = true, queuePort } = {}) {
  const route = {
    provider: "razorpay",
    namespace: "test",
    database: "webhook_inbox_probe",
    config: "razorpay_config:probe",
    id: "razorpay_order:probe",
  };
  const routeCodec = createWebhookRouteCodec("webhook-inbox-probe-secret");
  const capsule = routeCodec.seal(route);
  const persisted = new Map([
    [route.config, { id: route.config }],
    [route.id, {
      id: route.id,
      config: route.config,
      provider_order_id: "order_probe",
      amount_paise: 125,
      currency: "INR",
    }],
  ]);
  const calls = [];
  const selectedContexts = [];
  const store = {
    async load(id) { return persisted.get(String(id)) || null; },
    async execute(_query, variables) {
      return [...persisted.values()].filter((record) => record.id?.startsWith("razorpay_order:")
        && record.config === variables.config_id
        && record.provider_order_id === variables.provider_order_id);
    },
    async createWebhookReceipt(id, input) {
      calls.push("commit-start");
      if (failCommit) throw new Error("simulated receipt commit failure");
      const receipt = {
        id: String(id),
        ...input,
        execution_id: crypto.randomUUID(),
        revision: crypto.randomUUID(),
        rebase_outcome: undefined,
        rebase_cancel_requested: false,
      };
      persisted.set(String(id), receipt);
      calls.push("commit-complete");
      if (loseCommitResponse) throw new Error("simulated lost receipt commit response");
      return receipt;
    },
  };
  const contract = {
    mode: "queued",
    process: "async",
    events: ["CREATE"],
    patchFields: ["applied_at"],
    inputFields: [],
    references: [],
  };
  const handlers = {
    contracts: new Map([["rebase_webhook_receipt", contract]]),
    get(table) {
      return table === "rebase_webhook_receipt"
        ? { contract, async execute() { return { outcome: "success" }; } }
        : null;
    },
  };
  const webhookHandler = {
    validate({ record, verified }) {
      if (verified.order.id !== record.provider_order_id
        || verified.payment.orderId !== verified.order.id
        || verified.order.amount !== record.amount_paise
        || verified.payment.amount !== record.amount_paise
        || verified.order.currency !== record.currency
        || verified.payment.currency !== record.currency) {
        throw Object.assign(new Error("correlation mismatch"), { code: "CORRELATION_MISMATCH", status: 400 });
      }
    },
    on: { "order.paid": async () => ({ outcome: "success" }) },
  };
  const webhooks = { providers: ["razorpay"], get(provider, event) {
    return provider === "razorpay" && event === "order.paid" ? webhookHandler : null;
  } };
  const testQueue = {
    async publish(envelope) {
      calls.push(`publish:${envelope.kind}`);
      if (queueDown) throw new Error("simulated queue outage");
      return { queued: true };
    },
  };
  const adapter = {
    async extractRoute({ request }) { return request.capsule; },
    async verify({ request }) {
      return {
        event: "order.paid",
        eventId: request.eventId || "probe-event-1",
        order: { id: "order_probe", amount: 125, currency: "INR" },
        payment: { id: "payment_probe", orderId: "order_probe", amount: 125, currency: "INR" },
      };
    },
  };
  const runtime = createRuntime({
    stores: { async forContext(namespace, database) {
      selectedContexts.push([namespace, database]);
      return store;
    } },
    queue: queuePort || testQueue,
    handlers,
    webhooks,
    webhookAdapters: { razorpay: adapter },
    routeCodec,
    options: { allowedContexts: [route] },
  });
  return { runtime, route, routeCodec, capsule, calls, persisted, selectedContexts };
}

async function main() {
  const outage = createHarness();
  const accepted = await outage.runtime.webhook({
    provider: "razorpay",
    request: { capsule: outage.capsule },
    rawBody: Buffer.from('{"event":"order.paid"}'),
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.duplicate, false);
  assert.equal(accepted.queued, false);
  assert.equal(outage.calls[0], "commit-start");
  assert.equal(outage.calls[1], "commit-complete");
  assert.equal(outage.calls[2], "publish:receipt");
  assert(outage.persisted.get(accepted.receiptId));

  const lostResponse = createHarness({ loseCommitResponse: true, queueDown: false });
  const recoveredCommit = await lostResponse.runtime.webhook({
    provider: "razorpay",
    request: { capsule: lostResponse.capsule },
    rawBody: Buffer.from('{"event":"order.paid"}'),
  });
  assert.equal(recoveredCommit.accepted, true);
  assert.equal(recoveredCommit.duplicate, true);
  assert.equal(recoveredCommit.queued, true);
  assert.equal(lostResponse.calls[0], "commit-start");
  assert.equal(lostResponse.calls[1], "commit-complete");
  assert.equal(lostResponse.calls[2], "publish:receipt");
  assert(lostResponse.persisted.get(recoveredCommit.receiptId));

  const contextCount = outage.selectedContexts.length;
  const foreignCapsule = outage.routeCodec.seal({ ...outage.route, namespace: "foreign" });
  await assert.rejects(() => outage.runtime.webhook({
    provider: "razorpay",
    request: { capsule: foreignCapsule },
    rawBody: Buffer.from('{"event":"order.paid"}'),
  }), (error) => error.code === "CONTEXT_NOT_ALLOWED");
  assert.equal(outage.selectedContexts.length, contextCount,
    "a foreign route context must be rejected before selecting its database");
  await assert.rejects(() => outage.runtime.webhook({
    provider: "unknown-provider",
    request: { capsule: outage.capsule },
    rawBody: Buffer.from("{}"),
  }), (error) => error.code === "WEBHOOK_PROVIDER_NOT_FOUND");

  const failedCommit = createHarness({ failCommit: true });
  await assert.rejects(() => failedCommit.runtime.webhook({
    provider: "razorpay",
    request: { capsule: failedCommit.capsule },
    rawBody: Buffer.from('{"event":"order.paid"}'),
  }), /simulated receipt commit failure/);
  assert.deepEqual(failedCommit.calls, ["commit-start"]);
  assert.equal(failedCommit.persisted.size, 2);

  const configuredRoute = createHarness({ queueDown: false });
  const route = await configuredRoute.runtime.createWebhookRoute({
    provider: "razorpay",
    namespace: configuredRoute.route.namespace,
    database: configuredRoute.route.database,
    config: configuredRoute.route.config,
  });
  const routed = await configuredRoute.runtime.webhook({
    provider: "razorpay",
    routeCapsule: route.capsule,
    request: {},
    rawBody: Buffer.from('{"event":"order.paid"}'),
  });
  assert.equal(routed.accepted, true);
  assert.equal(configuredRoute.persisted.get(routed.receiptId).target_id, configuredRoute.route.id,
    "config-bound callback must resolve and persist the local order identity");
  await assert.rejects(() => configuredRoute.runtime.webhook({
    provider: "razorpay",
    routeCapsule: `${route.capsule}tampered`,
    request: {},
    rawBody: Buffer.from('{"event":"order.paid"}'),
  }), (error) => error.code === "INVALID_WEBHOOK_ROUTE");

  console.log("webhook inbox: receipt recovery, config-bound route resolution, tamper rejection, unknown providers, and foreign contexts passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`webhook inbox: FAIL: ${error.stack || error}`);
  process.exit(1);
});

module.exports = { createHarness, main };
