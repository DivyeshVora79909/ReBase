#!/usr/bin/env node

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { spawn, spawnSync } = require("node:child_process");
const { createServer } = require("node:http");
const { Surreal } = require("surrealdb");
const { createAuthenticationService } = require("../gateway/authentication");
const { createAuthenticationPayloadCipher } = require("../gateway/authentication-payload");
const { createRuntimeApp } = require("../gateway/app");
const { connectDatabase } = require("../gateway/connection");
const { createStoreDirectory, fixedStoreDirectory } = require("../gateway/directory");
const { loadTableHandlers } = require("../gateway/handlers");
const { createWebhookRouteCodec } = require("../gateway/webhook-routes");
const { loadWebhookHandlers } = require("../gateway/webhooks");
const { createWebhookAdapters } = require("../gateway/providers");
const { createMockOAuthAdapter, createOAuthVerifier } = require("../gateway/oauth");
const { createMemoryRateLimiter, createRedisRateLimiter } = require("../gateway/rate-limit");
const { createBullMqPort } = require("../gateway/queues/bullmq");
const { createRuntime } = require("../gateway/runtime");
const providerReceiptOperation = require("../gateway/operations/provider-receipt");
const { startServer } = require("../gateway/server");
const { createTableStore } = require("../gateway/store");
const { operationEnvelope } = require("../gateway/queues/port");
const { queryResult } = require("../gateway/utils");
const { createHarness: createWebhookInboxHarness } = require("./webhook-inbox-probe");
const { loadMaterials } = require("./compiler/materials");
const { runLifecycleMigration } = require("./lifecycle-migration");
const { generateBundle } = require("./compiler/pipeline");
const {
  generateLifecycleFields,
  generateLifecycleMigration,
  generateOperationEvents,
  generateRuntimeContracts,
} = require("../src/generators/effects");
const { parseSchema } = require("../src/schema");

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function listenHandler(handler, { hostname = "127.0.0.1", port = 0 } = {}) {
  const server = createServer(handler);
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, hostname);
  });
  const address = server.address();
  const baseUrl = `http://${hostname}:${address.port}`;
  return {
    server,
    baseUrl,
    fetch(input, init) {
      const target = new URL(input, "http://runtime.local");
      return fetch(`${baseUrl}${target.pathname}${target.search}`, init);
    },
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    },
  };
}

async function requestHandler(handler, input, init) {
  const local = await listenHandler(handler);
  try {
    return await local.fetch(input, init);
  } finally {
    await local.close();
  }
}

async function waitForPort(port, child, label) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`${label} exited before becoming ready`);
    const connected = await new Promise((resolve) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`${label} did not become ready`);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 2000))]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function waitForExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null) return child.exitCode;
  if (child.signalCode !== null) return child.signalCode;
  const exited = once(child, "exit").then(([code, signal]) => code ?? signal);
  if (child.exitCode !== null) return child.exitCode;
  if (child.signalCode !== null) return child.signalCode;
  let timer;
  try {
    return await Promise.race([
      exited,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(
          `Child process ${child.spawnfile} (pid ${child.pid}) did not exit; code=${child.exitCode}, signal=${child.signalCode}, killed=${child.killed}`,
        )), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function startRedis({ port: requestedPort, directory: requestedDirectory } = {}) {
  const port = requestedPort || await freePort();
  const directory = requestedDirectory || fs.mkdtempSync(path.join(os.tmpdir(), "rebase-redis-"));
  const child = spawn("redis-server", [
    "--bind", "127.0.0.1", "--port", String(port), "--save", "", "--appendonly", "no", "--dir", directory,
  ], { stdio: ["ignore", "ignore", "ignore"] });
  await waitForPort(port, child, "Redis");
  return { child, directory, port, url: `redis://127.0.0.1:${port}` };
}

async function startDatabase(runtimePort) {
  const port = await freePort();
  const child = spawn("surreal", [
    "start", "memory", "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--async-event-interval", "25ms",
    "--allow-net", `127.0.0.1:${runtimePort}`, "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "ignore"] });
  await waitForPort(port, child, "SurrealDB");
  const endpoint = `ws://127.0.0.1:${port}/rpc`;
  const namespace = `runtime_${Date.now().toString(36)}`;
  const database = "probe";
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.query(`DEFINE NAMESPACE ${namespace}; USE NS ${namespace}; DEFINE DATABASE ${database}; USE DB ${database};`);
  await db.use({ namespace, database });
  return { child, database, db, endpoint, namespace };
}

async function waitFor(check, message, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await check();
    if (last) return last;
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  const resolvedMessage = typeof message === "function" ? message() : message;
  throw new Error(`${resolvedMessage}${last ? `: ${JSON.stringify(last)}` : ""}`);
}

async function waitForMessage(messages, previousCount, label) {
  return waitFor(
    () => messages.length > previousCount ? messages.at(-1) : null,
    label,
  );
}

function recordId(record) {
  assert(record?.id, "Created record is missing an ID");
  return String(record.id);
}

async function createAndReload(db, table, assignments, variables = {}) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new Error(`Invalid probe table: ${table}`);
  return queryResult(await db.query(`
    LET $created = CREATE ONLY ${table} SET ${assignments};
    RETURN (SELECT * FROM $created.id)[0];
  `, variables));
}

async function createId(db, table, assignments, variables = {}) {
  return recordId(await createAndReload(db, table, assignments, variables));
}

async function passwordSignin(endpoint, namespace, database, identifier, password, access = "account_password", variables = {}) {
  const client = new Surreal();
  await client.connect(endpoint);
  try {
    const token = await client.signin({
      namespace,
      database,
      access,
      variables: access === "account_password"
        ? { identifier, password, ...variables }
        : variables,
    });
    return { client, token };
  } catch (error) {
    if (process.env.REBASE_RUNTIME_PROBE_DEBUG) {
      console.error("record signin failed", { access, variableNames: Object.keys(access === "account_password" ? { identifier, password, ...variables } : variables) });
    }
    await client.close();
    throw error;
  }
}

async function adapterScopeProbe() {
  const contract = {
    process: "sync",
    events: ["CREATE"],
    timeoutMs: 1000,
    inputFields: ["payload"],
    optionalInputs: [],
    patchFields: [],
    references: [],
    adapters: ["sendBrevoEmail"],
  };
  let receivedAdapters;
  const handler = {
    process: "sync",
    timeoutMs: 1000,
    contract,
    on: {
      async CREATE(input) {
        receivedAdapters = Object.keys(input.adapters);
        return { outcome: "success", patch: {} };
      },
    },
  };
  const handlers = {
    contracts: new Map([["scope_probe", contract]]),
    tables: ["scope_probe"],
    get(table) { return table === "scope_probe" ? handler : null; },
  };
  const stores = {
    async forContext() { return { async load() { return null; } }; },
  };
  const options = { allowedContexts: [{ namespace: "scope", database: "probe" }] };
  const snapshot = { id: "scope_probe:one", payload: "value" };
  const runtime = createRuntime({
    handlers,
    stores,
    contracts: handlers.contracts,
    adapters: { sendBrevoEmail: async () => {}, deleteS3Object: async () => {} },
    options,
  });
  assert.equal((await runtime.sync({
    namespace: "scope", database: "probe", id: snapshot.id,
    event: "CREATE", before: null, after: snapshot,
  })).outcome, "success");
  assert.deepEqual(receivedAdapters, ["sendBrevoEmail"]);
  const missing = createRuntime({
    handlers, stores, contracts: handlers.contracts, adapters: {}, options,
  });
  await assert.rejects(
    missing.sync({
      namespace: "scope", database: "probe", id: snapshot.id,
      event: "CREATE", before: null, after: snapshot,
    }),
    (error) => error.code === "ADAPTER_NOT_FOUND",
  );
}

async function admissionProbe(redisUrl) {
  const prefix = `rebase-admission-probe-${crypto.randomUUID()}`;
  const portOptions = {
    url: redisUrl,
    prefix,
    admission: { maxLiveHints: 3, receiptReserve: 1 },
  };
  const ports = [createBullMqPort(portOptions), createBullMqPort(portOptions)];
  const [port, peer] = ports;
  const operation = (id) => operationEnvelope(
    { namespace: "tenant", database: "admission", id: `queued_probe:${id}` },
    { execution_id: crypto.randomUUID(), revision: crypto.randomUUID() },
  );
  try {
    const concurrent = await Promise.all(Array.from({ length: 16 }, (_, index) =>
      ports[index % ports.length].publish(operation(`concurrent-${index}`))));
    assert.equal(concurrent.filter((result) => result.queued === true).length, 2);
    assert.equal(concurrent.filter((result) => result.state === "capacity").length, 14);
    const webhookHarness = createWebhookInboxHarness({ queuePort: peer, queueDown: false });
    const acceptedWebhook = await webhookHarness.runtime.webhook({
      provider: "razorpay",
      request: { capsule: webhookHarness.capsule },
      rawBody: Buffer.from('{"event":"order.paid"}'),
    });
    assert.equal(acceptedWebhook.accepted, true);
    assert.equal(acceptedWebhook.queued, true,
      "receipt admission must use the queue's reserved capacity under operation saturation");
    assert.equal((await port.publish(operation("reserve-protected"))).state, "capacity");
    const jobs = await port.queue.getJobs(["wait", "paused", "prioritized", "delayed"]);
    assert.equal(jobs.length, 3);
    assert(jobs.some((job) => job.data?.kind === "receipt"
      && job.data?.locator?.id === acceptedWebhook.receiptId));
    const saturatedWebhookHarness = createWebhookInboxHarness({ queuePort: peer, queueDown: false });
    const acceptedAtCapacity = await saturatedWebhookHarness.runtime.webhook({
      provider: "razorpay",
      request: { capsule: saturatedWebhookHarness.capsule, eventId: "probe-event-at-capacity" },
      rawBody: Buffer.from('{"event":"order.paid","eventId":"at-capacity"}'),
    });
    assert.equal(acceptedAtCapacity.accepted, true);
    assert.equal(acceptedAtCapacity.queued, false,
      "a full queue must leave the receipt durable and report that it was not published");
    assert(saturatedWebhookHarness.persisted.get(acceptedAtCapacity.receiptId));
    assert.equal((await port.queue.getJobs(["wait", "paused", "prioritized", "delayed"])).length, 3);
    await Promise.all(jobs.map((job) => job.remove()));
    const recoveredReceipt = await saturatedWebhookHarness.runtime.enqueue({
      namespace: saturatedWebhookHarness.route.namespace,
      database: saturatedWebhookHarness.route.database,
      id: acceptedAtCapacity.receiptId,
    });
    assert.equal(recoveredReceipt.queued, true,
      "a committed receipt rejected at queue capacity must be publishable after recovery");
    assert.equal((await port.publish(operation("after-recovery"))).queued, true);
  } finally {
    await Promise.all(ports.map((item) => item.close()));
  }
}

async function persistentReceiptAdmissionProbe({
  state,
  store,
  contracts,
  webhooks,
  webhookAdapters,
  routeCodec,
  razorpayOrder,
  razorpayRoute,
  webhookSecret,
}) {
  const isolatedRedis = await startRedis();
  let isolatedRedisChild = isolatedRedis.child;
  const prefix = `rebase-persistent-receipt-admission-${crypto.randomUUID()}`;
  const queue = createBullMqPort({
    url: isolatedRedis.url,
    prefix,
    admission: { maxLiveHints: 3, receiptReserve: 1 },
    redisOptions: { enableOfflineQueue: false },
  });
  const contract = contracts.get("rebase_webhook_receipt");
  const receiptContracts = new Map([["rebase_webhook_receipt", contract]]);
  const receiptHandlers = {
    contracts: receiptContracts,
    tables: ["rebase_webhook_receipt"],
    get(table) { return table === "rebase_webhook_receipt" ? providerReceiptOperation : null; },
  };
  let cursor = {
    version: 0,
    cursors: {},
    high_water: {},
    retention_cursors: {},
    retention_high_water: {},
    table_offset: 0,
  };
  const scanStore = {
    ...store,
    async loadReconciliationCursor() { return structuredClone(cursor); },
    async compareAndSetReconciliationCursor(input) {
      if (Number(input.expectedVersion) !== cursor.version) return false;
      cursor = {
        version: cursor.version + 1,
        cursors: input.cursors,
        high_water: input.highWater,
        retention_cursors: input.retentionCursors,
        retention_high_water: input.retentionHighWater,
        table_offset: input.tableOffset,
      };
      return true;
    },
  };
  const runtime = createRuntime({
    stores: { async forContext() { return scanStore; } },
    queue,
    handlers: receiptHandlers,
    webhooks,
    webhookAdapters,
    contracts: receiptContracts,
    routeCodec,
    options: {
      allowedContexts: [{ namespace: state.namespace, database: state.database }],
      reconcilePageSize: 10,
    },
  });
  const createdAt = Math.floor(Date.now() / 1000);
  const rawBody = Buffer.from(JSON.stringify({
    event: "order.paid",
    created_at: createdAt,
    payload: {
      order: { entity: {
        id: razorpayOrder.provider_order_id,
        amount: razorpayOrder.amount_paise,
        currency: razorpayOrder.currency,
        status: "paid",
        notes: { rebase_route: razorpayRoute },
        created_at: createdAt,
      } },
      payment: { entity: {
        id: "pay_persistent_admission_probe",
        order_id: razorpayOrder.provider_order_id,
        amount: razorpayOrder.amount_paise,
        currency: razorpayOrder.currency,
        status: "captured",
        created_at: createdAt,
      } },
    },
  }));
  const sign = (eventId) => ({
    headers: new Headers({
      "x-razorpay-event-id": eventId,
      "x-razorpay-signature": crypto.createHmac("sha256", webhookSecret).update(rawBody).digest("hex"),
    }),
  });
  const submit = (eventId) => runtime.webhook({
    provider: "razorpay",
    request: sign(eventId),
    rawBody,
  });
  const operation = (id) => operationEnvelope(
    { namespace: "tenant", database: "persistent-admission", id: `queued_probe:${id}` },
    { execution_id: crypto.randomUUID(), revision: crypto.randomUUID() },
  );
  const receiptIds = [];
  try {
    await waitFor(async () => (await queue.health()).ok,
      "persistent receipt queue did not become ready");
    await Promise.all([
      queue.publish(operation("normal-1")),
      queue.publish(operation("normal-2")),
    ]);
    const reserved = await submit("persistent-admission-reserved");
    assert.equal(reserved.accepted, true);
    assert.equal(reserved.queued, true);
    receiptIds.push(reserved.receiptId);
    assert.equal((await store.load(reserved.receiptId))?.rebase_outcome, undefined);
    const atCapacity = await submit("persistent-admission-at-capacity");
    assert.equal(atCapacity.accepted, true);
    assert.equal(atCapacity.queued, false);
    receiptIds.push(atCapacity.receiptId);
    assert(await store.load(atCapacity.receiptId), "the full-queue callback must be durably stored");
    assert.equal((await queue.queue.getJobs(["wait", "paused", "prioritized", "delayed"])).length, 3);

    const beforeCleanup = await queue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]);
    await Promise.all(beforeCleanup.map((job) => job.remove()));
    const recovered = await runtime.reconcile({ namespace: state.namespace, database: state.database });
    assert(recovered.queuedIds.includes(atCapacity.receiptId),
      `bounded reconciliation must rediscover the committed receipt from SurrealDB: ${JSON.stringify({ recovered, receipt: await store.load(atCapacity.receiptId) })}`);
    assert.equal((await queue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]))
      .some((job) => job.data?.locator?.id === atCapacity.receiptId), true);

    const recoveredJobs = await queue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]);
    await Promise.all(recoveredJobs.map((job) => job.remove()));
    await stopChild(isolatedRedisChild);
    const outage = await submit("persistent-admission-redis-outage");
    assert.equal(outage.accepted, true,
      "a Redis outage after receipt commit must not reject the verified callback");
    assert.equal(outage.queued, false,
      "an unavailable Redis queue must be reported as unqueued");
    receiptIds.push(outage.receiptId);
    assert(await store.load(outage.receiptId),
      "the Redis-outage callback must have a durable SurrealDB receipt");

    isolatedRedisChild = (await startRedis({
      port: isolatedRedis.port,
      directory: isolatedRedis.directory,
    })).child;
    await waitFor(async () => (await queue.health()).ok,
      "receipt queue did not reconnect after the Redis outage");
    let outageRecovery = null;
    for (let attempt = 0; attempt < 4 && !outageRecovery; attempt += 1) {
      const page = await runtime.reconcile({ namespace: state.namespace, database: state.database });
      if (page.queuedIds.includes(outage.receiptId)) outageRecovery = page;
    }
    assert(outageRecovery,
      "bounded SurrealDB reconciliation must republish a receipt accepted during Redis outage");
    assert((await queue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]))
      .some((job) => job.data?.locator?.id === outage.receiptId));
  } finally {
    const jobs = await queue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]).catch(() => []);
    await Promise.all(jobs.map((job) => job.remove().catch(() => {})));
    await Promise.all(receiptIds.map((id) => store.execute("DELETE type::record($id);", { id }).catch(() => {})));
    await queue.close();
    await stopChild(isolatedRedisChild);
    fs.rmSync(isolatedRedis.directory, { recursive: true, force: true });
  }
}

async function oneShotMigrationProbe(endpoint, { restartAfterFirstBatch } = {}) {
  let client = new Surreal();
  await client.connect(endpoint);
  await client.signin({ username: "root", password: "root" });
  const namespace = `migration_${Date.now().toString(36)}`;
  const database = "probe";
  try {
    await client.query(`DEFINE NAMESPACE ${namespace}; USE NS ${namespace}; DEFINE DATABASE ${database}; USE DB ${database};`);
    await client.use({ namespace, database });
    await client.query(`
      DEFINE TABLE migration_probe SCHEMAFULL;
      DEFINE FIELD payload ON migration_probe TYPE string;
      DEFINE FIELD schedule ON migration_probe TYPE option<object> FLEXIBLE DEFAULT NONE;
      DEFINE FIELD rebase_schedule_next_at ON migration_probe TYPE option<datetime> DEFAULT NONE;
      DEFINE FIELD rebase_schedule_index ON migration_probe TYPE option<int> DEFAULT NONE;
      DEFINE FIELD rebase_schedule_finished_at ON migration_probe TYPE option<datetime> DEFAULT NONE;
      DEFINE FIELD rebase_cancel_requested ON migration_probe TYPE bool DEFAULT false;
      DEFINE FIELD rebase_lease_token ON migration_probe TYPE option<uuid> DEFAULT NONE;
      DEFINE FIELD rebase_lease_until ON migration_probe TYPE option<datetime> DEFAULT NONE;
      DEFINE FIELD rebase_outcome ON migration_probe TYPE option<string> DEFAULT NONE;
      DEFINE FIELD rebase_wake_at ON migration_probe TYPE option<datetime> DEFAULT NONE;
      DEFINE FIELD rebase_finished_at ON migration_probe TYPE option<datetime> DEFAULT NONE;
      DEFINE FIELD rebase_error ON migration_probe TYPE option<object> FLEXIBLE DEFAULT NONE;
      DEFINE INDEX idx_migration_probe_rebase_schedule_next_at ON migration_probe FIELDS rebase_schedule_next_at;
      CREATE ONLY migration_probe:scheduled SET payload = 'scheduled',
        schedule = { cron: '0 * * * *', repeat: 2 },
        rebase_schedule_next_at = time::now() + 3m,
        rebase_schedule_index = 4;
      CREATE ONLY migration_probe:active SET payload = 'active',
        rebase_cancel_requested = true,
        rebase_lease_token = rand::uuid::v7(),
        rebase_lease_until = time::now() + 1m;
    `);
    const extraLegacyRows = 2003;
    for (let offset = 0; offset < extraLegacyRows; offset += 250) {
      const end = Math.min(extraLegacyRows, offset + 250);
      const creates = Array.from({ length: end - offset }, (_, index) => {
        const id = `zzz_bulk_${String(offset + index).padStart(4, "0")}`;
        return `CREATE ONLY migration_probe:${id} SET payload = 'bulk';`;
      });
      await client.query(creates.join("\n"));
    }
    const legacyNextAt = queryResult(await client.query("RETURN migration_probe:scheduled.rebase_schedule_next_at;"));
    const migrationSchema = parseSchema(`
      DEFINE TABLE migration_probe SCHEMAFULL COMMENT '@rebase-effect async';
      DEFINE FIELD payload ON migration_probe TYPE string COMMENT '@rebase-effect-input';
    `, "");
    const migration = generateLifecycleMigration(migrationSchema, { namespace, database });
    await client.query(generateLifecycleFields(migrationSchema));
    await assert.rejects(client.query(migration.finalize), /REBASE_ONE_SHOT_BACKFILL_INCOMPLETE/);
    const beforeBackfillInfo = queryResult(await client.query("INFO FOR TABLE migration_probe;"));
    assert(beforeBackfillInfo.fields.schedule, "finalizer must preserve legacy fields while any row is unbackfilled");
    const firstBatch = queryResult(await client.query(migration.backfill));
    assert.deepEqual(firstBatch, { table: "migration_probe", processed: 1000 });
    const scheduled = queryResult(await client.query("RETURN (SELECT * FROM migration_probe:scheduled)[0];"));
    const active = queryResult(await client.query("RETURN (SELECT * FROM migration_probe:active)[0];"));
    assert.match(String(scheduled.execution_id), /^[0-9a-f-]{36}$/i);
    assert.match(String(scheduled.revision), /^[0-9a-f-]{36}$/i);
    assert.equal(scheduled.priority, 50);
    assert.equal(scheduled.rebase_attempt, 0);
    assert.equal(Math.abs(new Date(scheduled.execute_at).getTime() - new Date(legacyNextAt).getTime()) < 1000, true);
    assert.equal(scheduled.schedule, undefined);
    assert.equal(scheduled.rebase_schedule_next_at, undefined);
    assert.equal(active.rebase_outcome, "ambiguous");
    assert.equal(active.rebase_cancel_requested, true);
    assert.equal(active.rebase_attempt, 1);
    assert(Math.abs(Date.now() - new Date(active.execute_at).getTime()) < 2000);
    assert.equal(active.rebase_lease_token, undefined);
    assert.equal(active.rebase_status, "ambiguous");
    if (restartAfterFirstBatch) {
      await client.close();
      await restartAfterFirstBatch();
      client = new Surreal();
      await client.connect(endpoint);
      await client.signin({ username: "root", password: "root" });
      await client.use({ namespace, database });
      assert.match(String(queryResult(await client.query(
        "RETURN (SELECT * FROM migration_probe:scheduled)[0].execution_id;",
      ))), /^[0-9a-f-]{36}$/i, "the first committed batch must survive a database-process restart");
      assert.equal(queryResult(await client.query(
        "RETURN (SELECT * FROM migration_probe:zzz_bulk_2002)[0].execution_id;",
      )), undefined, "rows beyond the first batch must still need migration after restart");
    }
    assert.equal(queryResult(await client.query("RETURN (SELECT * FROM migration_probe:zzz_bulk_2002)[0].execution_id;")), undefined);
    const migrationPasses = [];
    const migrationRun = await runLifecycleMigration({
      db: client,
      backfillSql: migration.backfill,
      finalizeSql: migration.finalize,
      maxPasses: 5,
      onPass({ reports }) {
        migrationPasses.push(reports[0].processed);
      },
    });
    assert.deepEqual(migrationPasses, [1000, 5, 0]);
    assert.equal(migrationRun.complete, true);
    assert.equal(migrationRun.passes, 3);
    const finalBulkRow = queryResult(await client.query("RETURN (SELECT * FROM migration_probe:zzz_bulk_2002)[0];"));
    assert.match(String(finalBulkRow.execution_id), /^[0-9a-f-]{36}$/i);
    assert.match(String(finalBulkRow.revision), /^[0-9a-f-]{36}$/i);
    const tableInfo = queryResult(await client.query("INFO FOR TABLE migration_probe;"));
    assert.equal(tableInfo.fields.schedule, undefined);
    assert.equal(tableInfo.fields.rebase_schedule_next_at, undefined);
    assert.equal(tableInfo.indexes.idx_migration_probe_rebase_schedule_next_at, undefined);
    console.log(`runtime: one-shot legacy backfill processes bounded repeat-safe batches${restartAfterFirstBatch ? " across a file-backed database restart" : ""}, preserves next execution time, quarantines active leases, and finalizes after three passes`);
  } finally {
    await client.close().catch(() => {});
  }
}

async function fileBackedMigrationRestartProbe() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-migration-durable-"));
  const storagePath = `rocksdb://${path.join(directory, "database")}`;
  const port = await freePort();
  let child;
  const endpoint = `ws://127.0.0.1:${port}/rpc`;
  async function start() {
    child = spawn("surreal", [
      "start", storagePath, "--user", "root", "--pass", "root",
      "--bind", `127.0.0.1:${port}`, "--async-event-interval", "25ms", "--no-banner", "--log", "error",
    ], { stdio: ["ignore", "ignore", "ignore"] });
    await waitForPort(port, child, "file-backed SurrealDB migration probe");
  }
  try {
    await start();
    await oneShotMigrationProbe(endpoint, {
      async restartAfterFirstBatch() {
        child.kill("SIGKILL");
        await waitForExit(child);
        await start();
      },
    });
    assert(fs.readdirSync(directory).length > 0, "the migration probe must use on-disk database files");
  } finally {
    await stopChild(child);
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

async function main() {
  await assert.rejects(
    startServer({ port: 8788 }),
    /is process-profile configuration/,
  );
  await adapterScopeProbe();
  const runtimePort = await freePort();
  const redis = await startRedis();
  await admissionProbe(redis.url);
  const redisRateLimiter = createRedisRateLimiter({
    url: redis.url,
    prefix: `rebase-rate-probe-${Date.now().toString(36)}`,
  });
  assert.equal((await redisRateLimiter.consume("account", { limit: 1, windowMs: 60000 })).allowed, true);
  assert.equal((await redisRateLimiter.consume("account", { limit: 1, windowMs: 60000 })).allowed, false);
  assert.equal((await redisRateLimiter.health()).ok, true);
  await redisRateLimiter.close();
  const state = await startDatabase(runtimePort);
  await oneShotMigrationProbe(state.endpoint);
  await fileBackedMigrationRestartProbe();
  const secret = "runtime-probe-secret";
  const authenticationPayloadCipher = createAuthenticationPayloadCipher("runtime-probe-authentication-payload-secret");
  const materials = loadMaterials({ groups: [
    { name: "framework", roots: ["framework"] },
    { name: "project", roots: ["designs/test"] },
  ] });
  const generated = generateBundle(materials, {
    context: { runtimeUrl: `http://127.0.0.1:${runtimePort}`, runtimeSecret: secret },
  });
  const contracts = new Map(Object.entries(generated.contracts.tables));
  const operationSource = `
    DEFINE TABLE grant_probe SCHEMAFULL COMMENT '@rebase-operation grant CREATE UPDATE @rebase-adapter createS3UploadGrant';
    DEFINE FIELD owned_by ON grant_probe TYPE record<rebase_group>;
    DEFINE FIELD key ON grant_probe TYPE string COMMENT '@rebase-operation-input';
    DEFINE FIELD expires_in ON grant_probe TYPE int DEFAULT 60 COMMENT '@rebase-operation-input';
    DEFINE FIELD access_url ON grant_probe TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    DEFINE TABLE inline_probe SCHEMAFULL COMMENT '@rebase-operation inline CREATE @rebase-timeout 100ms';
    DEFINE FIELD owned_by ON inline_probe TYPE record<rebase_group>;
    DEFINE FIELD mode ON inline_probe TYPE string READONLY ASSERT $value IN ['success', 'failed', 'timeout'] COMMENT '@rebase-operation-input';
    DEFINE FIELD result ON inline_probe TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    DEFINE TABLE queued_probe SCHEMAFULL COMMENT '@rebase-operation queued CREATE';
    DEFINE FIELD owned_by ON queued_probe TYPE record<rebase_group>;
    DEFINE FIELD value ON queued_probe TYPE string READONLY COMMENT '@rebase-operation-input';
    DEFINE FIELD result ON queued_probe TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    DEFINE TABLE page_probe SCHEMAFULL COMMENT '@rebase-operation queued CREATE';
    DEFINE FIELD owned_by ON page_probe TYPE record<rebase_group>;
    DEFINE FIELD value ON page_probe TYPE string READONLY COMMENT '@rebase-operation-input';
    DEFINE FIELD result ON page_probe TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    DEFINE TABLE cursor_probe SCHEMAFULL COMMENT '@rebase-operation queued CREATE';
    DEFINE FIELD owned_by ON cursor_probe TYPE record<rebase_group>;
    DEFINE FIELD value ON cursor_probe TYPE string READONLY COMMENT '@rebase-operation-input';
    DEFINE FIELD result ON cursor_probe TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    DEFINE TABLE retention_probe SCHEMAFULL COMMENT '@rebase-operation queued CREATE';
    DEFINE FIELD owned_by ON retention_probe TYPE record<rebase_group>;
    DEFINE FIELD value ON retention_probe TYPE string READONLY COMMENT '@rebase-operation-input';
    DEFINE FIELD result ON retention_probe TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
  `;
  const operationSchema = parseSchema(operationSource, "");
  const operationContracts = generateRuntimeContracts(operationSchema, generated.contracts.principals).tables;
  for (const [table, contract] of Object.entries(operationContracts)) contracts.set(table, contract);
  const handlers = loadTableHandlers("designs/test/table-handlers", { contracts, mutable: true });
  handlers.register({
    table: "grant_probe",
    grant: {
      async CREATE({ record, adapters }) {
        const grant = await adapters.createS3UploadGrant({
          objectKey: record.key,
          expiresIn: record.expires_in,
        });
        return { patch: { access_url: grant.uploadUrl } };
      },
      async UPDATE({ record, adapters }) {
        const grant = await adapters.createS3UploadGrant({
          objectKey: record.key,
          expiresIn: record.expires_in,
        });
        return { patch: { access_url: grant.uploadUrl } };
      },
    },
  }, { label: "runtime-probe/grant_probe" });
  handlers.register({
    table: "inline_probe",
    async execute({ record }) {
      if (record.mode === "failed") return { outcome: "failed", error: { code: "EXPECTED_FAILURE" } };
      if (record.mode === "timeout") {
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      return { patch: { result: "completed" } };
    },
  }, { label: "runtime-probe/inline_probe" });
  handlers.register({
    table: "queued_probe",
    async execute({ record }) {
      return { patch: { result: `queued:${record.value}` } };
    },
  }, { label: "runtime-probe/queued_probe" });
  handlers.register({
    table: "page_probe",
    async execute({ record }) {
      return { patch: { result: `paged:${record.value}` } };
    },
  }, { label: "runtime-probe/page_probe" });
  handlers.register({
    table: "cursor_probe",
    async execute({ record }) {
      return { patch: { result: `cursor:${record.value}` } };
    },
  }, { label: "runtime-probe/cursor_probe" });
  handlers.register({
    table: "retention_probe",
    async execute() { return { patch: { result: "retained" } }; },
    async reconcile() { return { outcome: "success", patch: { result: "reconciled" } }; },
  }, { label: "runtime-probe/retention_probe" });
  const webhooks = loadWebhookHandlers("designs/test/webhook-handlers");
  const routeCodec = createWebhookRouteCodec(secret);
  const queueErrors = [];
  const queue = createBullMqPort({
    url: redis.url,
    prefix: `rebase-probe-${Date.now().toString(36)}`,
    deadLetterRetentionMs: 250,
    deadLetterPruneIntervalMs: 25,
    deadLetterPruneBatchSize: 2,
    onError: (error) => queueErrors.push(error.message),
    onFailed: ({ error }) => queueErrors.push(error.message),
  });
  let emailCalls = 0;
  const emailIdempotencyKeys = [];
  const authenticationEmailMessages = [];
  const authenticationSmsMessages = [];
  let failNextEmail = false;
  let failPermanently = false;
  let razorpayRoute;
  let storageDeletes = 0;
  let storageVersionsPurged = 0;
  let storageHeadChecks = 0;
  let failStorageDeleteOnce = false;
  let loseStorageDeleteResponseOnce = false;
  const cleanupObjects = new Set();
  const cleanupVersions = new Map();
  let store;
  const adapters = Object.freeze({
    async sendBrevoEmail(input) {
      emailCalls += 1;
      emailIdempotencyKeys.push(String(input.idempotencyKey || ""));
      if (input.apiKey === "probe-email-api-key") {
        authenticationEmailMessages.push(structuredClone(input));
      }
      if (failPermanently) {
        throw Object.assign(new Error("Permanent adapter failure"), { code: "ADAPTER_REJECTED", status: 400 });
      }
      if (failNextEmail) {
        failNextEmail = false;
        throw Object.assign(new Error("Temporary adapter failure"), { code: "ADAPTER_TEMPORARY", retryable: true });
      }
      return {
        provider: "brevo",
        messageId: crypto.createHash("sha256").update(String(input.idempotencyKey)).digest("hex").slice(0, 24),
        accepted: input.to,
      };
    },
    async getBrevoEmailEvents() { return []; },
    async sendTwilioSms(input) {
      authenticationSmsMessages.push(structuredClone(input));
      return { provider: "twilio", messageId: `sms-${authenticationSmsMessages.length}` };
    },
    async openAuthenticationPayload(value) {
      return authenticationPayloadCipher.open(value);
    },
    async createS3UploadGrant(input) {
      return {
        provider: input.provider,
        uploadUrl: `https://storage.local/upload/${encodeURIComponent(input.objectKey)}`,
        headers: { "content-type": input.contentType, "content-length": String(input.contentLength) },
        expiresAt: new Date(Date.now() + input.expiresIn * 1000).toISOString(),
      };
    },
    async createS3AccessGrant(input) {
      return {
        provider: input.provider,
        accessUrl: `https://storage.local/access/${encodeURIComponent(input.objectKey)}`,
        expiresAt: new Date(Date.now() + input.expiresIn * 1000).toISOString(),
      };
    },
    async deleteS3Object(input) {
      storageDeletes += 1;
      if (input.taskId) {
        const task = await store.load(input.taskId);
        assert(task?.rebase_provider_started_at, "provider deletion ran before its lease marker was committed");
      }
      if (failStorageDeleteOnce) {
        failStorageDeleteOnce = false;
        throw Object.assign(new Error("Storage delete failed before applying"), {
          code: "STORAGE_DELETE_FAILED",
          status: 503,
          retryable: true,
        });
      }
      const existed = cleanupObjects.has(input.objectKey);
      cleanupObjects.delete(input.objectKey);
      if (loseStorageDeleteResponseOnce) {
        loseStorageDeleteResponseOnce = false;
        throw Object.assign(new Error("Storage delete response was lost"), {
          code: "STORAGE_DELETE_RESPONSE_LOST",
          status: 503,
          retryable: true,
        });
      }
      return { deleted: existed };
    },
    async headS3Object(input) {
      storageHeadChecks += 1;
      return { exists: cleanupObjects.has(input.objectKey) };
    },
    async purgeS3Object(input) {
      storageDeletes += 1;
      if (input.taskId) {
        const task = await store.load(input.taskId);
        assert(task?.rebase_provider_started_at, "version purge ran before its lease marker was committed");
      }
      if (failStorageDeleteOnce) {
        failStorageDeleteOnce = false;
        throw Object.assign(new Error("Storage version purge failed before applying"), {
          code: "STORAGE_PURGE_FAILED",
          status: 503,
          retryable: true,
        });
      }
      const versions = cleanupVersions.get(input.objectKey)
        || (cleanupObjects.has(input.objectKey) ? [{ versionId: "null" }] : []);
      cleanupVersions.delete(input.objectKey);
      cleanupObjects.delete(input.objectKey);
      storageVersionsPurged += versions.length;
      if (loseStorageDeleteResponseOnce) {
        loseStorageDeleteResponseOnce = false;
        throw Object.assign(new Error("Storage purge response was lost"), {
          code: "STORAGE_PURGE_RESPONSE_LOST",
          status: 503,
          retryable: true,
        });
      }
      return { deleted: versions.length > 0, versionsDeleted: versions.length };
    },
    async createRazorpayOrder(input) {
      razorpayRoute = input.notes?.rebase_route;
      return {
        provider: "razorpay",
        id: `order_${crypto.createHash("sha256").update(input.receipt).digest("hex").slice(0, 18)}`,
        amount: input.amount,
        amountPaid: 0,
        amountDue: input.amount,
        attempts: 0,
        currency: input.currency,
        receipt: input.receipt,
        status: "created",
        createdAt: new Date().toISOString(),
      };
    },
  });
  const webhookAdapters = createWebhookAdapters();
  store = createTableStore({ db: state.db });
  const stores = fixedStoreDirectory(store, state);
  let nextChallengeCode = 100000;
  const authenticationRateLimiter = createMemoryRateLimiter();
  const authentication = createAuthenticationService({
    stores,
    principals: generated.contracts.principals,
    allowedContexts: [{ namespace: state.namespace, database: state.database }],
    sealAuthenticationPayload: authenticationPayloadCipher.seal,
    generateCode() {
      const code = String(nextChallengeCode);
      nextChallengeCode = nextChallengeCode >= 999999 ? 100000 : nextChallengeCode + 1;
      return code;
    },
    rateLimiter: authenticationRateLimiter,
    rateLimits: { windowMs: 60000, ip: 20, identifier: 2 },
  });
  const oauth = createOAuthVerifier({
    mock: createMockOAuthAdapter({
      "existing-user-token": "oauth-client@example.com",
      "unverified-user-token": "oauth-unverified@example.com",
      "missing-user-token": "oauth-missing@example.com",
    }),
  });
  const runtime = createRuntime({
    handlers,
    webhooks,
    adapters,
    webhookAdapters,
    queue,
    stores,
    contracts,
    routeCodec,
    options: {
      leaseMs: 5000,
      allowedContexts: [{ namespace: state.namespace, database: state.database }],
    },
  });
  let wakeCalls = 0;
  const enqueue = runtime.enqueue;
  runtime.enqueue = async (...args) => { wakeCalls += 1; return enqueue(...args); };
  const stops = [];
  stops.push(await queue.start((delivery) => runtime.consume(delivery)));
  const app = createRuntimeApp({
    runtime, handlers, webhooks, adapters, webhookAdapters, authentication, oauth, queue, runtimeSecret: secret,
    defaultContext: { namespace: state.namespace, database: state.database },
    allowBearer: true,
    trustProxy: true,
  });
  let httpServer;
  let appRequest;
  let runtimeChild;
  let processWorkerChild;
  let processProviderServer;
  let gatewayRestartRedis;
  let gatewayRestartRedisChild;
  let gatewayRestartQueue;
  try {
    const localRuntime = await listenHandler(app, { port: runtimePort });
    httpServer = localRuntime.server;
    appRequest = localRuntime.fetch;
    await state.db.query(generated.bundle);
    await state.db.query(`${operationSource}\n${generateLifecycleFields(operationSchema)}\n${generateOperationEvents(operationSchema, {
      runtimeUrl: `http://127.0.0.1:${runtimePort}`,
      runtimeSecret: secret,
    })}`);
    const unauthenticatedGrant = await appRequest("http://runtime/internal/grant", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        namespace: state.namespace, database: state.database, id: "grant_probe:missing",
        event: "CREATE", before: null, after: { id: "grant_probe:missing", key: "object" },
      }),
    });
    assert.equal(unauthenticatedGrant.status, 401);
    const unauthenticatedInline = await appRequest("http://runtime/internal/inline", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ namespace: state.namespace, database: state.database, id: "inline_probe:missing" }),
    });
    assert.equal(unauthenticatedInline.status, 401);
    const disallowedOperationContext = await appRequest("http://runtime/internal/inline", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: JSON.stringify({ namespace: "outside", database: state.database, id: "inline_probe:missing" }),
    });
    assert.equal(disallowedOperationContext.status, 403);
    const grantProbe = await createAndReload(state.db, "grant_probe", `
      owned_by = rebase_group:root, key = 'object/a', expires_in = 60
    `);
    assert.match(grantProbe.access_url, /storage\.local\/upload\/object%2Fa/);
    const updatedGrant = queryResult(await state.db.query(`
      UPDATE type::record($id) SET key = 'object/b';
      RETURN (SELECT * FROM type::record($id))[0];
    `, { id: recordId(grantProbe) }));
    assert.match(updatedGrant.access_url, /storage\.local\/upload\/object%2Fb/);

    const inlineSucceeded = await createAndReload(state.db, "inline_probe", `
      owned_by = rebase_group:root, mode = 'success'
    `);
    const inlineSucceededId = recordId(inlineSucceeded);
    const inlineSucceededRow = await waitFor(
      async () => (await store.load(inlineSucceededId))?.rebase_outcome === "succeeded"
        ? store.load(inlineSucceededId)
        : null,
      "committed inline operation did not finish",
    );
    assert.equal(inlineSucceededRow.result, "completed");

    const inlineFailed = await createAndReload(state.db, "inline_probe", `
      owned_by = rebase_group:root, mode = 'failed'
    `);
    const inlineFailedRow = await waitFor(
      async () => (await store.load(recordId(inlineFailed)))?.rebase_outcome === "failed"
        ? store.load(recordId(inlineFailed))
        : null,
      "failed inline operation did not persist its outcome",
    );
    assert.equal(inlineFailedRow.rebase_error.code, "EXPECTED_FAILURE");

    const inlineTimedOut = await createAndReload(state.db, "inline_probe", `
      owned_by = rebase_group:root, mode = 'timeout'
    `);
    const inlineTimedOutRow = await waitFor(
      async () => (await store.load(recordId(inlineTimedOut)))?.rebase_outcome === "ambiguous"
        ? store.load(recordId(inlineTimedOut))
        : null,
      "timed out inline operation did not persist an ambiguous outcome",
    );
    assert.equal(inlineTimedOutRow.rebase_error.code, "OPERATION_TIMEOUT");
    const queuedCreated = await createAndReload(state.db, "queued_probe", `
      owned_by = rebase_group:root, value = 'task'
    `);
    let queuedRow;
    try {
      queuedRow = await waitFor(
        async () => (await store.load(recordId(queuedCreated)))?.rebase_outcome === "succeeded"
          ? store.load(recordId(queuedCreated))
          : null,
        "queued operation did not run through the task lane",
      );
    } catch (error) {
      console.error("queued lane diagnostic", await store.load(recordId(queuedCreated)), queueErrors);
      throw error;
    }
    assert.equal(queuedRow.result, "queued:task");
    await state.db.query("DEFINE USER rebase_session_probe ON ROOT PASSWORD 'session-probe-password' ROLES OWNER DURATION FOR TOKEN 1s, FOR SESSION NONE;");
    const renewableAdmin = await connectDatabase({
      endpoint: state.endpoint,
      username: "rebase_session_probe",
      password: "session-probe-password",
      namespace: state.namespace,
      database: state.database,
      expiryMargin: 0,
      reconnect: false,
    });
    try {
      assert.deepEqual(queryResult(await renewableAdmin.db.query("RETURN 1;")), 1);
      await new Promise((resolve) => setTimeout(resolve, 1500));
      assert.deepEqual(queryResult(await renewableAdmin.db.query("RETURN 1;")), 1);
    } finally {
      await renewableAdmin.close();
    }
    await assert.rejects(
      state.db.query("CREATE file_storage_config:missing_credential SET owned_by = rebase_group:root;"),
      /access_key_id|secret_access_key|endpoint|region|field|schema|required/i,
    );
    await assert.rejects(
      state.db.query("CREATE rebase_email_delivery_config:missing_api_key SET owned_by = rebase_group:root, from_email = 'missing@example.com', from_name = 'Missing';"),
      /api_key|field|schema|required/i,
    );
    await assert.rejects(
      state.db.query("CREATE razorpay_config:missing_secret SET owned_by = rebase_group:root, label = 'Missing', key_id = 'key';"),
      /key_secret|webhook_secret|field|schema|required/i,
    );
    const storage = await createAndReload(state.db, "file_storage_config", `
      owned_by = rebase_group:root, visibility = true,
      access_key_id = 'client-storage-id', secret_access_key = 'client-storage-secret',
      endpoint = 'https://storage.local', region = 'local'
    `);
    const storageId = recordId(storage);
    const emailConfig = await createAndReload(state.db, "rebase_email_delivery_config", `
      owned_by = rebase_group:root,
      from_email = 'from@example.com', from_name = 'Probe', api_key = 'client-brevo-api-key'
    `);
    const emailConfigId = recordId(emailConfig);
    const razorpayConfig = await createAndReload(state.db, "razorpay_config", `
      owned_by = rebase_group:root, label = 'Probe', visibility = true,
      key_id = 'client-razorpay-key', key_secret = 'client-razorpay-secret',
      webhook_secret = 'razorpay-webhook-secret'
    `);
    const razorpayConfigId = recordId(razorpayConfig);
    await state.db.query(`
      CREATE rebase_group:runtime_clients SET name = 'Runtime Clients', parents = [rebase_group:root], role = [
        'send_brevo_email_create', 'send_brevo_email_select', 'send_brevo_email_update',
        'file_storage_config_select',
        'test_attachment_create', 'test_attachment_delete', 'test_primitive_select'
      ];
      CREATE rebase_user:runtime_client SET name = 'Runtime Client', parents = [rebase_group:runtime_clients], login_access = true;
      CREATE rebase_user:recovery_client SET name = 'Recovery Client', username = 'recovery_user',
        parents = [rebase_group:runtime_clients], login_access = true;
      CREATE rebase_user:oauth_client SET name = 'OAuth Client',
        parents = [rebase_group:runtime_clients], login_access = true;
      CREATE rebase_user:oauth_unverified SET name = 'OAuth Unverified',
        parents = [rebase_group:runtime_clients], login_access = true;
      CREATE rebase_user:no_delivery SET name = 'No Delivery', username = 'no_delivery_user',
        password = crypto::argon2::generate('no-delivery-password'),
        parents = [rebase_group:runtime_clients], login_access = true;
      CREATE authentication_email:runtime_client SET principal = rebase_user:runtime_client, address = 'runtime-client@example.com';
      CREATE authentication_email:recovery_client SET principal = rebase_user:recovery_client, address = 'recovery-client@example.com';
      CREATE authentication_email:oauth_client SET principal = rebase_user:oauth_client, address = 'oauth-client@example.com';
      CREATE authentication_email:oauth_unverified SET principal = rebase_user:oauth_unverified, address = 'oauth-unverified@example.com';
      CREATE rebase_email_delivery_config:recovery SET owned_by = rebase_group:root, api_key = 'probe-email-api-key',
        from_email = 'recovery@example.com', from_name = 'ReBase Recovery';
      CREATE rebase_sms_delivery_config:recovery SET owned_by = rebase_group:root, account_sid = 'ACprobe',
        auth_token = 'probe-twilio-token', from_number = '+10000000000';
      CREATE rebase_authentication_delivery_policy:default SET
        email_configuration = rebase_email_delivery_config:recovery,
        phone_configuration = rebase_sms_delivery_config:recovery;
      CREATE rebase_email_delivery_config:platform SET owned_by = rebase_group:root,
        from_email = 'client@example.com', from_name = 'Client', api_key = 'customer-brevo-api-key';
    `);

    await assert.rejects(
      passwordSignin(state.endpoint, state.namespace, state.database, "no_delivery_user", "no-delivery-password"),
      /signin|authentication|access|record/i,
    );

    // Reuse a challenge written by the preceding implementation, whose ID is
    // not derived from the target identity.
    await state.db.query(`
      LET $principal = (SELECT * FROM rebase_user:recovery_client)[0];
      LET $identity = (SELECT * FROM authentication_email:recovery_client)[0];
      CREATE authentication_challenge:legacy_recovery SET
        principal = $principal.id, target = $identity.id,
        principal_revision = $principal.authentication_revision,
        target_revision = $identity.revision,
        code_hash = crypto::argon2::generate('654321'), attempts = 0,
        expires_at = time::now() + 10m, consumed_at = NONE,
        delivery_nonce = type::uuid($nonce);
    `, { nonce: crypto.randomUUID() });

    const challengeRequest = {
      namespace: state.namespace,
      database: state.database,
      identifier: "RECOVERY_USER",
    };
    const recoveryEmailCount = authenticationEmailMessages.length;
    const challengeResponse = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: JSON.stringify(challengeRequest),
    });
    assert.equal(challengeResponse.status, 202);
    assert.deepEqual(await challengeResponse.json(), { ok: true });
    const recoveryEmail = await waitForMessage(authenticationEmailMessages, recoveryEmailCount, "queued recovery email was not delivered");
    assert.deepEqual(recoveryEmail.to, ["recovery-client@example.com"]);
    const recoveryDeliveryTask = queryResult(await state.db.query(`
      SELECT id, execution_id FROM authentication_delivery_task
      WHERE target = authentication_email:recovery_client AND channel = 'email' LIMIT 1;
    `))[0];
    assert.equal(
      recoveryEmail.idempotencyKey,
      String(recoveryDeliveryTask.execution_id),
    );
    const emailCode = recoveryEmail.text.match(/\b\d{6}\b/)?.[0];
    assert(emailCode);
    const recoveryChallenge = queryResult(await state.db.query(`
      SELECT * FROM authentication_challenge WHERE target = authentication_email:recovery_client;
    `))[0];
    assert.equal(String(recoveryChallenge.id), "authentication_challenge:legacy_recovery");
    const queuedPayload = queryResult(await state.db.query(`
      SELECT id, payload_ciphertext FROM authentication_delivery_task
      WHERE target = authentication_email:recovery_client ORDER BY id DESC LIMIT 1;
    `))[0]?.payload_ciphertext;
    assert.equal(typeof queuedPayload, "string");
    assert.equal(queuedPayload.includes(emailCode), false);

    const ignoredMessageCount = authenticationEmailMessages.length;
    const staleDelivery = await createAndReload(state.db, "authentication_delivery_task", `
      configuration = rebase_email_delivery_config:recovery,
      principal = rebase_user:recovery_client,
      target = authentication_email:recovery_client,
      challenge = authentication_challenge:legacy_recovery,
      channel = 'email', principal_revision = $principal_revision,
      target_revision = $target_revision,
      delivery_nonce = type::uuid($delivery_nonce), payload_ciphertext = $payload_ciphertext
    `, {
      principal_revision: Number(recoveryChallenge.principal_revision),
      target_revision: Number(recoveryChallenge.target_revision),
      delivery_nonce: crypto.randomUUID(),
      payload_ciphertext: authenticationPayloadCipher.seal({
        subject: "stale", text: "stale", html: "stale",
      }),
    });
    const staleDeliveryId = recordId(staleDelivery);
    await waitFor(
      async () => (await store.load(staleDeliveryId))?.rebase_outcome === "succeeded",
      "stale challenge delivery task did not finish as ignored",
    );
    assert.equal(authenticationEmailMessages.length, ignoredMessageCount);
    await assert.rejects(
      passwordSignin(
        state.endpoint,
        state.namespace,
        state.database,
        "recovery-client@example.com",
        "recovery-password",
      ),
      /signin|authentication|access|record/i,
    );
    const activated = await passwordSignin(
      state.endpoint,
      state.namespace,
      state.database,
      "recovery_user",
      null,
      "account_code",
      { identifier: "recovery_user", code: emailCode, password_action: "set", new_password: "recovered-password" },
    );
    assert(activated.token.access);
    await activated.client.close();
    const recovered = await passwordSignin(
      state.endpoint,
      state.namespace,
      state.database,
      "recovery_user",
      "recovered-password",
    );
    assert(recovered.token.access);
    await recovered.client.close();

    await state.db.query("CREATE authentication_phone:recovery_phone SET principal = rebase_user:recovery_client, number = '+917990910580', priority = 10;");
    const phoneMessageCount = authenticationSmsMessages.length;
    const phoneResponse = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.11" },
      body: JSON.stringify({ ...challengeRequest, identifier: "+917990910580" }),
    });
    assert.equal(phoneResponse.status, 202);
    const phoneMessage = await waitForMessage(authenticationSmsMessages, phoneMessageCount, "queued recovery SMS was not delivered");
    const phoneCode = phoneMessage.body.match(/\b\d{6}\b/)?.[0];
    assert(phoneCode);
    const phoneLogin = await passwordSignin(
      state.endpoint,
      state.namespace,
      state.database,
      null,
      null,
      "account_code",
      { identifier: "+917990910580", code: phoneCode, password_action: "keep" },
    );
    assert(phoneLogin.token.access);
    await phoneLogin.client.close();

    // Failed code submissions consume attempts, and the sixth submission is
    // rejected even when the code is otherwise correct.
    const attemptMessageCount = authenticationEmailMessages.length;
    const attemptResponse = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.15" },
      body: JSON.stringify({ ...challengeRequest, identifier: "runtime-client@example.com" }),
    });
    assert.equal(attemptResponse.status, 202);
    const attemptMessage = await waitForMessage(authenticationEmailMessages, attemptMessageCount, "queued attempt test email was not delivered");
    const attemptCode = attemptMessage.text.match(/\b\d{6}\b/)?.[0];
    assert(attemptCode);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await assert.rejects(
        passwordSignin(state.endpoint, state.namespace, state.database, null, null, "account_code", {
          identifier: "runtime-client@example.com", code: "000000", password_action: "keep",
        }),
        /signin|authentication|access|record/i,
      );
    }
    const attemptState = queryResult(await state.db.query(
      "SELECT attempts, consumed_at FROM authentication_challenge WHERE target = authentication_email:runtime_client;",
    ))[0];
    assert.equal(attemptState.attempts, 5);
    await assert.rejects(
      passwordSignin(state.endpoint, state.namespace, state.database, null, null, "account_code", {
        identifier: "runtime-client@example.com", code: attemptCode, password_action: "keep",
      }),
      /signin|authentication|access|record/i,
    );

    // A challenge is a single-use capability: concurrent correct redemptions
    // have exactly one winner.
    const concurrentMessageCount = authenticationEmailMessages.length;
    const concurrentResponse = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.16" },
      body: JSON.stringify({ ...challengeRequest, identifier: "oauth-client@example.com" }),
    });
    assert.equal(concurrentResponse.status, 202);
    const concurrentMessage = await waitForMessage(authenticationEmailMessages, concurrentMessageCount, "queued concurrent test email was not delivered");
    const concurrentCode = concurrentMessage.text.match(/\b\d{6}\b/)?.[0];
    assert(concurrentCode);
    const concurrent = await Promise.allSettled([
      passwordSignin(state.endpoint, state.namespace, state.database, null, null, "account_code", {
        identifier: "oauth-client@example.com", code: concurrentCode, password_action: "keep",
      }),
      passwordSignin(state.endpoint, state.namespace, state.database, null, null, "account_code", {
        identifier: "oauth-client@example.com", code: concurrentCode, password_action: "keep",
      }),
    ]);
    assert.equal(concurrent.filter((entry) => entry.status === "fulfilled").length, 1);
    assert.equal(concurrent.filter((entry) => entry.status === "rejected").length, 1);
    for (const entry of concurrent) if (entry.status === "fulfilled") await entry.value.client.close();

    // Expired challenges fail without changing the identity state.
    const expiredMessageCount = authenticationEmailMessages.length;
    const expiredResponse = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.17" },
      body: JSON.stringify({ ...challengeRequest, identifier: "oauth-unverified@example.com" }),
    });
    assert.equal(expiredResponse.status, 202);
    const expiredMessage = await waitForMessage(authenticationEmailMessages, expiredMessageCount, "queued expiry test email was not delivered");
    const expiredCode = expiredMessage.text.match(/\b\d{6}\b/)?.[0];
    await state.db.query("UPDATE authentication_challenge SET expires_at = time::now() - 1s WHERE target = authentication_email:oauth_unverified;");
    await assert.rejects(
      passwordSignin(state.endpoint, state.namespace, state.database, null, null, "account_code", {
        identifier: "oauth-unverified@example.com", code: expiredCode, password_action: "keep",
      }),
      /signin|authentication|access|record/i,
    );

    const messagesBeforeMissing = authenticationEmailMessages.length;
    const missingRecovery = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: JSON.stringify({ ...challengeRequest, identifier: "missing-user@example.com" }),
    });
    assert.equal(missingRecovery.status, 202);
    assert.deepEqual(await missingRecovery.json(), { ok: true });
    assert.equal(authenticationEmailMessages.length, messagesBeforeMissing);
    const disallowedRecovery = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: JSON.stringify({ ...challengeRequest, namespace: "outside" }),
    });
    assert.equal(disallowedRecovery.status, 202);
    assert.deepEqual(await disallowedRecovery.json(), { ok: true });
    assert.equal(authenticationEmailMessages.length, messagesBeforeMissing);
    const rateLimitedRequest = JSON.stringify({ ...challengeRequest, identifier: "rate-limit@example.com" });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      assert.equal((await appRequest("http://runtime/anonymous/authentication/challenges", {
        method: "POST",
        headers: { "content-type": "application/json", "x-real-ip": "192.0.2.12" },
        body: rateLimitedRequest,
      })).status, 202);
    }
    const rateLimited = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.12" },
      body: rateLimitedRequest,
    });
    assert.equal(rateLimited.status, 429);
    assert(Number(rateLimited.headers.get("retry-after")) >= 1);

    // A provider-verified email is sufficient for the stateless OAuth path;
    // it does not require a second local challenge or an OAuth table row.
    const unverifiedOAuth = await passwordSignin(
      state.endpoint,
      state.namespace,
      state.database,
      null,
      null,
      "oauth",
      { provider: "mock", oauth_token: "unverified-user-token" },
    );
    assert.equal(String(queryResult(await unverifiedOAuth.client.query("RETURN $auth.id;"))), "rebase_user:oauth_unverified");
    await unverifiedOAuth.client.close();

    const oauthMessageCount = authenticationEmailMessages.length;
    const oauthChallenge = await appRequest("http://runtime/anonymous/authentication/challenges", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.13" },
      body: JSON.stringify({ ...challengeRequest, identifier: "oauth-client@example.com" }),
    });
    assert.equal(oauthChallenge.status, 202);
    const oauthMessage = await waitForMessage(authenticationEmailMessages, oauthMessageCount, "queued OAuth activation email was not delivered");
    const oauthCode = oauthMessage.text.match(/\b\d{6}\b/)?.[0];
    assert(oauthCode);
    const oauthActivation = await passwordSignin(
      state.endpoint,
      state.namespace,
      state.database,
      null,
      null,
      "account_code",
      { identifier: "oauth-client@example.com", code: oauthCode, password_action: "keep" },
    );
    await oauthActivation.client.close();
    assert.throws(() => createOAuthVerifier({ invalid: {} }), /must be a function/);
    assert.deepEqual(await oauth.verify("unknown", "token"), { verified: false });
    assert.deepEqual(await oauth.verify("mock", ""), { verified: false });
    const oauthBody = JSON.stringify({ provider: "mock", token: "existing-user-token" });
    assert.equal((await appRequest("http://runtime/internal/oauth", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: oauthBody,
    })).status, 401);
    const verifiedOAuth = await appRequest("http://runtime/internal/oauth", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: oauthBody,
    });
    assert.deepEqual(await verifiedOAuth.json(), { verified: true, email: "oauth-client@example.com" });
    const oauthLogin = await passwordSignin(
      state.endpoint,
      state.namespace,
      state.database,
      null,
      null,
      "oauth",
      { provider: "mock", oauth_token: "existing-user-token" },
    );
    assert.equal(String(queryResult(await oauthLogin.client.query("RETURN $auth.id;"))), "rebase_user:oauth_client");
    await oauthLogin.client.close();
    const userCountBeforeFailedOAuth = queryResult(await state.db.query("RETURN (SELECT VALUE id FROM rebase_user).len();"));
    await assert.rejects(
      passwordSignin(
        state.endpoint,
        state.namespace,
        state.database,
        null,
        null,
        "oauth",
        { provider: "mock", oauth_token: "missing-user-token" },
      ),
      /signin|authentication|access|record/i,
    );
    assert.equal(
      queryResult(await state.db.query("RETURN (SELECT VALUE id FROM rebase_user).len();")),
      userCountBeforeFailedOAuth,
    );

    const target = await createAndReload(state.db, "test_primitive", `
      owned_by = rebase_group:root, a_string = 'Attachment target', a_decimal = 0dec
    `);
    const targetId = recordId(target);
    const attachment = await createAndReload(state.db, "test_attachment", `
      owned_by = rebase_group:root, storage_config = type::record($storage_id),
      attached_to = type::record($target_id), file_name = 'invoice.pdf',
      media_type = 'application/pdf', byte_length_limit = 0, access_duration = 60
    `, { storage_id: storageId, target_id: targetId });
    const attachmentId = recordId(attachment);
    assert.equal(attachmentId.includes(":u'"), false);
    assert.match(attachment.access_url, /storage\.local\/upload/);
    assert.match(attachment.object_key, /^rebase\/[a-f0-9]{24}\/test_attachment\/[a-f0-9]{32}$/);
    const syncId = attachmentId;
    const beforeSync = {
      ...attachment,
      id: syncId,
      access_mode: "upload",
    };
    const sync = await runtime.sync({
      namespace: state.namespace, database: state.database, id: syncId,
      event: "UPDATE",
      before: beforeSync,
      after: { ...beforeSync, access_mode: "download" },
    });
    assert.equal(sync.outcome, "success");
    assert.match(sync.patch.access_url, /storage\.local\/access/);

    const automaticSync = queryResult(await state.db.query(`
      UPDATE type::record($id) SET access_mode = 'download', access_duration = 120;
      RETURN (SELECT * FROM type::record($id))[0];
    `, { id: attachmentId }));
    assert.match(automaticSync.access_url, /storage\.local\/access/);

    const deleteTarget = await createAndReload(state.db, "test_primitive", `
      owned_by = rebase_group:root, a_string = 'Delete target', a_decimal = 0dec
    `);
    const deleteTargetId = recordId(deleteTarget);
    const deleteCandidate = await createAndReload(state.db, "test_attachment", `
      owned_by = rebase_group:root, storage_config = type::record($storage_id),
      attached_to = type::record($delete_target_id), file_name = 'delete-me.txt',
      media_type = 'text/plain', byte_length_limit = 0, access_duration = 60
    `, { storage_id: storageId, delete_target_id: deleteTargetId });
    const deleteCandidateId = recordId(deleteCandidate);
    await state.db.query("UPDATE type::record($id) SET access_expires_at = time::now() - 1s;", { id: deleteCandidateId });
    cleanupObjects.add(deleteCandidate.object_key);
    cleanupVersions.set(deleteCandidate.object_key, [
      { versionId: "v3", deleteMarker: true },
      { versionId: "v2" },
      { versionId: "v1" },
    ]);
    const firstDeleteCalls = storageDeletes;
    const firstHeadChecks = storageHeadChecks;
    const firstVersionCount = storageVersionsPurged;
    loseStorageDeleteResponseOnce = true;
    await state.db.query("DELETE type::record($id);", { id: deleteCandidateId });
    assert.equal(await store.load(deleteCandidateId), undefined);
    const firstCleanupTask = await waitFor(async () => {
      const rows = queryResult(await state.db.query(
        "SELECT * FROM test_attachment_cleanup WHERE object_key = $object_key;",
        { object_key: deleteCandidate.object_key },
      ));
      return rows?.[0] || null;
    }, "attachment deletion did not commit its durable cleanup request", 15000);
    assert.equal(String(firstCleanupTask.storage_config), storageId);
    assert.equal(firstCleanupTask.object_key, deleteCandidate.object_key);
    const firstCleanupDone = await waitFor(async () => {
      const row = await store.load(recordId(firstCleanupTask));
      return row?.rebase_outcome === "succeeded" ? row : null;
    }, "cleanup did not reconcile a lost delete response", 15000);
    assert.equal(firstCleanupDone.rebase_outcome, "succeeded");
    assert.equal(storageDeletes - firstDeleteCalls, 2);
    assert.equal(storageHeadChecks - firstHeadChecks, 0);
    assert.equal(storageVersionsPurged - firstVersionCount, 3);
    assert.equal(cleanupObjects.has(deleteCandidate.object_key), false);
    assert.equal(cleanupVersions.has(deleteCandidate.object_key), false);

    const retryCandidate = await createAndReload(state.db, "test_attachment", `
      owned_by = rebase_group:root, storage_config = type::record($storage_id),
      attached_to = type::record($delete_target_id), file_name = 'retry-delete.txt',
      media_type = 'text/plain', byte_length_limit = 0, access_duration = 60
    `, { storage_id: storageId, delete_target_id: deleteTargetId });
    const retryCandidateId = recordId(retryCandidate);
    await state.db.query("UPDATE type::record($id) SET access_expires_at = time::now() - 1s;", { id: retryCandidateId });
    cleanupObjects.add(retryCandidate.object_key);
    cleanupVersions.set(retryCandidate.object_key, [
      { versionId: "retry-v2", deleteMarker: true },
      { versionId: "retry-v1" },
    ]);
    const retryDeleteCalls = storageDeletes;
    const retryHeadChecks = storageHeadChecks;
    const retryVersionCount = storageVersionsPurged;
    failStorageDeleteOnce = true;
    await state.db.query("DELETE type::record($id);", { id: retryCandidateId });
    assert.equal(await store.load(retryCandidateId), undefined);
    const retryCleanupTask = await waitFor(async () => {
      const rows = queryResult(await state.db.query(
        "SELECT * FROM test_attachment_cleanup WHERE object_key = $object_key;",
        { object_key: retryCandidate.object_key },
      ));
      return rows?.[0] || null;
    }, "second attachment deletion did not commit its cleanup request", 15000);
    const retryCleanupDone = await waitFor(async () => {
      const row = await store.load(recordId(retryCleanupTask));
      return row?.rebase_outcome === "succeeded" ? row : null;
    }, "cleanup reconciliation did not retry a confirmed-present object", 15000);
    assert.equal(retryCleanupDone.rebase_outcome, "succeeded");
    assert.equal(storageDeletes - retryDeleteCalls, 2);
    assert.equal(storageHeadChecks - retryHeadChecks, 0);
    assert.equal(storageVersionsPurged - retryVersionCount, 2);
    assert.equal(cleanupObjects.has(retryCandidate.object_key), false);

    const razorpayOrder = await createAndReload(state.db, "razorpay_order", `
      owned_by = rebase_group:root, config = type::record($config_id),
      amount_paise = 100, currency = 'INR'
    `, { config_id: razorpayConfigId });
    const razorpayId = recordId(razorpayOrder);
    assert.equal(razorpayId.includes(":u'"), false);
    assert.match(razorpayOrder.provider_order_id, /^order_/);
    assert.equal(razorpayOrder.status, "created");
    assert(razorpayOrder.provider_created_at);

    const automatic = await createAndReload(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Automatic'
    `, { config_id: emailConfigId });
    const automaticId = recordId(automatic);
    let automaticLast;
    const automaticFinished = await waitFor(async () => {
      const row = await store.load(automaticId);
      automaticLast = row;
      if (process.env.REBASE_RUNTIME_PROBE_DEBUG && row) console.error("automatic", row);
      return row?.rebase_outcome === "succeeded" ? row : null;
    }, () => `automatic async effect did not finish (${JSON.stringify({ automaticLast, wakeCalls, queueErrors })})`);
    assert.equal(automaticFinished.rebase_status, "succeeded");
    assert(automaticFinished.provider_reference);
    assert(emailIdempotencyKeys.includes(String(automaticFinished.execution_id)));

    await state.db.query("REMOVE EVENT rebase_effect_send_brevo_email ON TABLE send_brevo_email;");
    const duplicate = await createAndReload(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Duplicate'
    `, { config_id: emailConfigId });
    const duplicateId = recordId(duplicate);
    const callsBefore = emailCalls;
    const duplicateResults = await Promise.all([
      runtime.execute({ namespace: state.namespace, database: state.database, id: duplicateId }, { attempts: 1, maxAttempts: 5 }),
      runtime.execute({ namespace: state.namespace, database: state.database, id: duplicateId }, { attempts: 1, maxAttempts: 5 }),
    ]);
    assert.equal(emailCalls, callsBefore + 1);
    assert(duplicateResults.some((result) => result.state === "succeeded"));
    assert(duplicateResults.some((result) => result.state === "busy"));

    const clientAttachmentTarget = await createAndReload(state.db, "test_primitive", `
      owned_by = rebase_user:runtime_client, a_string = 'Client cleanup target', a_decimal = 0dec
    `);
    const client = new Surreal();
    await client.connect(state.endpoint);
    await client.signin({
      namespace: state.namespace,
      database: state.database,
      access: "account_code",
      variables: {
        identifier: "runtime-client@example.com",
        code: (await (async () => {
          const previousMessageCount = authenticationEmailMessages.length;
          const response = await appRequest("http://runtime/anonymous/authentication/challenges", {
            method: "POST",
            headers: { "content-type": "application/json", "x-real-ip": "192.0.2.14" },
            body: JSON.stringify({ namespace: state.namespace, database: state.database, identifier: "runtime-client@example.com" }),
          });
          assert.equal(response.status, 202);
          const email = await waitForMessage(authenticationEmailMessages, previousMessageCount, "queued password setup email was not delivered");
          return email.text.match(/\b\d{6}\b/)?.[0];
        })()),
        password_action: "set",
        new_password: "runtime-password",
      },
    });
    try {
      const clientCreated = queryResult(await client.query(`
        CREATE ONLY send_brevo_email SET
          owned_by = rebase_user:runtime_client,
          config = NONE,
          to = ['client@example.com'],
          subject = 'Client lifecycle'
        RETURN AFTER;
      `));
      const clientId = recordId(clientCreated);
      assert.equal(queryResult(await client.query(
        "RETURN type::is_none(rebase_email_delivery_config:platform.api_key);",
      )), true);
      const visibleStorage = queryResult(await client.query(`SELECT id, access_key_id, secret_access_key, endpoint, region FROM ${storageId};`))[0];
      assert.equal(String(visibleStorage.id).split(":", 1)[0], "file_storage_config");
      assert.equal(visibleStorage.access_key_id, undefined);
      assert.equal(visibleStorage.secret_access_key, undefined);
      assert.equal(visibleStorage.endpoint, undefined);
      assert.equal(visibleStorage.region, undefined);
      await client.query("UPDATE rebase_email_delivery_config:platform SET api_key = 'client-must-not-write';");
      assert.equal(queryResult(await state.db.query("RETURN rebase_email_delivery_config:platform.api_key;")), "customer-brevo-api-key");
      assert.notEqual(clientCreated.rebase_cancel_requested, true);
      assert.equal(clientCreated.rebase_outcome, undefined);
      assert.equal(clientCreated.rebase_lease_token, undefined);
      assert.equal(clientCreated.rebase_status, "pending");
      assert.equal((await runtime.execute({ namespace: state.namespace, database: state.database, id: clientId })).state, "succeeded");

      await client.query(`CREATE test_attachment_cleanup SET
        owned_by = rebase_user:runtime_client,
        storage_config = type::record($storage_id), object_key = 'forged/object/key';`,
      { storage_id: storageId });
      assert.equal(queryResult(await state.db.query(
        "SELECT VALUE id FROM test_attachment_cleanup WHERE object_key = 'forged/object/key';",
      )).length, 0, "record users cannot insert a cleanup request directly");
      const clientAttachmentId = "test_attachment:client_cleanup";
      await client.query(`CREATE ONLY ${clientAttachmentId} SET
        owned_by = rebase_user:runtime_client,
        storage_config = type::record($storage_id),
        attached_to = type::record($target_id),
        file_name = 'client-owned.txt', media_type = 'text/plain', byte_length_limit = 0,
        access_duration = 60;`, { storage_id: storageId, target_id: recordId(clientAttachmentTarget) });
      const clientAttachment = await store.load(clientAttachmentId);
      assert(clientAttachment?.object_key);
      await state.db.query("UPDATE type::record($id) SET access_expires_at = time::now() - 1s;", { id: clientAttachmentId });
      cleanupObjects.add(clientAttachment.object_key);
      cleanupVersions.set(clientAttachment.object_key, [
        { versionId: "client-v1" },
      ]);
      await state.db.query(`DEFINE FIELD OVERWRITE object_key ON test_attachment_cleanup
        TYPE string READONLY ASSERT $value = 'no-object-can-match' COMMENT '@rebase-operation-input';`);
      await assert.rejects(client.query("DELETE type::record($id);", { id: clientAttachmentId }), /object_key|assert|REBASE|event/i);
      assert(await store.load(clientAttachmentId), "failed cleanup-request creation must roll back the attachment deletion");
      assert.equal(queryResult(await state.db.query(
        "SELECT VALUE id FROM test_attachment_cleanup WHERE object_key = $object_key;",
        { object_key: clientAttachment.object_key },
      )).length, 0);
      await state.db.query(`DEFINE FIELD OVERWRITE object_key ON test_attachment_cleanup
        TYPE string READONLY ASSERT $value.len() > 0 COMMENT '@rebase-operation-input';`);
      const clientDeleteCalls = storageDeletes;
      await client.query("DELETE type::record($id);", { id: clientAttachmentId });
      assert.equal(await store.load(clientAttachmentId), undefined);
      const clientCleanupTask = await waitFor(async () => {
        const rows = queryResult(await state.db.query(
          "SELECT * FROM test_attachment_cleanup WHERE object_key = $object_key;",
          { object_key: clientAttachment.object_key },
        ));
        return rows?.[0] || null;
      }, "record-user deletion did not create a private cleanup request", 15000);
      const clientCleanupDone = await waitFor(async () => {
        const row = await store.load(recordId(clientCleanupTask));
        return row?.rebase_outcome === "succeeded" ? row : null;
      }, "record-user cleanup request did not complete", 15000);
      assert.equal(clientCleanupDone.rebase_outcome, "succeeded");
      assert.equal(storageDeletes, clientDeleteCalls + 1);

      await state.db.query("REMOVE EVENT rebase_operation_test_attachment_cleanup ON TABLE test_attachment_cleanup;");
      const reusableAttachmentId = "test_attachment:cleanup_reuse";
      const reusableInput = `
        owned_by = rebase_user:runtime_client,
        storage_config = type::record($storage_id),
        attached_to = type::record($target_id),
        file_name = 'reused-id.txt', media_type = 'text/plain', byte_length_limit = 0,
        access_duration = 60`;
      await client.query(`CREATE ONLY ${reusableAttachmentId} SET ${reusableInput};`, {
        storage_id: storageId,
        target_id: recordId(clientAttachmentTarget),
      });
      await state.db.query("UPDATE type::record($id) SET access_expires_at = time::now() + 1m;", {
        id: reusableAttachmentId,
      });
      const oldAttachment = await store.load(reusableAttachmentId);
      const oldObjectKey = oldAttachment.object_key;
      const oldAccessExpiresAt = oldAttachment.access_expires_at;
      cleanupObjects.add(oldObjectKey);
      cleanupVersions.set(oldObjectKey, [
        { versionId: "old-v1" },
        { versionId: "old-marker", deleteMarker: true },
      ]);
      await client.query("DELETE type::record($id);", { id: reusableAttachmentId });
      const oldCleanupTask = queryResult(await state.db.query(
        "SELECT * FROM test_attachment_cleanup WHERE object_key = $object_key;",
        { object_key: oldObjectKey },
      ))[0];
      assert(oldCleanupTask);
      assert(new Date(oldCleanupTask.execute_at).getTime() > new Date(oldAccessExpiresAt).getTime());
      await client.query(`CREATE ONLY ${reusableAttachmentId} SET ${reusableInput};`, {
        storage_id: storageId,
        target_id: recordId(clientAttachmentTarget),
      });
      const newObjectKey = (await store.load(reusableAttachmentId)).object_key;
      assert.notEqual(newObjectKey, oldObjectKey, "recreated attachment IDs receive fresh object keys");
      cleanupObjects.add(newObjectKey);
      cleanupVersions.set(newObjectKey, [{ versionId: "new-v1" }]);
      await state.db.query("UPDATE type::record($id) SET access_expires_at = time::now() - 1s;", {
        id: reusableAttachmentId,
      });
      await state.db.query("UPDATE type::record($id) SET execute_at = time::now() - 1s;", {
        id: recordId(oldCleanupTask),
      });
      assert.equal((await runtime.execute({
        namespace: state.namespace,
        database: state.database,
        id: recordId(oldCleanupTask),
      })).state, "succeeded");
      assert.equal(cleanupObjects.has(oldObjectKey), false);
      assert.equal(cleanupVersions.has(oldObjectKey), false);
      assert.equal(cleanupObjects.has(newObjectKey), true, "old cleanup cannot delete the recreated attachment object");
      assert.equal(cleanupVersions.get(newObjectKey)?.length, 1, "old cleanup cannot delete versions of the recreated attachment object");
      await client.query("DELETE type::record($id);", { id: reusableAttachmentId });
      const newCleanupTask = queryResult(await state.db.query(
        "SELECT * FROM test_attachment_cleanup WHERE object_key = $object_key;",
        { object_key: newObjectKey },
      ))[0];
      assert(newCleanupTask);
      await state.db.query("UPDATE type::record($id) SET execute_at = time::now() - 1s;", {
        id: recordId(newCleanupTask),
      });
      assert.equal((await runtime.execute({
        namespace: state.namespace,
        database: state.database,
        id: recordId(newCleanupTask),
      })).state, "succeeded");
      assert.equal(cleanupObjects.has(newObjectKey), false);

      const cancelCreated = queryResult(await client.query(`CREATE ONLY send_brevo_email SET
        owned_by = rebase_user:runtime_client, config = NONE,
        to = ['client@example.com'], subject = 'Client cancel' RETURN AFTER;`));
      const cancelId = recordId(cancelCreated);
      const cancelled = queryResult(await client.query("RETURN (UPDATE type::record($id) SET rebase_cancel_requested = true RETURN AFTER)[0];", { id: cancelId }));
      assert.equal(cancelled.rebase_cancel_requested, true);
      assert.equal(cancelled.rebase_status, "cancelled");
      const monotonic = queryResult(await client.query("RETURN (UPDATE type::record($id) SET rebase_cancel_requested = false RETURN AFTER)[0];", { id: cancelId }));
      assert.equal(monotonic.rebase_cancel_requested, true);
      await assert.rejects(
        client.query(`CREATE send_brevo_email SET owned_by = rebase_user:runtime_client, config = NONE,
          to = ['client@example.com'], subject = 'Bad priority', priority = 0;`),
        /priority|assert/i,
      );
    } finally {
      await client.close();
    }

    const retryId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Retry'
    `, { config_id: emailConfigId });
    failNextEmail = true;
    const firstRetry = await runtime.execute({ namespace: state.namespace, database: state.database, id: retryId }, { attempts: 1, maxAttempts: 3 });
    assert.equal(firstRetry.action, "ack");
    assert.equal(firstRetry.state, "waiting");
    const secondRetry = await waitFor(async () => {
      const row = await store.load(retryId);
      return row?.rebase_outcome === "succeeded" ? row : null;
    }, "database-owned retry did not complete", 8000);
    assert.equal(secondRetry.rebase_attempt, 2);

    const ambiguousHandlers = loadTableHandlers("designs/test/table-handlers", { contracts, mutable: true });
    const emailImplementation = ambiguousHandlers.get("send_brevo_email").implementation;
    let reconciliationStillAmbiguous = true;
    ambiguousHandlers.unregister("send_brevo_email");
    ambiguousHandlers.register({
      ...emailImplementation,
      on: {
        ...emailImplementation.on,
        async CREATE() {
          return { outcome: "ambiguous", retryAfterMs: 1000, patch: { provider_state: "unknown" } };
        },
      },
      async reconcile() {
        return reconciliationStillAmbiguous
          ? { outcome: "ambiguous", retryAfterMs: 1000 }
          : { outcome: "success", patch: { provider_state: "reconciled" } };
      },
    });
    const ambiguousRuntime = createRuntime({
      handlers: ambiguousHandlers,
      adapters,
      queue: { async publish() { return { jobId: "probe", duplicate: false }; } },
      stores,
      contracts,
      options: {
        leaseMs: 5000,
        allowedContexts: [{ namespace: state.namespace, database: state.database }],
      },
    });
    const ambiguousId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Ambiguous'
    `, { config_id: emailConfigId });
    assert.equal((await ambiguousRuntime.execute({ namespace: state.namespace, database: state.database, id: ambiguousId })).state, "ambiguous");
    await state.db.query(`UPDATE ${ambiguousId} SET rebase_attempt = 100, rebase_wake_at = time::now();`);
    const stillAmbiguous = await ambiguousRuntime.reconcileWebhook({
      namespace: state.namespace,
      database: state.database,
      id: ambiguousId,
    });
    assert.equal(stillAmbiguous.state, "waiting");
    assert.equal((await store.load(ambiguousId)).rebase_outcome, "ambiguous");
    reconciliationStillAmbiguous = false;
    await state.db.query(`UPDATE ${ambiguousId} SET rebase_wake_at = time::now();`);
    assert.equal((await ambiguousRuntime.reconcileWebhook({
      namespace: state.namespace,
      database: state.database,
      id: ambiguousId,
    })).state, "succeeded");
    const reconciledAmbiguous = await store.load(ambiguousId);
    assert.equal(reconciledAmbiguous.rebase_outcome, "succeeded");
    assert.equal(reconciledAmbiguous.provider_state, "reconciled");

    const deadId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Dead letter'
    `, { config_id: emailConfigId });
    failPermanently = true;
    await runtime.enqueue({ namespace: state.namespace, database: state.database, id: deadId }, { attempts: 1 });
    await waitFor(async () => (await store.load(deadId))?.rebase_outcome === "failed", "permanent failure was not persisted");
    await waitFor(async () => {
      const counts = await queue.deadLetterQueue.getJobCounts("wait", "active", "completed");
      return (counts.wait || 0) + (counts.active || 0) + (counts.completed || 0) > 0;
    },
      "permanent failure was not dead-lettered");
    await waitFor(async () => Number((await queue.deadLetterQueue.getJobCounts("wait")).wait || 0) === 0,
      "expired dead-letter diagnostic was not pruned");
    assert.equal((await store.load(deadId))?.rebase_outcome, "failed",
      "pruning the Redis diagnostic must preserve the durable SurrealDB task outcome");
    failPermanently = false;

    const staleId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Fence'
    `, { config_id: emailConfigId });
    const staleRecord = await store.load(staleId);
    const staleIdentity = {
      executionId: String(staleRecord.execution_id),
      revision: String(staleRecord.revision),
    };
    const staleToken = crypto.randomUUID();
    assert(await store.claim(staleId, {
      token: staleToken,
      leaseUntil: Date.now() + 5000,
      outcome: "pending",
      ...staleIdentity,
    }));
    await state.db.query(`UPDATE ${staleId} SET rebase_lease_token = rand::uuid::v7();`);
    assert.equal(await store.finalize(
      staleId,
      staleToken,
      {},
      contracts.get("send_brevo_email").patchFields,
      "succeeded",
      null,
      "pending",
      staleIdentity,
    ), undefined);

    const revisionId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Revision transition'
    `, { config_id: emailConfigId });
    const revisionRecord = await store.load(revisionId);
    const revisionIdentity = {
      executionId: String(revisionRecord.execution_id),
      revision: String(revisionRecord.revision),
    };
    const revisionToken = crypto.randomUUID();
    assert(await store.claim(revisionId, {
      token: revisionToken,
      leaseUntil: Date.now() + 5000,
      outcome: "pending",
      ...revisionIdentity,
    }));
    const revisionFinalized = await store.finalize(
      revisionId,
      revisionToken,
      {},
      contracts.get("send_brevo_email").patchFields,
      "succeeded",
      null,
      "pending",
      revisionIdentity,
    );
    assert(revisionFinalized);
    assert.notEqual(String(revisionFinalized.revision), revisionIdentity.revision);
    assert.equal(await store.claim(revisionId, {
      token: crypto.randomUUID(),
      leaseUntil: Date.now() + 5000,
      outcome: "pending",
      ...revisionIdentity,
    }), undefined);

    const expiredLeaseId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Expired lease'
    `, { config_id: emailConfigId });
    const expiredLeaseRecord = await store.load(expiredLeaseId);
    const expiredLeaseIdentity = {
      executionId: String(expiredLeaseRecord.execution_id),
      revision: String(expiredLeaseRecord.revision),
    };
    const expiredLeaseToken = crypto.randomUUID();
    assert(await store.claim(expiredLeaseId, {
      token: expiredLeaseToken,
      leaseUntil: Date.now() - 1000,
      outcome: "pending",
      ...expiredLeaseIdentity,
    }));
    assert.equal(await store.finalize(
      expiredLeaseId,
      expiredLeaseToken,
      {},
      contracts.get("send_brevo_email").patchFields,
      "succeeded",
      null,
      "pending",
      expiredLeaseIdentity,
    ), undefined);

    const oldEnvelope = {
      version: 1,
      kind: "operation",
      locator: { namespace: state.namespace, database: state.database, id: staleId },
      executionId: staleIdentity.executionId,
      revision: staleIdentity.revision,
    };
    await state.db.query(`DELETE ${staleId};`);
    await state.db.query(`CREATE ONLY ${staleId} SET
      owned_by = rebase_group:root,
      config = type::record($config_id),
      to = ['to@example.com'],
      subject = 'Recreated fence'
    ;`, { config_id: emailConfigId });
    const recreatedRecord = await store.load(staleId);
    assert.notEqual(String(recreatedRecord.execution_id), staleIdentity.executionId);
    assert.notEqual(String(recreatedRecord.revision), staleIdentity.revision);
    assert.equal((await runtime.execute(oldEnvelope)).state, "stale");

    const cancelledId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Cancelled'
    `, { config_id: emailConfigId });
    await state.db.query("UPDATE type::record($id) SET rebase_cancel_requested = true;", { id: cancelledId });
    const cancelledCalls = emailCalls;
    assert.equal((await runtime.execute({ namespace: state.namespace, database: state.database, id: cancelledId })).state, "cancelled");
    assert.equal(emailCalls, cancelledCalls);

    const body = JSON.stringify({ namespace: state.namespace, database: state.database, id: cancelledId });
    const timestamp = String(Date.now());
    const signature = crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
    const wake = await appRequest("http://runtime/internal/wake/task", {
      method: "POST", headers: { "content-type": "application/json", "x-rebase-timestamp": timestamp, "x-rebase-signature": signature }, body,
    });
    assert.equal(wake.status, 202);
    const staleTimestamp = String(Date.now() - 10 * 60 * 1000);
    const staleSignature = crypto.createHmac("sha256", secret).update(`${staleTimestamp}.${body}`).digest("hex");
    assert.equal((await appRequest("http://runtime/internal/wake/task", {
      method: "POST", headers: { "content-type": "application/json", "x-rebase-timestamp": staleTimestamp, "x-rebase-signature": staleSignature }, body,
    })).status, 401);
    assert.equal((await appRequest("http://runtime/internal/wake/task", {
      method: "POST", headers: { "x-rebase-timestamp": timestamp, "x-rebase-signature": signature }, body,
    })).status, 415);
    const wrongContextBody = JSON.stringify({ namespace: "outside", database: state.database, id: cancelledId });
    const wrongContextTimestamp = String(Date.now());
    const wrongContextSignature = crypto.createHmac("sha256", secret).update(`${wrongContextTimestamp}.${wrongContextBody}`).digest("hex");
    assert.equal((await appRequest("http://runtime/internal/wake/task", {
      method: "POST",
      headers: { "content-type": "application/json", "x-rebase-timestamp": wrongContextTimestamp, "x-rebase-signature": wrongContextSignature },
      body: wrongContextBody,
    })).status, 403);
    const oversizedBody = JSON.stringify({ namespace: state.namespace, database: state.database, id: cancelledId, padding: "x".repeat(300000) });
    assert.equal((await appRequest("http://runtime/internal/wake/task", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${secret}` }, body: oversizedBody,
    })).status, 413);
    const productionAuthApp = createRuntimeApp({
      runtime,
      handlers,
      adapters,
      webhookAdapters,
      queue,
      runtimeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      allowBearer: false,
      allowInternalBearer: true,
    });
    assert.equal((await requestHandler(productionAuthApp, "http://runtime/internal/wake/task", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body,
    })).status, 202);
    assert.equal((await requestHandler(productionAuthApp, "http://runtime/internal/oauth", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: JSON.stringify({ provider: "mock", token: "existing-user-token" }),
    })).status, 401);

    assert(razorpayRoute);
    const razorpayCreatedAt = Math.floor(Date.now() / 1000);
    const razorpayBody = JSON.stringify({
      event: "order.paid",
      note: "raw ₹ webhook bytes",
      created_at: razorpayCreatedAt,
      payload: {
        order: { entity: {
          id: razorpayOrder.provider_order_id,
          amount: razorpayOrder.amount_paise,
          currency: razorpayOrder.currency,
          status: "paid",
          notes: { rebase_route: razorpayRoute },
          created_at: razorpayCreatedAt,
        } },
        payment: { entity: {
          id: "pay_probe",
          order_id: razorpayOrder.provider_order_id,
          amount: razorpayOrder.amount_paise,
          currency: razorpayOrder.currency,
          status: "captured",
          method: "card",
          created_at: razorpayCreatedAt,
        } },
      },
    });
    const razorpayHeaders = {
      "content-type": "application/json",
      "x-razorpay-event-id": "razorpay-event-1",
      "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(razorpayBody).digest("hex"),
    };
    const razorpayWebhook = await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST", headers: razorpayHeaders, body: razorpayBody,
    });
    if (razorpayWebhook.status !== 200) console.error("razorpay webhook", razorpayWebhook.status, await razorpayWebhook.clone().text());
    assert.equal(razorpayWebhook.status, 200);
    const acceptedReceipt = await razorpayWebhook.json();
    assert.equal(acceptedReceipt.data.accepted, true);
    assert.equal(acceptedReceipt.data.duplicate, false);
    const receiptLocator = {
      namespace: state.namespace,
      database: state.database,
      id: acceptedReceipt.data.receiptId,
    };
    const paidOrder = await waitFor(async () => {
      const row = await store.load(razorpayId);
      const receipt = await store.load(receiptLocator.id);
      if (receipt?.rebase_outcome === "failed") {
        throw new Error(`durable Razorpay receipt failed: ${JSON.stringify(receipt.rebase_error)}`);
      }
      return row?.status === "paid" && receipt?.applied_at ? row : null;
    }, "durable Razorpay receipt was not applied by a worker", 8000);
    assert.equal(paidOrder.status, "paid");
    const appliedReceipt = await store.load(receiptLocator.id);
    assert.equal(appliedReceipt.rebase_outcome, "succeeded");
    assert(appliedReceipt.applied_at);
    const paymentRows = queryResult(await state.db.query("SELECT * FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';"));
    assert.equal(paymentRows.length, 1);
    assert.equal(paymentRows[0].status, "captured");
    assert.equal(paymentRows[0].order, razorpayId);
    const duplicateWebhook = await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST", headers: razorpayHeaders, body: razorpayBody,
    });
    assert.equal(duplicateWebhook.status, 200);
    assert.equal((await duplicateWebhook.json()).data.duplicate, true);
    assert.equal(queryResult(await state.db.query("SELECT id FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';")).length, 1);
    const conflictingBody = JSON.stringify({
      event: "order.paid",
      created_at: razorpayCreatedAt + 1,
      payload: JSON.parse(razorpayBody).payload,
    });
    const conflictResponse = await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST",
      headers: {
        ...razorpayHeaders,
        "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(conflictingBody).digest("hex"),
      },
      body: conflictingBody,
    });
    assert.equal(conflictResponse.status, 409, "an event ID cannot be reused with a different signed body");
    const paymentSnapshotBody = (event, status, createdAt, paymentId = "pay_probe") => JSON.stringify({
      event,
      created_at: createdAt,
      payload: { payment: { entity: {
        id: paymentId,
        order_id: razorpayOrder.provider_order_id,
        amount: razorpayOrder.amount_paise,
        currency: razorpayOrder.currency,
        status,
        method: "card",
        notes: { rebase_route: razorpayRoute },
        created_at: razorpayCreatedAt,
      } } },
    });
    const submitPaymentSnapshot = async (event, status, eventId, createdAt, paymentId = "pay_probe") => {
      const body = paymentSnapshotBody(event, status, createdAt, paymentId);
      return appRequest("http://runtime/webhooks/razorpay", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-razorpay-event-id": eventId,
          "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(body).digest("hex"),
        },
        body,
      });
    };
    const routeResponse = await requestHandler(app, "http://runtime/internal/webhook-route", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: JSON.stringify({
        provider: "razorpay",
        namespace: state.namespace,
        database: state.database,
        config: razorpayConfigId,
      }),
    });
    assert.equal(routeResponse.status, 200, "Razorpay config route should be provisioned internally");
    const configuredRazorpayRoute = await routeResponse.json();
    const submitRefund = async ({ eventId, refundId, refundAmount, amountRefunded, createdAt }) => {
      const body = JSON.stringify({
        event: "refund.processed",
        created_at: createdAt,
        payload: {
          refund: { entity: {
            id: refundId,
            payment_id: "pay_probe",
            amount: refundAmount,
            currency: "INR",
            status: "processed",
            created_at: createdAt,
          } },
          payment: { entity: {
            id: "pay_probe",
            order_id: razorpayOrder.provider_order_id,
            amount: razorpayOrder.amount_paise,
            amount_refunded: amountRefunded,
            currency: razorpayOrder.currency,
            status: "captured",
            method: "card",
            created_at: razorpayCreatedAt,
            notes: [],
          } },
        },
      });
      return appRequest(`http://runtime${configuredRazorpayRoute.path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-razorpay-event-id": eventId,
          "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(body).digest("hex"),
        },
        body,
      });
    };
    const authorizedSnapshot = await submitPaymentSnapshot(
      "payment.authorized", "authorized", "razorpay-event-late-authorized", razorpayCreatedAt - 1,
    );
    assert.equal(authorizedSnapshot.status, 200,
      "a payment-only authorized snapshot with its local order route must be accepted");
    const authorizedReceiptId = (await authorizedSnapshot.json()).data.receiptId;
    await waitFor(async () => (await store.load(authorizedReceiptId))?.rebase_outcome === "succeeded",
      "late authorized snapshot did not settle");
    assert.equal(queryResult(await state.db.query(
      "SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';",
    ))[0].status, "captured", "a stale authorized snapshot must not regress a captured payment");
    const capturedSnapshot = await submitPaymentSnapshot(
      "payment.captured", "captured", "razorpay-event-payment-captured", razorpayCreatedAt + 1,
    );
    assert.equal(capturedSnapshot.status, 200, "a payment-only captured snapshot must be accepted");
    const capturedReceiptId = (await capturedSnapshot.json()).data.receiptId;
    await waitFor(async () => (await store.load(capturedReceiptId))?.rebase_outcome === "succeeded",
      "payment-only captured snapshot did not settle");
    assert.equal((await store.load(razorpayId)).status, "paid");
    const failedSnapshot = await submitPaymentSnapshot(
      "payment.failed", "failed", "razorpay-event-late-failed", razorpayCreatedAt - 1,
    );
    assert.equal(failedSnapshot.status, 200, "a payment-only failed snapshot must be accepted for audit");
    const failedReceiptId = (await failedSnapshot.json()).data.receiptId;
    await waitFor(async () => (await store.load(failedReceiptId))?.rebase_outcome === "succeeded",
      "late failed snapshot did not settle");
    assert.equal(queryResult(await state.db.query(
      "SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';",
    ))[0].status, "captured", "a stale failed snapshot must not regress a captured payment");
    const lateFailure = await submitPaymentSnapshot(
      "payment.failed", "failed", "razorpay-event-late-auth-failure", razorpayCreatedAt + 3, "pay_late_auth_probe",
    );
    const lateFailureBody = await lateFailure.clone().text();
    assert.equal(lateFailure.status, 200, `late authorization fixture failure was rejected: ${lateFailureBody}`);
    const lateFailureReceiptId = (await lateFailure.json()).data.receiptId;
    await waitFor(async () => (await store.load(lateFailureReceiptId))?.rebase_outcome === "succeeded",
      "late payment failure snapshot did not settle");
    assert.equal(queryResult(await state.db.query(
      "SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_late_auth_probe';",
    ))[0].status, "failed");
    const lateAuthorization = await submitPaymentSnapshot(
      "payment.authorized", "authorized", "razorpay-event-late-auth-success", razorpayCreatedAt + 4, "pay_late_auth_probe",
    );
    assert.equal(lateAuthorization.status, 200);
    const lateAuthorizationReceiptId = (await lateAuthorization.json()).data.receiptId;
    await waitFor(async () => (await store.load(lateAuthorizationReceiptId))?.rebase_outcome === "succeeded",
      "late authorization after failure did not settle");
    assert.equal(queryResult(await state.db.query(
      "SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_late_auth_probe';",
    ))[0].status, "authorized",
      "a later provider event must allow a documented late authorization after failure");
    const delayedFailure = await submitPaymentSnapshot(
      "payment.failed", "failed", "razorpay-event-delayed-old-failure", razorpayCreatedAt + 3, "pay_late_auth_probe",
    );
    assert.equal(delayedFailure.status, 200);
    const delayedFailureReceiptId = (await delayedFailure.json()).data.receiptId;
    await waitFor(async () => (await store.load(delayedFailureReceiptId))?.rebase_outcome === "succeeded",
      "older failure snapshot after late authorization did not settle");
    assert.equal(queryResult(await state.db.query(
      "SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_late_auth_probe';",
    ))[0].status, "authorized", "an older failed snapshot must not undo a later authorization");
    const partialRefund = await submitRefund({
      eventId: "razorpay-event-partial-refund",
      refundId: "rfnd_partial_probe",
      refundAmount: 40,
      amountRefunded: 40,
      createdAt: razorpayCreatedAt + 5,
    });
    assert.equal(partialRefund.status, 200, "config-bound partial refund callback should be accepted without payment notes");
    const partialRefundReceiptId = (await partialRefund.json()).data.receiptId;
    await waitFor(async () => (await store.load(partialRefundReceiptId))?.rebase_outcome === "succeeded",
      "partial refund receipt did not settle");
    const afterPartialRefund = queryResult(await state.db.query(
      "SELECT status, amount_refunded_paise FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';",
    ))[0];
    assert.equal(afterPartialRefund.status, "captured", "a partial refund must preserve captured payment status");
    assert.equal(afterPartialRefund.amount_refunded_paise, 40);
    const fullRefund = await submitRefund({
      eventId: "razorpay-event-full-refund",
      refundId: "rfnd_final_probe",
      refundAmount: 60,
      amountRefunded: 100,
      createdAt: razorpayCreatedAt + 6,
    });
    assert.equal(fullRefund.status, 200, "config-bound full refund callback should be accepted");
    const fullRefundReceiptId = (await fullRefund.json()).data.receiptId;
    await waitFor(async () => (await store.load(fullRefundReceiptId))?.rebase_outcome === "succeeded",
      "full refund receipt did not settle");
    const afterFullRefund = queryResult(await state.db.query(
      "SELECT status, amount_refunded_paise FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';",
    ))[0];
    assert.equal(afterFullRefund.status, "refunded", "a cumulative full refund must advance payment to refunded");
    assert.equal(afterFullRefund.amount_refunded_paise, 100);
    const delayedCapturedBody = JSON.stringify({
      ...JSON.parse(razorpayBody),
      created_at: razorpayCreatedAt + 2,
    });
    const delayedCapturedHeaders = {
      ...razorpayHeaders,
      "x-razorpay-event-id": "razorpay-event-delayed-capture",
      "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(delayedCapturedBody).digest("hex"),
    };
    const delayedCaptured = await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST", headers: delayedCapturedHeaders, body: delayedCapturedBody,
    });
    assert.equal(delayedCaptured.status, 200);
    const delayedReceiptId = (await delayedCaptured.json()).data.receiptId;
    await waitFor(async () => (await store.load(delayedReceiptId))?.rebase_outcome === "succeeded",
      "delayed order.paid receipt did not settle");
    assert.equal(queryResult(await state.db.query("SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';"))[0].status,
      "refunded", "a delayed captured snapshot must not reverse the later refunded phase");
    const staleEventId = "razorpay-event-stale-worker-fence";
    const staleReceiptId = "rebase_webhook_receipt:stale_worker_fence";
    await store.createWebhookReceipt(staleReceiptId, {
      provider_account_id: `razorpay:${razorpayConfigId}`,
      event_id: staleEventId,
      provider: "razorpay",
      event: "order.paid",
      config_id: razorpayConfigId,
      target_id: razorpayId,
      payload_hash: crypto.createHash("sha256").update(delayedCapturedBody).digest("hex"),
      normalized_payload: appliedReceipt.normalized_payload,
    });
    const staleLeaseToken = crypto.randomUUID();
    await state.db.query(`UPDATE type::record($id)
      SET rebase_lease_token = type::uuid($lease_token), rebase_lease_until = time::now() + 1m;`, {
      id: staleReceiptId,
      lease_token: staleLeaseToken,
    });
    const staleWorkerReceipt = await store.load(staleReceiptId);
    const currentLeaseToken = crypto.randomUUID();
    await state.db.query(`UPDATE type::record($id)
      SET rebase_lease_token = type::uuid($lease_token), rebase_lease_until = time::now() + 1m
      WHERE rebase_lease_token = type::uuid($previous_lease_token);`, {
      id: staleReceiptId,
      lease_token: currentLeaseToken,
      previous_lease_token: staleLeaseToken,
    });
    assert.equal(String((await store.load(staleReceiptId)).rebase_lease_token), currentLeaseToken);
    await assert.rejects(() => providerReceiptOperation.execute({
      context: { namespace: state.namespace, database: state.database },
      record: staleWorkerReceipt,
      webhooks,
      store,
    }), "a stale receipt lease must abort the target transaction");
    const afterStaleWorker = await store.load(staleReceiptId);
    assert.equal(afterStaleWorker.applied_at, undefined,
      "a stale receipt worker must not mark application complete");
    assert.equal(String(afterStaleWorker.rebase_lease_token), currentLeaseToken,
      "stale receipt work must not overwrite the current worker lease");
    assert.equal(queryResult(await state.db.query("SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';"))[0].status,
      "refunded", "a stale receipt worker must not mutate its target after lease loss");
    await state.db.query(`UPDATE type::record($id)
      SET rebase_lease_until = type::datetime($expired_until)
      WHERE rebase_lease_token = type::uuid($lease_token);`, {
      id: staleReceiptId,
      lease_token: currentLeaseToken,
      expired_until: new Date(Date.now() - 30000).toISOString(),
    });
    const expiredWorkerReceipt = await store.load(staleReceiptId);
    await assert.rejects(() => providerReceiptOperation.execute({
      context: { namespace: state.namespace, database: state.database },
      record: expiredWorkerReceipt,
      webhooks,
      store,
    }), "an expired receipt lease must abort the target transaction");
    const afterExpiredWorker = await store.load(staleReceiptId);
    assert.equal(afterExpiredWorker.applied_at, undefined,
      "an expired receipt worker must not mark application complete");
    assert.equal(String(afterExpiredWorker.rebase_lease_token), currentLeaseToken,
      "an expired receipt worker must not change its lease token");
    assert.equal(queryResult(await state.db.query("SELECT status FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';"))[0].status,
      "refunded", "an expired receipt worker must not mutate its target");
    await state.db.query("DELETE type::record($id);", { id: staleReceiptId });
    const invalidPaidPhaseBody = JSON.stringify({
      ...JSON.parse(razorpayBody),
      payload: {
        ...JSON.parse(razorpayBody).payload,
        payment: { entity: { ...JSON.parse(razorpayBody).payload.payment.entity, status: "authorized" } },
      },
    });
    assert.equal((await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST",
      headers: {
        ...razorpayHeaders,
        "x-razorpay-event-id": "razorpay-event-invalid-paid-phase",
        "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(invalidPaidPhaseBody).digest("hex"),
      },
      body: invalidPaidPhaseBody,
    })).status, 400, "order.paid must reject a non-captured payment snapshot");
    assert.equal((await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST", headers: { ...razorpayHeaders, "x-razorpay-signature": "invalid" }, body: razorpayBody,
    })).status, 401);
    assert.equal((await appRequest("http://runtime/webhooks/unknown-provider", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    })).status, 404, "unknown providers must be rejected at the HTTP boundary");
    const mismatchedBody = JSON.stringify({
      event: "order.paid",
      created_at: razorpayCreatedAt,
      payload: {
        order: { entity: {
          id: "order_other", amount: razorpayOrder.amount_paise, currency: razorpayOrder.currency,
          status: "paid", notes: { rebase_route: razorpayRoute }, created_at: razorpayCreatedAt,
        } },
        payment: { entity: {
          id: "pay_other", order_id: "order_other", amount: razorpayOrder.amount_paise,
          currency: razorpayOrder.currency, status: "captured", created_at: razorpayCreatedAt,
        } },
      },
    });
    assert.equal((await appRequest("http://runtime/webhooks/razorpay", {
      method: "POST",
      headers: { ...razorpayHeaders, "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(mismatchedBody).digest("hex") },
      body: mismatchedBody,
    })).status, 400);
    await stops[0]();
    try {
      await persistentReceiptAdmissionProbe({
        state,
        store,
        contracts,
        webhooks,
        webhookAdapters,
        routeCodec,
        razorpayOrder,
        razorpayRoute,
        webhookSecret: "razorpay-webhook-secret",
      });
    } finally {
      stops[0] = await queue.start((delivery) => runtime.consume(delivery));
    }

    const oneShotId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'One shot', execute_at = time::now() + 45s, priority = 20
    `, { config_id: emailConfigId });
    const initialOneShot = await store.load(oneShotId);
    assert.equal(initialOneShot.priority, 20);
    const initialRevision = String(initialOneShot.revision);
    await runtime.enqueue({ namespace: state.namespace, database: state.database, id: oneShotId });
    const delayedOneShot = await waitFor(async () => (await queue.queue.getJobs(["delayed"]))
      .find((job) => job.data?.locator?.id === oneShotId), "one-shot task was not delayed");
    assert.equal(delayedOneShot.data.revision, initialRevision);

    await state.db.query(`UPDATE ${oneShotId} SET execute_at = time::now() + 10m, priority = 10;`);
    const laterRevision = await waitFor(async () => {
      const row = await store.load(oneShotId);
      return String(row?.revision) !== initialRevision ? row : null;
    }, "pending edit did not rotate the task revision");
    assert.equal(laterRevision.priority, 10);
    assert.notEqual(String(laterRevision.revision), initialRevision);
    const farFuture = await runtime.enqueue({ namespace: state.namespace, database: state.database, id: oneShotId });
    assert.equal(farFuture.state, "outside-horizon");

    await state.db.query(`UPDATE ${oneShotId} SET execute_at = time::now(), priority = 15;`);
    await waitFor(async () => String((await store.load(oneShotId))?.revision) !== String(laterRevision.revision), "reschedule earlier did not rotate the task revision");
    await runtime.enqueue({ namespace: state.namespace, database: state.database, id: oneShotId });
    const oneShotDone = await waitFor(async () => {
      const row = await store.load(oneShotId);
      return row?.rebase_outcome === "succeeded" ? row : null;
    }, "rescheduled one-shot task did not execute", 8000);
    assert.equal(oneShotDone.priority, 15);
    const staleOneShotDelivery = await runtime.consume({ envelope: delayedOneShot.data, attempts: 1 });
    assert.equal(staleOneShotDelivery.state, "stale");

    const lostHintId = await createId(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'Recovered hint', execute_at = time::now() + 2m
    `, { config_id: emailConfigId });
    const lostHints = (await queue.queue.getJobs(["delayed", "wait", "prioritized"]))
      .filter((job) => job.data?.locator?.id === lostHintId);
    await Promise.all(lostHints.map((job) => job.remove()));
    await runtime.reconcile({ namespace: state.namespace, database: state.database });
    await waitFor(async () => (await queue.queue.getJobs(["delayed", "wait", "active", "prioritized"]))
      .some((job) => job.data?.locator?.id === lostHintId), "one-shot reconciliation did not restore a lost Redis hint");

    const stopQueueWorker = stops.pop();
    await stopQueueWorker();
    function deferred() {
      let resolve;
      let reject;
      const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
      return { promise, resolve, reject };
    }
    const gates = new Map();
    const cancellationHandler = {
      timeoutMs: 30000,
      async execute({ record }) {
        const gate = gates.get(record.value);
        gate.started.resolve();
        await gate.release.promise;
        return gate.result;
      },
      async reconcile() {
        return { patch: { result: "reconciled-after-cancel" } };
      },
    };
    const cancellationContract = contracts.get("queued_probe");
    const cancellationHandlers = {
      tables: ["queued_probe"],
      contracts: new Map([["queued_probe", cancellationContract]]),
      get(table) { return table === "queued_probe" ? cancellationHandler : null; },
    };
    const cancellationPublishes = [];
    const cancellationRuntime = createRuntime({
      handlers: cancellationHandlers,
      contracts: cancellationHandlers.contracts,
      stores,
      queue: {
        async publish(envelope, options) {
          cancellationPublishes.push({ envelope, options });
          return { queued: true, jobId: `cancel-${cancellationPublishes.length}` };
        },
      },
      options: {
        leaseMs: 5000,
        allowedContexts: [{ namespace: state.namespace, database: state.database }],
      },
    });
    async function activeCancellation(value, result) {
      const started = deferred();
      const release = deferred();
      gates.set(value, { started, release, result });
      const id = await createId(state.db, "queued_probe", `
        owned_by = rebase_group:root, value = $value, execute_at = time::now() - 1s
      `, { value });
      const execution = cancellationRuntime.execute({ namespace: state.namespace, database: state.database, id });
      await started.promise;
      return { id, release, execution };
    }

    const activeSuccess = await activeCancellation("cancel-active-success", {
      patch: { result: "provider-completed" },
    });
    await state.db.query(`UPDATE ${activeSuccess.id} SET rebase_cancel_requested = true;`);
    const activeCanceledRow = await store.load(activeSuccess.id);
    assert.equal(activeCanceledRow.rebase_status, "running", JSON.stringify(activeCanceledRow));
    activeSuccess.release.resolve();
    assert.equal((await activeSuccess.execution).state, "succeeded");
    assert.equal((await store.load(activeSuccess.id)).result, "provider-completed");

    const activeRetry = await activeCancellation("cancel-active-retry", {
      outcome: "retry", retryAfterMs: 1000, error: { code: "KNOWN_RETRY" },
    });
    await state.db.query(`UPDATE ${activeRetry.id} SET rebase_cancel_requested = true;`);
    activeRetry.release.resolve();
    assert.equal((await activeRetry.execution).state, "cancelled");
    const canceledRetry = await store.load(activeRetry.id);
    assert.equal(canceledRetry.rebase_status, "cancelled");
    assert.equal(canceledRetry.rebase_lease_token, undefined);
    assert.equal(cancellationPublishes.length, 0);

    const activeAmbiguous = await activeCancellation("cancel-active-ambiguous", {
      outcome: "ambiguous", retryAfterMs: 1000, patch: { result: "provider-unknown" },
    });
    await state.db.query(`UPDATE ${activeAmbiguous.id} SET rebase_cancel_requested = true;`);
    activeAmbiguous.release.resolve();
    assert.equal((await activeAmbiguous.execution).state, "ambiguous");
    assert.equal(cancellationPublishes.length, 1);
    await state.db.query(`UPDATE ${activeAmbiguous.id} SET rebase_wake_at = time::now();`);
    assert.equal((await cancellationRuntime.reconcileWebhook({
      namespace: state.namespace, database: state.database, id: activeAmbiguous.id,
    })).state, "succeeded");
    const reconciledAfterCancel = await store.load(activeAmbiguous.id);
    assert.equal(reconciledAfterCancel.rebase_outcome, "succeeded");
    assert.equal(reconciledAfterCancel.result, "reconciled-after-cancel");

    const pageContract = contracts.get("page_probe");
    const pageHandler = {
      async execute({ record }) {
        return { patch: { result: `paged:${record.value}` } };
      },
    };
    const pageHandlers = {
      tables: ["page_probe"],
      contracts: new Map([["page_probe", pageContract]]),
      get(table) { return table === "page_probe" ? pageHandler : null; },
    };
    const pagedHints = [];
    let rejectPageTen = true;
    const pageRuntime = createRuntime({
      handlers: pageHandlers,
      contracts: pageHandlers.contracts,
      stores,
      queue: {
        async publish(envelope) {
          pagedHints.push(envelope.locator.id);
          if (envelope.locator.id === "page_probe:page_10" && rejectPageTen) {
            return { queued: false, state: "capacity" };
          }
          return { queued: true, jobId: `page-${pagedHints.length}` };
        },
      },
      options: {
        allowedContexts: [{ namespace: state.namespace, database: state.database }],
        reconcilePageSize: 2,
      },
    });
    async function createPageTask(key) {
      await state.db.query(`CREATE ONLY page_probe:${key} SET
        owned_by = rebase_group:root, value = $value, execute_at = time::now() + 4m;`, { value: key });
    }
    await createPageTask("page_10");
    await createPageTask("page_20");
    await createPageTask("page_30");
    await createPageTask("page_40");
    await createPageTask("page_50");
    const firstPage = await pageRuntime.reconcile({ namespace: state.namespace, database: state.database });
    assert.deepEqual(firstPage.ids, ["page_probe:page_10", "page_probe:page_20"]);
    assert.equal(firstPage.queued, 1);
    assert.deepEqual(firstPage.deferred, [{ id: "page_probe:page_10", state: "capacity" }]);
    assert.deepEqual((await pageRuntime.reconcile({ namespace: state.namespace, database: state.database })).ids, [
      "page_probe:page_30", "page_probe:page_40",
    ]);
    await createPageTask("page_15");
    assert.deepEqual((await pageRuntime.reconcile({ namespace: state.namespace, database: state.database })).ids, [
      "page_probe:page_50",
    ]);
    rejectPageTen = false;
    const wrappedPage = await pageRuntime.reconcile({ namespace: state.namespace, database: state.database });
    assert.deepEqual(wrappedPage.ids, ["page_probe:page_10", "page_probe:page_15"]);
    assert.equal(wrappedPage.queued, 2);
    assert(wrappedPage.queuedIds.includes("page_probe:page_10"));

    const retentionContract = contracts.get("retention_probe");
    const retentionHandler = {
      async execute() { return { patch: { result: "retention" } }; },
      async reconcile() { return { outcome: "success", patch: { result: "retention-reconciled" } }; },
    };
    const retentionHandlers = {
      tables: ["retention_probe"],
      contracts: new Map([["retention_probe", retentionContract]]),
      get(table) { return table === "retention_probe" ? retentionHandler : null; },
    };
    const createRetentionRuntime = () => createRuntime({
        handlers: retentionHandlers,
        contracts: retentionHandlers.contracts,
        stores,
        queue: { async publish() { return { queued: true, jobId: "retention-probe" }; } },
        options: {
          allowedContexts: [{ namespace: state.namespace, database: state.database }],
          reconcilePageSize: 2,
          terminalTaskRetentionMs: 5000,
        },
      });
    async function createTerminalRetentionRecord(key, outcome) {
      const id = await createId(state.db, "retention_probe", `
        owned_by = rebase_group:root, value = $value, execute_at = time::now() - 1d
      `, { value: key });
      await state.db.query(`UPDATE type::record($id) SET
        rebase_outcome = $outcome, rebase_finished_at = time::now() - 1d;`, { id, outcome });
      return id;
    }
    const retentionOldIds = await Promise.all([
      createTerminalRetentionRecord("retention-old-a", "succeeded"),
      createTerminalRetentionRecord("retention-old-b", "failed"),
      createTerminalRetentionRecord("retention-old-c", "partial"),
      createTerminalRetentionRecord("retention-old-e", "succeeded"),
    ]);
    const cancelledRetentionId = await createId(state.db, "retention_probe", `
      owned_by = rebase_group:root, value = 'retention-old-d', execute_at = time::now() - 1d
    `);
    await state.db.query("UPDATE type::record($id) SET rebase_cancel_requested = true;", { id: cancelledRetentionId });
    const cancelledRetention = await store.load(cancelledRetentionId);
    assert(cancelledRetention.rebase_cancelled_at, "cancellation must have a retention timestamp");
    await new Promise((resolve) => setTimeout(resolve, 5100));
    const recentRetentionId = await createTerminalRetentionRecord("retention-recent", "succeeded");
    await state.db.query("UPDATE type::record($id) SET rebase_finished_at = time::now();", { id: recentRetentionId });
    const ambiguousRetentionId = await createId(state.db, "retention_probe", `
      owned_by = rebase_group:root, value = 'retention-ambiguous', execute_at = time::now() - 40d
    `);
    await state.db.query(`UPDATE type::record($id) SET
      rebase_outcome = 'ambiguous', rebase_wake_at = time::now() - 1d;`, { id: ambiguousRetentionId });
    const leasedRetentionId = await createTerminalRetentionRecord("retention-leased", "succeeded");
    await state.db.query(`UPDATE type::record($id) SET
      rebase_lease_token = rand::uuid::v7(), rebase_lease_until = time::now() + 1h;`, { id: leasedRetentionId });
    const retentionPages = [];
    for (let index = 0; index < 3; index += 1) {
      retentionPages.push(await createRetentionRuntime().reconcile({ namespace: state.namespace, database: state.database }));
    }
    assert.deepEqual(retentionPages.map((result) => result.purged), [2, 2, 1]);
    for (const id of [...retentionOldIds, cancelledRetentionId]) assert.equal(Boolean(await store.load(id)), false);
    assert((await store.load(recentRetentionId)), "recent terminal task must remain queryable");
    assert((await store.load(ambiguousRetentionId)), "ambiguous task must remain available for reconciliation");
    assert((await store.load(leasedRetentionId)), "leased task must never be purged");

    const cursorContract = contracts.get("cursor_probe");
    const cursorHandlers = {
      tables: ["cursor_probe"],
      contracts: new Map([["cursor_probe", cursorContract]]),
      get(table) { return table === "cursor_probe" ? handlers.get(table) : null; },
    };
    const cursorHints = [];
    function createCursorRuntime() {
      return createRuntime({
        handlers: cursorHandlers,
        contracts: cursorHandlers.contracts,
        stores,
        queue: {
          async publish(envelope) {
            cursorHints.push(envelope.locator.id);
            return { queued: true, jobId: `cursor-${cursorHints.length}` };
          },
        },
        options: {
          allowedContexts: [{ namespace: state.namespace, database: state.database }],
          reconcilePageSize: 1,
        },
      });
    }
    for (const key of ["cursor_a", "cursor_b", "cursor_c"]) {
      await state.db.query(`CREATE ONLY cursor_probe:${key} SET
        owned_by = rebase_group:root, value = '${key}', execute_at = time::now() + 4m;`);
    }
    const firstCursorRuntime = createCursorRuntime();
    assert.deepEqual((await firstCursorRuntime.reconcile({
      namespace: state.namespace, database: state.database,
    })).ids, ["cursor_probe:cursor_a"]);
    const persistedCursor = await store.loadReconciliationCursor();
    assert.equal(persistedCursor.cursors.cursor_probe, "cursor_probe:cursor_a");
    assert.equal(persistedCursor.high_water.cursor_probe, "cursor_probe:cursor_c");
    const restartedCursorRuntime = createCursorRuntime();
    assert.deepEqual((await restartedCursorRuntime.reconcile({
      namespace: state.namespace, database: state.database,
    })).ids, ["cursor_probe:cursor_b"]);
    const concurrentCursorPages = await Promise.all([
      createCursorRuntime().reconcile({ namespace: state.namespace, database: state.database }),
      createCursorRuntime().reconcile({ namespace: state.namespace, database: state.database }),
    ]);
    assert.deepEqual(concurrentCursorPages.flatMap((page) => page.ids).sort(), [
      "cursor_probe:cursor_a", "cursor_probe:cursor_c",
    ]);
    const concurrentCursorState = await store.loadReconciliationCursor();
    assert.equal(concurrentCursorState.cursors.cursor_probe, "cursor_probe:cursor_a");
    assert.equal(concurrentCursorState.high_water.cursor_probe, "cursor_probe:cursor_c");

    const isolatedRedis = await startRedis();
    let isolatedRedisChild = isolatedRedis.child;
    const isolatedQueue = createBullMqPort({
      url: isolatedRedis.url,
      prefix: `rebase-restart-probe-${crypto.randomUUID()}`,
    });
    try {
      const isolatedRuntime = createRuntime({
        handlers: pageHandlers,
        contracts: pageHandlers.contracts,
        stores,
        queue: isolatedQueue,
        options: {
          allowedContexts: [{ namespace: state.namespace, database: state.database }],
          reconcilePageSize: 100,
        },
      });
      const redisRecoveryId = "page_probe:page_redis_recovery";
      await state.db.query(`CREATE ONLY ${redisRecoveryId} SET owned_by = rebase_group:root,
        value = 'redis-recovery', execute_at = time::now() + 4m;`);
      let firstRedisAdmission = null;
      for (let attempt = 0; attempt < 4 && !firstRedisAdmission; attempt += 1) {
        const page = await isolatedRuntime.reconcile({ namespace: state.namespace, database: state.database });
        if (page.queuedIds.includes(redisRecoveryId)) firstRedisAdmission = page;
      }
      assert(firstRedisAdmission);
      assert((await isolatedQueue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]))
        .some((job) => job.data?.locator?.id === redisRecoveryId));

      await stopChild(isolatedRedisChild);
      isolatedRedisChild = (await startRedis({ port: isolatedRedis.port, directory: isolatedRedis.directory })).child;
      await waitFor(async () => (await isolatedQueue.health()).ok, "BullMQ did not reconnect after Redis restart");
      assert.equal((await isolatedQueue.queue.getJobs(["wait", "paused", "prioritized", "delayed"])).length, 0);
      const restartedRuntime = createRuntime({
        handlers: pageHandlers,
        contracts: pageHandlers.contracts,
        stores,
        queue: isolatedQueue,
        options: {
          allowedContexts: [{ namespace: state.namespace, database: state.database }],
          reconcilePageSize: 100,
        },
      });
      let restartRecovery = null;
      for (let attempt = 0; attempt < 4 && !restartRecovery; attempt += 1) {
        const page = await restartedRuntime.reconcile({ namespace: state.namespace, database: state.database });
        if (page.queuedIds.includes(redisRecoveryId)) restartRecovery = page;
      }
      assert(restartRecovery);
      await waitFor(async () => (await isolatedQueue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]))
        .some((job) => job.data?.locator?.id === redisRecoveryId), "database reconciliation did not restore Redis-lost work");
    } finally {
      await isolatedQueue.close();
      await stopChild(isolatedRedisChild);
      fs.rmSync(isolatedRedis.directory, { recursive: true, force: true });
    }

    const crashedTaskId = "page_probe:page_crashed_worker";
    await state.db.query(`CREATE ONLY ${crashedTaskId} SET owned_by = rebase_group:root,
      value = 'recover-after-worker-crash', execute_at = time::now() - 1s;`);
    const beforeCrash = await store.load(crashedTaskId);
    const crashedIdentity = {
      executionId: String(beforeCrash.execution_id),
      revision: String(beforeCrash.revision),
    };
    const crashedToken = crypto.randomUUID();
    assert(await store.claim(crashedTaskId, {
      token: crashedToken,
      leaseUntil: Date.now() + 100,
      outcome: "pending",
      ...crashedIdentity,
    }));
    await new Promise((resolve) => setTimeout(resolve, 150));
    const recoveredStarted = deferred();
    const recoveredRelease = deferred();
    const recoveryHandler = {
      timeoutMs: 30000,
      async execute() {
        recoveredStarted.resolve();
        await recoveredRelease.promise;
        return { patch: { result: "recovered-after-worker-crash" } };
      },
    };
    const recoveryHandlers = {
      tables: ["page_probe"],
      contracts: new Map([["page_probe", pageContract]]),
      get(table) { return table === "page_probe" ? recoveryHandler : null; },
    };
    const recoveryRuntime = createRuntime({
      handlers: recoveryHandlers,
      contracts: recoveryHandlers.contracts,
      stores,
      queue: { async publish() { return { queued: true, jobId: "crash-recovery" }; } },
      options: {
        allowedContexts: [{ namespace: state.namespace, database: state.database }],
        leaseMs: 5000,
      },
    });
    const recoveredExecution = recoveryRuntime.execute({
      namespace: state.namespace, database: state.database, id: crashedTaskId,
    });
    await recoveredStarted.promise;
    assert.equal(await store.finalize(
      crashedTaskId,
      crashedToken,
      { result: "late-crashed-worker-result" },
      pageContract.patchFields,
      "succeeded",
      null,
      "pending",
      crashedIdentity,
    ), undefined);
    recoveredRelease.resolve();
    assert.equal((await recoveredExecution).state, "succeeded");
    const recoveredTask = await store.load(crashedTaskId);
    assert.equal(recoveredTask.rebase_attempt, 2);
    assert.equal(recoveredTask.result, "recovered-after-worker-crash");

    const providerStartedTaskId = "page_probe:page_provider_started_recovery";
    await state.db.query(`CREATE ONLY ${providerStartedTaskId} SET owned_by = rebase_group:root,
      value = 'recover-ambiguous-after-provider-start', execute_at = time::now() - 1s;`);
    const providerStartedTask = await store.load(providerStartedTaskId);
    const providerStartedIdentity = {
      executionId: String(providerStartedTask.execution_id),
      revision: String(providerStartedTask.revision),
    };
    const providerStartedSignal = deferred();
    const providerRelease = deferred();
    const providerHints = [];
    let providerCalls = 0;
    const providerRecoveryHandler = {
      timeoutMs: 30000,
      async execute({ adapters }) {
        await adapters.sendBrevoEmail({ to: "probe@example.test", idempotencyKey: "provider-start-recovery" });
        return { patch: { result: "provider-returned" } };
      },
      async reconcile() {
        return { outcome: "ambiguous" };
      },
    };
    const providerRecoveryContract = { ...pageContract, adapters: ["sendBrevoEmail"] };
    const providerRecoveryHandlers = {
      tables: ["page_probe"],
      contracts: new Map([["page_probe", providerRecoveryContract]]),
      get(table) { return table === "page_probe" ? providerRecoveryHandler : null; },
    };
    const providerRecoveryRuntime = createRuntime({
      handlers: providerRecoveryHandlers,
      contracts: providerRecoveryHandlers.contracts,
      stores,
      queue: {
        async publish(envelope) {
          providerHints.push(envelope);
          return { queued: true, jobId: `provider-recovery-${providerHints.length}` };
        },
      },
      adapters: {
        async sendBrevoEmail() {
          providerCalls += 1;
          providerStartedSignal.resolve();
          await providerRelease.promise;
          return { messageId: "provider-response-after-worker-loss" };
        },
      },
      options: {
        allowedContexts: [{ namespace: state.namespace, database: state.database }],
        leaseMs: 5000,
      },
    });
    const providerExecution = providerRecoveryRuntime.execute({
      namespace: state.namespace, database: state.database, id: providerStartedTaskId,
    });
    await providerStartedSignal.promise;
    const providerInFlight = await store.load(providerStartedTaskId);
    assert(providerInFlight.rebase_provider_started_at);
    assert.equal(providerInFlight.rebase_status, "running");
    await state.db.query(`UPDATE ${providerStartedTaskId}
      SET rebase_cancel_requested = true, rebase_lease_until = time::now() - 1s;`);
    const expiredProviderAttempt = await store.load(providerStartedTaskId);
    assert.equal(expiredProviderAttempt.rebase_status, "ambiguous");
    assert.equal((await providerRecoveryRuntime.enqueue({
      namespace: state.namespace, database: state.database, id: providerStartedTaskId,
    })).queued, true);
    const providerRecovery = await providerRecoveryRuntime.execute({
      namespace: state.namespace, database: state.database, id: providerStartedTaskId,
    });
    assert.equal(providerRecovery.state, "ambiguous");
    assert.equal(providerCalls, 1);
    assert.equal(providerHints.at(-1).revision === providerStartedIdentity.revision, false);
    providerRelease.resolve();
    assert.equal((await providerExecution).state, "stale");
    const providerQuarantine = await store.load(providerStartedTaskId);
    assert.equal(providerQuarantine.rebase_outcome, "ambiguous");
    assert.equal(providerQuarantine.rebase_error.code, "WORKER_LOST_AFTER_PROVIDER_START");
    assert.equal(providerQuarantine.rebase_cancel_requested, true);
    assert.equal(providerQuarantine.rebase_provider_started_at, undefined);
    assert.equal(providerQuarantine.rebase_lease_token, undefined);

    const cancelledBeforeProviderId = "page_probe:page_cancel_before_provider_start";
    await state.db.query(`CREATE ONLY ${cancelledBeforeProviderId} SET owned_by = rebase_group:root,
      value = 'cancel-before-provider-start', execute_at = time::now() - 1s;`);
    const preparationStarted = deferred();
    const preparationRelease = deferred();
    let cancelledProviderCalls = 0;
    const cancelledBeforeProviderHandler = {
      timeoutMs: 30000,
      async execute({ adapters }) {
        preparationStarted.resolve();
        await preparationRelease.promise;
        await adapters.sendBrevoEmail({ to: "probe@example.test", idempotencyKey: "cancel-before-provider-start" });
        return { patch: { result: "should-not-send" } };
      },
    };
    const cancelledBeforeProviderHandlers = {
      tables: ["page_probe"],
      contracts: new Map([["page_probe", providerRecoveryContract]]),
      get(table) { return table === "page_probe" ? cancelledBeforeProviderHandler : null; },
    };
    const cancelledBeforeProviderRuntime = createRuntime({
      handlers: cancelledBeforeProviderHandlers,
      contracts: cancelledBeforeProviderHandlers.contracts,
      stores,
      queue: { async publish() { return { queued: true, jobId: "cancel-before-provider" }; } },
      adapters: {
        async sendBrevoEmail() {
          cancelledProviderCalls += 1;
          return { messageId: "must-not-be-called" };
        },
      },
      options: { allowedContexts: [{ namespace: state.namespace, database: state.database }] },
    });
    const cancelledBeforeProviderExecution = cancelledBeforeProviderRuntime.execute({
      namespace: state.namespace, database: state.database, id: cancelledBeforeProviderId,
    });
    await preparationStarted.promise;
    await state.db.query(`UPDATE ${cancelledBeforeProviderId} SET rebase_cancel_requested = true;`);
    preparationRelease.resolve();
    assert.equal((await cancelledBeforeProviderExecution).state, "cancelled");
    const cancelledBeforeProvider = await store.load(cancelledBeforeProviderId);
    assert.equal(cancelledProviderCalls, 0);
    assert.equal(cancelledBeforeProvider.rebase_status, "cancelled");
    assert.equal(cancelledBeforeProvider.rebase_provider_started_at, undefined);
    assert.equal(cancelledBeforeProvider.rebase_lease_token, undefined);

    stops.push(await queue.start((delivery) => runtime.consume(delivery)));

    let connects = 0;
    const directory = createStoreDirectory({
      async connect() {
        connects += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return { async close() {} };
      },
    });
    const burst = await Promise.all(Array.from({ length: 50 }, () => directory.forContext("tenant", "db")));
    assert.equal(connects, 1);
    assert(burst.every((item) => item === burst[0]));
    await directory.close();

    let failedConnects = 0;
    const failedDirectory = createStoreDirectory({
      async connect() {
        failedConnects += 1;
        throw new Error("intentional connection failure");
      },
      maxContexts: 1,
    });
    await assert.rejects(failedDirectory.forContext("failed", "db"), /intentional connection failure/);
    await assert.rejects(failedDirectory.forContext("failed", "db"), /intentional connection failure/);
    assert.equal(failedConnects, 2);
    await failedDirectory.close();

    let activeClosed = false;
    const idleDirectory = createStoreDirectory({
      idleMs: 1,
      async connect() {
        return {
          async health() { await new Promise((resolve) => setTimeout(resolve, 10)); return true; },
          async close() { activeClosed = true; },
        };
      },
    });
    const activeStore = await idleDirectory.forContext("active", "db");
    const inFlight = activeStore.health();
    await new Promise((resolve) => setTimeout(resolve, 3));
    await idleDirectory.sweep();
    assert.equal(activeClosed, false);
    await inFlight;
    await new Promise((resolve) => setTimeout(resolve, 3));
    await idleDirectory.sweep();
    assert.equal(activeClosed, true);
    await idleDirectory.close();

    const ready = await appRequest("http://runtime/readyz");
    assert.equal(ready.status, 200);
    const missingAdapterApp = createRuntimeApp({
      runtime,
      handlers,
      webhooks,
      adapters: { ...adapters, sendBrevoEmail: undefined },
      webhookAdapters,
      queue,
      runtimeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      readinessContexts: [{ namespace: state.namespace, database: state.database }],
      allowBearer: true,
    });
    const missingAdapterReadiness = await requestHandler(missingAdapterApp, "http://runtime/readyz");
    assert.equal(missingAdapterReadiness.status, 503);
    assert.deepEqual((await missingAdapterReadiness.json()).adapters.missing, ["sendBrevoEmail"]);
    const missingBucketApp = createRuntimeApp({
      runtime,
      handlers,
      webhooks,
      adapters,
      webhookAdapters,
      adapterConfiguration: { requiresStorageBucket: true },
      queue,
      runtimeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      readinessContexts: [{ namespace: state.namespace, database: state.database }],
      allowBearer: true,
    });
    const missingBucketReadiness = await requestHandler(missingBucketApp, "http://runtime/readyz");
    assert.equal(missingBucketReadiness.status, 503);
    assert.deepEqual((await missingBucketReadiness.json()).adapters.missingConfiguration, ["REBASE_STORAGE_BUCKET"]);
    const missingWebhookRoutingApp = createRuntimeApp({
      runtime,
      handlers,
      webhooks,
      adapters,
      webhookAdapters: {},
      queue,
      runtimeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      readinessContexts: [{ namespace: state.namespace, database: state.database }],
      allowBearer: true,
    });
    const missingWebhookReadiness = await requestHandler(missingWebhookRoutingApp, "http://runtime/readyz");
    assert.equal(missingWebhookReadiness.status, 503);
    assert.equal((await missingWebhookReadiness.json()).webhooks.ok, false);

    gatewayRestartRedis = await startRedis();
    gatewayRestartRedisChild = gatewayRestartRedis.child;
    const gatewayRestartPrefix = `rebase-gateway-restart-${crypto.randomUUID()}`;
    gatewayRestartQueue = createBullMqPort({ url: gatewayRestartRedis.url, prefix: gatewayRestartPrefix });
    const childPort = await freePort();
    const childEnvironment = {
      ...process.env,
      SURREAL_ENDPOINT: state.endpoint,
      SURREAL_USERNAME: "root",
      SURREAL_PASSWORD: "root",
      SURREAL_NAMESPACE: state.namespace,
      SURREAL_DATABASE: state.database,
      REBASE_RUNTIME_URL: `http://127.0.0.1:${childPort}`,
      REBASE_RUNTIME_SECRET: secret,
      REBASE_AUTHENTICATION_PAYLOAD_SECRET: "runtime-probe-server-payload-secret",
      REBASE_QUEUE_REDIS_URL: gatewayRestartRedis.url,
      REBASE_QUEUE_PREFIX: gatewayRestartPrefix,
      REBASE_RECONCILE_INTERVAL_MS: "1000",
      REBASE_STORAGE_BUCKET: "runtime-probe-bucket",
      REBASE_HTTP_PORT: String(childPort),
      REBASE_HTTP_BODY_LIMIT_BYTES: "2048",
    };
    const runtimeProfile = path.join(redis.directory, "runtime.env");
    fs.writeFileSync(runtimeProfile, Object.entries(childEnvironment)
      .filter(([name]) => /^(?:SURREAL_|REBASE_|NODE_ENV$)/.test(name))
      .map(([name, profileValue]) => `${name}=${profileValue}`)
      .join("\n"));
    const inheritedEnvironment = Object.fromEntries(Object.entries(process.env)
      .filter(([name]) => !/^(?:SURREAL_|REBASE_|NODE_ENV$)/.test(name)));
    const obsoleteArgument = spawnSync(process.execPath, [
      "gateway/server.js", "--env-file", runtimeProfile,
    ], {
      cwd: path.resolve(__dirname, ".."),
      env: inheritedEnvironment,
      encoding: "utf8",
    });
    assert.notEqual(obsoleteArgument.status, 0);
    assert.match(obsoleteArgument.stderr, /Use Node options before gateway\/server\.js/);
    runtimeChild = spawn(process.execPath, ["--env-file", runtimeProfile, "gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."), env: inheritedEnvironment, stdio: ["ignore", "ignore", "pipe"],
    });
    await waitForPort(childPort, runtimeChild, "ReBase server");
    assert.equal((await fetch(`http://127.0.0.1:${childPort}/healthz`)).status, 200);
    await waitFor(async () => (await fetch(`http://127.0.0.1:${childPort}/readyz`)).status === 200, "real server did not become ready");
    assert.equal((await fetch(`http://127.0.0.1:${childPort}/internal/wake/task`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: JSON.stringify({ padding: "x".repeat(3000) }),
    })).status, 413);

    const conflicting = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...childEnvironment, REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-conflict` },
      stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(conflicting), 0);

    const missingSecretEnvironment = { ...childEnvironment, REBASE_HTTP_PORT: String(await freePort()) };
    delete missingSecretEnvironment.REBASE_RUNTIME_SECRET;
    const missingSecret = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."), env: missingSecretEnvironment, stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(missingSecret), 0);

    const missingPayloadSecretEnvironment = {
      ...childEnvironment,
      NODE_ENV: "production",
      REBASE_HTTP_PORT: String(await freePort()),
      REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-missing-payload-secret`,
    };
    delete missingPayloadSecretEnvironment.REBASE_AUTHENTICATION_PAYLOAD_SECRET;
    const missingPayloadSecret = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: missingPayloadSecretEnvironment,
      stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(missingPayloadSecret), 0);

    const productionPort = await freePort();
    const productionServer = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...childEnvironment, NODE_ENV: "production", REBASE_HTTP_PORT: String(productionPort), REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-production` },
      stdio: ["ignore", "ignore", "ignore"],
    });
    await waitForPort(productionPort, productionServer, "production ReBase server");
    assert.equal((await fetch(`http://127.0.0.1:${productionPort}/healthz`)).status, 200);
    await stopChild(productionServer);

    const unavailableRedis = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: {
        ...childEnvironment,
        REBASE_HTTP_PORT: String(await freePort()),
        REBASE_QUEUE_REDIS_URL: `redis://127.0.0.1:${await freePort()}`,
        REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-unavailable`,
        REBASE_QUEUE_STARTUP_TIMEOUT_MS: "300",
        REBASE_QUEUE_REDIS_CONNECT_TIMEOUT_MS: "200",
      },
      stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(unavailableRedis), 0);

    runtimeChild.kill("SIGTERM");
    assert.equal(await waitForExit(runtimeChild), 0);
    runtimeChild = null;

    const processLossTask = await createAndReload(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id),
      to = ['process-loss@example.test'], subject = 'Process loss recovery'
    `, { config_id: emailConfigId });
    const processLossTaskId = recordId(processLossTask);
    const providerRequests = new Map();
    let providerRequestCount = 0;
    const providerRequestSeen = deferred();
    processProviderServer = await listenHandler(async (request, response) => {
      if (request.method !== "POST" || request.url !== "/smtp/email") {
        response.writeHead(404).end();
        return;
      }
      let rawBody = "";
      for await (const chunk of request) rawBody += chunk.toString();
      providerRequestCount += 1;
      const idempotencyKey = String(JSON.parse(rawBody).headers?.idempotencyKey || "");
      const receipt = { messageId: `provider-${providerRequests.size + 1}` };
      providerRequests.set(idempotencyKey, receipt);
      providerRequestSeen.resolve(idempotencyKey);
      // Hold the response open: the fake provider accepted the call, but the worker cannot commit it.
    });
    const workerReady = deferred();
    let workerStderr = "";
    let workerErrorMessage = "";
    let workerExecutionResult;
    processWorkerChild = spawn(process.execPath, ["dev-tools/runtime-probe-worker.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: {
        ...process.env,
        SURREAL_ENDPOINT: state.endpoint,
        SURREAL_USERNAME: "root",
        SURREAL_PASSWORD: "root",
        SURREAL_NAMESPACE: state.namespace,
        SURREAL_DATABASE: state.database,
        REBASE_WORKER_PROVIDER_URL: `${processProviderServer.baseUrl}/smtp/email`,
        REBASE_WORKER_LEASE_MS: "750",
      },
      stdio: ["ignore", "ignore", "pipe", "ipc"],
    });
    processWorkerChild.stderr.on("data", (chunk) => { workerStderr += chunk.toString(); });
    processWorkerChild.on("message", (message) => {
      if (message?.type === "ready") workerReady.resolve(message);
      else if (message?.type === "done") workerExecutionResult = message.result;
      else if (message?.type === "error") {
        workerErrorMessage = String(message.message || "worker runtime error");
        workerReady.reject(new Error(workerErrorMessage));
      }
    });
    processWorkerChild.on("exit", (code, signal) => {
      if (processWorkerChild && processWorkerChild.signalCode !== "SIGKILL" && code !== 0) {
        workerReady.reject(new Error(`worker probe exited before ready (${signal || code}): ${workerStderr}`));
      }
    });
    const readyTimeout = setTimeout(() => workerReady.reject(new Error(`worker probe did not become ready: ${workerStderr}`)), 5000);
    try {
      await workerReady.promise;
    } finally {
      clearTimeout(readyTimeout);
    }
    processWorkerChild.send({ type: "run", taskId: processLossTaskId });
    const providerSeenTimeout = setTimeout(() => {
      const details = [
        workerErrorMessage,
        workerExecutionResult ? `worker result: ${JSON.stringify(workerExecutionResult)}` : "",
      ].filter(Boolean).join("; ");
      providerRequestSeen.reject(new Error(
        `worker did not reach the fake provider${details ? `: ${details}` : ""}`,
      ));
    }, 5000);
    let providerIdempotencyKey;
    try {
      providerIdempotencyKey = await providerRequestSeen.promise;
    } finally {
      clearTimeout(providerSeenTimeout);
    }
    assert.equal(providerIdempotencyKey, String(processLossTask.execution_id));
    const startedAttempt = await store.load(processLossTaskId);
    assert(startedAttempt.rebase_provider_started_at, "provider call arrived before the database start marker");
    assert(new Date(startedAttempt.rebase_lease_until).getTime() > Date.now());
    processWorkerChild.kill("SIGKILL");
    await waitForExit(processWorkerChild);
    assert.equal(processWorkerChild.signalCode, "SIGKILL");
    processWorkerChild = null;
    await processProviderServer.close();
    processProviderServer = null;
    const expiredAttempt = await waitFor(async () => {
      const row = await store.load(processLossTaskId);
      return row?.rebase_provider_started_at
        && new Date(row.rebase_lease_until).getTime() <= Date.now()
        ? row
        : null;
    }, "killed worker lease did not expire", 5000);
    assert(expiredAttempt.rebase_provider_started_at);
    assert(new Date(expiredAttempt.rebase_lease_until).getTime() <= Date.now());
    const processRecoveryHandlers = loadTableHandlers("build/test/table-handlers", { contracts, mutable: true });
    const emailHandler = processRecoveryHandlers.get("send_brevo_email").implementation;
    processRecoveryHandlers.unregister("send_brevo_email");
    processRecoveryHandlers.register({
      ...emailHandler,
      async reconcile({ record }) {
        const receipt = providerRequests.get(String(record.execution_id));
        if (!receipt) return { outcome: "retry", retryAfterMs: 1000 };
        return {
          outcome: "success",
          patch: { provider_reference: receipt.messageId, provider_state: "accepted" },
        };
      },
    }, { label: "runtime-probe/process-loss-recovery" });
    const processRecoveryRuntime = createRuntime({
      handlers: processRecoveryHandlers,
      contracts,
      stores,
      adapters,
      queue: { async publish() { return { queued: true, jobId: "process-loss-recovery" }; } },
      options: { leaseMs: 1000, allowedContexts: [{ namespace: state.namespace, database: state.database }] },
    });
    const quarantine = await processRecoveryRuntime.execute({
      namespace: state.namespace, database: state.database, id: processLossTaskId,
    });
    assert.equal(quarantine.state, "ambiguous");
    const quarantinedRow = await store.load(processLossTaskId);
    assert.equal(quarantinedRow.rebase_outcome, "ambiguous");
    assert.notEqual(quarantinedRow.revision, processLossTask.revision);
    assert.equal(providerRequests.size, 1, "worker recovery must not repeat the provider submission");
    assert.equal(providerRequestCount, 1, "provider must receive exactly one submission");
    const processLossRecovered = await processRecoveryRuntime.execute({
      namespace: state.namespace, database: state.database, id: processLossTaskId,
    });
    assert.equal(processLossRecovered.state, "succeeded");
    const processLossResult = await store.load(processLossTaskId);
    assert.equal(processLossResult.provider_reference, "provider-1");
    assert.equal(processLossResult.rebase_outcome, "succeeded");
    assert.equal(providerRequests.size, 1);
    assert.equal(providerRequestCount, 1);

    runtimeChild = spawn(process.execPath, ["--env-file", runtimeProfile, "gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."), env: inheritedEnvironment, stdio: ["ignore", "ignore", "pipe"],
    });
    await waitForPort(childPort, runtimeChild, "ReBase server for restart recovery");
    await waitFor(async () => (await fetch(`http://127.0.0.1:${childPort}/readyz`)).status === 200,
      "gateway for restart recovery did not become ready");

    const gatewayRestartTask = await createAndReload(state.db, "send_brevo_email", `
      owned_by = rebase_group:root, config = type::record($config_id),
      to = ['gateway-restart@example.test'], subject = 'Gateway restart recovery',
      execute_at = time::now() + 4m
    `, { config_id: emailConfigId });
    const gatewayRestartTaskId = recordId(gatewayRestartTask);
    await waitFor(async () => (await gatewayRestartQueue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]))
      .some((job) => job.data?.locator?.id === gatewayRestartTaskId),
    "first gateway process did not publish the delayed task hint", 30000);
    const cursorBeforeGatewayRestart = await store.loadReconciliationCursor();
    assert(cursorBeforeGatewayRestart.version > 0);

    runtimeChild.kill("SIGKILL");
    await waitForExit(runtimeChild);
    assert.equal(runtimeChild.signalCode, "SIGKILL");
    runtimeChild = null;
    await stopChild(gatewayRestartRedisChild);
    gatewayRestartRedisChild = (await startRedis({
      port: gatewayRestartRedis.port,
      directory: gatewayRestartRedis.directory,
    })).child;
    await waitFor(async () => (await gatewayRestartQueue.health()).ok,
      "gateway queue monitor did not reconnect after Redis restart");
    assert.equal((await gatewayRestartQueue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]))
      .some((job) => job.data?.locator?.id === gatewayRestartTaskId), false,
    "restarted Redis should have lost its in-memory task hint");

    runtimeChild = spawn(process.execPath, ["--env-file", runtimeProfile, "gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."), env: inheritedEnvironment, stdio: ["ignore", "ignore", "pipe"],
    });
    await waitForPort(childPort, runtimeChild, "ReBase server after gateway restart");
    await waitFor(async () => (await fetch(`http://127.0.0.1:${childPort}/readyz`)).status === 200,
      "restarted gateway did not become ready");
    const gatewayRestartRecovery = await waitFor(async () => {
      const jobs = await gatewayRestartQueue.queue.getJobs(["wait", "paused", "prioritized", "delayed"]);
      const cursor = await store.loadReconciliationCursor();
      const restored = jobs.find((job) => job.data?.locator?.id === gatewayRestartTaskId);
      return restored && Number(cursor.version) > Number(cursorBeforeGatewayRestart.version)
        ? { job: restored, cursor }
        : null;
    }, "restarted gateway did not restore the hint from persisted reconciliation state", 30000);
    assert.equal(gatewayRestartRecovery.job.data.locator.id, gatewayRestartTaskId);
    assert(Number(gatewayRestartRecovery.cursor.version) > Number(cursorBeforeGatewayRestart.version));
    const gatewayRestartTaskState = await store.load(gatewayRestartTaskId);
    assert.equal(gatewayRestartTaskState.rebase_outcome, undefined);

    runtimeChild.kill("SIGTERM");
    assert.equal(await waitForExit(runtimeChild), 0);
    runtimeChild = null;
    console.log("runtime: operation tasks, bounded terminal retention, durable attachment cleanup, worker and gateway process recovery, cancellation/reconciliation, one-shot timing, cross-client admission, durable keyset recovery, Redis restart, revision fencing, authentication, effects, webhooks, readiness, and context races passed");
  } finally {
    await stopChild(processWorkerChild);
    if (processProviderServer?.server.listening) await processProviderServer.close().catch(() => {});
    await stopChild(runtimeChild);
    await gatewayRestartQueue?.close().catch(() => {});
    await stopChild(gatewayRestartRedisChild);
    if (gatewayRestartRedis?.directory) fs.rmSync(gatewayRestartRedis.directory, { recursive: true, force: true });
    if (httpServer?.listening) await new Promise((resolve) => httpServer.close(resolve));
    await Promise.all(stops.map((stop) => stop?.()));
    await authenticationRateLimiter.close();
    await queue.close();
    await state.db.close().catch(() => {});
    await stopChild(state.child);
    await stopChild(redis.child);
    fs.rmSync(redis.directory, { recursive: true, force: true });
  }
}

if (require.main === module) main().then(
  () => process.exit(0),
  (error) => { console.error(`runtime: FAIL: ${process.env.REBASE_RUNTIME_PROBE_DEBUG ? error.stack : error.message}`); process.exit(1); },
);

module.exports = { main };
