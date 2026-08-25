#!/usr/bin/env node

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { serve } = require("@hono/node-server");
const { Surreal } = require("surrealdb");
const { createRuntimeApp } = require("../gateway/app");
const { createStoreDirectory, fixedStoreDirectory } = require("../gateway/directory");
const { loadTableHandlers } = require("../gateway/handlers");
const { createLocalProviders } = require("../gateway/providers/local");
const { createRealProviders } = require("../gateway/providers/real");
const { createBullMqPort } = require("../gateway/queues/bullmq");
const { createRuntime } = require("../gateway/runtime");
const { createTableStore } = require("../gateway/store");
const { queryResult } = require("../gateway/utils");
const { loadMaterials } = require("./compiler/materials");
const { generateBundle } = require("./compiler/pipeline");

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
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
  if (!child || child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.kill("SIGTERM");
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 2000))]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

async function waitForExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null) return child.exitCode;
  return Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error("Child process did not exit")), timeoutMs)),
  ]);
}

async function startRedis() {
  const port = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-redis-"));
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

async function realProviderMappingProbe() {
  let request;
  const providers = createRealProviders({
    fetch: async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify({ messageId: "probe-message" }), { status: 201 });
    },
  });
  const email = await providers.email.forTable("email_brevo_config").sendMessage({
    config: { api_key: "database-api-key", from_email: "from@example.com", from_name: "Probe" },
    message: { to: ["to@example.com"], subject: "Probe", text: "Body" },
  });
  assert.equal(request.options.headers["api-key"], "database-api-key");
  assert.deepEqual(email.accepted, ["to@example.com"]);
  const grant = await providers.storage.createAccessGrant({
    config: {
      provider: "s3-compatible",
      bucket: "probe",
      access_key_id: "database-access-key",
      secret_access_key: "database-secret",
      endpoint: "https://storage.example.com",
      region: "probe-1",
    },
    objectKey: "probe.txt",
    expiresIn: 60,
  });
  assert.equal(grant.provider, "s3-compatible");
  assert.match(grant.accessUrl, /probe\/probe\.txt/);
}

async function main() {
  await realProviderMappingProbe();
  const runtimePort = await freePort();
  const redis = await startRedis();
  const state = await startDatabase(runtimePort);
  const secret = "runtime-probe-secret";
  const materials = loadMaterials({ groups: [
    { name: "framework", roots: ["framework"] },
    { name: "project", roots: ["designs/test"] },
  ] });
  const generated = generateBundle(materials, {
    context: { runtimeUrl: `http://127.0.0.1:${runtimePort}`, runtimeSecret: secret },
  });
  const contracts = new Map(Object.entries(generated.contracts.tables));
  const handlers = loadTableHandlers("designs/test/table-handlers", { contracts });
  const queueErrors = [];
  const queue = createBullMqPort({
    url: redis.url,
    prefix: `rebase-probe-${Date.now().toString(36)}`,
    onError: (error) => queueErrors.push(error.message),
    onFailed: ({ lane, error }) => queueErrors.push(`${lane}:${error.message}`),
  });
  const providers = createLocalProviders({ webhookSecret: secret });
  const originalProvider = providers.email.forResource.bind(providers.email);
  let emailCalls = 0;
  let failNextEmail = false;
  let failPermanently = false;
  providers.email.forResource = (resource) => {
    const provider = originalProvider(resource);
    return {
      ...provider,
      async sendMessage(input) {
        emailCalls += 1;
        if (failPermanently) {
          throw Object.assign(new Error("Permanent provider failure"), { code: "PROVIDER_REJECTED", status: 400 });
        }
        if (failNextEmail) {
          failNextEmail = false;
          throw Object.assign(new Error("Temporary provider failure"), { code: "PROVIDER_TEMPORARY", retryable: true });
        }
        return provider.sendMessage(input);
      },
    };
  };
  const store = createTableStore({ db: state.db });
  const stores = fixedStoreDirectory(store, state);
  const runtime = createRuntime({
    handlers,
    providers,
    queue,
    stores,
    contracts,
    options: {
      leaseMs: 5000,
      allowedContexts: [{ namespace: state.namespace, database: state.database }],
    },
  });
  let wakeCalls = 0;
  const enqueue = runtime.enqueue;
  runtime.enqueue = async (...args) => { wakeCalls += 1; return enqueue(...args); };
  const stops = [];
  for (const lane of ["task", "schedule", "webhook"]) stops.push(await queue.start(lane, (delivery) => runtime.consume(lane, delivery)));
  const app = createRuntimeApp({
    runtime, handlers, providers, queue, wakeSecret: secret,
    defaultContext: { namespace: state.namespace, database: state.database },
    allowBearer: true,
  });
  const httpServer = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: runtimePort });
  let runtimeChild;
  try {
    await state.db.query(generated.bundle);
    await assert.rejects(
      state.db.query("CREATE file_storage_config:missing_credential SET owned_by = groups:root, bucket = 'probe';"),
      /access_key_id|secret_access_key|endpoint|region|field|schema|required/i,
    );
    await assert.rejects(
      state.db.query("CREATE email_brevo_config:missing_api_key SET owned_by = groups:root, label = 'Missing', from_email = 'missing@example.com', from_name = 'Missing', provider_account_id = 'missing';"),
      /api_key|field|schema|required/i,
    );
    await state.db.query(`
      CREATE file_storage_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590da' SET owned_by = groups:root, bucket = 'probe', visibility = true, access_key_id = 'client-storage-id', secret_access_key = 'client-storage-secret', endpoint = 'https://storage.local', region = 'local';
      CREATE email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db' SET owned_by = groups:root, label = 'Probe', visibility = true, from_email = 'from@example.com', from_name = 'Probe', api_key = 'client-brevo-api-key', provider_account_id = 'probe';
      CREATE groups:runtime_clients SET name = 'Runtime Clients', parents = [groups:root], role = [
        'send_brevo_email_create', 'send_brevo_email_select', 'send_brevo_email_update',
        'email_brevo_config_select', 'file_storage_config_select'
      ];
      CREATE user:runtime_client SET name = 'Runtime Client', email = 'runtime-client@example.com',
        password = crypto::argon2::generate('runtime-password'), parents = [groups:runtime_clients], login_access = true;
      CREATE email_brevo_config:runtime_client SET owned_by = groups:root, label = 'Client Probe', visibility = true,
        from_email = 'client@example.com', from_name = 'Client', api_key = 'customer-brevo-api-key', provider_account_id = 'runtime-client';
    `);

    const storageId = "file_storage_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590da'";
    const emailConfigId = "email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db'";
    const syncId = "file_access_grant:u'0198c6c4-bd70-7d6d-8a7a-87bb773590dc'";
    const sync = await runtime.sync({
      namespace: state.namespace, database: state.database, id: syncId,
      record: { id: syncId, storage_config: storageId, object_key: "invoice/direct.pdf", expires_in: 60 },
    });
    assert.equal(sync.outcome, "success");
    assert.match(sync.patch.access_url, /storage\.local\/access/);

    const automaticSyncId = "file_access_grant:u'0198c6c4-bd70-7d6d-8a7a-87bb773590dd'";
    const automaticSync = queryResult(await state.db.query(`
      CREATE ONLY ${automaticSyncId} SET owned_by = groups:root, storage_config = ${storageId}, object_key = 'invoice/automatic.pdf', expires_in = 60;
      RETURN (SELECT * FROM ${automaticSyncId})[0];
    `));
    assert.match(automaticSync.access_url, /storage\.local\/access/);

    const automaticId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590de'";
    await state.db.query(`CREATE ${automaticId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Automatic';`);
    let automaticLast;
    const automatic = await waitFor(async () => {
      const row = await store.load(automaticId);
      automaticLast = row;
      if (process.env.REBASE_DEBUG && row) console.error("automatic", row);
      return row?.rebase_outcome === "succeeded" ? row : null;
    }, () => `automatic async effect did not finish (${JSON.stringify({ automaticLast, wakeCalls, queueErrors })})`);
    assert.equal(automatic.rebase_status, "succeeded");
    assert(automatic.provider_reference);

    await state.db.query("REMOVE EVENT rebase_effect_send_brevo_email ON TABLE send_brevo_email;");
    const duplicateId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590df'";
    await state.db.query(`CREATE ${duplicateId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Duplicate';`);
    const callsBefore = emailCalls;
    const duplicate = await Promise.all([
      runtime.execute({ namespace: state.namespace, database: state.database, id: duplicateId }, { attempts: 1, maxAttempts: 5 }),
      runtime.execute({ namespace: state.namespace, database: state.database, id: duplicateId }, { attempts: 1, maxAttempts: 5 }),
    ]);
    assert.equal(emailCalls, callsBefore + 1);
    assert(duplicate.some((result) => result.state === "succeeded"));
    assert(duplicate.some((result) => result.state === "busy"));

    const client = new Surreal();
    await client.connect(state.endpoint);
    await client.signin({
      namespace: state.namespace,
      database: state.database,
      access: "account",
      variables: { email: "runtime-client@example.com", password: "runtime-password" },
    });
    try {
      const clientId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e4'";
      assert.equal(queryResult(await client.query(
        "RETURN type::is_none(email_brevo_config:runtime_client.api_key);",
      )), true);
      const visibleStorage = queryResult(await client.query(`SELECT id, bucket, access_key_id, secret_access_key, endpoint, region FROM ${storageId};`))[0];
      assert.equal(String(visibleStorage.id).split(":", 1)[0], "file_storage_config");
      assert.equal(visibleStorage.access_key_id, undefined);
      assert.equal(visibleStorage.secret_access_key, undefined);
      assert.equal(visibleStorage.endpoint, undefined);
      assert.equal(visibleStorage.region, undefined);
      await client.query("UPDATE email_brevo_config:runtime_client SET api_key = 'client-must-not-write';");
      assert.equal(queryResult(await state.db.query("RETURN email_brevo_config:runtime_client.api_key;")), "customer-brevo-api-key");
      const clientCreated = queryResult(await client.query(`
        CREATE ONLY ${clientId} SET
          owned_by = user:runtime_client,
          config = email_brevo_config:runtime_client,
          to = ['client@example.com'],
          subject = 'Client lifecycle',
          rebase_cancel_requested = true,
          rebase_outcome = 'succeeded',
          rebase_lease_token = rand::uuid::v7(),
          rebase_lease_until = time::now() + 1h
        RETURN AFTER;
      `));
      assert.notEqual(clientCreated.rebase_cancel_requested, true);
      assert.equal(clientCreated.rebase_outcome, undefined);
      assert.equal(clientCreated.rebase_lease_token, undefined);
      assert.equal(clientCreated.rebase_status, "pending");
      assert.equal((await runtime.execute({ namespace: state.namespace, database: state.database, id: clientId })).state, "succeeded");

      const cancelId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e5'";
      await client.query(`CREATE ONLY ${cancelId} SET owned_by = user:runtime_client, config = email_brevo_config:runtime_client,
        to = ['client@example.com'], subject = 'Client cancel';`);
      const cancelled = queryResult(await client.query(`UPDATE ${cancelId} SET rebase_cancel_requested = true RETURN AFTER;`))[0];
      assert.equal(cancelled.rebase_cancel_requested, true);
      assert.equal(cancelled.rebase_status, "cancelled");
      const monotonic = queryResult(await client.query(`UPDATE ${cancelId} SET rebase_cancel_requested = false RETURN AFTER;`))[0];
      assert.equal(monotonic.rebase_cancel_requested, true);
      await assert.rejects(
        client.query(`CREATE send_brevo_email SET owned_by = user:runtime_client, config = email_brevo_config:runtime_client,
          to = ['client@example.com'], subject = 'Bad schedule', schedule = { cron: '* * *', repeat: 0, skip: [-1], misfire: 'unknown' };`),
        /schedule|coerce|assert/i,
      );
    } finally {
      await client.close();
    }

    const retryId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e0'";
    await state.db.query(`CREATE ${retryId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Retry';`);
    failNextEmail = true;
    const firstRetry = await runtime.execute({ namespace: state.namespace, database: state.database, id: retryId }, { attempts: 1, maxAttempts: 3 });
    assert.equal(firstRetry.action, "retry");
    await state.db.query(`UPDATE ${retryId} SET rebase_wake_at = time::now();`);
    const secondRetry = await runtime.execute({ namespace: state.namespace, database: state.database, id: retryId }, { attempts: 2, maxAttempts: 3 });
    assert.equal(secondRetry.state, "succeeded");

    const ambiguousHandlers = loadTableHandlers("designs/test/table-handlers", { contracts, mutable: true });
    const emailImplementation = ambiguousHandlers.get("send_brevo_email").implementation;
    ambiguousHandlers.unregister("send_brevo_email");
    ambiguousHandlers.register({
      ...emailImplementation,
      async execute() {
        return { outcome: "ambiguous", retryAfterMs: 1000, patch: { provider_state: "unknown" } };
      },
      async reconcile() {
        return { outcome: "success", patch: { provider_state: "reconciled" } };
      },
    });
    const ambiguousRuntime = createRuntime({
      handlers: ambiguousHandlers,
      providers,
      queue: { async publish() { return { jobId: "probe", duplicate: false }; } },
      stores,
      contracts,
      options: {
        leaseMs: 5000,
        allowedContexts: [{ namespace: state.namespace, database: state.database }],
      },
    });
    const ambiguousId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e7'";
    await state.db.query(`CREATE ${ambiguousId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Ambiguous';`);
    assert.equal((await ambiguousRuntime.execute({ namespace: state.namespace, database: state.database, id: ambiguousId })).state, "ambiguous");
    await state.db.query(`UPDATE ${ambiguousId} SET rebase_wake_at = time::now();`);
    assert.equal((await ambiguousRuntime.reconcileWebhook({
      namespace: state.namespace,
      database: state.database,
      id: ambiguousId,
    })).state, "succeeded");
    const reconciledAmbiguous = await store.load(ambiguousId);
    assert.equal(reconciledAmbiguous.rebase_outcome, "succeeded");
    assert.equal(reconciledAmbiguous.provider_state, "reconciled");

    const deadId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e6'";
    await state.db.query(`CREATE ${deadId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Dead letter';`);
    failPermanently = true;
    await runtime.enqueue("task", { namespace: state.namespace, database: state.database, id: deadId }, { attempts: 1 });
    await waitFor(async () => (await store.load(deadId))?.rebase_outcome === "failed", "permanent failure was not persisted");
    await waitFor(async () => {
      const counts = await queue.deadLetters.get("task").getJobCounts("wait", "active", "completed");
      return (counts.wait || 0) + (counts.active || 0) + (counts.completed || 0) > 0;
    },
      "permanent failure was not dead-lettered");
    failPermanently = false;

    const staleId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e1'";
    await state.db.query(`CREATE ${staleId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Fence';`);
    const staleToken = crypto.randomUUID();
    assert(await store.claim(staleId, { token: staleToken, leaseUntil: Date.now() + 5000, outcome: "pending" }));
    await state.db.query(`UPDATE ${staleId} SET rebase_lease_token = rand::uuid::v7();`);
    assert.equal(await store.finalize(staleId, staleToken, {}, contracts.get("send_brevo_email").patchFields, "succeeded"), undefined);

    const cancelledId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e2'";
    await state.db.query(`CREATE ${cancelledId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Cancelled'; UPDATE ${cancelledId} SET rebase_cancel_requested = true;`);
    const cancelledCalls = emailCalls;
    assert.equal((await runtime.execute({ namespace: state.namespace, database: state.database, id: cancelledId })).state, "cancelled");
    assert.equal(emailCalls, cancelledCalls);

    const body = JSON.stringify({ namespace: state.namespace, database: state.database, id: cancelledId });
    const timestamp = String(Date.now());
    const signature = crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
    const wake = await app.request("http://runtime/internal/wake/task", {
      method: "POST", headers: { "content-type": "application/json", "x-rebase-timestamp": timestamp, "x-rebase-signature": signature }, body,
    });
    assert.equal(wake.status, 202);
    const staleTimestamp = String(Date.now() - 10 * 60 * 1000);
    const staleSignature = crypto.createHmac("sha256", secret).update(`${staleTimestamp}.${body}`).digest("hex");
    assert.equal((await app.request("http://runtime/internal/wake/task", {
      method: "POST", headers: { "content-type": "application/json", "x-rebase-timestamp": staleTimestamp, "x-rebase-signature": staleSignature }, body,
    })).status, 401);
    assert.equal((await app.request("http://runtime/internal/wake/task", {
      method: "POST", headers: { "x-rebase-timestamp": timestamp, "x-rebase-signature": signature }, body,
    })).status, 415);
    const wrongContextBody = JSON.stringify({ namespace: "outside", database: state.database, id: cancelledId });
    const wrongContextTimestamp = String(Date.now());
    const wrongContextSignature = crypto.createHmac("sha256", secret).update(`${wrongContextTimestamp}.${wrongContextBody}`).digest("hex");
    assert.equal((await app.request("http://runtime/internal/wake/task", {
      method: "POST",
      headers: { "content-type": "application/json", "x-rebase-timestamp": wrongContextTimestamp, "x-rebase-signature": wrongContextSignature },
      body: wrongContextBody,
    })).status, 403);
    const oversizedBody = JSON.stringify({ namespace: state.namespace, database: state.database, id: cancelledId, padding: "x".repeat(300000) });
    assert.equal((await app.request("http://runtime/internal/wake/task", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${secret}` }, body: oversizedBody,
    })).status, 413);
    const productionAuthApp = createRuntimeApp({
      runtime,
      handlers,
      providers,
      queue,
      wakeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      allowBearer: false,
    });
    assert.equal((await productionAuthApp.request("http://runtime/internal/wake/task", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body,
    })).status, 401);

    const webhookBody = JSON.stringify({ id: automaticId, provider: "local", account: "probe", status: "delivered", timestamp: new Date().toISOString() });
    const webhookSignature = crypto.createHmac("sha256", secret).update(webhookBody).digest("hex");
    const webhookHeaders = { "content-type": "application/json", "x-rebase-signature": webhookSignature, "x-rebase-event-id": "delivery-1" };
    const webhook = await app.request("http://runtime/webhooks/local/status", { method: "POST", headers: webhookHeaders, body: webhookBody });
    if (webhook.status !== 202) console.error("webhook response", webhook.status, await webhook.clone().text());
    assert.equal(webhook.status, 202);
    const delivered = await store.load(automaticId);
    assert.equal(delivered.provider_state, "delivered");
    assert.equal(delivered.webhook_event_id, "delivery-1");
    const duplicateWebhook = await app.request("http://runtime/webhooks/local/status", { method: "POST", headers: webhookHeaders, body: webhookBody });
    assert.equal(duplicateWebhook.status, 200);
    const olderBody = JSON.stringify({ id: automaticId, provider: "local", account: "probe", status: "processing", timestamp: new Date(Date.now() - 1000).toISOString() });
    const olderHeaders = {
      "content-type": "application/json",
      "x-rebase-signature": crypto.createHmac("sha256", secret).update(olderBody).digest("hex"),
      "x-rebase-event-id": "delivery-older",
    };
    const olderWebhook = await app.request("http://runtime/webhooks/local/status", { method: "POST", headers: olderHeaders, body: olderBody });
    assert.equal(olderWebhook.status, 200);
    assert.equal((await olderWebhook.json()).data.stale, true);
    const afterOlder = await store.load(automaticId);
    assert.equal(afterOlder.provider_state, "delivered");
    assert.equal(afterOlder.webhook_event_id, "delivery-1");
    const rawWebhookBody = JSON.stringify({ id: automaticId, provider: "local", account: "probe", status: "raw-body", timestamp: new Date().toISOString() });
    const rawWebhook = await app.request("http://runtime/webhooks/local/status", {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        "x-rebase-signature": crypto.createHmac("sha256", secret).update(rawWebhookBody).digest("hex"),
        "x-rebase-event-id": "delivery-raw-body",
      },
      body: rawWebhookBody,
    });
    assert.equal(rawWebhook.status, 202);
    assert.equal((await store.load(automaticId)).provider_state, "raw-body");
    const wrongAccountBody = JSON.stringify({ id: automaticId, provider: "local", account: "other", status: "bounced", timestamp: new Date().toISOString() });
    const wrongAccountHeaders = {
      "content-type": "application/json",
      "x-rebase-signature": crypto.createHmac("sha256", secret).update(wrongAccountBody).digest("hex"),
      "x-rebase-event-id": "delivery-wrong-account",
    };
    assert.equal((await app.request("http://runtime/webhooks/local/status", {
      method: "POST", headers: wrongAccountHeaders, body: wrongAccountBody,
    })).status, 403);
    const replayBody = JSON.stringify({ id: automaticId, provider: "local", account: "probe", status: "late", timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString() });
    const replayHeaders = {
      "content-type": "application/json",
      "x-rebase-signature": crypto.createHmac("sha256", secret).update(replayBody).digest("hex"),
      "x-rebase-event-id": "delivery-replay",
    };
    assert.equal((await app.request("http://runtime/webhooks/local/status", { method: "POST", headers: replayHeaders, body: replayBody })).status, 401);
    assert.equal((await app.request("http://runtime/webhooks/local/status", {
      method: "POST", headers: { ...webhookHeaders, "x-rebase-signature": "invalid" }, body: webhookBody,
    })).status, 401);

    const scheduleId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e3'";
    await state.db.query(`CREATE ${scheduleId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'], subject = 'Scheduled', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'coalesce' };`);
    await runtime.enqueue("schedule", { namespace: state.namespace, database: state.database, id: scheduleId });
    await waitFor(async () => (await store.load(scheduleId))?.rebase_schedule_next_at, "schedule did not initialize");
    await state.db.query(`UPDATE ${scheduleId} SET rebase_schedule_next_at = time::now();`);
    const directSchedule = await runtime.schedule({ namespace: state.namespace, database: state.database, id: scheduleId });
    if (process.env.REBASE_DEBUG) console.error("direct schedule", directSchedule);
    let scheduleLast;
    const scheduled = await waitFor(async () => {
      const row = await store.load(scheduleId);
      scheduleLast = row;
      return row?.rebase_schedule_finished_at ? row : null;
    }, () => `schedule did not emit (${JSON.stringify({ scheduleLast, queueErrors })})`, 8000);
    assert.equal(scheduled.rebase_outcome, "succeeded");
    const scheduleRows = queryResult(await state.db.query("SELECT id, schedule FROM send_brevo_email WHERE subject = 'Scheduled';"));
    assert.equal(scheduleRows.length, 2);
    assert.equal(scheduleRows.filter((row) => row.schedule === undefined).length, 1);

    const concurrentScheduleId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590f0'";
    await state.db.query(`CREATE ${concurrentScheduleId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'],
      subject = 'Concurrent schedule', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'all' };`);
    await runtime.schedule({ namespace: state.namespace, database: state.database, id: concurrentScheduleId });
    await state.db.query(`UPDATE ${concurrentScheduleId} SET rebase_schedule_next_at = time::now();`);
    const concurrentSchedules = await Promise.all(Array.from({ length: 8 }, () => (
      runtime.schedule({ namespace: state.namespace, database: state.database, id: concurrentScheduleId })
    )));
    assert.equal(concurrentSchedules.flatMap((result) => result.occurrences || []).length, 1);
    assert.equal(queryResult(await state.db.query("SELECT id FROM send_brevo_email WHERE subject = 'Concurrent schedule';")).length, 2);

    const coalesceId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590f1'";
    await state.db.query(`CREATE ${coalesceId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'],
      subject = 'Coalesce schedule', schedule = { cron: '* * * * *', repeat: 2, skip: [], misfire: 'coalesce' };
      UPDATE ${coalesceId} SET rebase_schedule_next_at = time::now() - 5m, rebase_schedule_index = 0;`);
    const coalesced = await runtime.schedule({ namespace: state.namespace, database: state.database, id: coalesceId });
    assert.equal(coalesced.occurrences.length, 1);
    const coalesceSource = await store.load(coalesceId);
    assert.equal(coalesceSource.rebase_schedule_index, 1);
    assert(new Date(coalesceSource.rebase_schedule_next_at).getTime() > Date.now());

    const skipId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590f2'";
    await state.db.query(`CREATE ${skipId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'],
      subject = 'Skip schedule', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'skip' };
      UPDATE ${skipId} SET rebase_schedule_next_at = time::now() - 5m, rebase_schedule_index = 0;`);
    const skipped = await runtime.schedule({ namespace: state.namespace, database: state.database, id: skipId });
    assert.equal(skipped.occurrences.length, 0);
    const skipSource = await store.load(skipId);
    assert.equal(skipSource.rebase_schedule_index, 0);
    assert(new Date(skipSource.rebase_schedule_next_at).getTime() > Date.now());
    assert.equal(queryResult(await state.db.query("SELECT id FROM send_brevo_email WHERE subject = 'Skip schedule';")).length, 1);

    const allId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590f3'";
    await state.db.query(`CREATE ${allId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'],
      subject = 'All schedule', schedule = { cron: '* * * * *', repeat: 3, skip: [], misfire: 'all' };
      UPDATE ${allId} SET rebase_schedule_next_at = time::now() - 5m, rebase_schedule_index = 0;`);
    const allRuns = await runtime.schedule({ namespace: state.namespace, database: state.database, id: allId });
    assert.equal(allRuns.occurrences.length, 3);
    assert.equal((await store.load(allId)).rebase_outcome, "succeeded");
    assert.equal(queryResult(await state.db.query("SELECT id FROM send_brevo_email WHERE subject = 'All schedule';")).length, 4);

    const cancelledScheduleId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590f4'";
    await state.db.query(`CREATE ${cancelledScheduleId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'],
      subject = 'Cancelled schedule', schedule = { cron: '* * * * *', repeat: 2, skip: [], misfire: 'coalesce' };`);
    await runtime.schedule({ namespace: state.namespace, database: state.database, id: cancelledScheduleId });
    await state.db.query(`UPDATE ${cancelledScheduleId} SET rebase_cancel_requested = true;`);
    assert.equal((await runtime.schedule({ namespace: state.namespace, database: state.database, id: cancelledScheduleId })).state, "cancelled");
    const cancelledSchedule = await store.load(cancelledScheduleId);
    assert(cancelledSchedule.rebase_schedule_finished_at);
    assert.equal(cancelledSchedule.rebase_outcome, undefined);

    const recoveredScheduleId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590f5'";
    await state.db.query(`CREATE ${recoveredScheduleId} SET owned_by = groups:root, config = ${emailConfigId}, to = ['to@example.com'],
      subject = 'Recovered schedule', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'coalesce' };`);
    await runtime.schedule({ namespace: state.namespace, database: state.database, id: recoveredScheduleId });
    const lostJobs = (await queue.queues.get("schedule").getJobs(["delayed", "wait", "prioritized"]))
      .filter((job) => job.data?.id === recoveredScheduleId);
    await Promise.all(lostJobs.map((job) => job.remove()));
    assert.equal((await queue.queues.get("schedule").getJobs(["delayed", "wait", "prioritized"]))
      .filter((job) => job.data?.id === recoveredScheduleId).length, 0);
    await runtime.reconcile({ namespace: state.namespace, database: state.database, lane: "schedule" });
    await waitFor(async () => (await queue.queues.get("schedule").getJobs(["delayed", "wait", "active", "prioritized"]))
      .some((job) => job.data?.id === recoveredScheduleId), "schedule reconciliation did not restore lost Redis timing state");

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

    const ready = await app.request("http://runtime/readyz");
    assert.equal(ready.status, 200);
    const ambiguousWebhookRoutingApp = createRuntimeApp({
      runtime,
      handlers,
      providers,
      queue,
      wakeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      readinessContexts: [
        { namespace: state.namespace, database: state.database },
        { namespace: state.namespace, database: state.database },
      ],
      allowBearer: true,
    });
    const ambiguousWebhookReadiness = await ambiguousWebhookRoutingApp.request("http://runtime/readyz");
    assert.equal(ambiguousWebhookReadiness.status, 503);
    assert.equal((await ambiguousWebhookReadiness.json()).webhooks.ok, false);

    const childPort = await freePort();
    const childEnvironment = {
      ...process.env,
      SURREAL_ENDPOINT: state.endpoint,
      SURREAL_USER: "root",
      SURREAL_PASS: "root",
      REBASE_NAMESPACE: state.namespace,
      REBASE_DATABASE: state.database,
      REBASE_WAKE_SECRET: secret,
      REBASE_REDIS_URL: redis.url,
      REBASE_QUEUE_PREFIX: `rebase-server-probe-${Date.now().toString(36)}`,
      REBASE_PORT: String(childPort),
      REBASE_EMAIL_WEBHOOK_SECRET: secret,
      REBASE_STORAGE_WEBHOOK_SECRET: secret,
    };
    runtimeChild = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."), env: childEnvironment, stdio: ["ignore", "ignore", "pipe"],
    });
    await waitForPort(childPort, runtimeChild, "ReBase server");
    assert.equal((await fetch(`http://127.0.0.1:${childPort}/healthz`)).status, 200);
    await waitFor(async () => (await fetch(`http://127.0.0.1:${childPort}/readyz`)).status === 200, "real server did not become ready");

    const conflicting = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...childEnvironment, REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-conflict` },
      stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(conflicting), 0);

    const missingSecretEnvironment = { ...childEnvironment, REBASE_PORT: String(await freePort()) };
    delete missingSecretEnvironment.REBASE_WAKE_SECRET;
    const missingSecret = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."), env: missingSecretEnvironment, stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(missingSecret), 0);

    const productionLocal = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...childEnvironment, NODE_ENV: "production", REBASE_PORT: String(await freePort()), REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-production` },
      stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(productionLocal), 0);

    const unavailableRedis = spawn(process.execPath, ["gateway/server.js"], {
      cwd: path.resolve(__dirname, ".."),
      env: {
        ...childEnvironment,
        REBASE_PORT: String(await freePort()),
        REBASE_REDIS_URL: `redis://127.0.0.1:${await freePort()}`,
        REBASE_QUEUE_PREFIX: `${childEnvironment.REBASE_QUEUE_PREFIX}-unavailable`,
        REBASE_QUEUE_STARTUP_TIMEOUT_MS: "300",
        REBASE_REDIS_CONNECT_TIMEOUT_MS: "200",
      },
      stdio: ["ignore", "ignore", "ignore"],
    });
    assert.notEqual(await waitForExit(unavailableRedis), 0);

    runtimeChild.kill("SIGTERM");
    assert.equal(await waitForExit(runtimeChild), 0);
    runtimeChild = null;
    console.log("runtime: BullMQ lanes, lifecycle fencing, sync/async, retry, cancellation, schedule, webhook, readiness, and context races passed");
  } finally {
    await stopChild(runtimeChild);
    await new Promise((resolve) => httpServer.close(resolve));
    await Promise.all(stops.map((stop) => stop?.()));
    await queue.close();
    await state.db.close().catch(() => {});
    await stopChild(state.child);
    await stopChild(redis.child);
    fs.rmSync(redis.directory, { recursive: true, force: true });
  }
}

if (require.main === module) main().then(
  () => process.exit(0),
  (error) => { console.error(`runtime: FAIL: ${process.env.REBASE_DEBUG ? error.stack : error.message}`); process.exit(1); },
);

module.exports = { main };
