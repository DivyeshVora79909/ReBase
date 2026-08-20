#!/usr/bin/env node

const assert = require("node:assert/strict");
const net = require("node:net");
const { spawn } = require("node:child_process");
const { serve } = require("@hono/node-server");
const { Surreal } = require("surrealdb");
const { loadMaterials } = require("./compiler/materials");
const { generateBundle } = require("./compiler/pipeline");
const { createLocalProviders } = require("../gateway/providers/local");
const { createMemoryQueue } = require("../gateway/queues/memory");
const { createRuntimeApp } = require("../gateway/app");
const { createStoreDirectory } = require("../gateway/directory");
const { loadTableHandlers } = require("../gateway/handlers");
const { createRuntime } = require("../gateway/runtime");
const { createTableStore } = require("../gateway/store");

function rows(response) {
  const value = Array.isArray(response) ? response.at(-1) : response;
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, process) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (process.exitCode !== null) break;
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
  throw new Error("Disposable SurrealDB did not start");
}

async function startDatabase(runtimePort) {
  const port = await freePort();
  const process = spawn("surreal", [
    "start", "memory", "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--async-event-interval", "50ms",
    "--allow-net", `127.0.0.1:${runtimePort}`, "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "ignore"] });
  await waitForPort(port, process);
  const endpoint = `ws://127.0.0.1:${port}/rpc`;
  const namespace = `table_runtime_${Date.now().toString(36)}`;
  const database = "probe";
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.query(`DEFINE NAMESPACE ${namespace}; USE NS ${namespace}; DEFINE DATABASE ${database}; USE DB ${database};`);
  await db.use({ namespace, database });
  return { db, database, endpoint, namespace, process };
}

async function stopDatabase(state) {
  await state.db.close().catch(() => {});
  if (state.process.exitCode === null) state.process.kill("SIGTERM");
}

async function main() {
  const runtimePort = await freePort();
  const state = await startDatabase(runtimePort);
  const secret = "runtime-probe-secret";
  const queue = createMemoryQueue();
  const handlers = loadTableHandlers("build/test/table-handlers");
  const providers = createLocalProviders({ webhookSecret: secret });
  const originalProviderForResource = providers.email.forResource.bind(providers.email);
  let emailCalls = 0;
  let failNextEmail = false;
  providers.email.forResource = (resource) => {
    const provider = originalProviderForResource(resource);
    return {
      ...provider,
      async sendMessage(input) {
        emailCalls += 1;
        if (failNextEmail) {
          failNextEmail = false;
          throw Object.assign(new Error("Temporary provider failure"), {
            code: "PROVIDER_TEMPORARY",
            retryable: true,
          });
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
        return provider.sendMessage(input);
      },
    };
  };
  let connectedContexts = 0;
  const directory = createStoreDirectory({
    maxContexts: 2,
    async connect({ namespace, database }) {
      connectedContexts += 1;
      return { namespace, database, async close() {} };
    },
  });
  const firstContext = await directory.forContext("tenant", "one");
  const sameContext = await directory.forContext("tenant", "one");
  const secondContext = await directory.forContext("tenant", "two");
  assert.equal(firstContext, sameContext);
  assert.notEqual(firstContext, secondContext);
  assert.equal(connectedContexts, 2);
  await assert.rejects(directory.forContext("tenant", "three"), /context limit/i);
  await directory.close();
  const database = { db: state.db };
  const runtime = createRuntime({
    database: { ...database, store: createTableStore(database) },
    handlers,
    providers,
    queue,
  });
  const stop = await queue.start(runtime.consume);
  const app = createRuntimeApp({ runtime, handlers, wakeSecret: secret, defaultContext: { namespace: state.namespace, database: state.database } });
  const httpServer = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: runtimePort });
  try {
    const materials = loadMaterials({ groups: [
      { name: "framework", roots: ["framework"] },
      { name: "project", roots: ["designs/test"] },
    ] });
    const generated = generateBundle(materials, {
      context: {
        namespace: state.namespace,
        database: state.database,
        runtimeUrl: `http://127.0.0.1:${runtimePort}`,
        runtimeSecret: secret,
      },
    });
    await state.db.query(generated.bundle);
    await state.db.query(`
      CREATE file_storage_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590da' SET owned_by = groups:root, bucket = 'probe', credential_ref = 'env:TABLE_RUNTIME_SECRET';
      CREATE email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db' SET owned_by = groups:root, label = 'Probe', visibility = true, from_email = 'from@example.com', from_name = 'Probe', api_secret_ref = 'env:TABLE_RUNTIME_SECRET', account_key = 'probe';
    `);
    const config = rows(await state.db.query("SELECT id FROM file_storage_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590da';"))[0];
    const emailConfig = rows(await state.db.query("SELECT id FROM email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db';"))[0];

    const syncId = "file_access_grant:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db'";
    const syncResponse = await runtime.sync({
      namespace: state.namespace,
      database: state.database,
      id: syncId,
      event: "CREATE",
      record: { id: syncId, storage_config: String(config.id), object_key: "invoice/a.pdf", expires_in: 300 },
    });
    assert.equal(syncResponse.effect_state, "succeeded");
    assert.match(syncResponse.access_url, /storage\.local\/access/);
    assert.equal(syncResponse.expires_at !== undefined, true);

    const automaticSyncId = "file_access_grant:u'0198c6c4-bd70-7d6d-8a7a-87bb773590de'";
    const automaticSync = await state.db.query(`
      CREATE ONLY ${automaticSyncId} SET owned_by = groups:root, storage_config = file_storage_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590da', object_key = 'invoice/automatic.pdf', expires_in = 60;
      RETURN (SELECT * FROM ${automaticSyncId})[0];
    `);
    assert.equal(automaticSync[1].effect_state, "succeeded");
    assert.match(automaticSync[1].access_url, /storage\.local\/access/);

    const emailId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590dc'";
    await state.db.query(`CREATE ${emailId} SET owned_by = groups:root, config = email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db', to = ['to@example.com'], subject = 'Probe', effect_state = 'pending';`);
    await runtime.enqueue({ namespace: state.namespace, database: state.database, id: emailId });
    await queue.flush();
    const sent = rows(await state.db.query(`SELECT effect_state, provider_reference, result FROM ${emailId};`))[0];
    if (process.env.REBASE_DEBUG) console.error("sent", sent, queue.inspect());
    assert.equal(sent.effect_state, "succeeded");
    assert(sent.provider_reference);
    assert.equal(sent.result.provider, "brevo");

    const automaticEmailId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590df'";
    await state.db.query(`CREATE ${automaticEmailId} SET owned_by = groups:root, config = email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db', to = ['to@example.com'], subject = 'Automatic';`);
    let automaticEmail;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      automaticEmail = rows(await state.db.query(`SELECT effect_state, provider_reference FROM ${automaticEmailId};`))[0];
      if (automaticEmail?.effect_state === "succeeded") break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(automaticEmail.effect_state, "succeeded");
    assert(automaticEmail.provider_reference);

    const reconcileId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590dd'";
    await state.db.query(`CREATE ${reconcileId} SET owned_by = groups:root, config = email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db', to = ['to@example.com'], subject = 'Reconcile', effect_state = 'pending';`);
    const reconciliation = await runtime.reconcile({ namespace: state.namespace, database: state.database });
    assert(reconciliation.ids.includes(reconcileId));
    await queue.flush();
    assert.equal(rows(await state.db.query(`SELECT effect_state FROM ${reconcileId};`))[0].effect_state, "succeeded");

    await state.db.query("REMOVE EVENT rebase_effect_send_brevo_email ON TABLE send_brevo_email;");
    const duplicateId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e0'";
    await state.db.query(`CREATE ${duplicateId} SET owned_by = groups:root, config = email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db', to = ['to@example.com'], subject = 'Duplicate';`);
    const callsBeforeDuplicate = emailCalls;
    const duplicateResults = await Promise.all([
      runtime.asyncEffect({ namespace: state.namespace, database: state.database, id: duplicateId }),
      runtime.asyncEffect({ namespace: state.namespace, database: state.database, id: duplicateId }),
    ]);
    assert.equal(emailCalls, callsBeforeDuplicate + 1);
    assert(duplicateResults.some((result) => result.state === "handled"));
    assert(duplicateResults.some((result) => result.state === "claimed" || result.state === "processing"));

    const retryId = "send_brevo_email:u'0198c6c4-bd70-7d6d-8a7a-87bb773590e1'";
    await state.db.query(`CREATE ${retryId} SET owned_by = groups:root, config = email_brevo_config:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db', to = ['to@example.com'], subject = 'Retry';`);
    failNextEmail = true;
    const retryEnvelope = { namespace: state.namespace, database: state.database, id: retryId };
    assert.equal((await runtime.consume({ envelope: retryEnvelope, attempts: 1 })).action, "retry");
    assert.equal(rows(await state.db.query(`SELECT effect_state FROM ${retryId};`))[0].effect_state, "waiting");
    const retryDecision = await runtime.consume({ envelope: retryEnvelope, attempts: 2 });
    const retried = rows(await state.db.query(`SELECT effect_state, error_code, provider_reference FROM ${retryId};`))[0];
    if (process.env.REBASE_DEBUG) console.error("retry", retryDecision, retried);
    assert.equal(retryDecision.action, "ack");
    assert.equal(retried.effect_state, "succeeded");

    const denied = await app.request("http://runtime/internal/reconcile", { method: "POST", body: "{}" });
    assert.equal(denied.status, 401);
    const body = JSON.stringify({ namespace: state.namespace, database: state.database, id: syncId, record: { id: syncId, storage_config: String(config.id), object_key: "invoice/b.pdf", expires_in: 120 } });
    const accepted = await app.request("http://runtime/internal/sync", { method: "POST", headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" }, body });
    assert.equal(accepted.status, 200);
    assert.equal((await accepted.json()).patch.effect_state, "succeeded");

    const storageRaw = JSON.stringify({ id: automaticSyncId, provider: "local-storage", status: "stored", size: 4096, etag: "probe-etag" });
    const storageSignature = require("node:crypto").createHmac("sha256", secret).update(storageRaw).digest("hex");
    const storageWebhook = await app.request("http://runtime/webhooks/file_access_grant", { method: "POST", headers: { "x-rebase-signature": storageSignature, "x-rebase-event-id": "stored-1", "content-type": "application/json" }, body: storageRaw });
    assert.equal(storageWebhook.status, 200);
    const stored = rows(await state.db.query(`SELECT provider_state, object_size, object_etag, completed_at FROM ${automaticSyncId};`))[0];
    assert.equal(stored.provider_state, "stored");
    assert.equal(stored.object_size, 4096);
    assert.equal(stored.object_etag, "probe-etag");
    assert(stored.completed_at);

    const wrongStorageRaw = JSON.stringify({ id: emailId, provider: "local-storage", status: "stored", size: 1, etag: "wrong-table" });
    const wrongStorageSignature = require("node:crypto").createHmac("sha256", secret).update(wrongStorageRaw).digest("hex");
    const wrongStorageWebhook = await app.request("http://runtime/webhooks/file_access_grant", { method: "POST", headers: { "x-rebase-signature": wrongStorageSignature, "x-rebase-event-id": "stored-wrong", "content-type": "application/json" }, body: wrongStorageRaw });
    assert.equal(wrongStorageWebhook.status, 400);

    const raw = JSON.stringify({ id: emailId, provider: "local", status: "delivered" });
    const signature = require("node:crypto").createHmac("sha256", secret).update(raw).digest("hex");
    const webhook = await app.request("http://runtime/webhooks/send_brevo_email", { method: "POST", headers: { "x-rebase-signature": signature, "x-rebase-event-id": "delivered-1", "content-type": "application/json" }, body: raw });
    assert.equal(webhook.status, 200);
    console.log("runtime: dispatch, sync patch, async claim/retry, reconciliation, wake auth, and webhook flows passed");
  } finally {
    await new Promise((resolve) => httpServer.close(resolve));
    await stop?.();
    await queue.close();
    await stopDatabase(state);
  }
}

if (require.main === module) main().then(
  () => process.exit(0),
  (error) => { console.error(`runtime: FAIL: ${error.message}`); process.exit(1); },
);

module.exports = { main };
