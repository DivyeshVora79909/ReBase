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
const { createAccountService } = require("../gateway/accounts");
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

async function accountSignin(endpoint, namespace, database, identifier, password, access = "account", variables = {}) {
  const client = new Surreal();
  await client.connect(endpoint);
  try {
    const token = await client.signin({
      namespace,
      database,
      access,
      variables: access === "account"
        ? { identifier, password, ...variables }
        : variables,
    });
    return { client, token };
  } catch (error) {
    if (process.env.REBASE_RUNTIME_PROBE_DEBUG) {
      console.error("record signin failed", { access, variableNames: Object.keys(access === "account" ? { identifier, password, ...variables } : variables) });
    }
    await client.close();
    throw error;
  }
}

async function accountSignup(endpoint, namespace, database, invite, password) {
  const client = new Surreal();
  await client.connect(endpoint);
  try {
    return await client.signup({
      namespace,
      database,
      access: "account",
      variables: { invite, password },
    });
  } finally {
    await client.close();
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

async function main() {
  await adapterScopeProbe();
  const runtimePort = await freePort();
  const redis = await startRedis();
  const redisRateLimiter = createRedisRateLimiter({
    url: redis.url,
    prefix: `rebase-rate-probe-${Date.now().toString(36)}`,
  });
  assert.equal((await redisRateLimiter.consume("account", { limit: 1, windowMs: 60000 })).allowed, true);
  assert.equal((await redisRateLimiter.consume("account", { limit: 1, windowMs: 60000 })).allowed, false);
  assert.equal((await redisRateLimiter.health()).ok, true);
  await redisRateLimiter.close();
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
  const webhooks = loadWebhookHandlers("designs/test/webhook-handlers");
  const routeCodec = createWebhookRouteCodec(secret);
  const queueErrors = [];
  const queue = createBullMqPort({
    url: redis.url,
    prefix: `rebase-probe-${Date.now().toString(36)}`,
    onError: (error) => queueErrors.push(error.message),
    onFailed: ({ lane, error }) => queueErrors.push(`${lane}:${error.message}`),
  });
  let emailCalls = 0;
  let failNextEmail = false;
  let failPermanently = false;
  let razorpayRoute;
  let storageDeletes = 0;
  let failStorageDelete = false;
  const adapters = Object.freeze({
    async sendBrevoEmail(input) {
      emailCalls += 1;
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
    async deleteS3Object() {
      storageDeletes += 1;
      if (failStorageDelete) throw Object.assign(new Error("Storage delete failed"), { code: "STORAGE_DELETE_FAILED" });
      return { deleted: true };
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
  const store = createTableStore({ db: state.db });
  const stores = fixedStoreDirectory(store, state);
  const platformMessages = [];
  const recoveryRateLimiter = createMemoryRateLimiter();
  const accounts = createAccountService({
    stores,
    principals: generated.contracts.principals,
    allowedContexts: [{ namespace: state.namespace, database: state.database }],
    async sendEmail(message) { platformMessages.push(structuredClone(message)); return { id: `mail-${platformMessages.length}` }; },
    rateLimiter: recoveryRateLimiter,
    rateLimits: { windowMs: 60000, ip: 20, identifier: 2 },
  });
  const oauth = createOAuthVerifier({
    mock: createMockOAuthAdapter({
      "existing-user-token": "oauth-client@example.com",
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
  for (const lane of ["task", "schedule", "webhook"]) stops.push(await queue.start(lane, (delivery) => runtime.consume(lane, delivery)));
  const app = createRuntimeApp({
    runtime, handlers, webhooks, adapters, webhookAdapters, accounts, oauth, queue, runtimeSecret: secret,
    defaultContext: { namespace: state.namespace, database: state.database },
    allowBearer: true,
  });
  const httpServer = serve({ fetch: app.fetch, hostname: "127.0.0.1", port: runtimePort });
  let runtimeChild;
  try {
    await state.db.query(generated.bundle);
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
      state.db.query("CREATE file_storage_config:missing_credential SET owned_by = groups:root;"),
      /access_key_id|secret_access_key|endpoint|region|field|schema|required/i,
    );
    await assert.rejects(
      state.db.query("CREATE email_brevo_config:missing_api_key SET owned_by = groups:root, label = 'Missing', from_email = 'missing@example.com', from_name = 'Missing';"),
      /api_key|field|schema|required/i,
    );
    await assert.rejects(
      state.db.query("CREATE razorpay_config:missing_secret SET owned_by = groups:root, label = 'Missing', key_id = 'key';"),
      /key_secret|webhook_secret|field|schema|required/i,
    );
    const storage = await createAndReload(state.db, "file_storage_config", `
      owned_by = groups:root, visibility = true,
      access_key_id = 'client-storage-id', secret_access_key = 'client-storage-secret',
      endpoint = 'https://storage.local', region = 'local'
    `);
    const storageId = recordId(storage);
    const emailConfig = await createAndReload(state.db, "email_brevo_config", `
      owned_by = groups:root, label = 'Probe', visibility = true,
      from_email = 'from@example.com', from_name = 'Probe', api_key = 'client-brevo-api-key'
    `);
    const emailConfigId = recordId(emailConfig);
    const razorpayConfig = await createAndReload(state.db, "razorpay_config", `
      owned_by = groups:root, label = 'Probe', visibility = true,
      key_id = 'client-razorpay-key', key_secret = 'client-razorpay-secret',
      webhook_secret = 'razorpay-webhook-secret'
    `);
    const razorpayConfigId = recordId(razorpayConfig);
    await state.db.query(`
      CREATE groups:runtime_clients SET name = 'Runtime Clients', parents = [groups:root], role = [
        'send_brevo_email_create', 'send_brevo_email_select', 'send_brevo_email_update',
        'email_brevo_config_select', 'file_storage_config_select', 'razorpay_config_select'
      ];
      CREATE user:runtime_client SET name = 'Runtime Client', email = 'runtime-client@example.com',
        password = crypto::argon2::generate('runtime-password'), parents = [groups:runtime_clients], login_access = true;
      CREATE user:recovery_client SET name = 'Recovery Client', email = 'recovery-client@example.com', username = 'recovery_user',
        password = crypto::argon2::generate('recovery-password'), parents = [groups:runtime_clients], login_access = true;
      CREATE user:oauth_client SET name = 'OAuth Client', email = 'oauth-client@example.com',
        parents = [groups:runtime_clients], login_access = true;
      CREATE email_brevo_config:runtime_client SET owned_by = groups:root, label = 'Client Probe', visibility = true,
        from_email = 'client@example.com', from_name = 'Client', api_key = 'customer-brevo-api-key';
    `);

    const recoveryRequest = {
      namespace: state.namespace,
      database: state.database,
      identifier: "RECOVERY_USER",
    };
    const recoveryResponse = await app.request("http://runtime/anonymous/accounts/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: JSON.stringify(recoveryRequest),
    });
    assert.equal(recoveryResponse.status, 202);
    const genericRecoveryBody = await recoveryResponse.json();
    assert.deepEqual(genericRecoveryBody, { ok: true });
    assert.equal(platformMessages.length, 1);
    assert.deepEqual(platformMessages[0].to, ["recovery-client@example.com"]);
    const recoveryToken = platformMessages[0].text.match(/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i)?.[0];
    assert(recoveryToken);
    assert.equal(
      queryResult(await state.db.query("RETURN <string>user:recovery_client.invite_token;")),
      recoveryToken,
    );
    const stillValid = await accountSignin(
      state.endpoint,
      state.namespace,
      state.database,
      "recovery-client@example.com",
      "recovery-password",
    );
    await stillValid.client.close();
    await accountSignup(state.endpoint, state.namespace, state.database, recoveryToken, "recovered-password");
    await assert.rejects(
      accountSignin(state.endpoint, state.namespace, state.database, "recovery-client@example.com", "recovery-password"),
      /signin|authentication|access|record/i,
    );
    const recovered = await accountSignin(
      state.endpoint,
      state.namespace,
      state.database,
      "recovery_user",
      "recovered-password",
    );
    await recovered.client.close();

    const missingRecovery = await app.request("http://runtime/anonymous/accounts/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: JSON.stringify({ ...recoveryRequest, identifier: "missing-user@example.com" }),
    });
    assert.equal(missingRecovery.status, 202);
    assert.deepEqual(await missingRecovery.json(), genericRecoveryBody);
    assert.equal(platformMessages.length, 1);
    const disallowedRecovery = await app.request("http://runtime/anonymous/accounts/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: JSON.stringify({ ...recoveryRequest, namespace: "outside" }),
    });
    assert.equal(disallowedRecovery.status, 202);
    assert.deepEqual(await disallowedRecovery.json(), genericRecoveryBody);
    assert.equal(platformMessages.length, 1);
    const rateLimitedRequest = JSON.stringify({ ...recoveryRequest, identifier: "rate-limit@example.com" });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      assert.equal((await app.request("http://runtime/anonymous/accounts/recovery", {
        method: "POST",
        headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
        body: rateLimitedRequest,
      })).status, 202);
    }
    const rateLimited = await app.request("http://runtime/anonymous/accounts/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "x-real-ip": "192.0.2.10" },
      body: rateLimitedRequest,
    });
    assert.equal(rateLimited.status, 429);
    assert(Number(rateLimited.headers.get("retry-after")) >= 1);

    assert.throws(() => createOAuthVerifier({ invalid: {} }), /must be a function/);
    assert.deepEqual(await oauth.verify("unknown", "token"), { verified: false });
    assert.deepEqual(await oauth.verify("mock", ""), { verified: false });
    const oauthBody = JSON.stringify({ provider: "mock", token: "existing-user-token" });
    assert.equal((await app.request("http://runtime/internal/oauth", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: oauthBody,
    })).status, 401);
    const verifiedOAuth = await app.request("http://runtime/internal/oauth", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: oauthBody,
    });
    assert.deepEqual(await verifiedOAuth.json(), { verified: true, email: "oauth-client@example.com" });
    const oauthLogin = await accountSignin(
      state.endpoint,
      state.namespace,
      state.database,
      null,
      null,
      "oauth",
      { provider: "mock", oauth_token: "existing-user-token" },
    );
    assert.equal(String(queryResult(await oauthLogin.client.query("RETURN $auth.id;"))), "user:oauth_client");
    await oauthLogin.client.close();
    const userCountBeforeFailedOAuth = queryResult(await state.db.query("RETURN (SELECT VALUE id FROM user).len();"));
    await assert.rejects(
      accountSignin(
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
      queryResult(await state.db.query("RETURN (SELECT VALUE id FROM user).len();")),
      userCountBeforeFailedOAuth,
    );

    const target = await createAndReload(state.db, "test_primitive", `
      owned_by = groups:root, a_string = 'Attachment target', a_decimal = 0dec
    `);
    const targetId = recordId(target);
    const attachment = await createAndReload(state.db, "test_attachment", `
      owned_by = groups:root, storage_config = type::record($storage_id),
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
      owned_by = groups:root, a_string = 'Delete target', a_decimal = 0dec
    `);
    const deleteTargetId = recordId(deleteTarget);
    const deleteCandidate = await createAndReload(state.db, "test_attachment", `
      owned_by = groups:root, storage_config = type::record($storage_id),
      attached_to = type::record($delete_target_id), file_name = 'delete-me.txt',
      media_type = 'text/plain', byte_length_limit = 0, access_duration = 60
    `, { storage_id: storageId, delete_target_id: deleteTargetId });
    const deleteCandidateId = recordId(deleteCandidate);
    failStorageDelete = true;
    await assert.rejects(
      state.db.query("DELETE type::record($id);", { id: deleteCandidateId }),
      /STORAGE_DELETE_FAILED|REBASE_SYNC_EFFECT_FAILED|effect/i,
    );
    assert(await store.load(deleteCandidateId));
    failStorageDelete = false;
    await state.db.query("DELETE type::record($id);", { id: deleteCandidateId });
    assert.equal(await store.load(deleteCandidateId), undefined);
    assert(storageDeletes >= 2);

    const razorpayOrder = await createAndReload(state.db, "razorpay_order", `
      owned_by = groups:root, config = type::record($config_id),
      amount_paise = 100, currency = 'INR'
    `, { config_id: razorpayConfigId });
    const razorpayId = recordId(razorpayOrder);
    assert.equal(razorpayId.includes(":u'"), false);
    assert.match(razorpayOrder.provider_order_id, /^order_/);
    assert.equal(razorpayOrder.status, "created");
    assert(razorpayOrder.provider_created_at);

    const automatic = await createAndReload(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Automatic'
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

    await state.db.query("REMOVE EVENT rebase_effect_send_brevo_email ON TABLE send_brevo_email;");
    const duplicate = await createAndReload(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Duplicate'
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

    const client = new Surreal();
    await client.connect(state.endpoint);
    await client.signin({
      namespace: state.namespace,
      database: state.database,
      access: "account",
      variables: { email: "runtime-client@example.com", password: "runtime-password" },
    });
    try {
      const clientCreated = queryResult(await client.query(`
        CREATE ONLY send_brevo_email SET
          owned_by = user:runtime_client,
          config = email_brevo_config:runtime_client,
          to = ['client@example.com'],
          subject = 'Client lifecycle'
        RETURN AFTER;
      `));
      const clientId = recordId(clientCreated);
      assert.equal(queryResult(await client.query(
        "RETURN type::is_none(email_brevo_config:runtime_client.api_key);",
      )), true);
      const visibleStorage = queryResult(await client.query(`SELECT id, access_key_id, secret_access_key, endpoint, region FROM ${storageId};`))[0];
      assert.equal(String(visibleStorage.id).split(":", 1)[0], "file_storage_config");
      assert.equal(visibleStorage.access_key_id, undefined);
      assert.equal(visibleStorage.secret_access_key, undefined);
      assert.equal(visibleStorage.endpoint, undefined);
      assert.equal(visibleStorage.region, undefined);
      await client.query("UPDATE email_brevo_config:runtime_client SET api_key = 'client-must-not-write';");
      assert.equal(queryResult(await state.db.query("RETURN email_brevo_config:runtime_client.api_key;")), "customer-brevo-api-key");
      assert.notEqual(clientCreated.rebase_cancel_requested, true);
      assert.equal(clientCreated.rebase_outcome, undefined);
      assert.equal(clientCreated.rebase_lease_token, undefined);
      assert.equal(clientCreated.rebase_status, "pending");
      assert.equal((await runtime.execute({ namespace: state.namespace, database: state.database, id: clientId })).state, "succeeded");

      const cancelCreated = queryResult(await client.query(`CREATE ONLY send_brevo_email SET
        owned_by = user:runtime_client, config = email_brevo_config:runtime_client,
        to = ['client@example.com'], subject = 'Client cancel' RETURN AFTER;`));
      const cancelId = recordId(cancelCreated);
      const cancelled = queryResult(await client.query("RETURN (UPDATE type::record($id) SET rebase_cancel_requested = true RETURN AFTER)[0];", { id: cancelId }));
      assert.equal(cancelled.rebase_cancel_requested, true);
      assert.equal(cancelled.rebase_status, "cancelled");
      const monotonic = queryResult(await client.query("RETURN (UPDATE type::record($id) SET rebase_cancel_requested = false RETURN AFTER)[0];", { id: cancelId }));
      assert.equal(monotonic.rebase_cancel_requested, true);
      await assert.rejects(
        client.query(`CREATE send_brevo_email SET owned_by = user:runtime_client, config = email_brevo_config:runtime_client,
          to = ['client@example.com'], subject = 'Bad schedule', schedule = { cron: '* * *', repeat: 0, skip: [-1], misfire: 'unknown' };`),
        /schedule|coerce|assert/i,
      );
    } finally {
      await client.close();
    }

    const retryId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Retry'
    `, { config_id: emailConfigId });
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
      on: {
        ...emailImplementation.on,
        async CREATE() {
          return { outcome: "ambiguous", retryAfterMs: 1000, patch: { provider_state: "unknown" } };
        },
      },
      async reconcile() {
        return { outcome: "success", patch: { provider_state: "reconciled" } };
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
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Ambiguous'
    `, { config_id: emailConfigId });
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

    const deadId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Dead letter'
    `, { config_id: emailConfigId });
    failPermanently = true;
    await runtime.enqueue("task", { namespace: state.namespace, database: state.database, id: deadId }, { attempts: 1 });
    await waitFor(async () => (await store.load(deadId))?.rebase_outcome === "failed", "permanent failure was not persisted");
    await waitFor(async () => {
      const counts = await queue.deadLetters.get("task").getJobCounts("wait", "active", "completed");
      return (counts.wait || 0) + (counts.active || 0) + (counts.completed || 0) > 0;
    },
      "permanent failure was not dead-lettered");
    failPermanently = false;

    const staleId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Fence'
    `, { config_id: emailConfigId });
    const staleToken = crypto.randomUUID();
    assert(await store.claim(staleId, { token: staleToken, leaseUntil: Date.now() + 5000, outcome: "pending" }));
    await state.db.query(`UPDATE ${staleId} SET rebase_lease_token = rand::uuid::v7();`);
    assert.equal(await store.finalize(staleId, staleToken, {}, contracts.get("send_brevo_email").patchFields, "succeeded"), undefined);

    const cancelledId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Cancelled'
    `, { config_id: emailConfigId });
    await state.db.query("UPDATE type::record($id) SET rebase_cancel_requested = true;", { id: cancelledId });
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
      adapters,
      webhookAdapters,
      queue,
      runtimeSecret: secret,
      defaultContext: { namespace: state.namespace, database: state.database },
      allowBearer: false,
    });
    assert.equal((await productionAuthApp.request("http://runtime/internal/wake/task", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body,
    })).status, 401);

    assert(razorpayRoute);
    const razorpayCreatedAt = Math.floor(Date.now() / 1000);
    const razorpayBody = JSON.stringify({
      event: "order.paid",
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
    const razorpayWebhook = await app.request("http://runtime/webhooks/razorpay", {
      method: "POST", headers: razorpayHeaders, body: razorpayBody,
    });
    if (razorpayWebhook.status !== 200) console.error("razorpay webhook", razorpayWebhook.status, await razorpayWebhook.clone().text());
    assert.equal(razorpayWebhook.status, 200);
    const paidOrder = await store.load(razorpayId);
    assert.equal(paidOrder.status, "paid");
    const paymentRows = queryResult(await state.db.query("SELECT * FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';"));
    assert.equal(paymentRows.length, 1);
    assert.equal(paymentRows[0].status, "captured");
    assert.equal(paymentRows[0].order, razorpayId);
    assert.equal((await app.request("http://runtime/webhooks/razorpay", {
      method: "POST", headers: razorpayHeaders, body: razorpayBody,
    })).status, 200);
    assert.equal(queryResult(await state.db.query("SELECT id FROM razorpay_payment WHERE provider_payment_id = 'pay_probe';")).length, 1);
    assert.equal((await app.request("http://runtime/webhooks/razorpay", {
      method: "POST", headers: { ...razorpayHeaders, "x-razorpay-signature": "invalid" }, body: razorpayBody,
    })).status, 401);
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
    assert.equal((await app.request("http://runtime/webhooks/razorpay", {
      method: "POST",
      headers: { ...razorpayHeaders, "x-razorpay-signature": crypto.createHmac("sha256", "razorpay-webhook-secret").update(mismatchedBody).digest("hex") },
      body: mismatchedBody,
    })).status, 400);

    const scheduleId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'], subject = 'Scheduled',
      schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'coalesce' }
    `, { config_id: emailConfigId });
    await runtime.enqueue("schedule", { namespace: state.namespace, database: state.database, id: scheduleId });
    await waitFor(async () => (await store.load(scheduleId))?.rebase_schedule_next_at, "schedule did not initialize");
    await state.db.query(`UPDATE ${scheduleId} SET rebase_schedule_next_at = time::now();`);
    const directSchedule = await runtime.schedule({ namespace: state.namespace, database: state.database, id: scheduleId });
    if (process.env.REBASE_RUNTIME_PROBE_DEBUG) console.error("direct schedule", directSchedule);
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

    const concurrentScheduleId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'Concurrent schedule', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'all' }
    `, { config_id: emailConfigId });
    await runtime.schedule({ namespace: state.namespace, database: state.database, id: concurrentScheduleId });
    await state.db.query(`UPDATE ${concurrentScheduleId} SET rebase_schedule_next_at = time::now();`);
    const concurrentSchedules = await Promise.all(Array.from({ length: 8 }, () => (
      runtime.schedule({ namespace: state.namespace, database: state.database, id: concurrentScheduleId })
    )));
    assert.equal(concurrentSchedules.flatMap((result) => result.occurrences || []).length, 1);
    assert.equal(queryResult(await state.db.query("SELECT id FROM send_brevo_email WHERE subject = 'Concurrent schedule';")).length, 2);

    const coalesceId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'Coalesce schedule', schedule = { cron: '* * * * *', repeat: 2, skip: [], misfire: 'coalesce' }
    `, { config_id: emailConfigId });
    await state.db.query("UPDATE type::record($id) SET rebase_schedule_next_at = time::now() - 5m, rebase_schedule_index = 0;", { id: coalesceId });
    const coalesced = await runtime.schedule({ namespace: state.namespace, database: state.database, id: coalesceId });
    assert.equal(coalesced.occurrences.length, 1);
    const coalesceSource = await store.load(coalesceId);
    assert.equal(coalesceSource.rebase_schedule_index, 1);
    assert(new Date(coalesceSource.rebase_schedule_next_at).getTime() > Date.now());

    const skipId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'Skip schedule', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'skip' }
    `, { config_id: emailConfigId });
    await state.db.query("UPDATE type::record($id) SET rebase_schedule_next_at = time::now() - 5m, rebase_schedule_index = 0;", { id: skipId });
    const skipped = await runtime.schedule({ namespace: state.namespace, database: state.database, id: skipId });
    assert.equal(skipped.occurrences.length, 0);
    const skipSource = await store.load(skipId);
    assert.equal(skipSource.rebase_schedule_index, 0);
    assert(new Date(skipSource.rebase_schedule_next_at).getTime() > Date.now());
    assert.equal(queryResult(await state.db.query("SELECT id FROM send_brevo_email WHERE subject = 'Skip schedule';")).length, 1);

    const allId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'All schedule', schedule = { cron: '* * * * *', repeat: 3, skip: [], misfire: 'all' }
    `, { config_id: emailConfigId });
    await state.db.query("UPDATE type::record($id) SET rebase_schedule_next_at = time::now() - 5m, rebase_schedule_index = 0;", { id: allId });
    const allRuns = await runtime.schedule({ namespace: state.namespace, database: state.database, id: allId });
    assert.equal(allRuns.occurrences.length, 3);
    assert.equal((await store.load(allId)).rebase_outcome, "succeeded");
    assert.equal(queryResult(await state.db.query("SELECT id FROM send_brevo_email WHERE subject = 'All schedule';")).length, 4);

    const cancelledScheduleId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'Cancelled schedule', schedule = { cron: '* * * * *', repeat: 2, skip: [], misfire: 'coalesce' }
    `, { config_id: emailConfigId });
    await runtime.schedule({ namespace: state.namespace, database: state.database, id: cancelledScheduleId });
    await state.db.query(`UPDATE ${cancelledScheduleId} SET rebase_cancel_requested = true;`);
    assert.equal((await runtime.schedule({ namespace: state.namespace, database: state.database, id: cancelledScheduleId })).state, "cancelled");
    const cancelledSchedule = await store.load(cancelledScheduleId);
    assert(cancelledSchedule.rebase_schedule_finished_at);
    assert.equal(cancelledSchedule.rebase_outcome, undefined);

    const recoveredScheduleId = await createId(state.db, "send_brevo_email", `
      owned_by = groups:root, config = type::record($config_id), to = ['to@example.com'],
      subject = 'Recovered schedule', schedule = { cron: '* * * * *', repeat: 1, skip: [], misfire: 'coalesce' }
    `, { config_id: emailConfigId });
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
    const missingAdapterReadiness = await missingAdapterApp.request("http://runtime/readyz");
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
    const missingBucketReadiness = await missingBucketApp.request("http://runtime/readyz");
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
    const missingWebhookReadiness = await missingWebhookRoutingApp.request("http://runtime/readyz");
    assert.equal(missingWebhookReadiness.status, 503);
    assert.equal((await missingWebhookReadiness.json()).webhooks.ok, false);

    const childPort = await freePort();
    const childEnvironment = {
      ...process.env,
      SURREAL_ENDPOINT: state.endpoint,
      SURREAL_USERNAME: "root",
      SURREAL_PASSWORD: "root",
      SURREAL_NAMESPACE: state.namespace,
      SURREAL_DATABASE: state.database,
      REBASE_RUNTIME_SECRET: secret,
      REBASE_QUEUE_REDIS_URL: redis.url,
      REBASE_QUEUE_PREFIX: `rebase-server-probe-${Date.now().toString(36)}`,
      REBASE_STORAGE_BUCKET: "runtime-probe-bucket",
      REBASE_HTTP_PORT: String(childPort),
      REBASE_HTTP_BODY_LIMIT_BYTES: "2048",
    };
    const runtimeProfile = path.join(redis.directory, "runtime.env");
    fs.writeFileSync(runtimeProfile, Object.entries(childEnvironment)
      .filter(([name]) => /^(?:SURREAL_|REBASE_|NODE_ENV$|AWS_REGION$|SQS_ENDPOINT$)/.test(name))
      .map(([name, profileValue]) => `${name}=${profileValue}`)
      .join("\n"));
    const inheritedEnvironment = Object.fromEntries(Object.entries(process.env)
      .filter(([name]) => !/^(?:SURREAL_|REBASE_|NODE_ENV$|AWS_REGION$|SQS_ENDPOINT$)/.test(name)));
    runtimeChild = spawn(process.execPath, ["gateway/server.js", "--env-file", runtimeProfile], {
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
    console.log("runtime: queues, lifecycle fencing, recovery, OAuth signin, effects, schedules, webhooks, readiness, and context races passed");
  } finally {
    await stopChild(runtimeChild);
    await new Promise((resolve) => httpServer.close(resolve));
    await Promise.all(stops.map((stop) => stop?.()));
    await recoveryRateLimiter.close();
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
