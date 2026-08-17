#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { DatabaseRuntime } = require("../gateway/runtime/database");
const { createLocalProviders } = require("../gateway/providers/local");
const { createMemoryQueue } = require("../gateway/queues/memory");
const { startServer } = require("../gateway/server");
const { createWorker } = require("../gateway/worker");
const { populate } = require("./populate");

function queryResult(response) {
  if (!Array.isArray(response)) return response;
  const last = response.at(-1);
  return Array.isArray(last) ? last : last;
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function startDisposable() {
  if (process.env.REBASE_PROBE_DEBUG) console.error("probe: starting disposable server");
  const port = await freePort();
  const serverProcess = spawn("surreal", [
    "start", "memory", "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--async-event-interval", "100ms",
    "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  serverProcess.stderr.on("data", (chunk) => { stderr += chunk; });
  const endpoint = `ws://127.0.0.1:${port}/rpc`;
  let connected = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (serverProcess.exitCode !== null) break;
    connected = await new Promise((resolve) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (connected) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  if (!connected) {
    serverProcess.kill("SIGTERM");
    throw new Error(`Disposable SurrealDB did not start${stderr.trim() ? `: ${stderr.trim()}` : ""}`);
  }
  if (process.env.REBASE_PROBE_DEBUG) console.error("probe: disposable server ready");
  return { endpoint, process: serverProcess };
}

async function stopDisposable(disposable) {
  if (!disposable || disposable.process.exitCode !== null) return;
  const exited = new Promise((resolve) => disposable.process.once("exit", resolve));
  disposable.process.kill("SIGTERM");
  const stopped = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 2000)),
  ]);
  if (!stopped && disposable.process.exitCode === null) {
    disposable.process.kill("SIGKILL");
    await exited;
  }
}

function compile(projectDir, outputDir, namespace, database) {
  const result = spawnSync(process.execPath, ["compile.js", "--project", projectDir, "--output", outputDir], {
    cwd: path.resolve(__dirname, ".."),
    env: { ...process.env, SURREAL_NAMESPACE: namespace, SURREAL_DATABASE: database },
    encoding: "utf8",
  });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
}

async function connect(endpoint, namespace, database) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.query(`DEFINE NAMESPACE IF NOT EXISTS ${namespace}; USE NS ${namespace}; REMOVE DATABASE IF EXISTS ${database}; DEFINE DATABASE ${database}; USE DB ${database};`);
  await db.use({ namespace, database });
  return db;
}

async function signIn(endpoint, namespace, database, email, password) {
  const db = new Surreal();
  await db.connect(endpoint);
  const tokens = await db.signin({ namespace, database, access: "account", variables: { email, password } });
  return { db, token: tokens.access };
}

function rows(response) {
  const value = queryResult(response);
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

async function setup(options) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-probe-"));
  const buildDir = path.join(temp, "build");
  compile("designs/test", buildDir, options.namespace, options.database);
  const db = await connect(options.endpoint, options.namespace, options.database);
  await db.query(fs.readFileSync(path.join(buildDir, "schema.surql"), "utf8"));
  return { temp, buildDir, db };
}

async function securityProbe(options) {
  if (process.env.REBASE_PROBE_DEBUG) console.error("probe: security setup");
  const setupState = await setup(options);
  const { db } = setupState;
  try {
    const permissions = [
      "test_primitive_select", "test_primitive_create", "test_primitive_update", "test_primitive_delete",
      "test_relation_select", "test_relation_create", "test_relation_update", "test_relation_delete",
      "test_multiref_select", "test_multiref_create", "test_multiref_update", "test_multiref_delete",
      "test_tree_select", "test_tree_create", "test_tree_update", "test_tree_delete",
      "email_brevo_config_select", "email_campaign_profile_select",
    ];
    await db.query(`
      CREATE groups:team SET name = 'Team', parents = [groups:root], role = $permissions;
      CREATE groups:other SET name = 'Other', parents = [groups:root], role = $permissions;
      CREATE user:alice SET name = 'Alice', email = 'alice@example.com', password = crypto::argon2::generate('password123'), parents = [groups:team], login_access = true;
      CREATE user:bob SET name = 'Bob', email = 'bob@example.com', password = crypto::argon2::generate('password123'), parents = [groups:other], login_access = true;
    `, { permissions });
    const alice = await signIn(options.endpoint, options.namespace, options.database, "alice@example.com", "password123");
    const bob = await signIn(options.endpoint, options.namespace, options.database, "bob@example.com", "password123");
    try {
      const aliceActor = rows(await db.query("SELECT id, permissions, z_access_index FROM user:alice;"))[0];
      assert(aliceActor.permissions.includes("test_primitive_create"));
      assert(aliceActor.z_access_index.includes("groups:team"));
      await db.query("CREATE groups:team_child SET name = 'Team Child', parents = [groups:team], role = [];");
      await assert.rejects(
        db.query("UPDATE groups:team SET parents = [groups:team_child];"),
        /ERR_CYCLE/,
      );

      const delegated = rows(await alice.db.query("CREATE test_primitive:delegation SET owned_by = $auth, a_string = 'owned', a_decimal = 1dec; UPDATE test_primitive:delegation SET owned_by = groups:team RETURN AFTER;"));
      assert.equal(String(delegated.at(-1).owned_by), "groups:team");
      assert.equal(String(rows(await alice.db.query("UPDATE test_primitive:delegation SET owned_by = $auth RETURN AFTER;"))[0].owned_by), "groups:team");
      assert.equal(String(rows(await alice.db.query("UPDATE test_primitive:delegation SET owned_by = user:bob RETURN AFTER;"))[0].owned_by), "groups:team");

      await db.query(`
        CREATE test_primitive:scalar_source SET owned_by = user:alice, a_string = 'scalar', a_decimal = 1dec;
        CREATE test_primitive:array_source SET owned_by = user:alice, a_string = 'array', a_decimal = 1dec;
        CREATE test_relation:derived SET owned_by = user:bob, a_primitive = test_primitive:scalar_source, a_primitive_array = [test_primitive:array_source], a_polymorphic = user:bob;
        CREATE test_multiref:principal_refs SET owned_by = user:bob, a_name = 'principal', a_creator = user:alice, a_owning_group = groups:team;
        CREATE email_brevo_config:public SET owned_by = user:bob, label = 'Public', visibility = true, from_email = 'from@example.com', from_name = 'From', api_secret_ref = 'secret:x', account_key = 'public';
      `);
      let derived = rows(await db.query("SELECT readers_index FROM test_relation:derived;"))[0];
      assert.deepEqual(new Set(derived.readers_index), new Set(["user:alice"]));
      assert.equal(String(rows(await alice.db.query("SELECT id FROM test_relation:derived;"))[0].id), "test_relation:derived");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_multiref:principal_refs;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM email_brevo_config:public;")).length, 1);

      await db.query("UPDATE test_primitive:scalar_source SET owned_by = user:bob;");
      await db.query("UPDATE test_primitive:array_source SET owned_by = user:bob;");
      derived = rows(await db.query("SELECT readers_index FROM test_relation:derived;"))[0];
      assert.deepEqual(new Set(derived.readers_index), new Set(["user:bob"]));
      assert.equal(rows(await alice.db.query("SELECT id FROM test_relation:derived;")).length, 0);
      assert(rows(await alice.db.query("SELECT * FROM v_test_prim WHERE target = test_primitive:scalar_source;")).length > 0);

      await db.query(`
        CREATE test_tree:root_a SET owned_by = user:alice, a_name = 'A';
        CREATE test_tree:child_b SET owned_by = user:bob, a_name = 'B', a_parent = test_tree:root_a;
        CREATE test_tree:child_c SET owned_by = user:bob, a_name = 'C', a_parent = test_tree:child_b;
      `);
      let chain = rows(await db.query("SELECT id, readers_index FROM test_tree WHERE id IN [test_tree:child_b, test_tree:child_c] ORDER BY id;"));
      assert(chain.every((record) => record.readers_index.includes("user:alice")));
      await db.query("UPDATE test_tree:root_a SET owned_by = user:bob;");
      chain = rows(await db.query("SELECT id, readers_index FROM test_tree WHERE id IN [test_tree:child_b, test_tree:child_c] ORDER BY id;"));
      assert(chain.every((record) => !record.readers_index.includes("user:alice")));
      await assert.rejects(
        db.query("UPDATE test_tree:root_a SET a_parent = test_tree:child_c;"),
        /REBASE_READER_CYCLE/,
      );
      let audited = false;
      for (let attempt = 0; attempt < 40; attempt += 1) {
        audited = rows(await db.query("SELECT id FROM audit_mutation WHERE target = test_relation:derived LIMIT 1;")).length > 0;
        if (audited) break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert(audited);
      console.log("security: ownership, visibility, principal exclusion, readers, revocation, DAGs, views, and audit passed");
    } finally {
      await alice.db.close();
      await bob.db.close();
    }
  } finally {
    await db.close();
    fs.rmSync(setupState.temp, { recursive: true, force: true });
  }
}

async function gatewayProbe(options) {
  const setupState = await setup(options);
  const { db, buildDir } = setupState;
  let server;
  try {
    await db.query(`
      CREATE user:runtime SET name = 'Runtime', email = 'runtime@example.com', password = crypto::argon2::generate('runtime-password'), parents = [groups:root], login_access = true;
      CREATE email_brevo_config:primary SET owned_by = groups:root, label = 'Primary', visibility = false, from_email = 'from@example.com', from_name = 'Runtime', api_secret_ref = 'env:RUNTIME_TEST_SECRET', account_key = 'primary';
      CREATE email_campaign_profile:weekly SET owned_by = groups:root, profile_key = 'weekly', name = 'Weekly', visibility = false, config = email_brevo_config:primary, subject = 'Weekly', html = '<p>Hello</p>', recipients = ['to@example.com'];
    `);
    const auth = await signIn(options.endpoint, options.namespace, options.database, "runtime@example.com", "runtime-password");
    const runtime = new DatabaseRuntime({ db, namespace: options.namespace, database: options.database });
    const queue = createMemoryQueue();
    const secret = "probe-webhook-secret";
    server = await startServer({
      database: runtime,
      queue,
      providers: createLocalProviders({ webhookSecret: secret }),
      paths: { projectDir: buildDir },
      port: 0,
      outboxIntervalMs: 10,
    });
    const base = `http://${server.hostname}:${server.port}`;
    const request = async (method, route, body, headers = {}) => {
      const response = await fetch(base + route, {
        method,
        headers: { ...(auth.token ? { authorization: `Bearer ${auth.token}` } : {}), ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: response.status, body: JSON.parse(await response.text()) };
    };
    const immediate = await request("POST", "/v1/edge/sendMail", { records: { config: "email_brevo_config:primary" }, args: { message: { to: "to@example.com", subject: "Hello" } } });
    assert.equal(immediate.status, 200);
    const wrongTable = await request("POST", "/v1/edge/sendMail", { records: { config: "test_primitive:delegation" }, args: { message: { to: "to@example.com", subject: "Hello" } } });
    assert.equal(wrongTable.status, 400);
    const queued = await request("POST", "/v1/edge/campaignMail", { records: { config: "email_brevo_config:primary", profile: "email_campaign_profile:weekly" }, args: { campaign: { name: "Weekly" } }, requestId: "probe-job" });
    assert.equal(queued.status, 202);
    let job;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      job = await request("GET", queued.body.data.statusUrl);
      if (["succeeded", "failed", "cancelled"].includes(job.body.data.status)) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(job.body.data.status, "succeeded");
    const raw = JSON.stringify({ id: "probe-event", provider: "local", type: "delivered" });
    const signature = crypto.createHmac("sha256", secret).update(raw).digest("hex");
    const webhook = await request("POST", "/v1/webhooks/campaignWebhook", JSON.parse(raw), { "x-rebase-signature": signature, "x-rebase-event-id": "probe-event" });
    const duplicate = await request("POST", "/v1/webhooks/campaignWebhook", JSON.parse(raw), { "x-rebase-signature": signature, "x-rebase-event-id": "probe-event" });
    assert.equal(webhook.status, 200);
    assert.equal(duplicate.body.data.duplicate, true);
    const handlers = server.handlers;
    await server.close();
    server = null;

    const cancelledJob = await runtime.createJob({
      caller: "user:runtime",
      capability: "campaignMail",
      args: {},
      records: { config: "email_brevo_config:primary", profile: "email_campaign_profile:weekly" },
      requestId: "probe-cancel",
      maxAttempts: 5,
    });
    const cancelled = await runtime.cancelJob("user:runtime", String(cancelledJob.id));
    assert.equal(cancelled.status, "cancelled");

    let providerAttempts = 0;
    const retryProviders = createLocalProviders({ webhookSecret: secret });
    const originalForResource = retryProviders.email.forResource.bind(retryProviders.email);
    retryProviders.email.forResource = (resource) => {
      const provider = originalForResource(resource);
      return {
        ...provider,
        async sendCampaign(input) {
          providerAttempts += 1;
          if (providerAttempts === 1) throw Object.assign(new Error("Temporary provider failure"), { code: "PROVIDER_TEMPORARY", retryable: true, delaySeconds: 0 });
          return provider.sendCampaign(input);
        },
      };
    };
    const retryJob = await runtime.createJob({
      caller: "user:runtime",
      capability: "campaignMail",
      args: {},
      records: { config: "email_brevo_config:primary", profile: "email_campaign_profile:weekly" },
      requestId: "probe-retry",
      maxAttempts: 3,
    });
    const retryWorker = createWorker({ database: runtime, handlers, providers: retryProviders, workerId: "probe-retry-worker" });
    const retryEnvelope = { jobId: String(retryJob.id), capability: "campaignMail" };
    assert.equal((await retryWorker.consume({ envelope: retryEnvelope })).action, "ack");
    assert.equal((await runtime.job("user:runtime", String(retryJob.id))).status, "waiting");
    assert.equal((await retryWorker.consume({ envelope: retryEnvelope })).action, "ack");
    assert.equal((await runtime.job("user:runtime", String(retryJob.id))).status, "succeeded");

    const revokedJob = await runtime.createJob({
      caller: "user:runtime",
      capability: "campaignMail",
      args: {},
      records: { config: "email_brevo_config:primary", profile: "email_campaign_profile:weekly" },
      requestId: "probe-reauthorize",
      maxAttempts: 1,
    });
    await db.query("CREATE groups:isolated SET name = 'Isolated', parents = [groups:root], role = []; CREATE user:isolated SET name = 'Isolated', email = 'isolated@example.com', parents = [groups:isolated]; UPDATE email_brevo_config:primary SET owned_by = user:isolated;");
    const revokedWorker = createWorker({ database: runtime, handlers, providers: createLocalProviders(), workerId: "probe-revoked-worker" });
    assert.equal((await revokedWorker.consume({ envelope: { jobId: String(revokedJob.id), capability: "campaignMail" } })).action, "dead-letter");
    assert.equal((await runtime.job("user:runtime", String(revokedJob.id))).status, "failed");
    await auth.db.close();
    console.log("gateway: request, durable job, cancellation, retry, reauthorization, and webhook flows passed");
  } finally {
    await server?.close().catch(() => {});
    await db.close();
    fs.rmSync(setupState.temp, { recursive: true, force: true });
  }
}

async function dataProbe(options) {
  const states = [];
  try {
    const snapshots = [];
    for (const suffix of ["primary", "replay"]) {
      const setupState = await setup({ ...options, database: `${options.database}_${suffix}` });
      states.push(setupState);
      const result = await populate({
        project: "test",
        sourceDir: path.resolve(__dirname, "../designs/test"),
        buildDir: setupState.buildDir,
        endpoint: options.endpoint,
        username: "root",
        password: "root",
        namespace: options.namespace,
        database: `${options.database}_${suffix}`,
        table: "all",
        count: 3,
        batchSize: 2,
        reservoirSize: 100,
        pageSize: 50,
        seed: "rebase-data-probe",
      });
      assert(Object.values(result.created).every((count) => count === 3));
      assert.equal(rows(await setupState.db.query("SELECT id FROM test_relation;")).length, 3);
      snapshots.push(rows(await setupState.db.query(`
        SELECT
          <string>id AS id,
          <string>owned_by AS owned_by,
          a_string,
          a_int,
          <string>a_decimal AS a_decimal,
          a_bool,
          <string>a_datetime AS a_datetime,
          a_object,
          a_enum
        FROM test_primitive ORDER BY id;
      `)));
    }
    assert.deepEqual(snapshots[1], snapshots[0]);
    console.log("data: schema-driven generation, strict references, batching, reservoirs, and seed replay passed");
  } finally {
    for (const setupState of states) {
      await setupState.db.close().catch(() => {});
      fs.rmSync(setupState.temp, { recursive: true, force: true });
    }
  }
}

async function main() {
  const command = process.argv[2] || "all";
  const disposable = process.env.REBASE_PROBE_ENDPOINT ? null : await startDisposable();
  const endpoint = process.env.REBASE_PROBE_ENDPOINT || disposable.endpoint;
  const namespace = `rebase_probe_${Date.now().toString(36)}`;
  const database = "probe";
  const options = { endpoint, namespace, database };
  if (process.env.REBASE_PROBE_DEBUG) console.error(`probe: command=${command} endpoint=${endpoint}`);
  try {
    if (command === "security" || command === "all") await securityProbe(options);
    if (command === "gateway" || command === "all") await gatewayProbe(options);
    if (command === "data" || command === "all") await dataProbe(options);
    if (!["security", "gateway", "data", "all"].includes(command)) throw new Error(`Unknown probe: ${command}`);
    console.log("probe: PASS");
  } finally {
    await stopDisposable(disposable);
  }
}

if (require.main === module) {
  main().then(
    () => process.exit(0),
    (error) => {
      console.error(`probe: FAIL: ${error.message}`);
      process.exit(1);
    },
  );
}

module.exports = { dataProbe, gatewayProbe, securityProbe };
