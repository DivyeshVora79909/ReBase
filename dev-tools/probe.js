#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { populate } = require("./populate");
const { resolveConfiguration } = require("../config/environment");

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
  const result = spawnSync(process.execPath, [
    path.join("dev-tools", "compiler", "cli.js"),
    "--project", projectDir,
    "--output", outputDir,
    "--namespace", namespace,
    "--database", database,
  ], {
    cwd: path.resolve(__dirname, ".."),
    env: process.env,
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

async function signIn(endpoint, namespace, database, identifier, password) {
  const db = new Surreal();
  await db.connect(endpoint);
  const tokens = await db.signin({
    namespace,
    database,
    access: "account_password",
    variables: { identifier, password },
  });
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
      "node_create", "node_select", "node_update",
      "test_primitive_select", "test_primitive_create", "test_primitive_update", "test_primitive_delete",
      "test_relation_select", "test_relation_create", "test_relation_update", "test_relation_delete",
      "test_multiref_select", "test_multiref_create", "test_multiref_update", "test_multiref_delete",
      "test_tree_select", "test_tree_create", "test_tree_update", "test_tree_delete",
      "email_brevo_config_select",
    ];
    await db.query(`
      CREATE groups:team SET name = 'Team', parents = [groups:root], role = $permissions;
      CREATE groups:other SET name = 'Other', parents = [groups:root], role = $permissions;
      CREATE user:alice SET name = 'Alice', username = 'Alice_User', password = crypto::argon2::generate('password123'), parents = [groups:team], login_access = true;
      CREATE user:bob SET name = 'Bob', password = crypto::argon2::generate('password123'), parents = [groups:other], login_access = true;
      CREATE authentication_email:alice SET principal = user:alice, address = 'alice@example.com', verified_revision = 1;
      CREATE authentication_email:bob SET principal = user:bob, address = 'bob@example.com', verified_revision = 1;
    `, { permissions });
    await db.query(`
      UPDATE authentication_email:alice SET verified_revision = revision, verified_at = time::now();
      UPDATE authentication_email:bob SET verified_revision = revision, verified_at = time::now();
    `);
    await assert.rejects(
      db.query("CREATE user:empty_parent SET name = 'Empty', parents = [];"),
      /parents|assert|validation/i,
    );
    await assert.rejects(
      db.query("CREATE user:missing_parent SET name = 'Missing', parents = [groups:missing];"),
      /parents|assert|validation|exists/i,
    );
    await assert.rejects(
      db.query("CREATE groups:empty_parent SET name = 'Empty', parents = [];"),
      /parents|assert|validation/i,
    );
    const alice = await signIn(options.endpoint, options.namespace, options.database, "alice@example.com", "password123");
    const bob = await signIn(options.endpoint, options.namespace, options.database, "bob@example.com", "password123");
    const aliceByUsername = await signIn(options.endpoint, options.namespace, options.database, "ALICE_USER", "password123");
    try {
      assert.equal(rows(await db.query("SELECT VALUE username FROM user:alice;"))[0], "alice_user");
      assert(aliceByUsername.token);
      await assert.rejects(
        db.query("CREATE user:duplicate_username SET name = 'Duplicate', username = 'alice_user', parents = [groups:root];"),
        /unique|index|username/i,
      );
      await db.query(`
        CREATE user:username_claim_1 SET name = 'Claim 1', parents = [groups:root];
        CREATE user:username_claim_2 SET name = 'Claim 2', parents = [groups:root];
        CREATE user:username_claim_3 SET name = 'Claim 3', parents = [groups:root];
        CREATE user:username_claim_4 SET name = 'Claim 4', parents = [groups:root];
      `);
      const usernameClaims = await Promise.allSettled([
        db.query("UPDATE user:username_claim_1 SET username = 'shared_name';"),
        db.query("UPDATE user:username_claim_2 SET username = 'shared_name';"),
        db.query("UPDATE user:username_claim_3 SET username = 'shared_name';"),
        db.query("UPDATE user:username_claim_4 SET username = 'shared_name';"),
      ]);
      assert.equal(rows(await db.query("SELECT id FROM user WHERE username = 'shared_name';")).length, 1);
      assert(usernameClaims.filter((claim) => claim.status === "rejected").length >= 3);
      const aliceActor = rows(await db.query("SELECT id, permissions, z_access_index FROM user:alice;"))[0];
      assert(aliceActor.permissions.includes("test_primitive_create"));
      assert(aliceActor.z_access_index.includes("groups:team"));
      const defaultParent = rows(await alice.db.query(
        "CREATE user:alice_child SET name = 'Alice Child' RETURN AFTER;",
      ))[0];
      assert.deepEqual(defaultParent.parents.map(String), ["user:alice"]);

      // Identity addresses are separate records. Changing one fences its
      // verification and any outstanding challenge without changing the
      // authorization graph or the password credential.
      const identityBefore = rows(await db.query(
        "SELECT id, address, revision, verified_revision FROM authentication_email:alice;",
      ))[0];
      assert.equal(identityBefore.address, "alice@example.com");
      assert.equal(identityBefore.verified_revision, 1);
      await alice.db.query(
        "UPDATE authentication_email:alice SET address = 'alice-renamed@example.com';",
      );
      let identityAfter = identityBefore;
      for (let attempt = 0; attempt < 40; attempt += 1) {
        identityAfter = rows(await db.query(
          "SELECT id, address, revision, verified_revision FROM authentication_email:alice;",
        ))[0];
        if (identityAfter?.address === "alice-renamed@example.com" && identityAfter.revision > identityBefore.revision) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      assert.equal(identityAfter.address, "alice-renamed@example.com");
      assert(identityAfter.revision > identityBefore.revision);
      assert.equal(identityAfter.verified_revision, undefined);
      await assert.rejects(
        signIn(options.endpoint, options.namespace, options.database, "alice-renamed@example.com", "password123"),
        /signin|authentication|access|record/i,
      );
      await db.query(
        "UPDATE authentication_email:alice SET verified_revision = revision, verified_at = time::now();",
      );
      const renamedAlice = await signIn(
        options.endpoint,
        options.namespace,
        options.database,
        "alice-renamed@example.com",
        "password123",
      );
      assert(renamedAlice.token);
      await renamedAlice.db.close();
      await alice.db.query(
        "CREATE user:alice_team_child SET name = 'Alice Team Child', parents = [groups:team];",
      );
      const visibleParent = rows(await db.query(
        "SELECT * FROM user:alice_team_child;",
      ))[0];
      assert.deepEqual(visibleParent.parents.map(String), ["groups:team"]);
      await assert.rejects(
        alice.db.query("CREATE user:alice_empty_child SET name = 'Alice Empty Child', parents = [];"),
        /parents|assert|validation/i,
      );
      await assert.rejects(
        alice.db.query("CREATE user:alice_hidden_child SET name = 'Alice Hidden Child', parents = [groups:other];"),
        /parents|assert|validation|exists/i,
      );
      await db.query(`
        CREATE groups:other_child SET name = 'Other Child', parents = [groups:other], role = [];
        CREATE user:mixed_parent_child SET
          name = 'Mixed Parent Child',
          parents = [user:alice, groups:other];
      `);
      assert.equal(rows(await alice.db.query("SELECT id FROM groups:other;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM user:mixed_parent_child;")).length, 1);

      const retainedHidden = rows(await alice.db.query(`
        UPDATE user:mixed_parent_child
        SET parents = [user:alice, groups:other, groups:team]
        RETURN AFTER;
      `))[0];
      assert.deepEqual(
        new Set(retainedHidden.parents.map(String)),
        new Set(["user:alice", "groups:other", "groups:team"]),
      );
      await assert.rejects(
        alice.db.query(`
          UPDATE user:mixed_parent_child
          SET parents = [user:alice, groups:other, groups:team, groups:other_child];
        `),
        /parents|assert|validation|exists/i,
      );
      await assert.rejects(
        alice.db.query(`
          UPDATE user:mixed_parent_child
          SET parents = [user:alice, groups:team];
        `),
        /parents|assert|validation|exists/i,
      );
      const removedVisible = rows(await alice.db.query(`
        UPDATE user:mixed_parent_child
        SET parents = [user:alice, groups:other]
        RETURN AFTER;
      `))[0];
      assert.deepEqual(
        new Set(removedVisible.parents.map(String)),
        new Set(["user:alice", "groups:other"]),
      );
      await db.query("CREATE groups:team_child SET name = 'Team Child', parents = [groups:team], role = [];");
      await assert.rejects(
        db.query("UPDATE groups:team SET parents = [groups:team_child];"),
        /ERR_CYCLE/,
      );

      const delegated = rows(await alice.db.query("CREATE test_primitive:delegation SET owned_by = $auth, a_string = 'owned', a_decimal = 1dec; UPDATE test_primitive:delegation SET owned_by = groups:team RETURN AFTER;"));
      assert.equal(String(delegated.at(-1).owned_by), "groups:team");
      assert.equal(String(rows(await alice.db.query("UPDATE test_primitive:delegation SET owned_by = $auth RETURN AFTER;"))[0].owned_by), "groups:team");
      await assert.rejects(
        alice.db.query("UPDATE test_primitive:delegation SET owned_by = user:bob RETURN AFTER;"),
        /owned_by|assert|validation|exists/i,
      );

      await db.query(`
        CREATE test_primitive:scalar_source SET owned_by = user:alice, a_string = 'scalar', a_decimal = 1dec;
        CREATE test_primitive:array_source SET owned_by = user:alice, a_string = 'array', a_decimal = 1dec;
        CREATE test_primitive:hidden_reference SET owned_by = user:bob, a_string = 'hidden', a_decimal = 1dec;
        CREATE test_relation:derived SET owned_by = user:bob, a_primitive = test_primitive:scalar_source, a_primitive_array = [test_primitive:array_source], a_polymorphic = user:bob;
        CREATE test_multiref:principal_refs SET owned_by = user:bob, a_name = 'principal', a_creator = user:alice, a_owning_group = groups:team;
        CREATE email_brevo_config:public SET owned_by = user:bob, label = 'Public', visibility = true, from_email = 'from@example.com', from_name = 'From', api_key = 'client-brevo-key';
        CREATE test_primitive:change_log_live SET owned_by = user:alice, a_string = 'live', a_decimal = 1dec;
        CREATE test_primitive:change_log_deleted SET owned_by = user:alice, a_string = 'deleted', a_decimal = 1dec;
        CREATE change_logs:probe_resource CONTENT { at: time::now(), table_name: 'test_primitive', target: test_primitive:change_log_live, actor: NONE, before: { a_string: 'before' } };
        CREATE change_logs:probe_deleted CONTENT { at: time::now(), table_name: 'test_primitive', target: test_primitive:change_log_deleted, actor: NONE, before: { a_string: 'before' } };
        CREATE change_logs:probe_group CONTENT { at: time::now(), table_name: 'groups', target: groups:team, actor: NONE, before: { role: [] } };
        DELETE test_primitive:change_log_deleted;
      `);
      await assert.rejects(
        alice.db.query(`
          CREATE test_relation:missing_reference SET
            owned_by = $auth,
            a_primitive = test_primitive:missing;
        `),
        /a_primitive|assert|validation|exists/i,
      );
      await assert.rejects(
        alice.db.query(`
          CREATE test_relation:hidden_reference SET
            owned_by = $auth,
            a_primitive = test_primitive:hidden_reference;
        `),
        /a_primitive|assert|validation|exists/i,
      );
      await assert.rejects(
        alice.db.query(`
          CREATE test_relation:hidden_optional_reference SET
            owned_by = $auth,
            a_primitive = test_primitive:scalar_source,
            a_polymorphic = user:bob;
        `),
        /a_polymorphic|assert|validation|exists/i,
      );
      await assert.rejects(
        alice.db.query(`
          CREATE test_relation:hidden_array_reference SET
            owned_by = $auth,
            a_primitive = test_primitive:scalar_source,
            a_primitive_array = [test_primitive:array_source, test_primitive:hidden_reference];
        `),
        /a_primitive_array|assert|validation|exists/i,
      );
      assert.equal(rows(await alice.db.query(`
        CREATE test_relation:visible_references SET
          owned_by = $auth,
          a_primitive = test_primitive:scalar_source,
          a_polymorphic = NONE,
          a_primitive_array = [test_primitive:array_source]
        RETURN AFTER;
      `)).length, 1);
      let derived = rows(await db.query("SELECT readers_index FROM test_relation:derived;"))[0];
      assert.deepEqual(new Set(derived.readers_index), new Set(["user:alice"]));
      assert.equal(String(rows(await alice.db.query("SELECT id FROM test_relation:derived;"))[0].id), "test_relation:derived");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_multiref:principal_refs;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM email_brevo_config:public;")).length, 1);
      assert.equal(rows(await alice.db.query("SELECT id FROM change_logs:probe_resource;")).length, 1);
      assert.equal(rows(await alice.db.query("SELECT id FROM change_logs:probe_deleted;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM change_logs:probe_group;")).length, 1);
      assert.equal(rows(await bob.db.query("SELECT id FROM change_logs:probe_resource;")).length, 0);

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
      await db.query("UPDATE authentication_email:alice SET address = 'alice-final@example.com'; UPDATE groups:team SET role = ['node_select'];");
      let identityChangeLogs = [];
      let userChangeLogs = [];
      for (let attempt = 0; attempt < 40; attempt += 1) {
        identityChangeLogs = rows(await db.query("SELECT before FROM change_logs WHERE target = authentication_email:alice;"));
        userChangeLogs = rows(await db.query("SELECT before FROM change_logs WHERE target = user:alice;"));
        if (identityChangeLogs.some((entry) => entry.before?.address === "alice-renamed@example.com")
          && userChangeLogs.some((entry) => Array.isArray(entry.before?.permissions))) break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert(identityChangeLogs.some((entry) => entry.before?.address === "alice-renamed@example.com"));
      assert(userChangeLogs.some((entry) => Array.isArray(entry.before?.permissions)));
      const aliceVisibleLogs = rows(await alice.db.query("SELECT target FROM change_logs WHERE target = user:alice;"));
      const aliceVisibleIdentityLogs = rows(await alice.db.query("SELECT target FROM change_logs WHERE target = authentication_email:alice;"));
      const bobVisibleLogs = rows(await bob.db.query("SELECT target FROM change_logs WHERE target = user:alice;"));
      const bobVisibleIdentityLogs = rows(await bob.db.query("SELECT target FROM change_logs WHERE target = authentication_email:alice;"));
      assert(aliceVisibleLogs.length >= 1);
      assert(aliceVisibleLogs.every((entry) => String(entry.target) === "user:alice"));
      assert(aliceVisibleIdentityLogs.length >= 1);
      assert(aliceVisibleIdentityLogs.every((entry) => String(entry.target) === "authentication_email:alice"));
      assert.equal(bobVisibleLogs.length, 0);
      assert.equal(bobVisibleIdentityLogs.length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM change_logs:probe_resource;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM change_logs:probe_deleted;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM change_logs:probe_group;")).length, 1);
      console.log("security: authentication identities, ownership, readers, revocation, DAGs, views, audit, and change logs passed");
    } finally {
      await aliceByUsername.db.close();
      await alice.db.close();
      await bob.db.close();
    }
  } finally {
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
        configuration: resolveConfiguration({
          SURREAL_ENDPOINT: options.endpoint,
          SURREAL_USERNAME: "root",
          SURREAL_PASSWORD: "root",
          SURREAL_NAMESPACE: options.namespace,
          SURREAL_DATABASE: `${options.database}_${suffix}`,
        }),
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
          a_string,
          a_int,
          <string>a_decimal AS a_decimal,
          a_bool,
          <string>a_datetime AS a_datetime,
          a_object,
          a_enum
        FROM test_primitive;
      `)));
      snapshots.at(-1).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
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
    if (command === "data" || command === "all") await dataProbe(options);
    if (!["security", "data", "all"].includes(command)) throw new Error(`Unknown probe: ${command}`);
    console.log("probe: PASS");
  } finally {
    await stopDisposable(disposable);
  }
}

if (require.main === module) {
  main().then(
    () => process.exit(0),
    (error) => {
      console.error(`probe: FAIL: ${process.env.REBASE_PROBE_DEBUG ? error.stack : error.message}`);
      process.exit(1);
    },
  );
}

module.exports = { dataProbe, securityProbe };
