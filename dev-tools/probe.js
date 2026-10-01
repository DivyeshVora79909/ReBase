#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { populate } = require("./populate");
const { resolveConfiguration } = require("../config/environment");
const { compileFromArgs } = require("./compiler/cli");

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
  const configuration = resolveConfiguration({
    ...process.env,
    SURREAL_NAMESPACE: namespace,
    SURREAL_DATABASE: database,
  });
  return compileFromArgs({
    projectDir,
    frameworkDir: "framework",
    outputDir,
    configuration,
  }, path.resolve(__dirname, ".."));
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

async function setup(options, selectPolicy = "readers") {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-probe-"));
  const projectDir = path.join(temp, "project");
  fs.cpSync(path.resolve("designs/test"), projectDir, { recursive: true });
  if (selectPolicy !== "readers") {
    fs.appendFileSync(path.join(projectDir, "schema.surql"),
      `\nDEFINE TABLE rebase_select_policy SCHEMAFULL COMMENT '@rebase-select ${selectPolicy}';\n`);
  }
  const buildDir = path.join(temp, "build");
  compile(projectDir, buildDir, options.namespace, options.database);
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
      "unmarked_relation_select",
      "test_multiref_select", "test_multiref_create", "test_multiref_update", "test_multiref_delete",
      "test_tree_select", "test_tree_create", "test_tree_update", "test_tree_delete",
      "file_storage_config_select",
    ];
    await db.query(`
      CREATE rebase_group:team SET name = 'Team', parents = [rebase_group:root], role = $permissions;
      CREATE rebase_group:other SET name = 'Other', parents = [rebase_group:root], role = $permissions;
      CREATE rebase_group:outsider SET name = 'Outsider', parents = [rebase_group:root], role = $permissions;
      CREATE rebase_user:alice SET name = 'Alice', username = 'Alice_User', password = crypto::argon2::generate('password123'), parents = [rebase_group:team], login_access = true;
      CREATE rebase_user:bob SET name = 'Bob', password = crypto::argon2::generate('password123'), parents = [rebase_group:other], login_access = true;
      CREATE rebase_user:carol SET name = 'Carol', parents = [rebase_group:outsider], login_access = true;
      CREATE authentication_email:alice SET principal = rebase_user:alice, address = 'alice@example.com', verified_revision = 1;
      CREATE authentication_email:bob SET principal = rebase_user:bob, address = 'bob@example.com', verified_revision = 1;
    `, { permissions });
    await db.query(`
      UPDATE authentication_email:alice SET verified_revision = revision, verified_at = time::now();
      UPDATE authentication_email:bob SET verified_revision = revision, verified_at = time::now();
    `);
    await assert.rejects(
      db.query("CREATE rebase_user:empty_parent SET name = 'Empty', parents = [];"),
      /parents|assert|validation/i,
    );
    await assert.rejects(
      db.query("CREATE rebase_user:missing_parent SET name = 'Missing', parents = [rebase_group:missing];"),
      /parents|assert|validation|exists/i,
    );
    await assert.rejects(
      db.query("CREATE rebase_group:empty_parent SET name = 'Empty', parents = [];"),
      /parents|assert|validation/i,
    );
    const alice = await signIn(options.endpoint, options.namespace, options.database, "alice@example.com", "password123");
    const bob = await signIn(options.endpoint, options.namespace, options.database, "bob@example.com", "password123");
    const aliceByUsername = await signIn(options.endpoint, options.namespace, options.database, "ALICE_USER", "password123");
    try {
      assert.equal(rows(await db.query("SELECT VALUE username FROM rebase_user:alice;"))[0], "alice_user");
      assert(aliceByUsername.token);
      await assert.rejects(
        db.query("CREATE rebase_user:duplicate_username SET name = 'Duplicate', username = 'alice_user', parents = [rebase_group:root];"),
        /unique|index|username/i,
      );
      await db.query(`
        CREATE rebase_user:username_claim_1 SET name = 'Claim 1', parents = [rebase_group:root];
        CREATE rebase_user:username_claim_2 SET name = 'Claim 2', parents = [rebase_group:root];
        CREATE rebase_user:username_claim_3 SET name = 'Claim 3', parents = [rebase_group:root];
        CREATE rebase_user:username_claim_4 SET name = 'Claim 4', parents = [rebase_group:root];
      `);
      const usernameClaims = await Promise.allSettled([
        db.query("UPDATE rebase_user:username_claim_1 SET username = 'shared_name';"),
        db.query("UPDATE rebase_user:username_claim_2 SET username = 'shared_name';"),
        db.query("UPDATE rebase_user:username_claim_3 SET username = 'shared_name';"),
        db.query("UPDATE rebase_user:username_claim_4 SET username = 'shared_name';"),
      ]);
      assert.equal(rows(await db.query("SELECT id FROM rebase_user WHERE username = 'shared_name';")).length, 1);
      assert(usernameClaims.filter((claim) => claim.status === "rejected").length >= 3);
      const aliceActor = rows(await db.query("SELECT id, permissions, z_access_index FROM rebase_user:alice;"))[0];
      assert(aliceActor.permissions.includes("test_primitive_create"));
      assert(aliceActor.z_access_index.includes("rebase_group:team"));
      const defaultParent = rows(await alice.db.query(
        "CREATE rebase_user:alice_child SET name = 'Alice Child' RETURN AFTER;",
      ))[0];
      assert.deepEqual(defaultParent.parents.map(String), ["rebase_user:alice"]);

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
        "CREATE rebase_user:alice_team_child SET name = 'Alice Team Child', parents = [rebase_group:team];",
      );
      const visibleParent = rows(await db.query(
        "SELECT * FROM rebase_user:alice_team_child;",
      ))[0];
      assert.deepEqual(visibleParent.parents.map(String), ["rebase_group:team"]);
      await assert.rejects(
        alice.db.query("CREATE rebase_user:alice_empty_child SET name = 'Alice Empty Child', parents = [];"),
        /parents|assert|validation/i,
      );
      await assert.rejects(
        alice.db.query("CREATE rebase_user:alice_hidden_child SET name = 'Alice Hidden Child', parents = [rebase_group:other];"),
        /parents|assert|validation|exists/i,
      );
      await db.query(`
        CREATE rebase_group:other_child SET name = 'Other Child', parents = [rebase_group:other], role = [];
        CREATE rebase_user:mixed_parent_child SET
          name = 'Mixed Parent Child',
          parents = [rebase_user:alice, rebase_group:other];
      `);
      assert.equal(rows(await alice.db.query("SELECT id FROM rebase_group:other;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM rebase_user:mixed_parent_child;")).length, 1);

      const retainedHidden = rows(await alice.db.query(`
        UPDATE rebase_user:mixed_parent_child
        SET parents = [rebase_user:alice, rebase_group:other, rebase_group:team]
        RETURN AFTER;
      `))[0];
      assert.deepEqual(
        new Set(retainedHidden.parents.map(String)),
        new Set(["rebase_user:alice", "rebase_group:other", "rebase_group:team"]),
      );
      await assert.rejects(
        alice.db.query(`
          UPDATE rebase_user:mixed_parent_child
          SET parents = [rebase_user:alice, rebase_group:other, rebase_group:team, rebase_group:other_child];
        `),
        /parents|assert|validation|exists/i,
      );
      await assert.rejects(
        alice.db.query(`
          UPDATE rebase_user:mixed_parent_child
          SET parents = [rebase_user:alice, rebase_group:team];
        `),
        /parents|assert|validation|exists/i,
      );
      const removedVisible = rows(await alice.db.query(`
        UPDATE rebase_user:mixed_parent_child
        SET parents = [rebase_user:alice, rebase_group:other]
        RETURN AFTER;
      `))[0];
      assert.deepEqual(
        new Set(removedVisible.parents.map(String)),
        new Set(["rebase_user:alice", "rebase_group:other"]),
      );
      await db.query("CREATE rebase_group:team_child SET name = 'Team Child', parents = [rebase_group:team], role = [];");
      await assert.rejects(
        db.query("UPDATE rebase_group:team SET parents = [rebase_group:team_child];"),
        /ERR_CYCLE/,
      );

      const delegated = rows(await alice.db.query("CREATE test_primitive:delegation SET owned_by = $auth, a_string = 'owned', a_decimal = 1dec; UPDATE test_primitive:delegation SET owned_by = rebase_group:team RETURN AFTER;"));
      assert.equal(String(delegated.at(-1).owned_by), "rebase_group:team");
      assert.equal(String(rows(await alice.db.query("UPDATE test_primitive:delegation SET owned_by = $auth RETURN AFTER;"))[0].owned_by), "rebase_group:team");
      await assert.rejects(
        alice.db.query("UPDATE test_primitive:delegation SET owned_by = rebase_user:bob RETURN AFTER;"),
        /owned_by|assert|validation|exists/i,
      );

      await db.query(`
        CREATE test_primitive:scalar_source SET owned_by = rebase_user:alice, a_string = 'scalar', a_decimal = 1dec;
        CREATE test_primitive:array_source SET owned_by = rebase_user:alice, a_string = 'array', a_decimal = 1dec;
        CREATE test_primitive:hidden_reference SET owned_by = rebase_user:bob, a_string = 'hidden', a_decimal = 1dec;
        CREATE test_primitive:group_source SET owned_by = rebase_group:team, a_string = 'group parent', a_decimal = 1dec;
        CREATE test_relation:derived SET owned_by = rebase_user:bob, a_primitive = test_primitive:scalar_source, a_primitive_array = [test_primitive:array_source], a_polymorphic = rebase_user:bob;
        CREATE test_relation:group_reader SET owned_by = rebase_user:carol, a_primitive = test_primitive:group_source;
        CREATE unmarked_relation:unmarked_reader SET owned_by = rebase_user:carol, parent = test_primitive:scalar_source;
        CREATE test_multiref:principal_refs SET owned_by = rebase_user:bob, a_name = 'principal', a_creator = rebase_user:alice, a_owning_group = rebase_group:team;
        CREATE file_storage_config:public SET owned_by = rebase_user:bob, provider = 's3', visibility = true,
          access_key_id = 'client-storage-id', secret_access_key = 'client-storage-secret',
          endpoint = 'https://storage.local', region = 'local';
        CREATE test_primitive:change_log_live SET owned_by = rebase_user:alice, a_string = 'live', a_decimal = 1dec;
        CREATE test_primitive:change_log_deleted SET owned_by = rebase_user:alice, a_string = 'deleted', a_decimal = 1dec;
        CREATE audit_probe:change_only SET owned_by = rebase_user:alice, a_change_only = 'created';
        UPDATE audit_probe:change_only SET a_change_only = 'updated';
        DELETE test_primitive:change_log_deleted;
      `);
      const liveAudit = rows(await db.query("SELECT * FROM audit_mutation WHERE target = test_primitive:change_log_live AND event = 'CREATE';"));
      const deletedAudit = rows(await db.query("SELECT * FROM audit_mutation WHERE target = test_primitive:change_log_deleted ORDER BY event;"));
      assert.equal(liveAudit.length, 1, "CREATE audit is committed synchronously with the source row");
      assert.deepEqual(new Set(liveAudit[0].changed_fields), new Set([
        "a_string", "a_int", "a_decimal", "a_bool", "a_datetime", "a_enum",
      ]));
      assert.equal(liveAudit[0].before, undefined);
      assert.equal(liveAudit[0].after.a_string, "live");
      assert.equal(deletedAudit.filter((entry) => entry.event === "CREATE").length, 1);
      assert.equal(deletedAudit.filter((entry) => entry.event === "DELETE").length, 1);
      assert.equal(deletedAudit.find((entry) => entry.event === "DELETE").before.a_string, "deleted");
      assert.equal(deletedAudit.find((entry) => entry.event === "DELETE").after, undefined);
      const changeOnlyAudit = rows(await db.query("SELECT * FROM audit_mutation WHERE target = audit_probe:change_only ORDER BY event;"));
      assert.deepEqual(changeOnlyAudit.map((entry) => entry.event), ["CREATE", "UPDATE"]);
      assert(changeOnlyAudit.every((entry) => entry.changed_fields.length === 1 && entry.changed_fields[0] === "a_change_only"));
      assert(changeOnlyAudit.every((entry) => entry.before === undefined && entry.after === undefined),
        "value-free change audit records field names without copying their values");
      await assert.rejects(
        db.query("CREATE test_primitive:audit_failed SET owned_by = rebase_user:alice, a_string = 'invalid', a_decimal = -1dec;"),
        /a_decimal|assert|validation/i,
      );
      assert.equal(rows(await db.query("SELECT id FROM audit_mutation WHERE target = test_primitive:audit_failed;" )).length, 0,
        "a rejected source write leaves no audit row");
      const publicConfigAudit = rows(await db.query("SELECT after FROM audit_mutation WHERE target = file_storage_config:public AND event = 'CREATE';"))[0];
      assert(publicConfigAudit);
      assert.equal(publicConfigAudit.after.access_key_id, undefined, "private credentials are not copied into audit records");
      assert.equal(publicConfigAudit.after.secret_access_key, undefined);
      assert.equal(rows(await alice.db.query("SELECT id FROM audit_mutation;")).length, 0,
        "business audit rows are private to privileged operators");
      try {
        await alice.db.query("CREATE audit_mutation:forged CONTENT { event: 'CREATE', table_name: 'test_primitive', target: test_primitive:change_log_live };");
      } catch {
        // Native permissions can reject the statement or suppress the row.
      }
      assert.equal(rows(await db.query("SELECT id FROM audit_mutation:forged;")).length, 0,
        "record users cannot forge business audit rows");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_primitive:group_source;")).length, 1,
        "an authorized group owner is readable by its member");
      assert.equal(rows(await bob.db.query("SELECT id FROM test_primitive:group_source;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM test_relation:group_reader;")).length, 1,
        "a direct parent group intersects the caller's group access index");
      assert.equal(rows(await bob.db.query("SELECT id FROM test_relation:group_reader;")).length, 0);
      assert.deepEqual(rows(await db.query("SELECT readers_index FROM test_relation:group_reader;"))[0].readers_index,
        ["rebase_group:team"]);
      assert.equal(rows(await alice.db.query("SELECT id FROM unmarked_relation:unmarked_reader;")).length, 0,
        "an unmarked reference grants no reader access");
      const protectedReaderIndex = rows(await alice.db.query("SELECT readers_index FROM test_relation:group_reader;"))[0];
      assert.equal(protectedReaderIndex?.readers_index, undefined, "reader metadata is not exposed to clients");
      try {
        await alice.db.query("CREATE test_relation:forged_reader SET owned_by = $auth, a_primitive = test_primitive:scalar_source, readers_index = ['rebase_user:bob'];");
      } catch {
        // If the engine ignores a computed-field input, the stored index below
        // must still be calculated only from the marked parent.
      }
      const forgedReaderIndex = rows(await db.query("SELECT readers_index FROM test_relation:forged_reader;"))[0]?.readers_index;
      if (forgedReaderIndex) assert(!forgedReaderIndex.includes("rebase_user:bob"));
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
            a_polymorphic = rebase_user:bob;
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
      assert.deepEqual(new Set(derived.readers_index), new Set(["rebase_user:alice"]));
      assert.equal(String(rows(await alice.db.query("SELECT id FROM test_relation:derived;"))[0].id), "test_relation:derived");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_multiref:principal_refs;")).length, 0);
      assert.equal(rows(await alice.db.query("SELECT id FROM file_storage_config:public;")).length, 1);
      assert.equal(rows(await alice.db.query("SELECT id FROM audit_mutation;")).length, 0);
      assert.equal(rows(await bob.db.query("SELECT id FROM audit_mutation;")).length, 0);

      await db.query("UPDATE test_primitive:scalar_source SET owned_by = rebase_user:bob;");
      await db.query("UPDATE test_primitive:array_source SET owned_by = rebase_user:bob;");
      derived = rows(await db.query("SELECT readers_index FROM test_relation:derived;"))[0];
      assert.deepEqual(new Set(derived.readers_index), new Set(["rebase_user:bob"]));
      assert.equal(rows(await alice.db.query("SELECT id FROM test_relation:derived;")).length, 0);
      assert(rows(await alice.db.query("SELECT * FROM v_test_prim WHERE target = test_primitive:scalar_source;")).length > 0);

      await db.query(`
        CREATE test_tree:root_a SET owned_by = rebase_user:alice, a_name = 'A';
        CREATE test_tree:child_b SET owned_by = rebase_user:carol, a_name = 'B', a_parent = test_tree:root_a;
        CREATE test_tree:child_c SET owned_by = rebase_user:bob, a_name = 'C', a_parent = test_tree:child_b;
      `);
      let chain = rows(await db.query("SELECT id, readers_index FROM test_tree WHERE id IN [test_tree:child_b, test_tree:child_c] ORDER BY id;"));
      const childReaders = new Map(chain.map((record) => [String(record.id), new Set(record.readers_index)]));
      assert(childReaders.get("test_tree:child_b").has("rebase_user:alice"));
      assert(!childReaders.get("test_tree:child_c").has("rebase_user:alice"), "grandparent owners are not copied transitively");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_tree:child_c;")).length, 0,
        "tree ancestry does not grant access to a grandchild");
      await assert.rejects(
        db.query("CREATE test_tree:self_cycle SET owned_by = rebase_group:root, a_name = 'Self', a_parent = test_tree:self_cycle;"),
        /TOPOLOGY_ERR|REBASE_READER_CYCLE/,
      );
      await assert.rejects(
        db.query("UPDATE test_tree:root_a SET a_parent = test_tree:child_c;"),
        /REBASE_READER_CYCLE/,
      );
      await db.query("UPDATE test_tree:root_a SET owned_by = rebase_user:bob;");
      chain = rows(await db.query("SELECT id, readers_index FROM test_tree WHERE id IN [test_tree:child_b, test_tree:child_c] ORDER BY id;"));
      const changedParentReaders = new Map(chain.map((record) => [String(record.id), new Set(record.readers_index)]));
      assert(!changedParentReaders.get("test_tree:child_b").has("rebase_user:alice"));
      assert(!changedParentReaders.get("test_tree:child_c").has("rebase_user:alice"));
      await db.query("CREATE test_tree:root_other SET owned_by = rebase_group:team, a_name = 'Other';");
      await db.query("UPDATE test_tree:child_b SET a_parent = test_tree:root_other;");
      chain = rows(await db.query("SELECT id, readers_index FROM test_tree WHERE id IN [test_tree:child_b, test_tree:child_c] ORDER BY id;"));
      const reparentedReaders = new Map(chain.map((record) => [String(record.id), new Set(record.readers_index)]));
      assert(reparentedReaders.get("test_tree:child_b").has("rebase_group:team"));
      assert(!reparentedReaders.get("test_tree:child_c").has("rebase_group:team"), "reparented ancestors do not grant grandchild access");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_tree:child_b;")).length, 1,
        "a reader who belongs to the inherited group can read the direct child");
      assert.equal(rows(await bob.db.query("SELECT id FROM test_tree:child_b;")).length, 0,
        "an unrelated user cannot read through the inherited group");
      await db.query("UPDATE test_tree:root_other SET owned_by = rebase_group:other;");
      const finalReaders = rows(await db.query("SELECT readers_index FROM test_tree:child_b;"))[0].readers_index;
      assert.deepEqual(finalReaders, ["rebase_group:other"], "parent owner changes refresh direct readers");
      assert.equal(rows(await alice.db.query("SELECT id FROM test_tree:child_b;")).length, 0,
        "reparenting and parent owner changes revoke stale access");
      await db.query("UPDATE authentication_email:alice SET address = 'alice-final@example.com'; UPDATE rebase_group:team SET role = ['node_select'];");
      assert.equal(rows(await db.query("SELECT id FROM audit_mutation WHERE target = rebase_group:team;")).length, 0,
        "authorization graph maintenance is outside business audit");
      console.log("security: authentication, direct readers, group intersection, revocation, cycles, and synchronous field audit passed");
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

async function ownerSelectPolicyProbe(options) {
  const database = `${options.database}_owner_policy`;
  const setupState = await setup({ ...options, database }, "owner");
  const { db } = setupState;
  let reader;
  try {
    await db.query(`
      CREATE rebase_group:readers SET name = 'Readers', parents = [rebase_group:root],
        role = ['node_select', 'test_primitive_select', 'test_relation_select'];
      CREATE rebase_user:reader SET name = 'Reader', parents = [rebase_group:readers];
      CREATE rebase_user:owner SET name = 'Owner', parents = [rebase_group:root];
      CREATE test_primitive:owned SET owned_by = rebase_user:reader, a_string = 'owned', a_decimal = 1dec;
      CREATE test_relation:inherited SET owned_by = rebase_user:owner,
        a_primitive = test_primitive:owned;
      CREATE test_primitive:group_owned SET owned_by = rebase_group:readers,
        a_string = 'group owned', a_decimal = 1dec;
      DEFINE ACCESS c4_owner_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;
    `);
    reader = new Surreal();
    await reader.connect(options.endpoint);
    await reader.signin({ namespace: options.namespace, database, access: "c4_owner_reader" });

    assert.equal(rows(await reader.query("SELECT id FROM test_primitive:owned;")).length, 1,
      "owner access remains available under the owner profile");
    assert.equal(rows(await reader.query("SELECT id FROM test_primitive:group_owned;")).length, 1,
      "group ownership uses the same authorized principal intersection");
    assert.equal(rows(await reader.query("SELECT id FROM test_relation:inherited;")).length, 0,
      "the owner profile does not use inherited reader grants");
    const computed = rows(await db.query("SELECT readers_index FROM test_relation:inherited;"))[0].readers_index;
    assert.deepEqual(computed, ["rebase_user:reader"],
      "the protected reader index is computed identically under the owner profile");
    const projected = rows(await reader.query("SELECT readers_index FROM test_primitive:owned;"));
    assert.equal(projected[0]?.readers_index, undefined, "the protected reader index is not visible to clients");
    console.log("security: owner select policy keeps the direct reader index protected and unchanged");
  } finally {
    await reader?.close().catch(() => {});
    await db.close().catch(() => {});
    fs.rmSync(setupState.temp, { recursive: true, force: true });
  }
}

async function dataProbe(options) {
  const states = [];
  try {
    await assert.rejects(
      populate({ endpoint: "ws://override/rpc" }),
      /is process-profile configuration/,
    );
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
    if (command === "security" || command === "all") {
      await securityProbe(options);
      await ownerSelectPolicyProbe(options);
    }
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

module.exports = { dataProbe, ownerSelectPolicyProbe, securityProbe };
