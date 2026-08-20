#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { loadMaterials } = require("./compiler/materials");
const { generateBundle } = require("./compiler/pipeline");

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
      const finish = (value) => {
        socket.destroy();
        resolve(value);
      };
      socket.setTimeout(100, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Disposable SurrealDB did not start");
}

async function startDisposable(allowedPort) {
  const port = await freePort();
  const process = spawn("surreal", [
    "start", "memory",
    "--user", "root",
    "--pass", "root",
    "--bind", `127.0.0.1:${port}`,
    "--allow-net", `127.0.0.1:${allowedPort}`,
    "--no-banner",
    "--log", "error",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  process.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    await waitForPort(port, process);
  } catch (error) {
    process.kill("SIGTERM");
    throw new Error(`${error.message}${stderr.trim() ? `: ${stderr.trim()}` : ""}`);
  }
  return { endpoint: `ws://127.0.0.1:${port}/rpc`, process };
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

async function connectRoot(endpoint, namespace, database) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.query(`
    DEFINE NAMESPACE IF NOT EXISTS ${namespace};
    USE NS ${namespace};
    REMOVE DATABASE IF EXISTS ${database};
    DEFINE DATABASE ${database};
    USE DB ${database};
  `);
  await db.use({ namespace, database });
  return db;
}

async function connectExistingRoot(endpoint, namespace, database) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.use({ namespace, database });
  return db;
}

async function signIn(endpoint, namespace, database, email, password) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({
    namespace,
    database,
    access: "account",
    variables: { email, password },
  });
  return db;
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
}

async function startReceiver(state) {
  const server = http.createServer(async (request, response) => {
    try {
      if (request.method !== "POST") {
        response.writeHead(405).end();
        return;
      }
      if (request.headers.authorization !== "Bearer architecture-probe") {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "INVALID_WAKE_AUTH" }));
        return;
      }
      const body = await readJson(request);
      if (request.url === "/snapshot") {
        state.snapshots.push(body);
        const visible = rows(await state.observer.query(
          "SELECT id FROM type::record($id);",
          { id: body.id },
        ));
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
          provider_id: `provider:${body.id}`,
          observer_count: visible.length,
          snapshot_name: body.name,
        }));
        return;
      }
      if (request.url === "/effect") {
        state.effects.push(body);
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ accepted: true }));
        return;
      }
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "HANDLER_NOT_FOUND" }));
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: error.message }));
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, port: server.address().port };
}

async function uuidProbe(db) {
  await db.query(`
    DEFINE TABLE typed_id SCHEMAFULL;
    DEFINE FIELD id ON typed_id TYPE uuid;
    DEFINE FIELD value ON typed_id TYPE int;
    DEFINE TABLE untyped_id SCHEMAFULL;
    DEFINE FIELD value ON untyped_id TYPE int;
  `);
  await db.query(`
    CREATE typed_id SET value = 1;
    CREATE typed_id:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db' SET value = 2;
    CREATE type::record('typed_id', rand::uuid::v7()) SET value = 3;
    CREATE untyped_id SET value = 1;
  `);
  await assert.rejects(
    db.query("CREATE typed_id:bad SET value = 4;"),
    /Expected `uuid`/,
  );
  const typed = rows(await db.query(`
    SELECT
      <string>id AS id,
      <string>record::id(id) AS inner,
      type::is_uuid(record::id(id)) AS inner_is_uuid,
      value
    FROM typed_id ORDER BY value;
  `));
  assert.equal(typed.length, 3);
  assert(typed.every((record) => record.inner_is_uuid));
  assert(typed.every((record) => /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(record.inner)));
  const untyped = rows(await db.query(`
    SELECT type::is_uuid(record::id(id)) AS inner_is_uuid FROM untyped_id;
  `));
  assert.equal(untyped[0].inner_is_uuid, false);
  console.log("architecture: UUIDv7 record ID behavior passed");
}

async function synchronousEventProbe(db, receiverPort, state) {
  await db.query(`
    DEFINE TABLE sync_effect SCHEMAFULL;
    DEFINE FIELD id ON sync_effect TYPE uuid;
    DEFINE FIELD name ON sync_effect TYPE string;
    DEFINE FIELD provider_id ON sync_effect TYPE option<string> DEFAULT NONE;
    DEFINE FIELD observer_count ON sync_effect TYPE option<int> DEFAULT NONE;
    DEFINE FIELD snapshot_name ON sync_effect TYPE option<string> DEFAULT NONE;
    DEFINE EVENT sync_effect_create ON sync_effect
      WHEN $event = 'CREATE'
      THEN {
        LET $patch = http::post(
          'http://127.0.0.1:${receiverPort}/snapshot',
          { id: <string>$after.id, name: $after.name },
          { authorization: 'Bearer architecture-probe' }
        );
        UPDATE $after.id MERGE $patch;
      };

    DEFINE TABLE rollback_effect SCHEMAFULL;
    DEFINE FIELD id ON rollback_effect TYPE uuid;
    DEFINE FIELD name ON rollback_effect TYPE string;
    DEFINE EVENT rollback_effect_create ON rollback_effect
      WHEN $event = 'CREATE'
      THEN {
        LET $accepted = http::post(
          'http://127.0.0.1:${receiverPort}/effect',
          { id: <string>$after.id, name: $after.name },
          { authorization: 'Bearer architecture-probe' }
        );
        THROW 'PROBE_ROLLBACK_AFTER_HTTP';
      };

    DEFINE TABLE missing_handler_effect SCHEMAFULL;
    DEFINE FIELD id ON missing_handler_effect TYPE uuid;
    DEFINE EVENT missing_handler_effect_create ON missing_handler_effect
      WHEN $event = 'CREATE'
      THEN http::post(
        'http://127.0.0.1:${receiverPort}/missing',
        { id: <string>$after.id },
        { authorization: 'Bearer architecture-probe' }
      );
  `);
  const syncResponse = await db.query(`
    LET $id = type::record('sync_effect', rand::uuid::v7());
    CREATE ONLY $id SET name = 'snapshot' RETURN AFTER;
    RETURN (SELECT * FROM $id)[0];
  `);
  const created = syncResponse[1];
  const committed = syncResponse[2];
  if (process.env.REBASE_ARCHITECTURE_DEBUG) {
    console.error("sync created", created);
    console.error("sync committed", committed);
    console.error("sync snapshots", state.snapshots);
  }
  assert.match(String(created.id), /^sync_effect:u["']/);
  assert.equal(created.snapshot_name, undefined);
  assert.equal(committed.snapshot_name, "snapshot");
  assert.equal(committed.observer_count, 0);
  assert.equal(state.snapshots.length, 1);
  assert.equal(state.snapshots[0].name, "snapshot");
  assert.equal(String(committed.provider_id), `provider:${state.snapshots[0].id}`);

  await assert.rejects(
    db.query("CREATE rollback_effect SET name = 'external-effect';"),
    /PROBE_ROLLBACK_AFTER_HTTP/,
  );
  assert.equal(rows(await db.query("SELECT id FROM rollback_effect;")).length, 0);
  assert.equal(state.effects.length, 1);

  await assert.rejects(
    db.query("CREATE missing_handler_effect;"),
    /404|HANDLER_NOT_FOUND|HTTP request failed/i,
  );
  assert.equal(rows(await db.query("SELECT id FROM missing_handler_effect;")).length, 0);
  console.log("architecture: synchronous snapshot and rollback boundary passed");
}

async function referenceAuthorizationProbe(db, endpoint, namespace, database) {
  await db.query(`
    DEFINE TABLE principal SCHEMAFULL PERMISSIONS FOR select WHERE id = $auth;
    DEFINE FIELD email ON principal TYPE string;
    DEFINE FIELD password ON principal TYPE string PERMISSIONS NONE;

    DEFINE TABLE config SCHEMAFULL PERMISSIONS
      FOR select WHERE owned_by = $auth;
    DEFINE FIELD owned_by ON config TYPE record<principal>;
    DEFINE FIELD api_key ON config TYPE string PERMISSIONS NONE;

    DEFINE TABLE assert_exists_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON assert_exists_job TYPE record<config>
      ASSERT record::exists($value);

    DEFINE TABLE assert_owner_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON assert_owner_job TYPE record<config>
      ASSERT $value.owned_by = $auth;

    DEFINE TABLE assert_optional_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON assert_optional_job TYPE option<record<config>>
      ASSERT $value = NONE OR record::exists($value);

    DEFINE TABLE assert_array_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD configs ON assert_array_job TYPE array<record<config>>
      ASSERT array::all($value, |$reference| record::exists($reference));

    DEFINE TABLE assert_delta_job SCHEMAFULL PERMISSIONS
      FOR create, select, update WHERE true;
    DEFINE FIELD configs ON assert_delta_job TYPE array<record<config>>
      VALUE array::distinct($value ?? [])
      ASSERT array::all(
        array::difference($value ?? [], $before ?? []),
        |$reference| record::exists($reference)
      );

    DEFINE TABLE permission_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON permission_job TYPE record<config>
      PERMISSIONS FOR create WHERE record::exists($value);

    DEFINE TABLE owner_permission_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON owner_permission_job TYPE record<config>
      PERMISSIONS FOR create WHERE $value.owned_by = $auth;

    DEFINE TABLE exists_write SCHEMAFULL PERMISSIONS
      FOR create WHERE record::exists(config)
      FOR select WHERE true;
    DEFINE FIELD config ON exists_write TYPE record<config>;

    DEFINE TABLE owner_write SCHEMAFULL PERMISSIONS
      FOR create WHERE config.owned_by = $auth
      FOR select WHERE true;
    DEFINE FIELD config ON owner_write TYPE record<config>;

    DEFINE TABLE event_bypass_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON event_bypass_job TYPE record<config>;
    DEFINE FIELD event_saw_api_key ON event_bypass_job TYPE option<string>
      DEFAULT NONE PERMISSIONS NONE;
    DEFINE EVENT event_bypass_job_create ON event_bypass_job
      WHEN $event = 'CREATE'
      THEN UPDATE $after.id SET event_saw_api_key = $after.config.api_key;

    DEFINE TABLE event_guard_job SCHEMAFULL PERMISSIONS
      FOR create, select WHERE true;
    DEFINE FIELD config ON event_guard_job TYPE record<config>;
    DEFINE EVENT event_guard_job_create ON event_guard_job
      WHEN $event = 'CREATE'
      THEN {
        IF $after.config.owned_by != $auth {
          THROW 'REFERENCE_NOT_OWNED';
        };
      };

    DEFINE ACCESS account ON DATABASE TYPE RECORD
      SIGNIN (
        SELECT * FROM principal
        WHERE email = $email
          AND crypto::argon2::compare(password, $password)
      )
      AUTHENTICATE { RETURN $auth; }
      DURATION FOR SESSION 1h, FOR TOKEN 1h;

    CREATE principal:alice SET
      email = 'alice@example.com',
      password = crypto::argon2::generate('password123');
    CREATE principal:bob SET
      email = 'bob@example.com',
      password = crypto::argon2::generate('password123');
    CREATE config:alice SET owned_by = principal:alice, api_key = 'alice-key';
    CREATE config:alice_two SET owned_by = principal:alice, api_key = 'alice-two-key';
    CREATE config:bob SET owned_by = principal:bob, api_key = 'bob-key';
    CREATE config:bob_two SET owned_by = principal:bob, api_key = 'bob-two-key';
    CREATE assert_delta_job:mixed SET configs = [config:alice, config:bob];
  `);

  const alice = await signIn(
    endpoint,
    namespace,
    database,
    "alice@example.com",
    "password123",
  );
  try {
    const visible = rows(await alice.query(
      "SELECT id, owned_by, api_key FROM config ORDER BY id;",
    ));
    assert.deepEqual(visible.map((record) => String(record.id)), ["config:alice", "config:alice_two"]);
    assert(visible.every((record) => record.api_key === undefined));

    const existence = rows(await alice.query(`
      RETURN {
        accessible: record::exists(config:alice),
        hidden: record::exists(config:bob),
        missing: record::exists(config:missing)
      };
    `))[0];
    assert.deepEqual(existence, { accessible: true, hidden: false, missing: false });
    const dereference = rows(await alice.query(`
      RETURN {
        accessible_owner: config:alice.owned_by = principal:alice,
        hidden_owner_is_none: type::is_none(config:bob.owned_by),
        accessible_secret_is_none: type::is_none(config:alice.api_key)
      };
    `))[0];
    assert.deepEqual(dereference, {
      accessible_owner: true,
      accessible_secret_is_none: true,
      hidden_owner_is_none: true,
    });

    assert.equal(rows(await alice.query(
      "CREATE assert_exists_job:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
    await assert.rejects(
      alice.query("CREATE assert_exists_job:hidden SET config = config:bob;"),
      /field `config`|record::exists/i,
    );
    await assert.rejects(
      alice.query("CREATE assert_exists_job:missing SET config = config:missing;"),
      /field `config`|record::exists/i,
    );

    assert.equal(rows(await alice.query(
      "CREATE assert_owner_job:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
    await assert.rejects(
      alice.query("CREATE assert_owner_job:hidden SET config = config:bob;"),
      /field `config`|owned_by/i,
    );

    assert.equal(rows(await alice.query(
      "CREATE assert_optional_job:none SET config = NONE RETURN AFTER;",
    )).length, 1);
    assert.equal(rows(await alice.query(
      "CREATE assert_optional_job:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
    await assert.rejects(
      alice.query("CREATE assert_optional_job:hidden SET config = config:bob;"),
      /field `config`|record::exists/i,
    );
    await assert.rejects(
      alice.query("CREATE assert_optional_job:missing SET config = config:missing;"),
      /field `config`|record::exists/i,
    );

    assert.equal(rows(await alice.query(
      "CREATE assert_array_job:allowed SET configs = [config:alice, config:alice_two] RETURN AFTER;",
    )).length, 1);
    await assert.rejects(
      alice.query("CREATE assert_array_job:hidden SET configs = [config:alice, config:bob];"),
      /field `configs`|record::exists/i,
    );
    await assert.rejects(
      alice.query("CREATE assert_array_job:missing SET configs = [config:alice, config:missing];"),
      /field `configs`|record::exists/i,
    );

    const retainedHidden = rows(await alice.query(`
      UPDATE assert_delta_job:mixed
      SET configs = [config:alice, config:bob, config:alice_two]
      RETURN AFTER;
    `))[0];
    assert.deepEqual(
      new Set(retainedHidden.configs.map(String)),
      new Set(["config:alice", "config:bob", "config:alice_two"]),
    );
    await assert.rejects(
      alice.query(`
        UPDATE assert_delta_job:mixed
        SET configs = [config:alice, config:bob, config:alice_two, config:bob_two];
      `),
      /field `configs`|record::exists/i,
    );
    await assert.rejects(
      alice.query(`
        UPDATE assert_delta_job:mixed
        SET configs = [config:alice, config:alice_two];
      `),
      /field `configs`|record::exists/i,
    );
    const removedVisible = rows(await alice.query(`
      UPDATE assert_delta_job:mixed
      SET configs = [config:alice, config:bob]
      RETURN AFTER;
    `))[0];
    assert.deepEqual(
      new Set(removedVisible.configs.map(String)),
      new Set(["config:alice", "config:bob"]),
    );

    const permissionResult = rows(await alice.query(
      "CREATE permission_job:hidden SET config = config:bob RETURN AFTER;",
    ))[0];
    if (process.env.REBASE_ARCHITECTURE_DEBUG) {
      console.error("permission job returned", permissionResult);
      console.error("permission job client read", rows(await alice.query(
        "SELECT * FROM permission_job:hidden;",
      )));
      console.error("permission job root read", rows(await db.query(
        "SELECT * FROM permission_job:hidden;",
      )));
    }
    assert.equal(String(permissionResult.config), "config:bob");
    assert.equal(String(rows(await alice.query(
      "SELECT config FROM permission_job:hidden;",
    ))[0].config), "config:bob");
    const missingPermissionResult = rows(await alice.query(
      "CREATE permission_job:missing SET config = config:missing RETURN AFTER;",
    ))[0];
    assert.equal(missingPermissionResult.config, undefined);

    assert.equal(rows(await alice.query(
      "CREATE owner_permission_job:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
    assert.equal(rows(await alice.query(
      "CREATE owner_permission_job:hidden SET config = config:bob RETURN AFTER;",
    ))[0].config, undefined);
    assert.equal(rows(await alice.query(
      "CREATE owner_permission_job:missing SET config = config:missing RETURN AFTER;",
    ))[0].config, undefined);

    assert.equal(rows(await alice.query(
      "CREATE exists_write:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
    assert.equal(rows(await alice.query(
      "CREATE exists_write:hidden SET config = config:bob RETURN AFTER;",
    )).length, 1);
    assert.equal(rows(await alice.query(
      "CREATE exists_write:missing SET config = config:missing RETURN AFTER;",
    )).length, 0);

    assert.equal(rows(await alice.query(
      "CREATE owner_write:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
    assert.equal(rows(await alice.query(
      "CREATE owner_write:hidden SET config = config:bob RETURN AFTER;",
    )).length, 0);
    assert.equal(rows(await alice.query(
      "CREATE owner_write:missing SET config = config:missing RETURN AFTER;",
    )).length, 0);

    await alice.query(
      "CREATE event_bypass_job:accepted SET config = config:bob;",
    );
    const bypassed = rows(await db.query(
      "SELECT event_saw_api_key FROM event_bypass_job:accepted;",
    ))[0];
    assert.equal(bypassed.event_saw_api_key, "bob-key");

    await assert.rejects(
      alice.query("CREATE event_guard_job:rejected SET config = config:bob;"),
      /REFERENCE_NOT_OWNED/,
    );
    assert.equal(rows(await alice.query(
      "CREATE event_guard_job:allowed SET config = config:alice RETURN AFTER;",
    )).length, 1);
  } finally {
    await alice.close();
  }
  console.log("architecture: reference authorization and event permission boundary passed");
}

async function principalCompilerProbe(db, namespace, database) {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-principals-"));
  try {
    fs.writeFileSync(path.join(projectDir, "schema.surql"), `
      DEFINE TABLE employee SCHEMAFULL COMMENT '@rebase-principal user';
      DEFINE TABLE department SCHEMAFULL COMMENT '@rebase-principal group';
      DEFINE TABLE resource SCHEMAFULL;
      DEFINE FIELD label ON resource TYPE string;
      DEFINE TABLE note SCHEMAFULL COMMENT '@rebase-audit';
      DEFINE FIELD body ON note TYPE string;
      DEFINE FIELD target ON note TYPE option<record<resource>> DEFAULT NONE
        ASSERT $value = NONE OR $value != resource:blocked
        REFERENCE ON DELETE REJECT;
      DEFINE FIELD generic_target ON note TYPE option<record> DEFAULT NONE;
      DEFINE FIELD nested_target ON note TYPE object FLEXIBLE DEFAULT {};
      DEFINE FIELD nested_target.resource ON note TYPE option<record<resource>> DEFAULT NONE;
    `);
    const materials = loadMaterials({
      groups: [
        { name: "framework", roots: [path.resolve(__dirname, "..", "framework")] },
        { name: "project", roots: [projectDir] },
      ],
    });
    const generated = generateBundle(materials, {
      context: { namespace, database },
    });
    assert.deepEqual(generated.principals, { user: "employee", group: "department" });
    assert.match(generated.bundle, /record<employee \| department>/);
    assert.match(generated.bundle, /CREATE department:root/);
    assert.match(generated.bundle, /SELECT id from employee/i);
    assert.doesNotMatch(generated.bundle, /record<user \| groups>/);
    assert.doesNotMatch(generated.bundle, /groups:root/);
    assert.match(
      generated.bundle,
      /ALTER FIELD target ON TABLE note ASSERT \(\$value = NONE OR \$value != resource:blocked\) AND \(\$value = NONE OR record::exists\(\$value\)\)/,
    );
    assert.match(
      generated.bundle,
      /ALTER FIELD generic_target ON TABLE note ASSERT \$value = NONE OR record::exists\(\$value\)/,
    );
    assert.doesNotMatch(generated.bundle, /ALTER FIELD nested_target ON TABLE note/);
    await db.query(generated.bundle);
    const root = rows(await db.query("SELECT name FROM department:root;"))[0];
    assert.equal(root.name, "System Admins");
  } finally {
    fs.rmSync(projectDir, { recursive: true, force: true });
  }
  console.log("architecture: custom principal compiler binding passed");
}

async function main() {
  const state = { effects: [], observer: null, snapshots: [] };
  const receiver = await startReceiver(state);
  const disposable = await startDisposable(receiver.port);
  const namespace = `rebase_architecture_${Date.now().toString(36)}`;
  const database = "probe";
  const db = await connectRoot(disposable.endpoint, namespace, database);
  state.observer = await connectExistingRoot(
    disposable.endpoint,
    namespace,
    database,
  );
  try {
    await uuidProbe(db);
    await synchronousEventProbe(db, receiver.port, state);
    await referenceAuthorizationProbe(
      db,
      disposable.endpoint,
      namespace,
      database,
    );
    await principalCompilerProbe(db, namespace, database);
    console.log("architecture: PASS");
  } finally {
    await state.observer?.close().catch(() => {});
    await db.close().catch(() => {});
    await new Promise((resolve) => receiver.server.close(resolve));
    await stopDisposable(disposable);
  }
}

if (require.main === module) {
  main().then(
    () => process.exit(0),
    (error) => {
      console.error(`architecture: FAIL: ${error.message}`);
      process.exit(1);
    },
  );
}

module.exports = {
  principalCompilerProbe,
  referenceAuthorizationProbe,
  synchronousEventProbe,
  uuidProbe,
};
