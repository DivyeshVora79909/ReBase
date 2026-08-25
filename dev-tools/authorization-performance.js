#!/usr/bin/env node

const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { spawn } = require("node:child_process");
const { Surreal } = require("surrealdb");

const ROOT = path.resolve(__dirname, "..");
const NAMESPACE = "rebase_perf";
const DATABASE = "authorization";
const PASSWORD = "password123";

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

async function startSurreal() {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-authorization-performance-"));
  const datastore = process.env.REBASE_PERF_MEMORY === "1"
    ? "memory"
    : `rocksdb://${dataDir}`;
  const child = spawn("nice", ["-n", "10", "surreal",
    "start", datastore, "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) break;
    const ready = await new Promise((resolve) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (ready) return { child, endpoint: `ws://127.0.0.1:${port}/rpc`, dataDir };
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  child.kill("SIGTERM");
  throw new Error(`SurrealDB failed to start${stderr.trim() ? `: ${stderr.trim()}` : ""}`);
}

async function stopSurreal(server) {
  if (!server) return;
  if (server.child.exitCode === null) {
    const exited = new Promise((resolve) => server.child.once("exit", resolve));
    server.child.kill("SIGTERM");
    const stopped = await Promise.race([
      exited.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 5000)),
    ]);
    if (!stopped && server.child.exitCode === null) {
      server.child.kill("SIGKILL");
      await exited;
    }
  }
  if (server.dataDir) fs.rmSync(server.dataDir, { recursive: true, force: true });
}

function pause(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function rootConnection(endpoint) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({ username: "root", password: "root" });
  await db.query(`
    DEFINE NAMESPACE IF NOT EXISTS ${NAMESPACE};
    USE NS ${NAMESPACE};
    DEFINE DATABASE IF NOT EXISTS ${DATABASE};
    USE DB ${DATABASE};
  `);
  await db.use({ namespace: NAMESPACE, database: DATABASE });
  return db;
}

async function actorConnection(endpoint, email) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({
    namespace: NAMESPACE,
    database: DATABASE,
    access: "account",
    variables: { email, password: PASSWORD },
  });
  return db;
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
}

async function measure(db, query, variables = {}, repetitions = 12, warmups = 3) {
  repetitions = Math.max(2, Number(process.env.REBASE_PERF_REPETITIONS || repetitions));
  warmups = Math.max(1, Number(process.env.REBASE_PERF_WARMUPS || warmups));
  for (let i = 0; i < warmups; i += 1) await db.query(query, variables);
  const samples = [];
  let result;
  for (let i = 0; i < repetitions; i += 1) {
    const started = performance.now();
    result = await db.query(query, variables);
    samples.push(performance.now() - started);
  }
  samples.sort((a, b) => a - b);
  return {
    p50_ms: Number(percentile(samples, 0.50).toFixed(3)),
    p95_ms: Number(percentile(samples, 0.95).toFixed(3)),
    min_ms: Number(samples[0].toFixed(3)),
    max_ms: Number(samples.at(-1).toFixed(3)),
    returned: rows(result).length,
  };
}

async function concurrency(endpoint, email, query, clients, operationsPerClient) {
  const connections = [];
  for (let i = 0; i < clients; i += 1) {
    connections.push(await actorConnection(endpoint, email));
    await pause(25);
  }
  const latencies = [];
  const started = performance.now();
  try {
    const maxInflight = Math.max(1, Number(process.env.REBASE_PERF_QUERY_CONCURRENCY || 8));
    for (let offset = 0; offset < connections.length; offset += maxInflight) {
      await Promise.all(connections.slice(offset, offset + maxInflight).map(async (db) => {
        for (let i = 0; i < operationsPerClient; i += 1) {
          const operationStarted = performance.now();
          await db.query(query);
          latencies.push(performance.now() - operationStarted);
          await pause(10);
        }
      }));
      await pause(100);
    }
  } finally {
    await Promise.all(connections.map((db) => db.close()));
  }
  const elapsed = performance.now() - started;
  latencies.sort((a, b) => a - b);
  return {
    clients,
    operations: latencies.length,
    throughput_qps: Number((latencies.length / (elapsed / 1000)).toFixed(1)),
    p50_ms: Number(percentile(latencies, 0.50).toFixed(3)),
    p95_ms: Number(percentile(latencies, 0.95).toFixed(3)),
  };
}

function rssKb(pid) {
  try {
    const match = fs.readFileSync(`/proc/${pid}/status`, "utf8").match(/^VmRSS:\s+(\d+) kB$/m);
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

async function defineBenchmark(root) {
  const schema = fs.readFileSync(path.join(ROOT, "build", "test", "schema.surql"), "utf8");
  await root.query(schema);
  await root.query(`
    DEFINE TABLE bench_default SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_default_select' IN $auth.permissions AND
        (!!visibility OR readers_index CONTAINS <string>$auth.id OR <string>owned_by IN $auth.z_access_index)
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_default TYPE bool;
    DEFINE FIELD readers_index ON bench_default TYPE array<string>;
    DEFINE FIELD owned_by ON bench_default TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_default TYPE int;
    DEFINE FIELD bucket ON bench_default TYPE int;
    DEFINE FIELD payload ON bench_default TYPE string;
    DEFINE INDEX bench_default_owned_by ON bench_default FIELDS owned_by;
    DEFINE INDEX bench_default_readers ON bench_default FIELDS readers_index.*;
    DEFINE INDEX bench_default_bucket_seq ON bench_default FIELDS bucket, seq;

    DEFINE TABLE bench_owner_current SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_owner_current_select' IN $auth.permissions AND
        (!!visibility OR <string>owned_by IN $auth.z_access_index)
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_owner_current TYPE bool;
    DEFINE FIELD readers_index ON bench_owner_current TYPE array<string>;
    DEFINE FIELD owned_by ON bench_owner_current TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_owner_current TYPE int;
    DEFINE FIELD bucket ON bench_owner_current TYPE int;
    DEFINE FIELD payload ON bench_owner_current TYPE string;
    DEFINE INDEX bench_owner_current_owned_by ON bench_owner_current FIELDS owned_by;
    DEFINE INDEX bench_owner_current_readers ON bench_owner_current FIELDS readers_index.*;
    DEFINE INDEX bench_owner_current_bucket_seq ON bench_owner_current FIELDS bucket, seq;

    DEFINE TABLE bench_owner_lean SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_owner_lean_select' IN $auth.permissions AND
        (!!visibility OR <string>owned_by IN $auth.z_access_index)
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_owner_lean TYPE bool;
    DEFINE FIELD owned_by ON bench_owner_lean TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_owner_lean TYPE int;
    DEFINE FIELD bucket ON bench_owner_lean TYPE int;
    DEFINE FIELD payload ON bench_owner_lean TYPE string;
    DEFINE INDEX bench_owner_lean_owned_by ON bench_owner_lean FIELDS owned_by;
    DEFINE INDEX bench_owner_lean_bucket_seq ON bench_owner_lean FIELDS bucket, seq;

    DEFINE TABLE bench_open SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_open_select' IN $auth.permissions
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_open TYPE bool;
    DEFINE FIELD readers_index ON bench_open TYPE array<string>;
    DEFINE FIELD owned_by ON bench_open TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_open TYPE int;
    DEFINE FIELD bucket ON bench_open TYPE int;
    DEFINE FIELD payload ON bench_open TYPE string;
    DEFINE INDEX bench_open_bucket_seq ON bench_open FIELDS bucket, seq;

    DEFINE TABLE bench_visibility_index SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_visibility_index_select' IN $auth.permissions AND
        (!!visibility OR readers_index CONTAINS <string>$auth.id OR <string>owned_by IN $auth.z_access_index)
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_visibility_index TYPE bool;
    DEFINE FIELD readers_index ON bench_visibility_index TYPE array<string>;
    DEFINE FIELD owned_by ON bench_visibility_index TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_visibility_index TYPE int;
    DEFINE FIELD bucket ON bench_visibility_index TYPE int;
    DEFINE FIELD payload ON bench_visibility_index TYPE string;
    DEFINE INDEX bench_visibility_index_visibility ON bench_visibility_index FIELDS visibility;
    DEFINE INDEX bench_visibility_index_owned_by ON bench_visibility_index FIELDS owned_by;
    DEFINE INDEX bench_visibility_index_readers ON bench_visibility_index FIELDS readers_index.*;

    DEFINE TABLE bench_owner_string SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_owner_string_select' IN $auth.permissions AND
        (!!visibility OR readers_index CONTAINS <string>$auth.id OR owned_by_key IN $auth.z_access_index)
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_owner_string TYPE bool;
    DEFINE FIELD readers_index ON bench_owner_string TYPE array<string>;
    DEFINE FIELD owned_by_key ON bench_owner_string TYPE string;
    DEFINE FIELD seq ON bench_owner_string TYPE int;
    DEFINE FIELD bucket ON bench_owner_string TYPE int;
    DEFINE FIELD payload ON bench_owner_string TYPE string;
    DEFINE INDEX bench_owner_string_key ON bench_owner_string FIELDS owned_by_key;
    DEFINE INDEX bench_owner_string_readers ON bench_owner_string FIELDS readers_index.*;

    DEFINE TABLE bench_owner_only SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_owner_only_select' IN $auth.permissions
        AND owned_by IN $auth.z_access_index
      FOR create, update, delete NONE;
    DEFINE FIELD owned_by ON bench_owner_only TYPE string;
    DEFINE FIELD seq ON bench_owner_only TYPE int;
    DEFINE FIELD bucket ON bench_owner_only TYPE int;
    DEFINE FIELD payload ON bench_owner_only TYPE string;
    DEFINE INDEX bench_owner_only_owned_by ON bench_owner_only FIELDS owned_by;

    DEFINE TABLE bench_owner_record_only SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_owner_record_only_select' IN $auth.permissions
        AND <string>owned_by IN $auth.z_access_index
      FOR create, update, delete NONE;
    DEFINE FIELD owned_by ON bench_owner_record_only TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_owner_record_only TYPE int;
    DEFINE FIELD bucket ON bench_owner_record_only TYPE int;
    DEFINE FIELD payload ON bench_owner_record_only TYPE string;
    DEFINE INDEX bench_owner_record_only_owned_by ON bench_owner_record_only FIELDS owned_by;

    DEFINE TABLE bench_reader_only SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_reader_only_select' IN $auth.permissions
        AND readers_index CONTAINS <string>$auth.id
      FOR create, update, delete NONE;
    DEFINE FIELD readers_index ON bench_reader_only TYPE array<string>;
    DEFINE FIELD seq ON bench_reader_only TYPE int;
    DEFINE FIELD bucket ON bench_reader_only TYPE int;
    DEFINE FIELD payload ON bench_reader_only TYPE string;
    DEFINE INDEX bench_reader_only_readers ON bench_reader_only FIELDS readers_index.*;

    DEFINE TABLE bench_visibility_only SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_visibility_only_select' IN $auth.permissions
        AND visibility = true
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_visibility_only TYPE bool;
    DEFINE FIELD seq ON bench_visibility_only TYPE int;
    DEFINE FIELD bucket ON bench_visibility_only TYPE int;
    DEFINE FIELD payload ON bench_visibility_only TYPE string;
    DEFINE INDEX bench_visibility_only_visibility ON bench_visibility_only FIELDS visibility;

    DEFINE TABLE bench_visibility_eq SCHEMAFULL PERMISSIONS
      FOR select WHERE 'bench_visibility_eq_select' IN $auth.permissions AND
        (visibility = true OR readers_index CONTAINS <string>$auth.id OR <string>owned_by IN $auth.z_access_index)
      FOR create, update, delete NONE;
    DEFINE FIELD visibility ON bench_visibility_eq TYPE bool;
    DEFINE FIELD readers_index ON bench_visibility_eq TYPE array<string>;
    DEFINE FIELD owned_by ON bench_visibility_eq TYPE record<user | groups>;
    DEFINE FIELD seq ON bench_visibility_eq TYPE int;
    DEFINE FIELD bucket ON bench_visibility_eq TYPE int;
    DEFINE FIELD payload ON bench_visibility_eq TYPE string;
    DEFINE INDEX bench_visibility_eq_visibility ON bench_visibility_eq FIELDS visibility;
    DEFINE INDEX bench_visibility_eq_owned_by ON bench_visibility_eq FIELDS owned_by;
    DEFINE INDEX bench_visibility_eq_readers ON bench_visibility_eq FIELDS readers_index.*;
  `);

  const permissions = [
    "bench_default_select", "bench_owner_current_select",
    "bench_owner_lean_select", "bench_open_select", "bench_visibility_index_select",
    "bench_owner_string_select", "bench_owner_only_select", "bench_owner_record_only_select",
    "bench_reader_only_select", "bench_visibility_only_select", "bench_visibility_eq_select",
  ];
  await root.query(`
    CREATE groups:bench_narrow SET name = 'Narrow', parents = [groups:root], role = $permissions;
    CREATE groups:bench_wide SET name = 'Wide', parents = [groups:root], role = $permissions;
    CREATE groups:bench_other SET name = 'Other', parents = [groups:root], role = $permissions;
    CREATE user:bench_narrow SET name = 'Narrow', email = 'narrow@example.com',
      password = crypto::argon2::generate($password), parents = [groups:bench_narrow], login_access = true;
    CREATE user:bench_wide SET name = 'Wide', email = 'wide@example.com',
      password = crypto::argon2::generate($password), parents = [groups:bench_wide], login_access = true;
  `, { permissions, password: PASSWORD });
  for (let offset = 0; offset < 100; offset += 20) {
    await root.query(`
      FOR $i IN $start..$end {
        CREATE type::record('groups', string::concat('bench_child_', <string>$i)) SET
          name = string::concat('Child ', <string>$i), parents = [user:bench_wide], role = [];
      };
    `, { start: offset, end: offset + 20 });
  }
  return {
    narrow: rows(await root.query("SELECT array::len(z_access_index) AS width FROM user:bench_narrow;"))[0].width,
    wide: rows(await root.query("SELECT array::len(z_access_index) AS width FROM user:bench_wide;"))[0].width,
  };
}

async function populateTable(root, table, from, to, includeReaders) {
  const started = performance.now();
  const readerPart = includeReaders
    ? "readers_index: IF $kind = 1 OR $kind = 5 THEN ['user:bench_narrow', 'user:bench_wide'] ELSE [] END,"
    : "";
  await root.query(`
    FOR $i IN $from..$to {
      LET $kind = $i % 6;
      CREATE type::record($table, $i) CONTENT {
        visibility: $kind = 0 OR $kind = 5,
        ${readerPart}
        owned_by: IF $kind = 2 THEN user:bench_narrow
          ELSE IF $kind = 3 THEN groups:bench_narrow
          ELSE IF $kind = 4 THEN groups:bench_child_1
          ELSE groups:bench_other END,
        seq: $i,
        bucket: $i % 100,
        payload: 'abcdefghijklmnopqrstuvwxyz0123456789'
      };
    };
  `, { table, from, to });
  return performance.now() - started;
}

async function populateStage(root, from, to) {
  const timings = {
    bench_default: 0,
    bench_owner_current: 0,
    bench_owner_lean: 0,
    bench_open: 0,
    bench_visibility_index: 0,
    bench_owner_string: 0,
    bench_owner_only: 0,
    bench_owner_record_only: 0,
    bench_reader_only: 0,
    bench_visibility_only: 0,
    bench_visibility_eq: 0,
  };
  const batchRows = Math.max(25, Number(process.env.REBASE_PERF_BATCH_ROWS || 250));
  const batchPauseMs = Math.max(0, Number(process.env.REBASE_PERF_BATCH_PAUSE_MS || 50));
  for (let start = from; start < to; start += batchRows) {
    const end = Math.min(to, start + batchRows);
    timings.bench_default += await populateTable(root, "bench_default", start, end, true);
    await pause(batchPauseMs);
    for (const [table, projection] of [
      ["bench_owner_current", "visibility, readers_index, owned_by, seq, bucket, payload"],
      ["bench_owner_lean", "visibility, owned_by, seq, bucket, payload"],
      ["bench_open", "visibility, readers_index, owned_by, seq, bucket, payload"],
      ["bench_visibility_index", "visibility, readers_index, owned_by, seq, bucket, payload"],
      ["bench_owner_string", "visibility, readers_index, <string>owned_by AS owned_by_key, seq, bucket, payload"],
    ]) {
      const started = performance.now();
      await root.query(`
        INSERT INTO ${table}
        SELECT type::record('${table}', seq) AS id, ${projection}
        FROM bench_default WHERE seq >= $from AND seq < $to;
      `, { from: start, to: end });
      timings[table] += performance.now() - started;
      await pause(batchPauseMs);
    }
    for (const [table, projection] of [
      ["bench_owner_only", "<string>owned_by AS owned_by, seq, bucket, payload"],
      ["bench_owner_record_only", "owned_by, seq, bucket, payload"],
      ["bench_reader_only", "readers_index, seq, bucket, payload"],
      ["bench_visibility_only", "visibility, seq, bucket, payload"],
      ["bench_visibility_eq", "visibility, readers_index, owned_by, seq, bucket, payload"],
    ]) {
      const started = performance.now();
      await root.query(`
        INSERT INTO ${table}
        SELECT type::record('${table}', seq) AS id, ${projection}
        FROM bench_default WHERE seq >= $from AND seq < $to;
      `, { from: start, to: end });
      timings[table] += performance.now() - started;
      await pause(batchPauseMs);
    }
    if ((start - from) % (batchRows * 20) === 0) {
      process.stderr.write(`authorization-performance: populated ${end}/${to} rows/table\n`);
    }
  }
  return Object.fromEntries(Object.entries(timings).map(([table, milliseconds]) => [
    table,
    Number(milliseconds.toFixed(1)),
  ]));
}

async function plans(db) {
  const queries = {
    default_page: "SELECT VALUE id FROM bench_default LIMIT 100 EXPLAIN FULL;",
    default_owner: "SELECT VALUE id FROM bench_default WHERE owned_by = user:bench_narrow LIMIT 100 EXPLAIN FULL;",
    default_reader: "SELECT VALUE id FROM bench_default WHERE readers_index CONTAINS 'user:bench_narrow' LIMIT 100 EXPLAIN FULL;",
    default_visible: "SELECT VALUE id FROM bench_default WHERE visibility = true LIMIT 100 EXPLAIN FULL;",
    default_selective: "SELECT VALUE id FROM bench_default WHERE bucket = 7 AND seq > 0 ORDER BY bucket, seq LIMIT 100 EXPLAIN FULL;",
    owner_page: "SELECT VALUE id FROM bench_owner_current LIMIT 100 EXPLAIN FULL;",
    open_page: "SELECT VALUE id FROM bench_open LIMIT 100 EXPLAIN FULL;",
    visibility_index_page: "SELECT VALUE id FROM bench_visibility_index LIMIT 100 EXPLAIN FULL;",
    visibility_index_filter: "SELECT VALUE id FROM bench_visibility_index WHERE visibility = true LIMIT 100 EXPLAIN FULL;",
    owner_string_filter: "SELECT VALUE id FROM bench_owner_string WHERE owned_by_key = 'user:bench_narrow' LIMIT 100 EXPLAIN FULL;",
    owner_only_page: "SELECT VALUE id FROM bench_owner_only LIMIT 100 EXPLAIN FULL;",
    owner_only_filter: "SELECT VALUE id FROM bench_owner_only WHERE owned_by = 'user:bench_narrow' LIMIT 100 EXPLAIN FULL;",
    owner_record_only_page: "SELECT VALUE id FROM bench_owner_record_only LIMIT 100 EXPLAIN FULL;",
    owner_record_only_filter: "SELECT VALUE id FROM bench_owner_record_only WHERE owned_by = user:bench_narrow LIMIT 100 EXPLAIN FULL;",
    reader_only_page: "SELECT VALUE id FROM bench_reader_only LIMIT 100 EXPLAIN FULL;",
    reader_only_filter: "SELECT VALUE id FROM bench_reader_only WHERE readers_index CONTAINS 'user:bench_narrow' LIMIT 100 EXPLAIN FULL;",
    visibility_only_page: "SELECT VALUE id FROM bench_visibility_only LIMIT 100 EXPLAIN FULL;",
    visibility_only_filter: "SELECT VALUE id FROM bench_visibility_only WHERE visibility = true LIMIT 100 EXPLAIN FULL;",
    visibility_eq_page: "SELECT VALUE id FROM bench_visibility_eq LIMIT 100 EXPLAIN FULL;",
  };
  const output = {};
  for (const [name, query] of Object.entries(queries)) output[name] = rows(await db.query(query));
  return output;
}

async function stageMeasurements(actor, rowCount) {
  const cases = {
    default_page_ids: "SELECT VALUE id FROM bench_default LIMIT 100;",
    default_page_full: "SELECT * FROM bench_default LIMIT 100;",
    default_count: "SELECT count() AS count FROM bench_default GROUP ALL;",
    default_owner: "SELECT VALUE id FROM bench_default WHERE owned_by = user:bench_narrow LIMIT 100;",
    default_reader: "SELECT VALUE id FROM bench_default WHERE readers_index CONTAINS 'user:bench_narrow' LIMIT 100;",
    default_visible: "SELECT VALUE id FROM bench_default WHERE visibility = true LIMIT 100;",
    default_selective: "SELECT VALUE id FROM bench_default WHERE bucket = 7 AND seq > 0 ORDER BY bucket, seq LIMIT 100;",
    default_keyset: `SELECT VALUE id FROM bench_default WHERE seq > ${Math.floor(rowCount / 2)} ORDER BY seq LIMIT 100;`,
    default_allowed_id: "SELECT VALUE id FROM bench_default:2;",
    default_denied_id: "SELECT VALUE id FROM bench_default:4;",
    owner_current_page: "SELECT VALUE id FROM bench_owner_current LIMIT 100;",
    owner_current_count: "SELECT count() AS count FROM bench_owner_current GROUP ALL;",
    owner_lean_page: "SELECT VALUE id FROM bench_owner_lean LIMIT 100;",
    owner_lean_count: "SELECT count() AS count FROM bench_owner_lean GROUP ALL;",
    open_page: "SELECT VALUE id FROM bench_open LIMIT 100;",
    open_count: "SELECT count() AS count FROM bench_open GROUP ALL;",
    visibility_index_page: "SELECT VALUE id FROM bench_visibility_index LIMIT 100;",
    visibility_index_count: "SELECT count() AS count FROM bench_visibility_index GROUP ALL;",
    visibility_index_filter: "SELECT VALUE id FROM bench_visibility_index WHERE visibility = true LIMIT 100;",
    visibility_index_visible_count: "SELECT count() AS count FROM bench_visibility_index WHERE visibility = true GROUP ALL;",
    owner_string_page: "SELECT VALUE id FROM bench_owner_string LIMIT 100;",
    owner_string_count: "SELECT count() AS count FROM bench_owner_string GROUP ALL;",
    owner_string_filter: "SELECT VALUE id FROM bench_owner_string WHERE owned_by_key = 'user:bench_narrow' LIMIT 100;",
    owner_string_filter_count: "SELECT count() AS count FROM bench_owner_string WHERE owned_by_key = 'user:bench_narrow' GROUP ALL;",
    owner_only_page: "SELECT VALUE id FROM bench_owner_only LIMIT 100;",
    owner_only_count: "SELECT count() AS count FROM bench_owner_only GROUP ALL;",
    owner_only_filter: "SELECT VALUE id FROM bench_owner_only WHERE owned_by = 'user:bench_narrow' LIMIT 100;",
    owner_only_filter_count: "SELECT count() AS count FROM bench_owner_only WHERE owned_by = 'user:bench_narrow' GROUP ALL;",
    owner_record_only_page: "SELECT VALUE id FROM bench_owner_record_only LIMIT 100;",
    owner_record_only_count: "SELECT count() AS count FROM bench_owner_record_only GROUP ALL;",
    owner_record_only_filter: "SELECT VALUE id FROM bench_owner_record_only WHERE owned_by = user:bench_narrow LIMIT 100;",
    owner_record_only_filter_count: "SELECT count() AS count FROM bench_owner_record_only WHERE owned_by = user:bench_narrow GROUP ALL;",
    reader_only_page: "SELECT VALUE id FROM bench_reader_only LIMIT 100;",
    reader_only_count: "SELECT count() AS count FROM bench_reader_only GROUP ALL;",
    reader_only_filter: "SELECT VALUE id FROM bench_reader_only WHERE readers_index CONTAINS 'user:bench_narrow' LIMIT 100;",
    reader_only_filter_count: "SELECT count() AS count FROM bench_reader_only WHERE readers_index CONTAINS 'user:bench_narrow' GROUP ALL;",
    visibility_only_page: "SELECT VALUE id FROM bench_visibility_only LIMIT 100;",
    visibility_only_count: "SELECT count() AS count FROM bench_visibility_only GROUP ALL;",
    visibility_only_filter: "SELECT VALUE id FROM bench_visibility_only WHERE visibility = true LIMIT 100;",
    visibility_only_filter_count: "SELECT count() AS count FROM bench_visibility_only WHERE visibility = true GROUP ALL;",
    visibility_eq_page: "SELECT VALUE id FROM bench_visibility_eq LIMIT 100;",
    visibility_eq_count: "SELECT count() AS count FROM bench_visibility_eq GROUP ALL;",
  };
  const output = {};
  for (const [name, query] of Object.entries(cases)) {
    try {
      output[name] = await measure(actor, query);
    } catch (error) {
      output[name] = { error: error.message };
      process.stderr.write(`authorization-performance: ${name} failed: ${error.message}\n`);
    }
  }
  return output;
}

async function main() {
  const targets = (process.env.REBASE_PERF_ROWS || "10000,50000,100000")
    .split(",").map(Number).filter((value) => Number.isInteger(value) && value > 0)
    .sort((a, b) => a - b);
  if (!targets.length) throw new Error("REBASE_PERF_ROWS must contain positive row counts");
  const server = await startSurreal();
  const report = {
    environment: {
      node: process.version,
      surrealdb: require("node:child_process").execFileSync("surreal", ["version"], { encoding: "utf8" }).trim(),
      platform: `${process.platform} ${process.arch}`,
      datastore: process.env.REBASE_PERF_MEMORY === "1" ? "memory" : "temporary RocksDB",
      batch_rows: Number(process.env.REBASE_PERF_BATCH_ROWS || 250),
      batch_pause_ms: Number(process.env.REBASE_PERF_BATCH_PAUSE_MS || 50),
      max_query_concurrency: Number(process.env.REBASE_PERF_QUERY_CONCURRENCY || 8),
    },
    targets,
    access_widths: {},
    stages: [],
    plans: {},
    concurrency: [],
  };
  let root;
  let narrow;
  let wide;
  const checkpoint = process.env.REBASE_PERF_OUTPUT;
  const saveCheckpoint = () => {
    if (checkpoint) fs.writeFileSync(checkpoint, `${JSON.stringify(report, null, 2)}\n`);
  };
  try {
    root = await rootConnection(server.endpoint);
    report.access_widths = await defineBenchmark(root);
    let current = 0;
    for (const target of targets) {
      const insert_ms = await populateStage(root, current, target);
      current = target;
      if (narrow) await narrow.close();
      if (wide) await wide.close();
      narrow = await actorConnection(server.endpoint, "narrow@example.com");
      wide = await actorConnection(server.endpoint, "wide@example.com");
      report.stages.push({
        rows_per_table: target,
        insert_ms,
        surreal_rss_kb: rssKb(server.child.pid),
        narrow: await stageMeasurements(narrow, target),
        wide: await stageMeasurements(wide, target),
      });
      saveCheckpoint();
      process.stderr.write(`authorization-performance: measured ${target} rows/table\n`);
    }
    await narrow.close();
    await wide.close();
    narrow = await actorConnection(server.endpoint, "narrow@example.com");
    wide = null;
    report.plans = await plans(narrow);
    for (const clients of [1, 8, 32]) {
      report.concurrency.push(await concurrency(
        server.endpoint,
        "narrow@example.com",
        "SELECT VALUE id FROM bench_default LIMIT 100;",
        clients,
        clients === 32 ? 5 : 10,
      ));
    }
    saveCheckpoint();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } finally {
    if (narrow) await narrow.close();
    if (wide) await wide.close();
    if (root) await root.close();
    await stopSurreal(server);
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
