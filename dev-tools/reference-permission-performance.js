#!/usr/bin/env node

/*
 * Disposable, on-disk benchmark for authorization access paths.
 *
 * The fixture is deliberately generated in bounded JS batches and sent as one
 * INSERT per table. There is no per-record network round trip and the server
 * always uses temporary RocksDB. The benchmark is evidence for a pinned
 * SurrealDB build, not a production capacity promise.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { spawn, execFileSync } = require("node:child_process");
const { Surreal, RecordId } = require("surrealdb");

const NAMESPACE = "rebase_reference_perf";
const DATABASE = "authorization";

class ResourceBudgetStop extends Error {
  constructor(message, snapshot) {
    super(message);
    this.name = "ResourceBudgetStop";
    this.snapshot = snapshot;
  }
}

function resolveSurrealBinary() {
  const configured = process.env.REBASE_REFERENCE_PERF_SURREAL_BIN;
  if (configured) return configured;
  try {
    return execFileSync("which", ["surreal"], { encoding: "utf8" }).trim() || "surreal";
  } catch {
    return "surreal";
  }
}

function numberEnv(name, fallback, minimum = 0) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value >= minimum ? value : fallback;
}

function parseScales(value) {
  const scales = String(value)
    .split(",")
    .map((part) => Number(part.trim()))
    .filter((part) => Number.isSafeInteger(part) && part > 0);
  return [...new Set(scales)].sort((a, b) => a - b);
}

function finalResult(response) {
  const last = Array.isArray(response) ? response.at(-1) : response;
  if (last && typeof last === "object" && Object.hasOwn(last, "result")) {
    if (last.status === "ERR") throw new Error(last.detail || "SurrealQL query failed");
    return last.result;
  }
  return last;
}

function rows(response) {
  const value = finalResult(response);
  return Array.isArray(value) ? value : value == null ? [] : [value];
}

function rowValue(response) {
  return rows(response)[0];
}

function operatorNames(value, names = []) {
  if (!value || typeof value !== "object") return names;
  if (typeof value.operator === "string") names.push(value.operator);
  for (const child of Object.values(value)) operatorNames(child, names);
  return names;
}

function planSummary(response) {
  const operators = [...new Set(operatorNames(finalResult(response)))];
  return {
    operators,
    access_path: operators.includes("ReferenceScan")
      ? "ReferenceScan"
      : operators.includes("IndexScan")
        ? "IndexScan"
        : operators.includes("TableScan")
          ? "TableScan"
          : operators.at(-1) || "unknown",
  };
}

function asStrings(values) {
  return values.map((value) => String(value));
}

function sortedStrings(values) {
  return asStrings(values).sort();
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    if (child.exitCode !== null) break;
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
  throw new Error("Disposable RocksDB SurrealDB did not start");
}

async function startSurreal() {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-reference-perf-"));
  const surrealBinary = resolveSurrealBinary();
  const child = spawn("nice", [
    "-n", "10", surrealBinary, "start", `rocksdb://${dataDir}`,
    "--user", "root", "--pass", "root", "--bind", `127.0.0.1:${port}`,
    "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  try {
    await waitForPort(port, child);
  } catch (error) {
    if (child.exitCode === null) child.kill("SIGTERM");
    throw new Error(`${error.message}${stderr.trim() ? `: ${stderr.trim()}` : ""}`);
  }
  return { child, endpoint: `ws://127.0.0.1:${port}/rpc`, dataDir, surrealBinary };
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
  fs.rmSync(server.dataDir, { recursive: true, force: true });
}

function directoryBytes(directory) {
  let total = 0;
  const stack = [directory];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      try {
        if (entry.isDirectory()) stack.push(full);
        else if (entry.isFile()) total += fs.statSync(full).size;
      } catch {
        // The database may rotate a file while this best-effort guard runs.
      }
    }
  }
  return total;
}

function rssBytes(pid) {
  try {
    const match = fs.readFileSync(`/proc/${pid}/status`, "utf8")
      .match(/^VmRSS:\s+(\d+) kB$/m);
    return match ? Number(match[1]) * 1024 : null;
  } catch {
    return null;
  }
}

function snapshot(server) {
  return {
    rss_mb: server ? Number(((rssBytes(server.child.pid) || 0) / 1024 / 1024).toFixed(1)) : null,
    datastore_mb: server
      ? Number((directoryBytes(server.dataDir) / 1024 / 1024).toFixed(1))
      : null,
  };
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

async function actorConnection(endpoint, id) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({
    namespace: NAMESPACE,
    database: DATABASE,
    access: "bench_record",
    variables: { id },
  });
  return db;
}

async function defineSchema(root) {
  await root.query(`
    DEFINE ACCESS bench_record ON DATABASE TYPE RECORD
      SIGNIN {
        IF $id = NONE { RETURN NONE; };
        RETURN type::record($id);
      }
      AUTHENTICATE { RETURN $auth; }
      DURATION FOR SESSION 1h, FOR TOKEN 1h;

    DEFINE TABLE auth_actor SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD label ON auth_actor TYPE string;
    DEFINE FIELD allowed ON auth_actor TYPE array<string> DEFAULT [];

    DEFINE TABLE resource_plain SCHEMAFULL PERMISSIONS
      FOR select WHERE $auth.id != NONE AND
        (visibility = true OR readers_index CONTAINS <string>$auth.id
          OR <string>owned_by IN $auth.allowed)
      FOR create, update, delete WHERE true;
    DEFINE FIELD visibility ON resource_plain TYPE bool DEFAULT false;
    DEFINE FIELD readers_index ON resource_plain TYPE array<string> DEFAULT [];
    DEFINE FIELD owned_by ON resource_plain TYPE record<auth_actor>;
    DEFINE FIELD controllers ON resource_plain TYPE array<record<auth_actor>> DEFAULT [];
    DEFINE FIELD seq ON resource_plain TYPE int;
    DEFINE FIELD tenant_key ON resource_plain TYPE string;
    DEFINE FIELD status ON resource_plain TYPE string;
    DEFINE FIELD amount_cents ON resource_plain TYPE int;
    DEFINE FIELD created_at ON resource_plain TYPE datetime;
    DEFINE FIELD tags ON resource_plain TYPE array<string> DEFAULT [];
    DEFINE FIELD payload ON resource_plain TYPE object FLEXIBLE DEFAULT {};
    DEFINE INDEX resource_plain_owner ON resource_plain FIELDS owned_by;
    DEFINE INDEX resource_plain_reader ON resource_plain FIELDS readers_index.*;
    DEFINE INDEX resource_plain_seq ON resource_plain FIELDS seq;

    DEFINE TABLE resource_ref SCHEMAFULL PERMISSIONS
      FOR select WHERE $auth.id != NONE AND
        (visibility = true OR readers_index CONTAINS <string>$auth.id
          OR <string>owned_by IN $auth.allowed)
      FOR create, update, delete WHERE true;
    DEFINE FIELD visibility ON resource_ref TYPE bool DEFAULT false;
    DEFINE FIELD readers_index ON resource_ref TYPE array<string> DEFAULT [];
    DEFINE FIELD owned_by ON resource_ref TYPE record<auth_actor>;
    DEFINE FIELD controllers ON resource_ref TYPE array<record<auth_actor>>
      REFERENCE ON DELETE UNSET DEFAULT [];
    DEFINE FIELD seq ON resource_ref TYPE int;
    DEFINE FIELD tenant_key ON resource_ref TYPE string;
    DEFINE FIELD status ON resource_ref TYPE string;
    DEFINE FIELD amount_cents ON resource_ref TYPE int;
    DEFINE FIELD created_at ON resource_ref TYPE datetime;
    DEFINE FIELD tags ON resource_ref TYPE array<string> DEFAULT [];
    DEFINE FIELD payload ON resource_ref TYPE object FLEXIBLE DEFAULT {};
    DEFINE INDEX resource_ref_owner ON resource_ref FIELDS owned_by;
    DEFINE INDEX resource_ref_reader ON resource_ref FIELDS readers_index.*;
    DEFINE INDEX resource_ref_seq ON resource_ref FIELDS seq;

    DEFINE TABLE resource_closure SCHEMAFULL PERMISSIONS
      FOR select WHERE $auth.id != NONE AND $auth.id IN controllers
      FOR create, update, delete WHERE true;
    DEFINE FIELD controllers ON resource_closure TYPE array<record<auth_actor>>
      REFERENCE ON DELETE UNSET DEFAULT [];
    DEFINE FIELD seq ON resource_closure TYPE int;
    DEFINE FIELD tenant_key ON resource_closure TYPE string;
    DEFINE FIELD status ON resource_closure TYPE string;
    DEFINE FIELD amount_cents ON resource_closure TYPE int;
    DEFINE FIELD created_at ON resource_closure TYPE datetime;
    DEFINE FIELD tags ON resource_closure TYPE array<string> DEFAULT [];
    DEFINE FIELD payload ON resource_closure TYPE object FLEXIBLE DEFAULT {};
    DEFINE INDEX resource_closure_seq ON resource_closure FIELDS seq;

    DEFINE TABLE resource_owner_ref SCHEMAFULL PERMISSIONS
      FOR select WHERE $auth.id != NONE AND $auth.id IN controllers
      FOR create, update, delete WHERE true;
    DEFINE FIELD controllers ON resource_owner_ref TYPE array<record<auth_actor>>
      REFERENCE ON DELETE UNSET DEFAULT [];
    DEFINE FIELD seq ON resource_owner_ref TYPE int;
    DEFINE FIELD tenant_key ON resource_owner_ref TYPE string;
    DEFINE FIELD status ON resource_owner_ref TYPE string;
    DEFINE FIELD amount_cents ON resource_owner_ref TYPE int;
    DEFINE FIELD owned_by ON resource_owner_ref TYPE record<auth_actor>;
    DEFINE FIELD created_at ON resource_owner_ref TYPE datetime;
    DEFINE FIELD tags ON resource_owner_ref TYPE array<string> DEFAULT [];
    DEFINE FIELD payload ON resource_owner_ref TYPE object FLEXIBLE DEFAULT {};
    DEFINE INDEX resource_owner_ref_seq ON resource_owner_ref FIELDS seq;

    DEFINE TABLE resource_indexed SCHEMAFULL PERMISSIONS
      FOR select WHERE $auth.id != NONE AND
        (visibility = true OR readers_index CONTAINS <string>$auth.id
          OR <string>owned_by IN $auth.allowed)
      FOR create, update, delete WHERE true;
    DEFINE FIELD visibility ON resource_indexed TYPE bool DEFAULT false;
    DEFINE FIELD readers_index ON resource_indexed TYPE array<string> DEFAULT [];
    DEFINE FIELD owned_by ON resource_indexed TYPE record<auth_actor>;
    DEFINE FIELD controllers ON resource_indexed TYPE array<record<auth_actor>> DEFAULT [];
    DEFINE FIELD seq ON resource_indexed TYPE int;
    DEFINE FIELD tenant_key ON resource_indexed TYPE string;
    DEFINE FIELD status ON resource_indexed TYPE string;
    DEFINE FIELD amount_cents ON resource_indexed TYPE int;
    DEFINE FIELD created_at ON resource_indexed TYPE datetime;
    DEFINE FIELD tags ON resource_indexed TYPE array<string> DEFAULT [];
    DEFINE FIELD payload ON resource_indexed TYPE object FLEXIBLE DEFAULT {};
    DEFINE INDEX resource_indexed_controllers ON resource_indexed FIELDS controllers.*;
    DEFINE INDEX resource_indexed_seq ON resource_indexed FIELDS seq;

    DEFINE TABLE mutation_plain SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD refs ON mutation_plain TYPE array<record<auth_actor>> DEFAULT [];
    DEFINE TABLE mutation_indexed SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD refs ON mutation_indexed TYPE array<record<auth_actor>> DEFAULT [];
    DEFINE INDEX mutation_indexed_refs ON mutation_indexed FIELDS refs.*;
    DEFINE TABLE mutation_reference SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD refs ON mutation_reference TYPE array<record<auth_actor>>
      REFERENCE ON DELETE UNSET DEFAULT [];

    DEFINE TABLE parent_unset SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE child_unset SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parents ON child_unset TYPE array<record<parent_unset>>
      REFERENCE ON DELETE UNSET DEFAULT [] ASSERT $value.len() > 0;
    DEFINE TABLE child_unset_empty SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE parent_unset_empty SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parents ON child_unset_empty TYPE array<record<parent_unset_empty>>
      REFERENCE ON DELETE UNSET DEFAULT [];
    DEFINE TABLE parent_reject SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE child_reject SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parents ON child_reject TYPE array<record<parent_reject>>
      REFERENCE ON DELETE REJECT DEFAULT [];
    DEFINE TABLE parent_scalar_optional SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE child_scalar_optional SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parent ON child_scalar_optional TYPE option<record<parent_scalar_optional>>
      REFERENCE ON DELETE UNSET DEFAULT NONE;
    DEFINE TABLE parent_scalar_required SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE child_scalar_required SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parent ON child_scalar_required TYPE record<parent_scalar_required>
      REFERENCE ON DELETE UNSET;
    DEFINE TABLE poly_user SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE poly_group SCHEMAFULL PERMISSIONS FULL;
    DEFINE TABLE poly_child SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parents ON poly_child TYPE array<record<poly_user | poly_group>>
      REFERENCE ON DELETE UNSET DEFAULT [] ASSERT $value.len() > 0;

    DEFINE TABLE closure_graph SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parents ON closure_graph TYPE array<record<closure_graph>>
      REFERENCE ON DELETE REJECT DEFAULT [];
    DEFINE FIELD descendants ON closure_graph TYPE array<record<closure_graph>>
      REFERENCE ON DELETE UNSET DEFAULT [];

    DEFINE TABLE computed_graph SCHEMAFULL PERMISSIONS FULL;
    DEFINE FIELD parents ON computed_graph TYPE array<record<computed_graph>>
      REFERENCE ON DELETE REJECT DEFAULT [];
    DEFINE FIELD dominates ON computed_graph TYPE array<record<computed_graph>> VALUE {
      LET $children = $this.id<~(computed_graph FIELD parents);
      RETURN array::distinct(array::flatten([
        $children,
        array::flatten($children.dominates)
      ])).filter(|$node| $node != NONE);
    } REFERENCE ON DELETE UNSET;
  `);
}

async function seedActors(root, closureWidth) {
  await root.query(`
    CREATE auth_actor:narrow SET label = 'Narrow actor', allowed = [];
    CREATE auth_actor:wide SET label = 'Wide actor', allowed = [];
    CREATE auth_actor:other SET label = 'Other actor', allowed = [];
  `);
  const groupRows = Array.from({ length: closureWidth }, (_, index) => ({
    id: new RecordId("auth_actor", `g${index}`),
    label: `Dominated group ${index}`,
    allowed: [],
  }));
  await root.query("INSERT INTO auth_actor $rows RETURN NONE;", { rows: groupRows });
  const mutationRows = Array.from({ length: Math.max(closureWidth, 256) }, (_, index) => ({
    id: new RecordId("auth_actor", `m${index}`),
    label: `Mutation reference ${index}`,
    allowed: [],
  }));
  await root.query("INSERT INTO auth_actor $rows RETURN NONE;", { rows: mutationRows });
  const narrowAllowed = ["auth_actor:narrow", "auth_actor:g0"];
  const wideAllowed = ["auth_actor:wide", ...Array.from(
    { length: closureWidth },
    (_, index) => `auth_actor:g${index}`,
  )];
  await root.query(`
    UPDATE auth_actor:narrow SET allowed = $narrow;
    UPDATE auth_actor:wide SET allowed = $wide;
  `, { narrow: narrowAllowed, wide: wideAllowed });
  await root.query(`
    CREATE mutation_plain:row SET refs = [];
    CREATE mutation_indexed:row SET refs = [];
    CREATE mutation_reference:row SET refs = [];
    CREATE parent_unset:p1;
    CREATE parent_unset:p2;
    CREATE child_unset:c SET parents = [parent_unset:p1, parent_unset:p2];
    CREATE parent_unset_empty:p1;
    CREATE parent_unset_empty:p2;
    CREATE child_unset_empty:c SET parents = [parent_unset_empty:p1, parent_unset_empty:p2];
    CREATE parent_reject:p1;
    CREATE child_reject:c SET parents = [parent_reject:p1];
    CREATE parent_scalar_optional:p;
    CREATE child_scalar_optional:c SET parent = parent_scalar_optional:p;
    CREATE parent_scalar_required:p;
    CREATE child_scalar_required:c SET parent = parent_scalar_required:p;
    CREATE poly_user:u;
    CREATE poly_group:g;
    CREATE poly_child:c SET parents = [poly_user:u, poly_group:g];
    CREATE closure_graph:root SET parents = [], descendants = [closure_graph:child];
    CREATE closure_graph:other SET parents = [], descendants = [];
    CREATE closure_graph:child SET parents = [closure_graph:root], descendants = [];
    CREATE computed_graph:root SET parents = [];
    CREATE computed_graph:child SET parents = [computed_graph:root];
    CREATE computed_graph:grandchild SET parents = [computed_graph:child];
  `);
}

function hash32(value) {
  let x = (value + 0x9e3779b9) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x85ebca6b) >>> 0;
  x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35) >>> 0;
  return (x ^ (x >>> 16)) >>> 0;
}

function fixtureRow(seq, closureWidth, distribution = {
  visible: 8,
  reader: 40,
  narrowOwner: 50,
  wideOwner: 100,
}) {
  const slot = hash32(seq) % 1000;
  const visibleEnd = distribution.visible;
  const readerEnd = visibleEnd + distribution.reader;
  const narrowOwnerEnd = readerEnd + distribution.narrowOwner;
  const wideOwnerEnd = narrowOwnerEnd + distribution.wideOwner;
  const visible = slot < visibleEnd;
  const reader = slot >= visibleEnd && slot < readerEnd;
  const narrowOwner = slot >= readerEnd && slot < narrowOwnerEnd;
  const wideOwner = slot >= narrowOwnerEnd && slot < wideOwnerEnd;
  const owner = narrowOwner
    ? new RecordId("auth_actor", "narrow")
    : wideOwner
      ? new RecordId("auth_actor", `g${1 + (seq % Math.max(1, closureWidth - 1))}`)
      : new RecordId("auth_actor", "other");
  const narrowAuthorized = visible || reader || narrowOwner;
  const wideAuthorized = visible || reader || narrowOwner || wideOwner;
  const controllers = wideAuthorized
    ? (narrowAuthorized
      ? [new RecordId("auth_actor", "narrow"), new RecordId("auth_actor", "wide")]
      : [new RecordId("auth_actor", "wide")])
    : [new RecordId("auth_actor", "other")];
  const statusRoll = hash32(seq * 17) % 100;
  const status = statusRoll < 70 ? "active" : statusRoll < 92 ? "pending" : "archived";
  const tenantRoll = hash32(seq * 31) / 0xffffffff;
  const tenant = Math.min(19, Math.floor(Math.pow(tenantRoll, 3) * 20));
  const createdAt = new Date(Date.UTC(2022, 0, 1) + seq * 60000);
  return {
    visibility: visible,
    readers_index: reader
      ? ["auth_actor:narrow", "auth_actor:wide"]
      : [],
    owned_by: owner,
    controllers,
    owner_only_controllers: [owner],
    seq,
    tenant_key: `tenant_${tenant}`,
    status,
    amount_cents: 500 + (hash32(seq * 43) % 250000),
    created_at: createdAt,
    tags: [`region_${seq % 8}`, `segment_${seq % 5}`, status],
    payload: {
      title: `Customer order ${String(seq).padStart(8, "0")}`,
      summary: "A bounded benchmark payload with realistic skew and nested metadata.",
      customer: {
        segment: ["startup", "smb", "enterprise"][seq % 3],
        region: ["ap-south", "eu-west", "us-east"][seq % 3],
      },
      risk_score: Number((hash32(seq * 59) / 0xffffffff).toFixed(6)),
    },
    narrowAuthorized,
    wideAuthorized,
  };
}

function tableRow(row, mode) {
  const common = {
    seq: row.seq,
    tenant_key: row.tenant_key,
    status: row.status,
    amount_cents: row.amount_cents,
    created_at: row.created_at,
    tags: row.tags,
    payload: row.payload,
  };
  if (mode === "closure") return { ...common, controllers: row.controllers };
  if (mode === "owner") return {
    ...common,
    owned_by: row.owned_by,
    controllers: row.owner_only_controllers,
  };
  return {
    ...common,
    visibility: row.visibility,
    readers_index: row.readers_index,
    owned_by: row.owned_by,
    controllers: row.controllers,
  };
}

async function insertBatch(root, batch) {
  const inserts = [
    ["resource_plain", batch.map((row) => tableRow(row, "current"))],
    ["resource_ref", batch.map((row) => tableRow(row, "current"))],
    ["resource_closure", batch.map((row) => tableRow(row, "closure"))],
    ["resource_owner_ref", batch.map((row) => tableRow(row, "owner"))],
    ["resource_indexed", batch.map((row) => tableRow(row, "current"))],
  ];
  for (const [table, rowsToInsert] of inserts) {
    await root.query(`INSERT INTO ${table} $rows RETURN NONE;`, { rows: rowsToInsert });
  }
}

async function populate(root, server, target, current, options, report) {
  const started = performance.now();
  let batches = 0;
  for (let start = current; start < target; start += options.batchSize) {
    const end = Math.min(target, start + options.batchSize);
    const batch = Array.from({ length: end - start }, (_, offset) => (
      fixtureRow(start + offset, options.closureWidth, options.distribution)
    ));
    await insertBatch(root, batch);
    batches += 1;
    if (batches % options.guardEveryBatches === 0) {
      const state = snapshot(server);
      if (state.rss_mb > options.maxRssMb || state.datastore_mb > options.maxDiskMb) {
        throw new ResourceBudgetStop(
          `resource budget reached at ${end} rows/table`,
          { rows_per_table: end, ...state },
        );
      }
      if (performance.now() - options.startedAt > options.maxRuntimeMs) {
        throw new ResourceBudgetStop(
          `runtime budget reached at ${end} rows/table`,
          { rows_per_table: end, ...state },
        );
      }
    }
    if (process.env.REBASE_REFERENCE_PERF_PROGRESS === "1") {
      process.stderr.write(`reference-permission-performance: populated ${end}/${target}\n`);
    }
  }
  return {
    elapsed_ms: Number((performance.now() - started).toFixed(3)),
    batches,
    resource: snapshot(server),
  };
}

async function measure(db, query, variables = {}, options = {}) {
  const repetitions = options.repetitions;
  const warmups = options.warmups;
  for (let index = 0; index < warmups; index += 1) await db.query(query, variables);
  const samples = [];
  let result;
  for (let index = 0; index < repetitions; index += 1) {
    const started = performance.now();
    result = await db.query(query, variables);
    samples.push(performance.now() - started);
  }
  samples.sort((a, b) => a - b);
  const value = rowValue(result);
  return {
    p50_ms: Number(percentile(samples, 0.5).toFixed(3)),
    p95_ms: Number(percentile(samples, 0.95).toFixed(3)),
    min_ms: Number(samples[0].toFixed(3)),
    max_ms: Number(samples.at(-1).toFixed(3)),
    returned: rows(result).length,
    value: value && typeof value === "object" && Object.hasOwn(value, "count")
      ? Number(value.count)
      : undefined,
  };
}

async function measurePrebound(db, options, sourceId) {
  const samples = [];
  let returned = 0;
  let candidateCount = 0;
  let truncated = false;
  for (let index = 0; index < options.repetitions; index += 1) {
    const started = performance.now();
    const candidates = rows(await db.query(
      `SELECT VALUE id FROM ${sourceId}<~(resource_closure FIELD controllers) LIMIT ${options.maxCandidateRows};`,
    ));
    candidateCount = candidates.length;
    truncated = candidates.length >= options.maxCandidateRows;
    const result = await db.query(
      "SELECT VALUE seq FROM resource_closure WHERE id IN $ids ORDER BY seq LIMIT 100;",
      { ids: candidates },
    );
    samples.push(performance.now() - started);
    returned = rows(result).length;
  }
  samples.sort((a, b) => a - b);
  return {
    p50_ms: Number(percentile(samples, 0.5).toFixed(3)),
    p95_ms: Number(percentile(samples, 0.95).toFixed(3)),
    min_ms: Number(samples[0].toFixed(3)),
    max_ms: Number(samples.at(-1).toFixed(3)),
    returned,
    candidate_count: candidateCount,
    candidate_truncated: truncated,
    note: "explicit candidate reference scan followed by a parameter-bound fetch",
  };
}

async function collectPlans(db) {
  const queries = {
    current_permission: "SELECT VALUE seq FROM resource_plain LIMIT 100 EXPLAIN FULL;",
    reference_field_permission: "SELECT VALUE seq FROM resource_ref LIMIT 100 EXPLAIN FULL;",
    materialized_closure_permission: "SELECT VALUE seq FROM resource_closure LIMIT 100 EXPLAIN FULL;",
    explicit_reference_scan: "SELECT VALUE seq FROM auth_actor:narrow<~(resource_closure FIELD controllers) LIMIT 100 EXPLAIN FULL;",
    owner_reference_scan: "SELECT VALUE seq FROM auth_actor:narrow<~(resource_owner_ref FIELD controllers) LIMIT 100 EXPLAIN FULL;",
    explicit_owner_filter: "SELECT VALUE seq FROM resource_plain WHERE owned_by = auth_actor:g0 LIMIT 100 EXPLAIN FULL;",
    explicit_reader_filter: "SELECT VALUE seq FROM resource_plain WHERE readers_index CONTAINS 'auth_actor:narrow' LIMIT 100 EXPLAIN FULL;",
    prebound_id_filter: "SELECT VALUE seq FROM resource_closure WHERE id IN $ids LIMIT 100 EXPLAIN FULL;",
  };
  const plans = {};
  const candidateIds = rows(await db.query(
    "SELECT VALUE id FROM auth_actor:narrow<~(resource_closure FIELD controllers) LIMIT 100;",
  ));
  for (const [name, query] of Object.entries(queries)) {
    const variables = name === "prebound_id_filter" ? { ids: candidateIds } : {};
    plans[name] = {
      sql: query,
      ...(planSummary(await db.query(query, variables))),
    };
  }
  return plans;
}

async function stageMeasurements(actor, options, rowCount, sourceId) {
  const cases = {
    current_permission_page: "SELECT VALUE seq FROM resource_plain ORDER BY seq LIMIT 100;",
    current_permission_count: "SELECT count() AS count FROM resource_plain GROUP ALL;",
    reference_field_permission_page: "SELECT VALUE seq FROM resource_ref ORDER BY seq LIMIT 100;",
    reference_field_permission_count: "SELECT count() AS count FROM resource_ref GROUP ALL;",
    closure_permission_page: "SELECT VALUE seq FROM resource_closure ORDER BY seq LIMIT 100;",
    closure_permission_count: "SELECT count() AS count FROM resource_closure GROUP ALL;",
    explicit_reference_page: `SELECT VALUE seq FROM ${sourceId}<~(resource_closure FIELD controllers) LIMIT 100;`,
    owner_reference_page: `SELECT VALUE seq FROM ${sourceId}<~(resource_owner_ref FIELD controllers) ORDER BY seq LIMIT 100;`,
    indexed_array_permission_page: "SELECT VALUE seq FROM resource_indexed ORDER BY seq LIMIT 100;",
  };
  const output = {};
  for (const [name, query] of Object.entries(cases)) {
    output[name] = await measure(actor, query, {}, options);
  }
  output.explicit_reference_sorted_page = rowCount <= options.maxSortedRows
    ? await measure(
      actor,
      `SELECT VALUE seq FROM ${sourceId}<~(resource_closure FIELD controllers) ORDER BY seq LIMIT 100;`,
      {},
      options,
    )
    : { skipped: true, reason: `row count exceeds sorted-scan cap ${options.maxSortedRows}` };
  output.explicit_reference_count = rowCount <= options.maxCountRows
    ? await measure(
      actor,
      `SELECT count() AS count FROM ${sourceId}<~(resource_closure FIELD controllers) GROUP ALL;`,
      {},
      options,
    )
    : { skipped: true, reason: `row count exceeds count cap ${options.maxCountRows}` };
  output.prebound_candidate_fetch = await measurePrebound(actor, options, sourceId);
  return output;
}

async function correctnessProbe(narrow, options, maxRows) {
  if (maxRows > options.correctnessRows) {
    return { skipped: true, reason: `scale exceeds correctness cap ${options.correctnessRows}` };
  }
  const current = rows(await narrow.query(
    "SELECT VALUE seq FROM resource_plain ORDER BY seq;",
  ));
  const refPermission = rows(await narrow.query(
    "SELECT VALUE seq FROM resource_ref ORDER BY seq;",
  ));
  const closurePermission = rows(await narrow.query(
    "SELECT VALUE seq FROM resource_closure ORDER BY seq;",
  ));
  const explicit = rows(await narrow.query(
    "SELECT VALUE seq FROM auth_actor:narrow<~(resource_closure FIELD controllers) ORDER BY seq;",
  ));
  const ownerOnly = rows(await narrow.query(
    "SELECT VALUE seq FROM auth_actor:narrow<~(resource_owner_ref FIELD controllers) ORDER BY seq;",
  ));
  assert.deepEqual(sortedStrings(refPermission), sortedStrings(current));
  assert.deepEqual(sortedStrings(closurePermission), sortedStrings(current));
  assert.deepEqual(sortedStrings(explicit), sortedStrings(current));
  const ownerSet = new Set(asStrings(ownerOnly));
  const omitted = current.filter((value) => !ownerSet.has(String(value)));
  assert(omitted.length > 0, "owner-only reverse references should omit non-owner grants");
  return {
    passed: true,
    current_rows: current.length,
    explicit_reference_rows: explicit.length,
    owner_only_rows: ownerOnly.length,
    owner_only_omitted_rows: omitted.length,
  };
}

async function mutationBenchmark(root, options) {
  const sizes = parseScales(process.env.REBASE_REFERENCE_PERF_MUTATION_SIZES || "1,8,32,128,256")
    .filter((size) => size <= options.mutationActors);
  const output = [];
  for (const size of sizes) {
    const refs = Array.from({ length: size }, (_, index) => new RecordId("auth_actor", `m${index}`));
    const appendId = `m${size}`;
    const base = "UPDATE %TABLE%:row SET refs = $refs RETURN NONE;";
    const values = {};
    for (const table of ["mutation_plain", "mutation_indexed", "mutation_reference"]) {
      await root.query(base.replace("%TABLE%", table), { refs });
      const samples = [];
      for (let index = 0; index < options.repetitions; index += 1) {
        await root.query(base.replace("%TABLE%", table), { refs });
        const started = performance.now();
        await root.query(
          `UPDATE ${table}:row SET refs = array::append(refs, type::record('auth_actor', $append)) RETURN NONE;`,
          { append: appendId },
        );
        samples.push(performance.now() - started);
      }
      samples.sort((a, b) => a - b);
      values[table] = {
        p50_ms: Number(percentile(samples, 0.5).toFixed(3)),
        p95_ms: Number(percentile(samples, 0.95).toFixed(3)),
      };
    }
    output.push({
      references_before: size,
      expected_secondary_array_update_keys: 2 * size + 1,
      expected_reference_append_keys: 1,
      values,
    });
  }
  return output;
}

async function deletionProbe(root) {
  const result = {};
  const first = rows(await root.query("SELECT VALUE parents FROM child_unset:c;"))[0];
  await root.query("DELETE parent_unset:p1;");
  const afterFirst = rows(await root.query("SELECT VALUE parents FROM child_unset:c;"))[0];
  let finalError = null;
  try {
    await root.query("DELETE parent_unset:p2;");
  } catch (error) {
    finalError = error.message;
  }
  const afterFinal = rows(await root.query("SELECT VALUE parents FROM child_unset:c;"))[0];
  result.array_unset_with_non_empty_assert = {
    before: asStrings(first),
    after_first_delete: asStrings(afterFirst),
    final_delete_rejected: Boolean(finalError),
    final_delete_error: finalError,
    retained_after_rejection: asStrings(afterFinal),
  };

  await root.query("DELETE parent_unset_empty:p1; DELETE parent_unset_empty:p2;");
  const emptyAfter = rows(await root.query("SELECT VALUE parents FROM child_unset_empty:c;"))[0];
  result.array_unset_without_assert = { after_both_parents_deleted: asStrings(emptyAfter) };

  let rejectError = null;
  try {
    await root.query("DELETE parent_reject:p1;");
  } catch (error) {
    rejectError = error.message;
  }
  const rejectAfter = rows(await root.query("SELECT VALUE parents FROM child_reject:c;"))[0];
  result.array_reject = {
    delete_rejected: Boolean(rejectError),
    error: rejectError,
    retained: asStrings(rejectAfter),
  };

  await root.query("DELETE poly_user:u;");
  const polymorphicAfterFirst = rows(await root.query("SELECT VALUE parents FROM poly_child:c;"))[0];
  let polymorphicFinalError = null;
  try {
    await root.query("DELETE poly_group:g;");
  } catch (error) {
    polymorphicFinalError = error.message;
  }
  result.polymorphic_array_unset = {
    after_user_delete: asStrings(polymorphicAfterFirst),
    group_delete_rejected_by_non_empty_assert: Boolean(polymorphicFinalError),
    group_delete_error: polymorphicFinalError,
  };

  await root.query("DELETE parent_scalar_optional:p;");
  const optional = rowValue(await root.query("SELECT VALUE parent FROM child_scalar_optional:c;"));
  result.optional_scalar_unset = {
    value_after_delete: optional == null || String(optional) === "NONE" ? null : optional,
  };

  let requiredError = null;
  try {
    await root.query("DELETE parent_scalar_required:p;");
  } catch (error) {
    requiredError = error.message;
  }
  result.required_scalar_unset = {
    delete_rejected: Boolean(requiredError),
    error: requiredError,
  };
  return result;
}

async function staleClosureProbe(root) {
  const before = rows(await root.query(
    "SELECT VALUE id FROM closure_graph:root<~(closure_graph FIELD parents);",
  ));
  const storedBefore = rows(await root.query(
    "SELECT VALUE descendants FROM closure_graph:root;",
  ))[0];
  await root.query("UPDATE closure_graph:child SET parents = [closure_graph:other];");
  const after = rows(await root.query(
    "SELECT VALUE id FROM closure_graph:root<~(closure_graph FIELD parents);",
  ));
  const storedAfter = rows(await root.query(
    "SELECT VALUE descendants FROM closure_graph:root;",
  ))[0];
  const computedInitial = rows(await root.query(
    "SELECT id, dominates FROM computed_graph ORDER BY id;",
  ));
  const computedReverse = rows(await root.query(
    "SELECT VALUE id FROM computed_graph:root<~(computed_graph FIELD dominates);",
  ));
  return {
    reverse_reference_before: asStrings(before),
    reverse_reference_after_parent_move: asStrings(after),
    stored_closure_before: asStrings(storedBefore),
    stored_closure_after_parent_move: asStrings(storedAfter),
    stale_without_maintenance: asStrings(storedAfter).includes("closure_graph:child"),
    computed_reference_initial: computedInitial.map((row) => ({
      id: String(row.id),
      dominates: asStrings(row.dominates ?? []),
    })),
    computed_reference_reverse_scan: asStrings(computedReverse),
    computed_reference_note: "VALUE plus REFERENCE is accepted, but transitive values are not propagated to ancestors without explicit update/event maintenance",
  };
}

async function main() {
  const scales = parseScales(
    process.env.REBASE_REFERENCE_PERF_ROWS || "1000,10000,100000",
  );
  if (!scales.length) throw new Error("REBASE_REFERENCE_PERF_ROWS must contain positive integers");
  const options = {
    scales,
    batchSize: Math.max(100, numberEnv("REBASE_REFERENCE_PERF_BATCH_ROWS", 2000, 1)),
    repetitions: Math.max(3, numberEnv("REBASE_REFERENCE_PERF_REPETITIONS", 5, 1)),
    warmups: Math.max(1, numberEnv("REBASE_REFERENCE_PERF_WARMUPS", 1, 1)),
    closureWidth: Math.max(2, numberEnv("REBASE_REFERENCE_PERF_CLOSURE_WIDTH", 128, 2)),
    distribution: {
      visible: Math.min(1000, numberEnv("REBASE_REFERENCE_PERF_VISIBLE_PER_1000", 8, 0)),
      reader: Math.min(1000, numberEnv("REBASE_REFERENCE_PERF_READER_PER_1000", 40, 0)),
      narrowOwner: Math.min(1000, numberEnv("REBASE_REFERENCE_PERF_NARROW_OWNER_PER_1000", 50, 0)),
      wideOwner: Math.min(1000, numberEnv("REBASE_REFERENCE_PERF_WIDE_OWNER_PER_1000", 100, 0)),
    },
    mutationActors: Math.max(256, numberEnv("REBASE_REFERENCE_PERF_MUTATION_ACTORS", 512, 256)),
    correctnessRows: Math.max(1, numberEnv("REBASE_REFERENCE_PERF_CORRECTNESS_ROWS", 20000, 1)),
    maxCandidateRows: Math.max(100, numberEnv("REBASE_REFERENCE_PERF_MAX_CANDIDATE_ROWS", 250000, 100)),
    maxSortedRows: Math.max(1000, numberEnv("REBASE_REFERENCE_PERF_MAX_SORTED_ROWS", 200000, 1000)),
    maxCountRows: Math.max(1000, numberEnv("REBASE_REFERENCE_PERF_MAX_COUNT_ROWS", 200000, 1000)),
    maxRssMb: numberEnv("REBASE_REFERENCE_PERF_MAX_RSS_MB", 4096, 128),
    maxDiskMb: numberEnv("REBASE_REFERENCE_PERF_MAX_DISK_MB", 200000, 256),
    maxRuntimeMs: numberEnv("REBASE_REFERENCE_PERF_MAX_RUNTIME_MS", 900000, 1000),
    guardEveryBatches: Math.max(1, numberEnv("REBASE_REFERENCE_PERF_GUARD_BATCHES", 4, 1)),
    startedAt: performance.now(),
  };
  const distributionTotal = Object.values(options.distribution).reduce((sum, value) => sum + value, 0);
  if (distributionTotal > 1000) {
    throw new Error("authorization distribution values must sum to <= 1000 per 1000 rows");
  }
  const server = await startSurreal();
  const report = {
    status: "running",
    environment: {
      node: process.version,
      surrealdb: execFileSync(server.surrealBinary, ["version"], { encoding: "utf8" }).trim(),
      platform: `${process.platform} ${process.arch}`,
      datastore: "temporary RocksDB",
      scales,
      batch_rows: options.batchSize,
      repetitions: options.repetitions,
      warmups: options.warmups,
      closure_width: options.closureWidth,
      authorization_distribution_per_1000: options.distribution,
      max_rss_mb: options.maxRssMb,
      max_disk_mb: options.maxDiskMb,
      max_runtime_ms: options.maxRuntimeMs,
      max_candidate_rows: options.maxCandidateRows,
      max_sorted_rows: options.maxSortedRows,
      max_count_rows: options.maxCountRows,
    },
    stages: [],
    plans: {},
    correctness: null,
    mutation_append: [],
    deletion_semantics: null,
    stale_closure: null,
    stopped: null,
  };
  const outputPath = process.env.REBASE_REFERENCE_PERF_OUTPUT;
  const checkpoint = () => {
    if (outputPath) fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
  };
  let root;
  let narrow;
  let wide;
  try {
    root = await rootConnection(server.endpoint);
    await defineSchema(root);
    await seedActors(root, options.closureWidth);
    let current = 0;
    for (const target of scales) {
      const population = await populate(root, server, target, current, options, report);
      current = target;
      if (narrow) await narrow.close();
      if (wide) await wide.close();
      narrow = await actorConnection(server.endpoint, "auth_actor:narrow");
      wide = await actorConnection(server.endpoint, "auth_actor:wide");
      report.stages.push({
        rows_per_table: target,
        population,
        narrow: await stageMeasurements(narrow, options, target, "auth_actor:narrow"),
        wide: await stageMeasurements(wide, options, target, "auth_actor:wide"),
      });
      checkpoint();
      process.stderr.write(`reference-permission-performance: measured ${target} rows/table\n`);
    }
    report.plans = await collectPlans(narrow);
    report.correctness = await correctnessProbe(narrow, options, current);
    report.mutation_append = await mutationBenchmark(root, options);
    report.deletion_semantics = await deletionProbe(root);
    report.stale_closure = await staleClosureProbe(root);
    report.status = "complete";
    checkpoint();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    if (error instanceof ResourceBudgetStop) {
      report.status = "stopped_at_budget";
      report.stopped = { message: error.message, ...error.snapshot };
      checkpoint();
      process.stderr.write(`reference-permission-performance: ${error.message}\n`);
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      if (process.env.REBASE_REFERENCE_PERF_ALLOW_BUDGET_STOP !== "1") process.exitCode = 2;
    } else {
      report.status = "failed";
      report.stopped = { message: error.message };
      checkpoint();
      throw error;
    }
  } finally {
    if (narrow) await narrow.close();
    if (wide) await wide.close();
    if (root) await root.close();
    await stopSurreal(server);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`reference-permission-performance: FAIL: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

module.exports = {
  finalResult,
  rows,
  planSummary,
  fixtureRow,
  main,
};
