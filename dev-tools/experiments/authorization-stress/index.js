#!/usr/bin/env node
"use strict";

// One opt-in suite: real compiled authorization, real intrusive tree nodes,
// independent expected rows, disposable persistent storage, bounded resources.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createHash } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { performance } = require("node:perf_hooks");
const { parseArgs } = require("node:util");
const { Surreal, RecordId, Decimal } = require("surrealdb");
const { start } = require("../../temporal-tree/harness");
const { prepare } = require("../..");
const fixture = require("./fixture");
const access = require("./access");
const { readPage, filterPage } = require("./paging");

const CONFIGS = [{ table: "stress_1_1", slots: 1, measures: 1 },
  { table: "stress_0_0", slots: 0, measures: 0 }, { table: "stress_1_0", slots: 1, measures: 0 },
  { table: "stress_4_1", slots: 4, measures: 1 }, { table: "stress_4_8", slots: 4, measures: 8 }];
const ROOT = path.resolve(__dirname, "../../..");

class BudgetStop extends Error {}
function options(argv) {
  const { values } = parseArgs({ args: argv, options: {
    scales: { type: "string", default: "100,1000,10000,100000,1000000" },
    samples: { type: "string", default: "3" }, "owner-count": { type: "string", default: "32" },
    "batch-rows": { type: "string", default: "500" }, "budget-seconds": { type: "string", default: "1200" },
    "max-stage-seconds": { type: "string", default: "600" }, "max-rss-mb": { type: "string", default: "6000" },
    "max-disk-mb": { type: "string", default: "10000" }, "scan-timeout-ms": { type: "string", default: "3000" },
    "variant-rows": { type: "string", default: "1000" }, output: { type: "string", default: "/tmp/rebase-authorization-stress.json" },
    "seed-mode": { type: "string", default: "image" },
    quick: { type: "boolean" }, help: { type: "boolean", short: "h" },
  } });
  const result = { ...values, scales: (values.quick ? "100,1000" : values.scales).split(",").map(Number) };
  assert(result.scales.length && result.scales.every(n => Number.isSafeInteger(n) && n > 0 && n <= 100000000), "invalid scales");
  result.scales = [...new Set(result.scales)].sort((a, b) => a - b);
  for (const key of ["samples", "owner-count", "batch-rows", "budget-seconds", "max-stage-seconds", "max-rss-mb", "max-disk-mb", "scan-timeout-ms", "variant-rows"]) {
    result[key] = Number(values[key]);
    assert(Number.isSafeInteger(result[key]) && result[key] > 0, `--${key} must be a positive integer`);
  }
  assert(result.samples >= 3 && result.samples <= 30, "use 3..30 samples");
  assert(result["owner-count"] >= 3 && result["owner-count"] <= 256, "owner count must be 3..256 (two reachable owners for transfer tests)");
  assert(["image", "native"].includes(result["seed-mode"]), "seed mode must be image or native");
  return result;
}

function bytes(directory) {
  if (!directory) return 0;
  let size = 0;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    try { size += entry.isDirectory() ? bytes(file) : fs.statSync(file).size; } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  return size;
}
function serverPid(directory) {
  for (const name of fs.readdirSync("/proc")) if (/^\d+$/.test(name)) {
    try { if (fs.readFileSync(`/proc/${name}/cmdline`, "utf8").split("\0").some(arg => arg === `surrealkv://${directory}`)) return Number(name); } catch {}
  }
  return null;
}
function resources(server, pid) {
  const rss = pid ? fs.readFileSync(`/proc/${pid}/status`, "utf8").match(/^VmRSS:\s+(\d+)/m)?.[1] : null;
  return { server_rss_mb: rss == null ? null : Number(rss) / 1024,
    client_rss_mb: process.memoryUsage().rss / 1048576, disk_mb: bytes(server.directory) / 1048576 };
}
function percentiles(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const p = quantile => sorted[Math.min(sorted.length - 1, Math.ceil(quantile * sorted.length) - 1)];
  return { samples_ms: samples, sample_count: samples.length, p50_ms: p(0.5), p95_ms: p(0.95),
    min_ms: sorted[0], max_ms: sorted.at(-1), throughput_ops_s: 1000 * samples.length / samples.reduce((sum, n) => sum + n, 0) };
}
const timedOut = error => /timeout|timed out|time limit|query timed|query execution was cancelled/i.test(String(error));
function assertRows(rows, expected, label) {
  assert.deepEqual(rows.map(row => Number(row.seq)), expected, label);
  assert.equal(new Set(rows.map(row => String(row.id))).size, rows.length, `${label}: no duplicates`);
}
const idFor = (table, seq) => new RecordId(table, `r${String(seq).padStart(10, "0")}`);
const cursorFor = (table, seq) => seq == null ? null : [Math.floor(seq / 3), String(idFor(table, seq)), "z0"];

async function measure(action, { samples, guard, validate = () => {}, warmup = true }) {
  let last;
  const operationStart = performance.now();
  try {
    if (warmup) { guard(); validate(await action()); } // excluded from samples
    const durations = [];
    for (let i = 0; i < samples; i++) {
      guard(); const began = performance.now(); last = await action(); durations.push(performance.now() - began); validate(last);
    }
    return { ...percentiles(durations), returned: last?.rows?.length,
      candidates: last?.candidates, visited: last?.visited, requests: last?.requests,
      truncated: last?.truncated, result_object_bytes: Buffer.byteLength(JSON.stringify(last, (_, v) => typeof v === "bigint" ? String(v) : v)) };
  } catch (error) {
    if (timedOut(error)) return { status: "server-query-timeout", elapsed_ms: performance.now() - operationStart, error: error.message };
    throw error;
  }
}

async function discover(db) {
  const began = performance.now();
  const [ids] = await db.query(`RETURN array::distinct(array::concat([$auth], $auth.parent_groups, $auth->rebase_access.out));`);
  return { ids, ms: performance.now() - began };
}

async function reads(db, graph, actorName, config, n, run, results = []) {
  const { table } = config, actor = graph.actors[actorName], all = [];
  const allowed = new Set(graph.owners.filter(owner => access.canAccess(graph, actor, owner)).map(String));
  for (let seq = 0; seq < n; seq++) if (allowed.has(String(graph.owners[seq % graph.owners.length]))) all.push(seq);
  const found = await discover(db);
  const discovered = new Set(found.ids.map(String));
  const owners = graph.owners.filter(owner => discovered.has(String(owner)));
  assert.deepEqual(owners.map(String).sort(), [...allowed].sort(), "native candidate discovery matches source DAG");
  const slot = fixture.rootSlot(table, "z0"), timeout = run.options["scan-timeout-ms"];
  const descriptors = [
    { location: "first", size: 1 }, { location: "first", size: 50 }, { location: "first", size: 200 },
    { location: "middle", size: 50 }, { location: "last", size: 50 }, { location: "middle", size: 50, reverse: true },
  ];
  for (const descriptor of descriptors) {
    const { size, reverse = false, location } = descriptor;
    const ordered = reverse ? all.toReversed() : all;
    const offset = location === "first" ? 0 : location === "middle" ? Math.floor(ordered.length / 2) : Math.max(0, ordered.length - size);
    const expected = ordered.slice(offset, offset + size), after = cursorFor(table, ordered[offset - 1]);
    const meta = { actor: actorName, n, size, location, reverse, authorized_rows: all.length, roots: owners.length, discovery_ms: found.ms };
    results.push({ ...meta, path: "custom-roots-bounded-heap-and-native-hydration", ...await measure(() => readPage(db, owners, slot, { limit: size, after, reverse }),
      { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, expected, "custom page") }) });
    if (actorName === "wide" && location === "first" && size === 50) {
      results.push({ ...meta, path: "custom-roots-full-prefetch-heap-and-native-hydration",
        ...await measure(() => readPage(db, owners, slot, { limit: size, after, reverse, strategy: "full" }),
          { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, expected, "full-prefetch custom page") }) });
      results.push({ ...meta, path: "custom-roots-bounded-heap-parallel4",
        ...await measure(() => readPage(db, owners, slot, { limit: size, after, reverse, fanout: 4 }),
          { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, expected, "bounded concurrent candidate fetch") }) });
    }
    const sql = `SELECT id, seq, rank, status, owned_by, read_by FROM ${table}
      WHERE ($after ?? NONE) = NONE OR rank ${reverse ? "<" : ">"} $after[0]
        OR (rank = $after[0] AND <string>id ${reverse ? "<" : ">"} $after[1])
      ORDER BY rank ${reverse ? "DESC" : "ASC"}, id ${reverse ? "DESC" : "ASC"} LIMIT $limit TIMEOUT ${timeout}ms;`;
    results.push({ ...meta, path: "native-rls-table-keyset", ...await measure(async () => ({ rows: (await db.query(sql, { after, limit: size }))[0] }),
      { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, expected, "native page") }) });
  }
  if (all.length) {
    const seq = all[Math.floor(all.length / 2)];
    results.push({ actor: actorName, n, path: "native-record-id-lookup",
      ...await measure(async () => ({ rows: (await db.query("SELECT id,seq FROM $id;", { id: idFor(table, seq) }))[0] }),
        { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, [seq], "keyed permission check") }) });
  }
  // A reference traversal narrows candidates, but materializing and sorting the
  // whole selected set still has a different cost from ordered tree paging.
  if (all.length <= 20000) {
    const sql = `LET $ids = array::flatten($owners.map(|$owner| $owner<~(${table} FIELD owned_by)));
      SELECT id, seq, rank, status, owned_by, read_by FROM $ids ORDER BY rank,id LIMIT 50 TIMEOUT ${timeout}ms;`;
    results.push({ actor: actorName, n, path: "native-reference-candidates-sort", materializes: all.length,
      ...await measure(async () => ({ rows: (await db.query(sql, { owners })).at(-1) }),
        { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, all.slice(0, 50), "reference candidates") }) });
  } else results.push({ actor: actorName, n, path: "native-reference-candidates-sort", status: "skipped", reason: "selected candidate set exceeds materialization cap 20000" });
  if (n <= 10000) {
    const offset = Math.floor(all.length / 2);
    results.push({ actor: actorName, n, path: "native-rls-deep-offset", offset,
      ...await measure(async () => ({ rows: (await db.query(`SELECT id,seq FROM ${table} ORDER BY rank,id LIMIT 50 START $offset TIMEOUT ${timeout}ms;`, { offset }))[0] }),
        { samples: run.options.samples, guard: run.guard, validate: page => assertRows(page.rows, all.slice(offset, offset + 50), "native offset") }) });
  }
  // Deliberately unindexed predicates: report the work, and never interpret a
  // budget-truncated search as a complete empty result.
  for (const status of ["hot", "absent"]) {
    const wanted = all.filter(seq => status === "hot" && seq % 100 === 0).slice(0, 10);
    results.push({ actor: actorName, n, path: "custom-page-unindexed-postfilter", predicate: status,
      sample_policy: "one bounded post-filter pass after preceding page warmups",
      ...await measure(() => filterPage(db, owners, slot, { limit: 10, maxVisited: 1000, predicate: row => row.status === status }),
        { samples: 1, warmup: false, guard: run.guard, validate: page => {
          assertRows(page.rows, wanted.slice(0, page.rows.length), "post-filter valid prefix");
          if (!page.truncated) assertRows(page.rows, wanted, "complete post-filter result");
        } }) });
  }
  return results;
}

async function queryPlans(db, root, table, owner) {
  return {
    plain: (await db.query(`SELECT id,rank FROM ${table} ORDER BY rank,id LIMIT 50 EXPLAIN;`))[0],
    reference: (await db.query(`SELECT id,rank FROM $owner<~(${table} FIELD owned_by) ORDER BY rank,id LIMIT 50 EXPLAIN;`, { owner }))[0],
    point: (await db.query("SELECT id,seq FROM $id EXPLAIN;", { id: idFor(table, 0) }))[0],
    authored_secondary_indexes: (await root.query(`INFO FOR TABLE ${table};`))[0].indexes,
  };
}

async function walkPages(db, owners, slot, table, expected) {
  const checks = [];
  for (const reverse of [false, true]) {
    let after = null, previousRevisions;
    const rows = [], seenCursors = new Set();
    do {
      const page = await readPage(db, owners, slot, { limit: 13, after, reverse });
      if (previousRevisions) assert.deepEqual(page.revisions, previousRevisions, "immutable walk has stable revisions");
      previousRevisions = page.revisions;
      rows.push(...page.rows); after = page.next;
      const key = JSON.stringify(after);
      if (after) { assert(!seenCursors.has(key), "pagination must advance"); seenCursors.add(key); }
    } while (after);
    assertRows(rows, reverse ? expected.toReversed() : expected, `${table}: full ${reverse ? "reverse" : "forward"} walk`);
    checks.push({ reverse, records: rows.length, requests: seenCursors.size + 1 });
  }
  return checks;
}

async function aggregateReads(db, graph, config, n, run) {
  if (!config.slots) return [];
  const owners = graph.owners.filter(owner => access.canAccess(graph, graph.actors.wide, owner));
  const keys = new Set(owners.map(String)), lower = Math.floor(n / 12), upper = Math.floor(n / 4);
  const expected = { summary: 0, range: 0 };
  for (let seq = 0; seq < n; seq++) if (keys.has(String(graph.owners[seq % graph.owners.length]))) {
    expected.summary++; if (Math.floor(seq / 3) >= lower && Math.floor(seq / 3) < upper) expected.range++;
  }
  const results = [];
  for (const operation of ["summary", "range"]) results.push({ operation, table: config.table, n,
    ...await measure(async () => {
      const [summaries] = await db.query("RETURN $owners.map(|$owner| fn::tree::read($owner,$slot,$operation,$args));",
        { owners, slot: fixture.rootSlot(config.table, "z0"), operation, args: operation === "summary" ? [] : [[lower], [upper]] });
      const count = summaries.reduce((sum, value) => sum + value.count, 0);
      for (let measureIndex = 0; measureIndex < config.measures; measureIndex++) {
        const total = summaries.reduce((sum, value) => sum + Number(value.measures[`m${measureIndex}`]?.sum ?? 0), 0);
        assert.equal(total, expected[operation] * (measureIndex + 1));
      }
      return { rows: [], count };
    }, { samples: run.options.samples, guard: run.guard, validate: result => assert.equal(result.count, expected[operation]) }) });
  return results;
}

// Full, source-derived structural verification after native writes at small
// sizes. Unlike the initial seed-image check it accepts every valid AVL shape.
async function nativeIntegrity(db, config, n, owners) {
  if (n > 1000) return { status: "not-run", reason: "post-write full oracle capped at 1000; seed-image validation covers every initial node and head at all scales" };
  const plain = value => value instanceof RecordId ? String(value) : value instanceof Decimal ? Number(value)
    : Array.isArray(value) ? value.map(plain) : value && typeof value === "object"
      ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, plain(item)])) : value;
  const [raw] = await db.query(`RETURN { records:(SELECT * FROM ${config.table}), owners:(SELECT * FROM $owners) };`, { owners });
  const snapshot = plain(raw);
  assert.equal(snapshot.records.length, n);
  const roots = snapshot.owners.map(owner => Object.fromEntries([["id", owner.id],
    ...Array.from({ length: config.slots }, (_, s) => { const slot = fixture.rootSlot(config.table, `z${s}`); return [slot, owner[slot]]; })]));
  const entries = snapshot.records.flatMap(row => Array.from({ length: config.slots }, (_, s) => ({
    link: { rid: row.id, slot: `z${s}` }, owner: { rid: row.owned_by, slot: fixture.rootSlot(config.table, `z${s}`) },
    key: [row.rank, row.id, `z${s}`], tags: {}, measures: Object.fromEntries(Array.from({ length: config.measures }, (_, m) => [`m${m}`, row.amount * (m + 1)])),
  })));
  require("../../temporal-tree/oracle").verify(roots, snapshot.records, entries, require("./paging").compareKeys);
  return { status: "passed", records: n, nodes: entries.length, method: "independent source membership / AVL / chronology / aggregate oracle" };
}

async function mutations(db, root, graph, config, n, run) {
  const { table, slots, measures } = config, owner = graph.owners[0], other = graph.owners[1];
  const [before] = await root.query("SELECT * FROM $owners;", { owners: [owner, other] });
  const results = { table, n, slots, measures, operations: {}, correctness: [] };
  const samples = Object.fromEntries(["create", "payload_update", "aggregate_update", "rekey", "owner_move", "delete"].map(key => [key, []]));
  const expectedCount = Math.ceil(n / graph.owners.length);
  for (let index = 0; index < run.options.samples; index++) {
    const id = new RecordId(table, `mutation_${index}`);
    const actions = [
      ["create", "CREATE $id CONTENT $content;", { id, content: { owned_by: owner, seq: n + index, rank: -10,
        amount: 1, status: "hot", payload: "authenticated native create" } }],
      ["payload_update", "UPDATE $id SET payload='native payload edit';", { id }],
      ["aggregate_update", "UPDATE $id SET amount=2;", { id }],
      ["rekey", "UPDATE $id SET rank=100000001;", { id }],
      ["owner_move", "UPDATE $id SET owned_by=$owner;", { id, owner: other }],
      ["delete", "DELETE $id;", { id }],
    ];
    for (const [name, sql, variables] of actions) {
      run.guard(); const began = performance.now(); await db.query(sql, variables); samples[name].push(performance.now() - began);
      const [saved] = await root.query("SELECT * FROM $id;", { id });
      assert.equal(saved.length, name === "delete" ? 0 : 1, `${table}/${name} actually changed a record`);
      if (saved.length) {
        assert.equal(String(saved[0].owned_by), String(name === "owner_move" ? other : owner));
        assert.equal(String(saved[0].read_by), String(saved[0].owned_by));
        assert.equal(saved[0].amount, ["aggregate_update", "rekey", "owner_move"].includes(name) ? 2 : 1);
        assert.equal(saved[0].payload, name === "create" ? "authenticated native create" : "native payload edit");
        assert.equal(saved[0].rank, ["rekey", "owner_move"].includes(name) ? 100000001 : -10);
      }
      if (slots && name === "aggregate_update") {
        const [head] = await root.query(`RETURN $owner.${fixture.rootSlot(table, "z0")};`, { owner });
        if (measures) assert.equal(Number(head.summary.measures.m0.sum), expectedCount + 2, "aggregate update repairs parent sum");
      }
    }
  }
  for (const [name, values] of Object.entries(samples)) results.operations[name] = percentiles(values);
  const [after] = await root.query("SELECT * FROM $owners;", { owners: [owner, other] });
  for (let i = 0; i < before.length; i++) for (let s = 0; s < slots; s++) {
    const field = fixture.rootSlot(table, `z${s}`);
    assert.deepEqual(after[i][field].summary, before[i][field].summary, "native CRUD restores exact root aggregates");
    assert(after[i][field].revision > before[i][field].revision);
  }
  results.correctness.push("each authenticated mutation changed its intended row", "root summaries restored after insert/update/rekey/owner move/delete");
  results.structural_oracle = await nativeIntegrity(root, config, n, graph.owners);
  return results;
}

async function concurrentReads(endpoint, graph, config, n, run) {
  const owners = graph.owners.filter(owner => access.canAccess(graph, graph.actors.wide, owner));
  const accessible = new Set(owners.map(String)), expected = [];
  for (let seq = 0; seq < n && expected.length < 50; seq++) if (accessible.has(String(graph.owners[seq % graph.owners.length]))) expected.push(seq);
  const records = [];
  for (const clients of [1, 2, 4]) {
    const connections = [];
    try {
      for (let index = 0; index < clients; index++) connections.push(await access.actorConnection(endpoint, graph.actors.wide));
      const samples = [], began = performance.now();
      await Promise.all(connections.map(async db => {
        for (let index = 0; index < 3; index++) {
          run.guard(); const start = performance.now();
          const result = await readPage(db, owners, fixture.rootSlot(config.table, "z0"), { limit: 50 });
          assertRows(result.rows, expected, "every concurrent reader returns a complete authorized page");
          samples.push(performance.now() - start);
        }
      }));
      records.push({ clients, operations: samples.length, n, ...percentiles(samples),
        throughput_ops_s: samples.length * 1000 / (performance.now() - began) });
    } finally { await Promise.all(connections.map(db => db.close())); }
  }
  return records;
}

async function concurrentWrites(endpoint, root, graph, config, n, run) {
  const connections = [], owner = graph.owners[0], ids = Array.from({ length: 4 }, (_, i) => new RecordId(config.table, `contended_${i}`));
  const [before] = await root.query(`RETURN $owner.${fixture.rootSlot(config.table, "z0")};`, { owner });
  let surfacedConflicts = 0;
  const attempts = [], durations = [], committed = [];
  try {
    for (let i = 0; i < ids.length; i++) connections.push(await access.actorConnection(endpoint, graph.actors.wide));
    const began = performance.now();
    const outcomes = await Promise.allSettled(connections.map(async (db, index) => {
      const started = performance.now();
      for (let attempt = 1; attempt <= 4; attempt++) {
        run.guard();
        try {
          await db.query("CREATE $id CONTENT $content;", { id: ids[index], content: {
            owned_by: owner, seq: n + index, rank: 100000002, amount: 1, status: "hot", payload: "concurrent authenticated write" } });
          committed.push(ids[index]); attempts[index] = attempt; durations.push(performance.now() - started); return;
        } catch (error) {
          if (!/conflict|retry|concurrent|transaction.*failed/i.test(String(error))) throw error;
          surfacedConflicts++; if (attempt === 4) attempts[index] = attempt;
        }
      }
    }));
    for (const outcome of outcomes) if (outcome.status === "rejected") throw outcome.reason;
    assert(committed.length > 0, "some shared-root writes must commit");
    const elapsed = performance.now() - began;
    const [actual] = await root.query("SELECT id FROM $ids;", { ids });
    assert.deepEqual(actual.map(row => String(row.id)).sort(), committed.map(String).sort(), "failed contenders leave no partial records");
    const [after] = await root.query(`RETURN $owner.${fixture.rootSlot(config.table, "z0")};`, { owner });
    assert.equal(after.summary.count, before.summary.count + committed.length);
    assert.equal(Number(after.summary.measures.m0.sum), Number(before.summary.measures.m0.sum) + committed.length);
    // Intrusive tree sources must be deleted sequentially: tombstoning linked
    // source rows in one DELETE can hide neighbours needed by their events.
    for (const id of committed) await connections[0].query("DELETE ONLY $id;", { id });
    const [restored] = await root.query(`RETURN $owner.${fixture.rootSlot(config.table, "z0")};`, { owner });
    assert.deepEqual(restored.summary, before.summary, "contended cleanup restores all root metrics");
    return { clients: ids.length, committed: committed.length, retry_exhausted: ids.length - committed.length,
      surfaced_conflicts: surfacedConflicts, attempts, ...percentiles(durations), throughput_ops_s: committed.length * 1000 / elapsed,
      integrity: await nativeIntegrity(root, config, n, graph.owners) };
  } finally { await Promise.all(connections.map(db => db.close())); }
}

async function main(argv = process.argv.slice(2)) {
  const config = options(argv);
  if (config.help) { console.log("Authorization stress: node dev-tools/experiments/authorization-stress [--quick] [--scales 100,1000,10000,100000,1000000] [--budget-seconds 1200] [--output results.json]\nAlways starts its own disposable SurrealKV server. See README.md in this directory."); return; }
  const compiled = fixture.compileFixture(CONFIGS), started = performance.now();
  const report = { started_at: new Date().toISOString(), status: "running", options: config,
    environment: { node: process.version, surreal: execFileSync(process.env.REBASE_TREE_SURREAL_BIN || "surreal", ["version"], { encoding: "utf8" }).trim(),
      commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
      cpu: os.cpus()[0].model, logical_cpus: os.cpus().length,
      cpu_quota: fs.existsSync("/sys/fs/cgroup/cpu.max") ? fs.readFileSync("/sys/fs/cgroup/cpu.max", "utf8").trim() : null,
      schema_sha256: createHash("sha256").update(compiled.bundle).digest("hex"),
      suite_sha256: createHash("sha256").update(["index.js", "paging.js", "fixture.js", "access.js"].map(file => fs.readFileSync(path.join(__dirname, file))).join("\n")).digest("hex") },
    stages: [], variants: [], skipped_scales: [], limitations: [
      "Synthetic rows exercise the current compiled authorization/tree kernels; application accounting/business rules are separate tests.",
      "Warm-cache single-host measurements; sample counts are evidence, not production latency guarantees or a capacity proof.",
      "Bulk construction bypasses source events only; its time is separate from native authenticated mutation throughput.",
      "Pagination revisions do not create a multi-request snapshot; consumers must handle intervening writes.",
    ] };
  const checkpoint = () => { fs.mkdirSync(path.dirname(path.resolve(config.output)), { recursive: true }); fs.writeFileSync(config.output, JSON.stringify(report, null, 2) + "\n"); };
  let server, root, pid, clients = {}, watchdog, hardStop, serverClosing, hardBudgetExceeded = false;
  const closeServer = () => serverClosing ||= server?.close();
  const run = { options: config, guard: () => {
    if ((performance.now() - started) / 1000 > config["budget-seconds"]) throw new BudgetStop("suite runtime budget exhausted");
    if (server) {
      const state = resources(server, pid);
      if ((state.server_rss_mb || 0) + state.client_rss_mb > config["max-rss-mb"]) throw new BudgetStop("RSS budget exhausted");
      if (state.disk_mb > config["max-disk-mb"]) throw new BudgetStop("disk budget exhausted");
    }
  } };
  try {
    server = await start({ engine: "surrealkv" }); pid = serverPid(server.directory);
    watchdog = setTimeout(() => {
      hardBudgetExceeded = true; report.status = "budget-limited";
      report.error = { name: "BudgetStop", message: "hard suite deadline reached; terminating only the disposable server" }; checkpoint();
      void closeServer().catch(() => {});
      void Promise.allSettled([...Object.values(clients), root].filter(Boolean).map(db => db.close()));
      hardStop = setTimeout(() => { checkpoint(); process.exit(2); }, 5000); hardStop.unref();
    }, Math.max(1, config["budget-seconds"] * 1000 - (performance.now() - started))); watchdog.unref();
    root = new Surreal(); await root.connect(server.url.replace(/^http/, "ws") + "/rpc");
    await root.signin({ username: "root", password: "root" });
    await root.query("DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;");
    await root.use({ namespace: "temporal_probe", database: "fixture" });
    console.log("Installing the compiled synthetic authorization workload in disposable SurrealKV...");
    await prepare(root, { schema: compiled.bundle });
    const graph = await access.seedGraph(root, { width: config["owner-count"] });
    report.authorization = await access.authorizationCases(root, server.url, graph);
    console.log(`PASS authorization: ${report.authorization.assertions} assertions; ${report.authorization.cases.length} cases`); checkpoint();
    for (const name of ["wide", "sparse", "outsider", "crossTenant", "missingPermission"]) clients[name] = await access.actorConnection(server.url, graph.actors[name]);
    // Cover the slots/aggregate matrix before admitting potentially expensive
    // larger scales, so a resource stop cannot hide the basic write-cost matrix.
    for (const variant of CONFIGS.slice(1)) {
      run.guard(); const n = Math.min(config["variant-rows"], Math.max(...config.scales));
      const input = { ...variant, n, owners: graph.owners, batchRows: config["batch-rows"], seedMode: config["seed-mode"], onProgress: run.guard };
      console.log(`Variant ${variant.slots} slots / ${variant.measures} aggregates, ${n} rows...`);
      await fixture.loadFacts(root, input);
      const integrity = await fixture.verifyFacts(root, input);
      const mutation = await mutations(clients.wide, root, graph, variant, n, run);
      const aggregate_reads = await aggregateReads(clients.wide, graph, variant, n, run);
      report.variants.push({ ...variant, n, integrity, mutation, aggregate_reads }); checkpoint();
    }
    const base = CONFIGS[0];
    let previousRate = null;
    for (const n of config.scales) {
      const remaining = config["budget-seconds"] - (performance.now() - started) / 1000;
      const projection = previousRate == null ? 0 : n / previousRate;
      if (projection > Math.min(config["max-stage-seconds"], remaining * 0.65)) {
        report.skipped_scales.push({ n, reason: "measured full load+verification rate exceeds remaining stage budget", projected_seconds: projection }); checkpoint(); continue;
      }
      run.guard(); console.log(`Scale ${n}: building and verifying ${n * base.slots} real tree memberships...`);
      const stage = { n, slots: base.slots, measures: base.measures, status: "loading" }; report.stages.push(stage); checkpoint();
      let lastProgress = performance.now(); const loadStart = performance.now();
      const input = { ...base, n, owners: graph.owners, batchRows: config["batch-rows"], seedMode: config["seed-mode"], onProgress: async progress => {
        run.guard(); if (performance.now() - lastProgress > 15000) { console.log(`  ${progress.phase || "load"}: ${progress.loaded}/${n}`); lastProgress = performance.now(); }
      } };
      stage.fixture = await fixture.loadFacts(root, input); stage.load_ms = performance.now() - loadStart;
      const verificationStart = performance.now(); stage.integrity = await fixture.verifyFacts(root, input);
      stage.verify_ms = performance.now() - verificationStart;
      previousRate = n * 1000 / (stage.load_ms + stage.verify_ms);
      // Native backlinks must survive loading; a valid pointer image alone is
      // insufficient for authorization graph and ownership repair benchmarks.
      const [backlinks] = await root.query(`RETURN $owner<~(${base.table} FIELD owned_by);`, { owner: graph.owners[0] });
      assert.equal(backlinks.length, Math.ceil(n / graph.owners.length)); stage.reference_backlinks = backlinks.length;
      stage.status = "measuring"; checkpoint();
      console.log(`  Verified ${n} rows: load ${(stage.load_ms / 1000).toFixed(2)}s, validation ${(stage.verify_ms / 1000).toFixed(2)}s; measuring authorization paths...`);
      stage.plans = await queryPlans(clients.wide, root, base.table, graph.owners[0]);
      if (n <= 1000) {
        const owners = graph.owners.filter(owner => access.canAccess(graph, graph.actors.wide, owner));
        const expected = Array.from({ length: n }, (_, seq) => seq).filter(seq => owners.some(owner => String(owner) === String(graph.owners[seq % graph.owners.length])));
        stage.full_cursor_walk = await walkPages(clients.wide, owners, fixture.rootSlot(base.table, "z0"), base.table, expected);
      }
      stage.reads = [];
      for (const name of ["wide", "sparse"]) {
        await reads(clients[name], graph, name, base, n, run, stage.reads); checkpoint();
        console.log(`  ${name}: page comparisons completed`);
      }
      stage.denials = [];
      for (const name of ["outsider", "crossTenant", "missingPermission"]) {
        let nativeStatus = "no-rows";
        try {
          const [rows] = await clients[name].query(`SELECT id FROM ${base.table} LIMIT 1 TIMEOUT ${config["scan-timeout-ms"]}ms;`);
          assert.deepEqual(rows, [], `${name}: no row leakage`);
        } catch (error) { if (!timedOut(error)) throw error; nativeStatus = "server-query-timeout"; }
        await assert.rejects(readPage(clients[name], [graph.owners[0]], fixture.rootSlot(base.table, "z0")), /not allowed|permission/i);
        stage.denials.push({ actor: name, native_status: nativeStatus, inaccessible_custom_root: "rejected" });
      }
      stage.mutations = await mutations(clients.wide, root, graph, base, n, run);
      stage.aggregate_reads = await aggregateReads(clients.wide, graph, base, n, run);
      stage.concurrent_reads = await concurrentReads(server.url, graph, base, n, run);
      stage.concurrent_writes = await concurrentWrites(server.url, root, graph, base, n, run);
      stage.resources = resources(server, pid); stage.status = "passed"; checkpoint();
      console.log(`PASS scale ${n}: authenticated reads, CRUD, candidate completeness, no leaks; load ${(stage.load_ms / 1000).toFixed(2)}s, verify ${(stage.verify_ms / 1000).toFixed(2)}s`);
    }
    report.status = report.skipped_scales.length ? "passed-with-resource-skips" : "passed";
  } catch (error) {
    report.status = error instanceof BudgetStop || hardBudgetExceeded ? "budget-limited" : "failed";
    report.error = { name: error.name, message: error.message, stack: error.stack };
    if (!(error instanceof BudgetStop) && !hardBudgetExceeded) throw error;
    console.log(`RESOURCE STOP: ${error.message}`);
  } finally {
    clearTimeout(watchdog);
    report.duration_seconds = (performance.now() - started) / 1000; report.finished_at = new Date().toISOString(); checkpoint();
    await Promise.all(Object.values(clients).map(db => db.close()));
    try { if (root) await root.close(); } finally { if (server) await closeServer(); compiled.cleanup(); clearTimeout(hardStop); }
  }
  console.log(`Report: ${path.resolve(config.output)} (${report.status})`);
  return report;
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, options, percentiles, CONFIGS };
