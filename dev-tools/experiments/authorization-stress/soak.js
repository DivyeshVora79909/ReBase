"use strict";

const assert = require("node:assert/strict");
const { performance } = require("node:perf_hooks");
const { RecordId, Decimal } = require("surrealdb");
const access = require("./access");
const { readPage } = require("./paging");
const { rootSlot } = require("./fixture");

const transaction = `BEGIN TRANSACTION;
LET $created = CREATE ONLY $id CONTENT $content;
LET $payload = UPDATE ONLY $id SET payload='soak payload edit' RETURN AFTER;
LET $amount = UPDATE ONLY $id SET amount=2 RETURN AFTER;
LET $rekeyed = UPDATE ONLY $id SET rank=100000002 RETURN AFTER;
LET $moved = UPDATE ONLY $id SET owned_by=$other RETURN AFTER;
-- RETURN AFTER precedes nested event settlement; read the transaction's stored row.
LET $settled = SELECT * FROM ONLY $id;
LET $deleted = DELETE ONLY $id RETURN BEFORE;
IF $created.id != $id { THROW 'SOAK_CREATE_ID'; };
IF $created.rank != 100000001 { THROW 'SOAK_CREATE_RANK'; };
IF $created.amount != 1 { THROW 'SOAK_CREATE_AMOUNT'; };
IF $payload.payload != 'soak payload edit' { THROW 'SOAK_PAYLOAD_UPDATE'; };
IF $amount.amount != 2 { THROW 'SOAK_AMOUNT_UPDATE'; };
IF $rekeyed.rank != 100000002 { THROW 'SOAK_REKEY'; };
IF $moved.owned_by != $other { THROW 'SOAK_MOVE_RETURN_OWNER'; };
IF $settled.owned_by != $other { THROW 'SOAK_MOVE_STORED_OWNER'; };
IF $settled.read_by != $other { THROW 'SOAK_MOVE_STORED_READER'; };
IF $deleted.id != $id { THROW 'SOAK_DELETE_ID'; };
IF $deleted.read_by != $other { THROW 'SOAK_DELETE_READER'; };
COMMIT TRANSACTION;`;

// Synthetic measures are exact integers well inside JavaScript's transport range.
function plain(value) {
  if (value instanceof Decimal) { const n = Number(value); assert(Number.isSafeInteger(n)); return n; }
  if (value instanceof RecordId) return String(value);
  if (Array.isArray(value)) return value.map(plain);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
  return value;
}
function stats(samples, elapsedMs) {
  const sorted = [...samples].sort((a, b) => a - b);
  return { sample_count: samples.length, samples_ms: samples, throughput_ops_s: samples.length * 1000 / elapsedMs,
    p50_ms: sorted[Math.max(0, Math.ceil(sorted.length * 0.5) - 1)] ?? null,
    p95_ms: sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? null };
}
async function atomic(db, variables) {
  // Retain the actual conflict instead of an earlier transaction-cancelled reply.
  const replies = await db.query(transaction, variables).responses();
  const errors = replies.filter(reply => !reply.success).map(reply => reply.error);
  if (errors.length) throw new AggregateError(errors, errors.map(error => error.message).join("\n"));
}

async function soak({ endpoint, root, graph, config, n, seconds = 30, guard = () => {} }) {
  assert(["127.0.0.1", "localhost", "[::1]"].includes(new URL(endpoint).hostname), "soak requires a disposable loopback endpoint");
  assert(Number.isFinite(seconds) && seconds > 0);
  assert(Number.isSafeInteger(n) && n > 0 && Math.floor((n - 1) / 3) < 100000001);
  assert(Number.isSafeInteger(config.slots) && config.slots > 0);
  const { table, slots } = config, owners = graph.owners.filter(owner => access.canAccess(graph, graph.actors.wide, owner));
  assert.match(table, /^stress_[a-z0-9_]+$/, "soak is restricted to the synthetic workload");
  const pair = graph.owners.slice(0, 2);
  assert.equal(pair.length, 2);
  assert(pair.every(owner => access.canAccess(graph, graph.actors.wide, owner)), "both scratch owners must be accessible");
  const ownerSet = new Set(owners.map(String)), expected = [];
  for (let seq = 0; seq < n && expected.length < 50; seq++) if (ownerSet.has(String(graph.owners[seq % graph.owners.length]))) {
    expected.push(String(new RecordId(table, `r${String(seq).padStart(10, "0")}`)));
  }
  assert(expected.length, "baseline must contain authorized rows");
  const point = new RecordId(table, expected[0].split(":")[1]);
  assert(!access.canAccess(graph, graph.actors.outsider, graph.owners[0]), "point denial needs an inaccessible owner");
  const scratch = [0, 1].map(i => new RecordId(table, `soak_writer_${i}`));
  const connections = [], writerSamples = [[], []], readerSamples = Array.from({ length: 2 }, () => ({ page: [], point: [], denial: [] }));
  const writers = [0, 1].map(() => ({ committed: 0, conflicts: 0, retries: 0, exhausted: 0, deadline_interrupted: 0 }));
  let stopped = false;
  try {
    guard();
    const [existing] = await root.query("SELECT VALUE id FROM $ids;", { ids: scratch });
    assert.deepEqual(existing, [], "scratch IDs must start absent");
    const [before] = await root.query("SELECT * FROM $owners;", { owners: pair });
    assert.equal(before.length, pair.length, "both baseline root owners must exist");
    for (let i = 0; i < 4; i++) connections.push(await access.actorConnection(endpoint, graph.actors.wide));
    connections.push(await access.actorConnection(endpoint, graph.actors.outsider));
    const began = performance.now(), deadline = began + seconds * 1000;
    const active = () => !stopped && performance.now() < deadline;
    const worker = action => (async () => {
      try { while (active()) { guard(); await action(); } }
      catch (error) { stopped = true; throw error; }
    })();
    const write = index => worker(async () => {
      const started = performance.now(), state = writers[index];
      for (let attempt = 1; attempt <= 4; attempt++) {
        if (!active()) { state.deadline_interrupted++; return; }
        guard();
        if (attempt > 1) state.retries++;
        try {
          await atomic(connections[index], { id: scratch[index], other: pair[1], content: {
            owned_by: pair[0], seq: n + index, rank: 100000001, amount: 1,
            status: "hot", payload: "soak native create" } });
          state.committed++; writerSamples[index].push(performance.now() - started); return;
        } catch (error) {
          if (!/\bconflict\b|transaction[^\n]*(?:retry|concurrent)|can be retried/i.test(String(error))) throw error;
          state.conflicts++;
          if (attempt === 4) state.exhausted++;
        }
      }
    });
    const read = index => worker(async () => {
      const sample = readerSamples[index], db = connections[index + 2];
      let start = performance.now();
      const page = await readPage(db, owners, rootSlot(table, "z0"), { limit: expected.length });
      assert.deepEqual(page.rows.map(row => String(row.id)), expected, "stable authorized baseline prefix");
      sample.page.push(performance.now() - start);
      if (!active()) return;
      guard(); start = performance.now();
      const [allowed] = await db.query("SELECT VALUE id FROM $id;", { id: point });
      assert.deepEqual(allowed.map(String), [String(point)], "native point read must return the expected baseline ID");
      sample.point.push(performance.now() - start);
      if (!active()) return;
      guard(); start = performance.now();
      const [denied] = await connections[4].query("SELECT VALUE id FROM $id;", { id: point });
      assert.deepEqual(denied, [], "outsider point read must reveal no row");
      sample.denial.push(performance.now() - start);
    });
    const outcomes = await Promise.allSettled([write(0), write(1), read(0), read(1)]);
    const elapsedMs = performance.now() - began;
    for (const outcome of outcomes) if (outcome.status === "rejected") throw outcome.reason;
    assert(writers.every(writer => writer.committed > 0), "both writers must make committed progress");
    assert(readerSamples.every(samples => Object.values(samples).every(values => values.length > 0)), "both readers must exercise every path");
    const [remaining] = await root.query("SELECT VALUE id FROM $ids;", { ids: scratch });
    assert.deepEqual(remaining, [], "atomic scratch lifecycles must leave no records");
    const [after] = await root.query("SELECT * FROM $owners;", { owners: pair });
    assert.equal(after.length, pair.length, "both root owners must survive the soak");
    const afterById = new Map(after.map(row => [String(row.id), row]));
    for (const owner of before) for (let s = 0; s < slots; s++) {
      const field = rootSlot(table, `z${s}`), restored = afterById.get(String(owner.id))[field];
      assert.deepEqual(plain(restored.summary), plain(owner[field].summary), "soak restores exact root summaries");
      assert(restored.revision > owner[field].revision, "committed lifecycles must advance both root revisions");
    }
    return { requested_seconds: seconds, elapsed_seconds: elapsedMs / 1000, writer_clients: 2, reader_clients: 2, outsider_clients: 1,
      writers: writers.map((writer, i) => ({ ...writer, ...stats(writerSamples[i], elapsedMs), native_operations: writer.committed * 6 })),
      readers: readerSamples.map(samples => Object.fromEntries(Object.entries(samples).map(([path, values]) => [path, stats(values, elapsedMs)]))),
      integrity: { scratch_absent: true, restored_root_summaries: pair.length * slots, root_revisions_advanced: true } };
  } finally { stopped = true; await Promise.allSettled(connections.map(db => db.close())); }
}

module.exports = { soak };
