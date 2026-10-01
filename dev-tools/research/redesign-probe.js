"use strict";
// Bounded local research. No application configuration, production data, or provider APIs.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const { randomUUID } = require("node:crypto");
const { Queue, Worker } = require("bullmq");
const { start, client } = require("../temporal-tree/harness");

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function distribution(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return { min: sorted[0], median: sorted[Math.floor(sorted.length / 2)], max: sorted.at(-1) };
}
function milliseconds(value) {
  const match = /^([\d.]+)(ns|µs|μs|us|ms|s)$/.exec(value);
  assert(match, `Unexpected SurrealDB duration: ${value}`);
  return Number(match[1]) * { ns: 1e-6, "µs": 1e-3, "μs": 1e-3, us: 1e-3, ms: 1, s: 1000 }[match[2]];
}
// REST represents decimals as strings. These bounded fixtures have small,
// exact final results; this is not a general-purpose decimal transport codec.
function numericResult(value) {
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, numericResult(item)]));
  }
  return typeof value === "string" && /^-?\d+(\.\d+)?$/.test(value) ? Number(value) : value;
}

async function functionCalls({ iterations = 500, samples = 9 } = {}) {
  assert(Number.isInteger(iterations) && iterations >= 2 && iterations <= 1000);
  assert(Number.isInteger(samples) && samples >= 3 && samples <= 15);
  const server = await start({ engine: "surrealkv" });
  const q = client(server.url);
  const timed = async sql => {
    const began = performance.now();
    const response = await fetch(`${server.url}/sql`, {
      method: "POST", signal: AbortSignal.timeout(10000), body: sql,
      headers: { Authorization: `Basic ${Buffer.from("root:root").toString("base64")}`,
        "surreal-ns": "temporal_probe", "surreal-db": "fixture", Accept: "application/json" },
    });
    assert(response.ok, `SurrealDB HTTP ${response.status}`);
    const statements = await response.json();
    for (const statement of statements) assert.equal(statement.status, "OK", String(statement.result));
    const result = statements.at(-1);
    return { value: numericResult(result.result), databaseMs: milliseconds(result.time), wallMs: performance.now() - began };
  };
  try {
    await q(`DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;
      DEFINE FUNCTION fn::probe::arithmetic($i: decimal) { RETURN ($i * 17dec + 3dec) / 10dec; };
      DEFINE FUNCTION fn::probe::step($a: object, $d: decimal) {
        RETURN { sum: $a.sum + $d,
          min_prefix: math::min([$a.min_prefix, $a.sum + $d]),
          max_prefix: math::max([$a.max_prefix, $a.sum + $d]) };
      };`);
    const prefix = `array::range(0, ${iterations})`;
    const initial = "{ sum: 0dec, min_prefix: 0dec, max_prefix: 0dec }";
    const deltas = `${prefix}.map(|$i| IF $i % 2 = 0 THEN <decimal>$i ELSE -<decimal>$i END)`;
    const expectedSummary = { sum: 0, min_prefix: 0, max_prefix: 0 };
    for (let i = 0; i < iterations; i++) {
      expectedSummary.sum += i % 2 === 0 ? i : -i;
      expectedSummary.min_prefix = Math.min(expectedSummary.min_prefix, expectedSummary.sum);
      expectedSummary.max_prefix = Math.max(expectedSummary.max_prefix, expectedSummary.sum);
    }
    const cases = [
      { name: "decimal_arithmetic", expected: (17 * iterations * (iterations - 1) / 2 + 3 * iterations) / 10,
        inline: `RETURN math::sum(${prefix}.map(|$i| (<decimal>$i * 17dec + 3dec) / 10dec));`,
        call: `RETURN math::sum(${prefix}.map(|$i| fn::probe::arithmetic(<decimal>$i)));` },
      { name: "ordered_summary_fold", expected: expectedSummary,
        inline: `RETURN ${deltas}.fold(${initial}, |$a, $d| { sum: $a.sum + $d,
          min_prefix: math::min([$a.min_prefix, $a.sum + $d]),
          max_prefix: math::max([$a.max_prefix, $a.sum + $d]) });`,
        call: `RETURN ${deltas}.fold(${initial}, |$a, $d| fn::probe::step($a, $d));` },
    ];
    const comparisons = [];
    for (const example of cases) {
      for (let warmup = 0; warmup < 2; warmup++) {
        for (const variant of ["inline", "call"]) assert.deepEqual((await timed(example[variant])).value, example.expected);
      }
      const raw = [];
      for (let trial = 0; trial < samples; trial++) {
        const pair = {};
        for (const variant of trial % 2 ? ["call", "inline"] : ["inline", "call"]) {
          const result = await timed(example[variant]);
          assert.deepEqual(result.value, example.expected);
          pair[variant] = { databaseMs: result.databaseMs, wallMs: result.wallMs };
        }
        raw.push(pair);
      }
      comparisons.push({ name: example.name, iterations, samples,
        inlineDatabaseMs: distribution(raw.map(row => row.inline.databaseMs)),
        callDatabaseMs: distribution(raw.map(row => row.call.databaseMs)),
        pairedOverheadMicrosecondsPerCall: distribution(raw.map(row => (row.call.databaseMs - row.inline.databaseMs) * 1000 / iterations)),
        raw });
    }
    return { scope: "Read-only arithmetic and object folds; no trees, write amplification, concurrency, or provider calls.", comparisons };
  } finally { await server.close(); }
}

async function freePort() {
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, "127.0.0.1", resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  return port;
}
async function waitForPort(port, process) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (process.exitCode !== null) throw new Error("Disposable Redis exited during startup");
    const ready = await new Promise(resolve => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      const done = value => { socket.destroy(); resolve(value); };
      socket.once("connect", () => done(true));
      socket.once("error", () => done(false));
      socket.setTimeout(100, () => done(false));
    });
    if (ready) return;
    await sleep(20);
  }
  throw new Error("Disposable Redis startup timed out");
}
async function stopProcess(process) {
  if (process.exitCode !== null || process.signalCode !== null) return;
  const closed = new Promise(resolve => process.once("exit", resolve));
  process.kill("SIGTERM");
  const timer = setTimeout(() => process.kill("SIGKILL"), 2000);
  try { await closed; } finally { clearTimeout(timer); }
}

async function queueSemantics() {
  const port = await freePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-queue-research-"));
  const process = spawn("redis-server", ["--bind", "127.0.0.1", "--port", String(port),
    "--save", "", "--appendonly", "no", "--dir", directory], { stdio: ["ignore", "ignore", "pipe"] });
  let processError;
  process.on("error", error => { processError = error; });
  process.stderr.resume();
  let queue, worker;
  const queueErrors = [];
  try {
    await waitForPort(port, process);
    if (processError) throw processError;
    const connection = { host: "127.0.0.1", port, maxRetriesPerRequest: null };
    queue = new Queue("research", { connection });
    worker = new Worker("research", async () => {}, { connection, autorun: false });
    queue.on("error", error => queueErrors.push(error));
    worker.on("error", error => queueErrors.push(error));
    await Promise.all([queue.waitUntilReady(), worker.waitUntilReady()]);
    for (const [jobId, priority] of [["j-normal", 50], ["j-urgent", 1], ["j-default", 0]]) {
      await queue.add("wake", {}, { jobId, priority, removeOnComplete: true });
    }
    const order = [];
    for (let i = 0; i < 3; i++) {
      const token = randomUUID();
      const job = await worker.getNextJob(token, { block: false });
      assert(job);
      order.push(job.id);
      await job.moveToCompleted(null, token, false);
    }
    assert.deepEqual(order, ["j-default", "j-urgent", "j-normal"]);

    await queue.add("wake", { revision: 1 }, { jobId: "j-duplicate", priority: 50 });
    await queue.add("wake", { revision: 2 }, { jobId: "j-duplicate", priority: 1 });
    const retained = await queue.getJob("j-duplicate");
    assert.equal(retained.data.revision, 1);
    assert.equal(retained.opts.priority, 50);
    assert.equal(await queue.remove("j-duplicate"), 1);
    assert.equal(await queue.remove("j-duplicate"), 1); // BullMQ removal succeeds even if already absent.
    assert.equal(await queue.getJob("j-duplicate"), undefined);

    const delayed = await queue.add("wake", {}, { jobId: "j-delayed", priority: 1, delay: 400, removeOnComplete: true });
    const dueAt = delayed.timestamp + delayed.delay;
    const token = randomUUID();
    assert.equal(await worker.getNextJob(token, { block: false }), undefined);
    let job;
    for (let attempt = 0; attempt < 150; attempt++) {
      job = await worker.getNextJob(token, { block: false });
      if (job) break;
      await sleep(20);
    }
    assert(job, "Delayed work must eventually become eligible");
    const observedAt = Date.now();
    assert(observedAt >= dueAt - 1, "A delayed job must not run before eligibility");
    assert.equal(await queue.remove("j-delayed"), 0, "An active locked job cannot be removed");
    await job.moveToCompleted(null, token, false);
    assert.equal(queueErrors.length, 0, String(queueErrors[0]));
    return { priorityOrder: order, duplicateKeepsOriginal: true, missingRemovalSucceeds: true,
      activeRemovalRejected: true, delayMs: delayed.delay, observedLatenessMs: observedAt - dueAt,
      scope: "One disposable Redis and BullMQ queue; transport behavior only, not runtime durability or throughput." };
  } finally {
    await Promise.allSettled([worker?.close(), queue?.close()]);
    await stopProcess(process);
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

async function run(options = {}) {
  const report = { at: new Date().toISOString(), node: process.version,
    surreal: execFileSync("surreal", ["version"], { encoding: "utf8" }).trim(),
    redis: execFileSync("redis-server", ["--version"], { encoding: "utf8" }).trim(),
    bullmq: require("bullmq/package.json").version };
  report.functionCalls = await functionCalls(options.functionCalls);
  report.queueSemantics = await queueSemantics();
  return report;
}
if (require.main === module) run().then(report => console.log(JSON.stringify(report, null, 2))).catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
module.exports = { run, functionCalls, queueSemantics };
