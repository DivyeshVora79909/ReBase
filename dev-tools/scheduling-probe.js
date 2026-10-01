#!/usr/bin/env node

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { resolveConfiguration, QUEUE_HORIZON_MS } = require("../config/environment");
const { surrealDuration } = require("../config/runtime-timing");
const { createReconciler } = require("../gateway/reconciler");
const { createRuntime } = require("../gateway/runtime");

const CONTEXT = { namespace: "schedule_probe", database: "probe" };
const BASE_TIME = Date.UTC(2026, 0, 1);

function fakeClock(initial) {
  let now = initial;
  const pending = [];
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  const originalDateNow = Date.now;
  global.setTimeout = (callback, delayMs) => {
    const timer = { callback, delayMs, cancelled: false, unref() {} };
    pending.push(timer);
    return timer;
  };
  global.clearTimeout = (timer) => { if (timer) timer.cancelled = true; };
  Date.now = () => now;
  return {
    pending,
    now: () => now,
    async tick() {
      let timer;
      while ((timer = pending.shift())?.cancelled) {}
      assert(timer, "expected one scheduled reconciliation timer");
      now += timer.delayMs;
      await timer.callback();
      return timer.delayMs;
    },
    restore() {
      global.setTimeout = originalSetTimeout;
      global.clearTimeout = originalClearTimeout;
      Date.now = originalDateNow;
    },
  };
}

function makeFixture({ items, clock, saturated = false }) {
  const byId = new Map(items.map((item) => [item.id, item]));
  const queued = [];
  const horizons = [];
  let cursor = {
    version: 0, table_offset: 0, cursors: {}, high_water: {},
    retention_cursors: {}, retention_high_water: {},
  };
  const store = {
    async load(id) { return byId.get(String(id)) || null; },
    async loadReconciliationCursor() { return structuredClone(cursor); },
    async compareAndSetReconciliationCursor(input) {
      if (input.expectedVersion !== cursor.version) return false;
      cursor = {
        version: cursor.version + 1,
        table_offset: input.tableOffset,
        cursors: structuredClone(input.cursors),
        high_water: structuredClone(input.highWater),
        retention_cursors: structuredClone(input.retentionCursors),
        retention_high_water: structuredClone(input.retentionHighWater),
      };
      return true;
    },
    async pendingPage(tables, options) {
      horizons.push(options.horizon);
      const ids = [];
      const nextCursors = { ...options.cursors };
      const nextHighWater = { ...options.highWater };
      const sorted = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
      for (const table of tables) {
        const remaining = options.pageSize - ids.length;
        if (remaining <= 0) break;
        const upper = nextHighWater[table] || sorted.at(-1)?.id || null;
        if (!upper) { nextCursors[table] = null; continue; }
        nextHighWater[table] = upper;
        const after = nextCursors[table] || null;
        const eligible = sorted.filter((item) => item.dueAt <= clock.now() + QUEUE_HORIZON_MS
          && (!after || item.id.localeCompare(after) > 0)
          && item.id.localeCompare(upper) <= 0);
        const page = eligible.slice(0, remaining);
        ids.push(...page.map((item) => item.id));
        if (!page.length || page.length < remaining || page.at(-1).id === upper) {
          nextCursors[table] = null;
          nextHighWater[table] = null;
        } else {
          nextCursors[table] = page.at(-1).id;
        }
      }
      return { ids, cursors: nextCursors, highWater: nextHighWater };
    },
    async expiredTerminalPage(_tables, options) {
      return { rows: [], cursors: options.cursors, highWater: options.highWater };
    },
    async deleteExpiredTerminalRows() { return []; },
  };
  const handler = { process: "async", async execute() { return { patch: {} }; } };
  const contract = { mode: "queued", events: ["CREATE"], patchFields: [], adapters: [] };
  const handlers = {
    tables: ["work_item"],
    contracts: new Map([["work_item", contract]]),
    get(table) { return table === "work_item" ? handler : null; },
  };
  const runtime = createRuntime({
    stores: { async forContext() { return store; } },
    handlers,
    contracts: handlers.contracts,
    queue: { async publish(envelope, options) {
      if (saturated) return { jobId: "capacity", queued: false, state: "capacity" };
      queued.push({ envelope, options });
      return { jobId: `job-${queued.length}`, queued: true };
    } },
    options: { allowedContexts: [CONTEXT], reconcilePageSize: 100 },
  });
  return { runtime, queued, horizons, cursor: () => cursor };
}

function makeItems(count, dueAt) {
  return Array.from({ length: count }, (_, index) => {
    const suffix = String(index + 1).padStart(3, "0");
    return {
      id: `work_item:item-${suffix}`,
      dueAt,
      execute_at: new Date(dueAt).toISOString(),
      revision: crypto.randomUUID(),
      execution_id: crypto.randomUUID(),
      priority: 50,
    };
  });
}

async function scheduledAdmissionProbe(configuration) {
  const clock = fakeClock(BASE_TIME);
  const fixture = makeFixture({ items: makeItems(1, BASE_TIME + 10 * 60 * 1000), clock });
  const reconciler = createReconciler({ runtime: fixture.runtime, contexts: [CONTEXT], intervalMs: configuration.server.reconcileIntervalMs });
  try {
    reconciler.start();
    await clock.tick();
    assert.equal(fixture.queued.length, 0, "startup scan leaves a task beyond the five-minute horizon in the database");
    assert.equal(fixture.horizons.at(-1), "5m");
    for (let attempt = 0; attempt < 6 && !fixture.queued.length; attempt += 1) await clock.tick();
    assert.equal(fixture.queued.length, 1, "a timer-driven scan admits the task before due time, without a manual reconcile call");
    assert.equal(clock.now(), BASE_TIME + QUEUE_HORIZON_MS);
    assert.equal(fixture.queued[0].options.delayMs, QUEUE_HORIZON_MS);
    assert(fixture.horizons.every((value) => value === "5m"));
  } finally {
    await reconciler.stop();
    clock.restore();
  }
}

async function pageContinuationProbe(configuration) {
  const clock = fakeClock(BASE_TIME);
  const fixture = makeFixture({ items: makeItems(120, BASE_TIME + 2 * 60 * 1000), clock });
  const reconciler = createReconciler({ runtime: fixture.runtime, contexts: [CONTEXT], intervalMs: configuration.server.reconcileIntervalMs });
  try {
    reconciler.start();
    assert.equal(await clock.tick(), 0, "startup reconciliation runs immediately");
    assert.equal(fixture.queued.length, 100);
    assert.equal(fixture.cursor().cursors.work_item, makeItems(120, BASE_TIME)[99].id);
    assert.equal(clock.pending[0].delayMs, 0, "an admitted full page schedules a prompt continuation");
    assert.equal(await clock.tick(), 0);
    assert.equal(fixture.queued.length, 120, "the remaining page is admitted without a full interval delay");
    assert.equal(clock.pending[0].delayMs, configuration.server.reconcileIntervalMs);
  } finally {
    await reconciler.stop();
    clock.restore();
  }
}

async function backpressureProbe(configuration) {
  const clock = fakeClock(BASE_TIME);
  const fixture = makeFixture({ items: makeItems(120, BASE_TIME + 2 * 60 * 1000), clock, saturated: true });
  const reconciler = createReconciler({ runtime: fixture.runtime, contexts: [CONTEXT], intervalMs: configuration.server.reconcileIntervalMs });
  try {
    reconciler.start();
    await clock.tick();
    assert.equal(clock.pending[0].delayMs, configuration.server.reconcileIntervalMs,
      "a full page blocked by queue capacity waits for the regular scan instead of spinning");
  } finally {
    await reconciler.stop();
    clock.restore();
  }
}

async function main() {
  const configuration = resolveConfiguration({});
  assert.equal(QUEUE_HORIZON_MS, 300000);
  assert.equal(configuration.server.reconcileIntervalMs, 60000);
  assert(configuration.server.reconcileIntervalMs < QUEUE_HORIZON_MS);
  assert.equal(surrealDuration(QUEUE_HORIZON_MS), "5m");
  assert.equal(surrealDuration(1000), "1s");
  assert.equal(surrealDuration(1), "1ms");
  assert.throws(() => resolveConfiguration({ REBASE_RECONCILE_INTERVAL_MS: String(QUEUE_HORIZON_MS) }), /shorter than/);
  await scheduledAdmissionProbe(configuration);
  await pageContinuationProbe(configuration);
  await backpressureProbe(configuration);
  console.log("scheduling: timer-driven horizon admission, shared query/queue horizon, full-page continuation, and capacity backoff passed");
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`scheduling: FAIL: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { main };
