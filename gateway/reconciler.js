const { LANES } = require("./queues/port");

function normalizeContexts(contexts = []) {
  const map = new Map();
  for (const context of contexts) {
    if (!context?.namespace || !context?.database) throw new Error("Reconciliation contexts require namespace and database");
    map.set(`${context.namespace}\u0000${context.database}`, {
      namespace: String(context.namespace),
      database: String(context.database),
    });
  }
  return [...map.values()];
}

function createReconciler({
  runtime,
  contexts = [],
  lanes = LANES,
  intervalMs = 30 * 60 * 1000,
  onError,
} = {}) {
  if (!runtime?.reconcile) throw new Error("Reconciler requires a runtime");
  const selectedContexts = normalizeContexts(contexts);
  const selectedLanes = [...new Set(lanes)];
  if (selectedLanes.some((lane) => !LANES.includes(lane))) throw new Error("Reconciler received an invalid lane");
  if (!Number.isFinite(intervalMs) || intervalMs < 1000) throw new Error("Reconciliation interval must be at least one second");
  let timer = null;
  let stopped = false;
  let active = null;

  async function run({ deep = false } = {}) {
    if (active) return active;
    active = (async () => {
      const results = [];
      for (const context of selectedContexts) {
        for (const lane of selectedLanes) {
          try {
            results.push({
              context,
              lane,
              result: await runtime.reconcile({ ...context, lane, deep: deep || lane === "schedule" }),
            });
          } catch (error) {
            onError?.(error, { context, lane });
            results.push({ context, lane, error: error.message });
          }
        }
      }
      return results;
    })().finally(() => { active = null; });
    return active;
  }

  function schedule(delayMs, deep = false) {
    if (stopped || !selectedContexts.length) return;
    timer = setTimeout(async () => {
      timer = null;
      await run({ deep });
      schedule(intervalMs, false);
    }, delayMs);
    timer.unref?.();
  }

  function start({ immediate = true } = {}) {
    if (timer || stopped) throw new Error("Reconciler is already started or stopped");
    schedule(immediate ? 0 : intervalMs, immediate);
    return stop;
  }

  async function stop() {
    stopped = true;
    if (timer) clearTimeout(timer);
    timer = null;
    await active;
  }

  return { contexts: selectedContexts, lanes: selectedLanes, run, start, stop };
}

module.exports = { createReconciler, normalizeContexts };
