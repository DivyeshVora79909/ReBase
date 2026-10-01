const { DEFAULT_RECONCILE_INTERVAL_MS } = require("../config/runtime-timing");

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
  intervalMs = DEFAULT_RECONCILE_INTERVAL_MS,
  onError,
} = {}) {
  if (!runtime?.reconcile) throw new Error("Reconciler requires a runtime");
  const selectedContexts = normalizeContexts(contexts);
  if (!Number.isFinite(intervalMs) || intervalMs < 1000) throw new Error("Reconciliation interval must be at least one second");
  let timer = null;
  let stopped = false;
  let active = null;

  async function run() {
    if (active) return active;
    active = (async () => {
      const results = [];
      for (const context of selectedContexts) {
        try {
          results.push({ context, result: await runtime.reconcile(context) });
        } catch (error) {
          onError?.(error, { context });
          results.push({ context, error: error.message });
        }
      }
      return results;
    })().finally(() => { active = null; });
    return active;
  }

  function schedule(delayMs) {
    if (stopped || !selectedContexts.length) return;
    timer = setTimeout(async () => {
      timer = null;
      const results = await run();
      const hasUnblockedNextPage = results.some(({ error, result }) => (
        !error
        && result?.morePending === true
        && (!Array.isArray(result.deferred) || result.deferred.length === 0)
      ));
      schedule(hasUnblockedNextPage ? 0 : intervalMs);
    }, delayMs);
    timer.unref?.();
  }

  function start({ immediate = true } = {}) {
    if (timer || stopped) throw new Error("Reconciler is already started or stopped");
    schedule(immediate ? 0 : intervalMs);
    return stop;
  }

  async function stop() {
    stopped = true;
    if (timer) clearTimeout(timer);
    timer = null;
    await active;
  }

  return { contexts: selectedContexts, run, start, stop };
}

module.exports = { createReconciler, normalizeContexts };
