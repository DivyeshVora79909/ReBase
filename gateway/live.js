'use strict';

// Live messages wake the durable store; the queue never trusts message payloads.
// The bounded set coalesces bursts. Reconciliation recovers every dropped hint.
async function startLiveWakeups({
  store,
  getStore,
  runtime,
  handlers,
  reconciler,
  onError = () => {},
  maxPending = 1000,
  retryDelayMs = 1000,
  maxRetryDelayMs = 30000,
  attachShutdownTimeoutMs = 1000,
}) {
  if (typeof store?.watch !== 'function' && typeof getStore !== 'function') return async () => {};
  if (!Number.isSafeInteger(maxPending) || maxPending < 1) throw new Error('Live pending capacity must be positive');
  if (!Number.isSafeInteger(retryDelayMs) || retryDelayMs < 1
    || !Number.isSafeInteger(maxRetryDelayMs) || maxRetryDelayMs < retryDelayMs) {
    throw new Error('Live retry delays must be positive integers with maxRetryDelayMs >= retryDelayMs');
  }
  if (!Number.isSafeInteger(attachShutdownTimeoutMs) || attachShutdownTimeoutMs < 1) {
    throw new Error('Live attach shutdown timeout must be a positive integer');
  }
  const tables = handlers.tables.filter(table => {
    const contract = handlers.contracts?.get(table) || handlers.get(table)?.contract || {};
    return contract.process === 'async' || contract.mode === 'queued' || contract.mode === 'inline';
  });
  if (!tables.length) return async () => {};
  const pending = new Set();
  let stopped = false;
  let draining = null;
  let recovery = null;
  let activeWatchStop = null;
  let attachPromise = null;
  let retryTimer = null;
  let nextRetryDelayMs = retryDelayMs;
  const reportError = error => {
    try { onError(error); } catch { /* Logging hooks do not control recovery. */ }
  };
  const recover = () => {
    if (stopped || recovery) return;
    recovery = Promise.resolve().then(() => reconciler.run()).catch(reportError).finally(() => { recovery = null; });
  };
  function scheduleRetry() {
    if (stopped || activeWatchStop || attachPromise || retryTimer) return;
    const delayMs = nextRetryDelayMs;
    nextRetryDelayMs = Math.min(maxRetryDelayMs, Math.max(retryDelayMs, delayMs * 2));
    retryTimer = setTimeout(() => {
      retryTimer = null;
      void attachWatch();
    }, delayMs);
    retryTimer.unref?.();
  }
  async function attachWatch() {
    if (stopped || activeWatchStop || attachPromise) return;
    let failed = false;
    const attempt = (async () => {
      try {
        const currentStore = getStore ? await getStore() : store;
        if (stopped) return;
        if (typeof currentStore?.watch !== 'function') throw new Error('Live watch is unavailable from the configured store');
        const stopWatching = await currentStore.watch(tables, id => {
          if (stopped) return;
          if (pending.size >= maxPending && !pending.has(id)) { recover(); return; }
          pending.add(id);
          drain();
        }, recover, error => { reportError(error); recover(); });
        if (typeof stopWatching !== 'function') throw new Error('Store watch did not return a cleanup function');
        if (stopped) {
          await stopWatching();
          return;
        }
        activeWatchStop = stopWatching;
        nextRetryDelayMs = retryDelayMs;
      } catch (error) {
        failed = true;
        if (!stopped) {
          reportError(error);
          // A failed live hint path must not delay durable task recovery.
          recover();
        }
      }
    })();
    attachPromise = attempt;
    try {
      await attempt;
    } finally {
      if (attachPromise === attempt) attachPromise = null;
    }
    if (failed) scheduleRetry();
  }
  function drain() {
    if (draining || stopped) return;
    draining = Promise.resolve().then(async () => {
      while (!stopped && pending.size) {
        const id = pending.values().next().value;
        pending.delete(id);
        try { await runtime.enqueue({ id }); } catch (error) { reportError(error); }
      }
    }).finally(() => { draining = null; if (pending.size && !stopped) drain(); });
  }
  await attachWatch();
  return async () => {
    stopped = true;
    pending.clear();
    if (retryTimer) clearTimeout(retryTimer);
    retryTimer = null;
    // ManagedLivePromise has no abort signal. Let an in-flight attach finish
    // long enough to run its stopped-path cleanup, but bound server shutdown;
    // if it resolves later, attachWatch still kills the returned subscription.
    const pendingAttach = attachPromise;
    if (pendingAttach) {
      let timer;
      try {
        await Promise.race([pendingAttach, new Promise(resolve => {
          timer = setTimeout(resolve, attachShutdownTimeoutMs);
        })]);
      } finally {
        clearTimeout(timer);
      }
    }
    const stopWatching = activeWatchStop;
    activeWatchStop = null;
    await stopWatching?.();
    await draining;
    await recovery;
  };
}

module.exports = { startLiveWakeups };
