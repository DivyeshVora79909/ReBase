import { performance } from 'node:perf_hooks';

const DEFAULT_PROFILE = Object.freeze({
  durationMs: 300_000,
  maxActions: 10_000,
  ratePerSecond: 100,
  concurrency: 1,
  maxPending: 1,
  maxObservations: 10_000,
  maxArtifactBytes: 16 * 1024 * 1024,
  sampleIntervalMs: 1_000,
});
const PROFILE_CEILINGS = Object.freeze({
  durationMs: 86_400_000,
  ratePerSecond: 100_000,
  maxActions: 100_000,
  concurrency: 256,
  maxPending: 256,
  maxObservations: 100_000,
  maxArtifactBytes: 64 * 1024 * 1024,
  sampleIntervalMs: 86_400_000,
});

/** Run an ordinary async-iterable scenario with finite admission and retention. */
export async function runWorkload({ scenario, state, profile = {}, signal, observe, identity = {} } = {}) {
  if (typeof scenario !== 'function') throw new TypeError('scenario must be an async-iterable factory');
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('signal must be an AbortSignal');
  if (observe !== undefined && typeof observe !== 'function') throw new TypeError('observe must be a function');
  const limits = validateProfile(profile);
  const controller = new AbortController();
  const abortFromCaller = () => controller.abort(signal.reason ?? new Error('caller cancelled workload'));
  if (signal?.aborted) abortFromCaller();
  else signal?.addEventListener('abort', abortFromCaller, { once: true });
  const start = performance.now();
  const deadline = start + limits.durationMs;
  const rows = [];
  const rowBytes = [];
  const active = new Map();
  const ids = new Set();
  const costs = { generationMs: 0, setupMs: finiteOptional(profile.setupMs), rpcMs: 0, queueMs: 0, observationMs: 0, nativeMs: null, checkerMs: null };
  let retainedBytes = 0;
  let sampleBytes = 0;
  let reservedBytes = 0;
  let offered = 0;
  let completed = 0;
  let failed = 0;
  let droppedObservations = 0;
  let droppedActions = 0;
  let droppedSamples = 0;
  let droppedResults = 0;
  let unresolved = 0;
  let iterator = null;
  let exhausted = false;
  let timedOut = false;
  let sampleTimer = null;
  let samplerPending = false;
  let samplerTask = null;
  let samplerUnresolved = false;
  let iteratorUnresolved = false;
  let iteratorCleanupUnresolved = false;
  let cancelledResultResolve;
  const cancelledResult = new Promise(resolve => { cancelledResultResolve = resolve; });
  controller.signal.addEventListener('abort', () => cancelledResultResolve({ cancelled: true }), { once: true });
  let lastOfferAt = null;
  let deadlineTimer;
  const deadlineResult = new Promise(resolve => { deadlineTimer = setTimeout(() => resolve({ timeout: true }), limits.durationMs); });
  const samples = [];
  const maxSamples = Math.min(100_000, Math.ceil(limits.durationMs / limits.sampleIntervalMs) + 2);
  const retain = (row) => {
    let encoded;
    try { encoded = JSON.stringify(row); } catch { droppedObservations += 1; if (row.action === true) droppedActions += 1; return; }
    const bytes = Buffer.byteLength(encoded);
    if (rows.length >= limits.maxObservations || retainedBytes + sampleBytes + reservedBytes + bytes > limits.maxArtifactBytes) {
      droppedObservations += 1;
      if (row.action === true) droppedActions += 1;
      return;
    }
    retainedBytes += bytes;
    rowBytes.push(bytes);
    rows.push(JSON.parse(encoded));
  };
  const retainSample = sample => {
    let encoded;
    try { encoded = JSON.stringify(sample); } catch { droppedSamples += 1; return; }
    const bytes = Buffer.byteLength(encoded);
    if (samples.length >= maxSamples || retainedBytes + sampleBytes + reservedBytes + bytes > limits.maxArtifactBytes) { droppedSamples += 1; return; }
    sampleBytes += bytes;
    samples.push(JSON.parse(encoded));
  };
  const finalizeAction = (item, row) => {
    reservedBytes -= item.reservationSlack;
    const previousBytes = rowBytes[item.rowIndex];
    retainedBytes -= previousBytes;
    let encoded;
    try { encoded = JSON.stringify(row); } catch { encoded = undefined; }
    const available = limits.maxArtifactBytes - retainedBytes - sampleBytes - reservedBytes;
    if (encoded === undefined || Buffer.byteLength(encoded) > available) {
      if (row.status === 'completed') {
        row = { ...row, value: null, resultTruncated: true };
        droppedResults += 1;
      }
      encoded = JSON.stringify(row);
    }
    const bytes = Buffer.byteLength(encoded);
    if (bytes > available) {
      // Admission reserved this exact intent plus terminal metadata. This is a
      // defensive invariant guard; mutation dispatch must never lose its plan.
      row = { action: true, id: item.action.id, kind: item.action.kind, mutation: item.action.mutation === true,
        request: item.request, status: 'unresolved', value: null, error: null,
        queueMs: item.queueMs, elapsedMs: 0, outcomeUnknown: item.action.mutation === true };
      encoded = JSON.stringify(row);
    }
    rows[item.rowIndex] = JSON.parse(encoded);
    rowBytes[item.rowIndex] = Buffer.byteLength(encoded);
    retainedBytes += rowBytes[item.rowIndex];
  };
  const takeSample = async () => {
    if (!observe || samplerPending || samples.length >= maxSamples || controller.signal.aborted) return;
    samplerPending = true;
    const atMs = Math.max(0, performance.now() - start);
    const began = performance.now();
    try {
      const samplePromise = Promise.resolve().then(() => observe({ atMs, state, signal: controller.signal }));
      const sampled = await Promise.race([samplePromise.then(value => ({ value }), error => ({ error })), deadlineResult, cancelledResult]);
      if (sampled?.timeout) {
        samplerUnresolved = true;
        timedOut = true;
        if (!controller.signal.aborted) controller.abort(new Error('resource sampler exceeded the workload deadline'));
        return;
      }
      if (sampled?.cancelled) { samplerUnresolved = true; return; }
      if (sampled?.error) throw sampled.error;
      const value = sampled.value;
      retainSample({ atMs, status: 'observed', value: boundedValue(value, limits.maxArtifactBytes) });
    } catch (error) {
      retainSample({ atMs, status: 'failed', error: errorRecord(error) });
    } finally {
      costs.observationMs += performance.now() - began;
      samplerPending = false;
    }
  };
  const timer = observe ? setInterval(() => {
    if (samplerTask) return;
    const task = takeSample();
    samplerTask = task;
    void task.finally(() => { if (samplerTask === task) samplerTask = null; });
  }, limits.sampleIntervalMs) : null;
  sampleTimer = timer;
  let nextPending = null;
  try {
    let source;
    const genStart = performance.now();
    try {
      const created = Promise.resolve().then(() => scenario({ state, signal: controller.signal, profile: Object.freeze({ ...limits }) }));
      const startedScenario = await Promise.race([created.then(value => ({ value }), error => ({ error })), deadlineResult, cancelledResult]);
      if (startedScenario.cancelled) throw new Error('workload cancelled during scenario setup');
      if (startedScenario.timeout) { timedOut = true; controller.abort(new Error('workload duration limit reached')); throw new Error('scenario startup exceeded workload duration'); }
      if (startedScenario.error) throw startedScenario.error;
      source = startedScenario.value;
      iterator = source?.[Symbol.asyncIterator]?.();
      if (!iterator || typeof iterator.next !== 'function') throw new TypeError('scenario must return an AsyncIterable');
    } finally {
      costs.generationMs += performance.now() - genStart;
    }
    while (!controller.signal.aborted && performance.now() < deadline) {
      while (active.size < limits.concurrency && offered < limits.maxActions && !exhausted && performance.now() < deadline) {
        const queuedAt = performance.now();
        const intervalMs = 1000 / limits.ratePerSecond;
        if (lastOfferAt !== null) {
          const waitMs = intervalMs - (queuedAt - lastOfferAt);
          if (waitMs > 0) {
            const wait = cancellableDelay(Math.min(waitMs, deadline - performance.now(), 2_147_483_647));
            const rateWait = await Promise.race([wait.promise.then(() => ({ elapsed: true })), deadlineResult, cancelledResult]);
            wait.cancel();
            if (rateWait?.cancelled) break;
            if (rateWait?.timeout) { timedOut = true; controller.abort(new Error('workload duration limit reached')); break; }
          }
        }
        const offeredAt = performance.now();
        lastOfferAt = offeredAt;
        const pull = Promise.resolve().then(() => iterator.next());
        nextPending = pull;
        const step = await Promise.race([pull.then(value => ({ value }), error => ({ error })), deadlineResult, cancelledResult]);
        if (step?.value || step?.error) nextPending = null;
        costs.generationMs += Math.max(0, performance.now() - offeredAt);
        if (step.cancelled) break;
        if (step.timeout) { timedOut = true; controller.abort(new Error('workload duration limit reached')); break; }
        if (step.error) throw step.error;
        if (step.value.done) { exhausted = true; break; }
        const action = step.value.value;
        validateAction(action, ids);
        if (action.mutation === true && action.request === undefined) throw new TypeError('mutating actions must retain their exact request descriptor');
        const request = action.request === undefined ? null : deepFreeze(boundedValue(action.request, limits.maxArtifactBytes));
        offered += 1;
        const id = action.id;
        const queueMs = Math.max(0, performance.now() - queuedAt);
        const reservationRow = { action: true, id: action.id, kind: action.kind, mutation: action.mutation === true,
          request, status: 'unresolved', value: null, error: null, queueMs, elapsedMs: 0,
          outcomeUnknown: action.mutation === true };
        const reservationBytes = Buffer.byteLength(JSON.stringify(reservationRow));
        const reservationSlack = 64;
        if (rows.length >= limits.maxObservations || retainedBytes + sampleBytes + reservedBytes + reservationBytes + reservationSlack > limits.maxArtifactBytes) {
          droppedObservations += 1; droppedActions += 1;
          controller.abort(new Error('workload artifact bound cannot retain another action intent'));
          break;
        }
        const rowIndex = rows.length;
        rows.push(reservationRow); rowBytes.push(reservationBytes); retainedBytes += reservationBytes;
        reservedBytes += reservationSlack;
        const began = performance.now();
        let settled = false;
        const task = Promise.resolve().then(() => action.run({ state, signal: controller.signal })).then(
          value => ({ status: 'completed', value, elapsedMs: Math.max(0, performance.now() - began) }),
          error => ({ status: 'failed', error: errorRecord(error), elapsedMs: Math.max(0, performance.now() - began) }),
        ).then(result => {
          settled = true;
          return result;
        });
        const observedTask = Promise.race([task, deadlineResult, cancelledResult].map(promise => promise.then(value =>
          value?.timeout || value?.cancelled ? ({ status: 'unresolved', elapsedMs: Math.max(0, performance.now() - began) }) : value)));
        active.set(id, { task, observedTask, action, request, began, queueMs, reservationSlack, rowIndex, get settled() { return settled; } });
        if (active.size >= limits.maxPending) break;
      }
      if (controller.signal.aborted || performance.now() >= deadline) { timedOut ||= !controller.signal.aborted; break; }
      if (active.size === 0) {
        if (exhausted || offered >= limits.maxActions) break;
        continue;
      }
      const settled = await Promise.race([...active.values()].map(item => item.observedTask));
      const entry = [...active.entries()].find(([, item]) => item.settled || item.observedTask === settled);
      // Match completed tasks by settled state; timeouts are handled below as an
      // admission stop, since Promise.race returns a fresh object.
      const completedEntry = [...active.entries()].find(([, item]) => item.settled);
      if (completedEntry) {
        const [id, item] = completedEntry;
        active.delete(id);
        const result = await item.task;
        costs.queueMs += item.queueMs;
        costs.rpcMs += result.elapsedMs;
        if (result.status === 'failed') failed += 1;
        else completed += 1;
        const row = { action: true, id, kind: item.action.kind, mutation: item.action.mutation === true,
          request: item.request,
          status: result.status, value: result.status === 'completed' ? result.value : null,
          error: result.status === 'failed' ? result.error : null, queueMs: item.queueMs, elapsedMs: result.elapsedMs,
          outcomeUnknown: result.status === 'failed' && item.action.mutation === true };
        finalizeAction(item, row);
      } else if (settled?.status === 'unresolved') {
        timedOut = true;
        controller.abort(new Error('workload duration limit reached'));
        break;
      } else if (entry) {
        // A completion raced before its bookkeeping continuation.
        await Promise.resolve();
      }
    }
    if (iterator && !exhausted) {
      controller.abort(new Error('workload stopped at a declared bound'));
      iteratorCleanupUnresolved = !(await closeIterator(iterator));
    }
  } catch (error) {
    failed += 1;
    controller.abort(new Error('scenario failed; stop admission and preserve unresolved operations'));
    if (iterator && !exhausted) {
      iteratorCleanupUnresolved = !(await closeIterator(iterator));
    }
    retain({ action: false, id: 'scenario', kind: 'scenario', mutation: false, request: null,
      status: 'failed', value: null, error: errorRecord(error), queueMs: 0,
      elapsedMs: Math.max(0, performance.now() - start), outcomeUnknown: false });
  } finally {
    if (sampleTimer) clearInterval(sampleTimer);
    if (samplerPending) {
      const naturalFinish = exhausted && !controller.signal.aborted && !timedOut;
      if (naturalFinish && samplerTask) {
        const drained = await Promise.race([
          samplerTask.then(() => ({ drained: true })), deadlineResult, cancelledResult,
        ]);
        if (!drained?.drained) {
          samplerUnresolved = true;
          if (drained?.timeout) {
            timedOut = true;
            controller.abort(new Error('resource sampler exceeded the workload deadline'));
          }
        }
      } else {
        samplerUnresolved = true;
      }
      if (samplerPending) samplerUnresolved = true;
    }
    clearTimeout(deadlineTimer);
    if (signal) signal.removeEventListener('abort', abortFromCaller);
    if (controller.signal.aborted) {
      for (const [id, item] of active) {
        if (item.settled) {
          const result = await item.task;
          if (result.status === 'failed') failed += 1;
          else completed += 1;
          costs.rpcMs += result.elapsedMs;
          const row = { action: true, id, kind: item.action.kind, mutation: item.action.mutation === true,
            request: item.request, status: result.status,
            value: result.status === 'completed' ? result.value : null,
            error: result.status === 'failed' ? result.error : null, queueMs: item.queueMs,
            elapsedMs: result.elapsedMs, outcomeUnknown: result.status === 'failed' && item.action.mutation === true };
          finalizeAction(item, row);
        } else {
          unresolved += 1;
          finalizeAction(item, { action: true, id, kind: item.action.kind, mutation: item.action.mutation === true,
            request: item.request,
            status: 'unresolved', value: null, error: null, queueMs: item.queueMs,
            elapsedMs: Math.max(0, performance.now() - item.began), outcomeUnknown: item.action.mutation === true });
        }
      }
      if (nextPending) {
        unresolved += 1;
        iteratorUnresolved = true;
        retain({ action: false, id: 'scenario-iterator', kind: 'scenario', mutation: false,
          request: null, status: 'unresolved', value: null, error: null, queueMs: 0,
          elapsedMs: Math.max(0, performance.now() - start), outcomeUnknown: false });
      }
    }
  }
  const elapsedMs = Math.max(0, performance.now() - start);
  const complete = exhausted && !controller.signal.aborted && unresolved === 0 && !samplerUnresolved
    && !iteratorUnresolved && !iteratorCleanupUnresolved
    && droppedObservations === 0 && droppedSamples === 0 && droppedResults === 0 && failed === 0
    && samples.every(sample => sample.status === 'observed') && (!observe || samples.length > 0);
  return Object.freeze({
    format: 'rebase-node-workload-1', status: complete ? 'complete' : 'incomplete', observerEnabled: Boolean(observe),
    identity: deepFreeze(boundedValue(identity, limits.maxArtifactBytes)), profile: Object.freeze({ ...limits }),
    limits: Object.freeze({ ...limits }), durationMs: elapsedMs, durationLimitMs: limits.durationMs,
    offered, completed, failed, unresolved, exhausted, timedOut, cancelled: controller.signal.aborted,
    iteratorUnresolved, iteratorCleanupUnresolved,
    observations: deepFreeze(rows), samples: deepFreeze(samples), retainedBytes: retainedBytes + sampleBytes,
    dropped: droppedObservations + droppedSamples + droppedResults, droppedObservations, droppedActions, droppedSamples, droppedResults,
    costs: Object.freeze({ ...costs, nativeMs: null }),
  });
}

/** Independently check retained raw observations with a caller source oracle. */
export async function checkRun({ run, oracle, maxChecks = 100_000 } = {}) {
  if (!run || run.format !== 'rebase-node-workload-1' || !Array.isArray(run.observations)) throw new TypeError('run must be a retained workload report');
  if (typeof oracle !== 'function') throw new TypeError('oracle must be an independent source-only function');
  positiveInteger(maxChecks, 'maxChecks');
  const started = performance.now();
  const obligations = [];
  const seen = new Set();
  let rawCompleted = 0;
  let rawFailed = 0;
  let rawUnresolved = 0;
  let rawActions = 0;
  if (run.observations.length > maxChecks) return checkResult('incomplete', [{ name: 'observation-limit', status: 'incomplete', reason: 'retained observations exceed checker limit' }], started);
  for (let index = 0; index < run.observations.length; index += 1) {
    const observation = run.observations[index];
    if (!observation || typeof observation.id !== 'string' || seen.has(observation.id)) {
      obligations.push({ name: `observation-${index}-identity`, status: 'failed', reason: 'missing or repeated action identity' });
      continue;
    }
    seen.add(observation.id);
    if (!['completed', 'failed', 'unresolved'].includes(observation.status)) {
      obligations.push({ name: `action-${observation.id}`, status: 'failed', reason: 'unknown raw observation status' });
      continue;
    }
    if (observation.status === 'completed') rawCompleted += 1;
    if (observation.status === 'failed') rawFailed += 1;
    if (observation.status === 'unresolved') rawUnresolved += 1;
    if (observation.action === true) rawActions += 1;
    if (observation.status === 'unresolved' || observation.outcomeUnknown) {
      obligations.push({ name: `action-${observation.id}`, status: 'incomplete', reason: 'original action outcome is unresolved' });
    }
  }
  if (rawCompleted !== run.completed || rawFailed !== run.failed || rawUnresolved !== run.unresolved
    || run.offered !== rawActions + run.droppedActions
    || run.dropped !== run.droppedObservations + run.droppedSamples + (run.droppedResults ?? 0)) {
    obligations.push({ name: 'raw-counts', status: 'failed', reason: 'summary counts do not match retained observations and truncation counts' });
  }
  if (run.status !== 'complete' || run.dropped !== 0 || rawUnresolved !== 0
    || run.cancelled !== false || run.timedOut !== false || run.exhausted !== true
    || run.unresolved !== 0 || run.failed !== 0 || run.completed !== run.offered
    || run.iteratorUnresolved === true || run.iteratorCleanupUnresolved === true
    || (run.droppedResults ?? 0) !== 0 || run.observations.some(row => row.resultTruncated === true)
    || run.samples?.some(sample => sample.status !== 'observed') || (run.observerEnabled && run.samples.length === 0)) {
    obligations.push({ name: 'run-completeness', status: 'incomplete', reason: 'run is incomplete, truncated, unresolved, or has a failed sample' });
  }
  try {
    const result = await oracle(Object.freeze({
      observations: deepFreeze(structuredClone(run.observations)),
      samples: deepFreeze(structuredClone(run.samples ?? [])),
      profile: deepFreeze(structuredClone(run.profile)),
      identity: deepFreeze(structuredClone(run.identity)),
    }));
    const checks = Array.isArray(result) ? result : [{ name: 'source-oracle', status: result === true ? 'passed' : 'failed', reason: result === true ? undefined : 'source oracle rejected retained raw observations' }];
    for (const check of checks) {
      if (!check || typeof check.name !== 'string' || !['passed', 'failed', 'incomplete'].includes(check.status)) throw new TypeError('oracle must return named passed/failed/incomplete obligations');
      obligations.push({ name: check.name, status: check.status, ...(check.reason === undefined ? {} : { reason: String(check.reason) }) });
    }
  } catch (error) {
    obligations.push({ name: 'source-oracle', status: 'failed', reason: errorRecord(error).message });
  }
  return checkResult(aggregate(obligations), obligations, started);
}

function checkResult(status, obligations, started) {
  return Object.freeze({ status, obligations: Object.freeze(obligations.map(item => Object.freeze(item))),
    costs: Object.freeze({ checkerMs: Math.max(0, performance.now() - started) }) });
}

function aggregate(rows) {
  if (rows.some(row => row.status === 'failed')) return 'failed';
  if (rows.some(row => row.status === 'incomplete')) return 'incomplete';
  return rows.length ? 'passed' : 'incomplete';
}

function validateProfile(profile) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) throw new TypeError('profile must be an object');
  const unknown = Object.keys(profile).filter(key => !Object.hasOwn(DEFAULT_PROFILE, key) && key !== 'setupMs');
  if (unknown.length) throw new TypeError(`unknown workload profile fields: ${unknown.join(', ')}`);
  const limits = { ...DEFAULT_PROFILE, ...profile };
  for (const key of Object.keys(DEFAULT_PROFILE).filter(key => key !== 'ratePerSecond')) positiveInteger(limits[key], key);
  if (typeof limits.ratePerSecond !== 'number' || !Number.isFinite(limits.ratePerSecond) || limits.ratePerSecond <= 0) throw new TypeError('ratePerSecond must be finite and positive');
  for (const [key, ceiling] of Object.entries(PROFILE_CEILINGS)) if (limits[key] > ceiling) throw new RangeError(`${key} exceeds its hard workload ceiling`);
  if (limits.maxPending > limits.concurrency) throw new TypeError('maxPending cannot exceed concurrency');
  if (limits.maxObservations > limits.maxActions) throw new TypeError('maxObservations cannot exceed maxActions');
  if (limits.sampleIntervalMs > limits.durationMs) throw new TypeError('sampleIntervalMs cannot exceed durationMs');
  if (profile.setupMs !== undefined) finiteOptional(profile.setupMs);
  return limits;
}

function validateAction(action, ids) {
  if (!action || typeof action !== 'object' || Array.isArray(action) || typeof action.run !== 'function') throw new TypeError('scenario actions need an ordinary run function');
  if (typeof action.id !== 'string' || action.id.length < 1 || action.id.length > 256 || ids.has(action.id)) throw new TypeError('scenario action IDs must be unique bounded strings');
  if (typeof action.kind !== 'string' || action.kind.length < 1 || action.kind.length > 128) throw new TypeError('scenario action kind must be a bounded string');
  ids.add(action.id);
}

function boundedValue(value, limit) {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError('workload observations must be JSON values');
  if (Buffer.byteLength(encoded) > limit) throw new RangeError('workload value exceeds artifact byte limit');
  return JSON.parse(encoded);
}
function captureValue(value, limit) {
  try { return { ok: true, value: boundedValue(value, limit) }; }
  catch { return { ok: false, value: null }; }
}
async function closeIterator(iterator) {
  if (typeof iterator.return !== 'function') return true;
  try {
    const timeout = cancellableDelay(10);
    const result = await Promise.race([Promise.resolve(iterator.return()).then(() => true, () => false), timeout.promise.then(() => false)]);
    timeout.cancel();
    return result;
  } catch { return false; }
}

function errorRecord(error) {
  const name = typeof error?.name === 'string' ? error.name.slice(0, 128) : 'Error';
  const message = typeof error?.message === 'string' ? error.message.slice(0, 1024) : 'action failed';
  return { name, message };
}

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`);
}

function finiteOptional(value) {
  if (value === undefined) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new TypeError('setupMs must be a finite nonnegative measured duration');
  return value;
}

function cancellableDelay(ms) {
  let timer;
  let resolvePromise;
  const promise = new Promise(resolve => { resolvePromise = resolve; timer = setTimeout(resolve, Math.max(0, ms)); });
  return { promise, cancel() { clearTimeout(timer); resolvePromise(); } };
}
function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
