import { performance } from 'node:perf_hooks';
import { checkRun, runWorkload } from './workload.mjs';

const FORMAT = 'rebase-node-experiment-1';
const MAX_ACTIONS = 256;
const MAX_TRACE_BYTES = 8 * 1024 * 1024;

/** A readable projection of the retained trace; request and raw result stay intact. */
export function walk(run) {
  assertRun(run);
  return Object.freeze(run.observations.map((row, index) => Object.freeze({
    index, id: row.id, kind: row.kind, status: row.status, mutation: row.mutation === true,
    request: row.request ?? null, value: row.value ?? null, error: row.error ?? null,
    outcomeUnknown: row.outcomeUnknown === true, elapsedMs: row.elapsedMs,
  })));
}

/**
 * Run deterministic generated actions against a caller-created disposable target.
 * A failing trace is retained before bounded deletion shrinking begins.
 */
export async function explore({ seed, createTarget, scenario, profile, oracle,
  replayCandidate, shrink = { maxAttempts: 32, timeMs: 1_000 }, identity = {} } = {}) {
  validateExperiment({ seed, createTarget, scenario, profile, oracle });
  const random = seeded(seed);
  const target = await createTarget({ seed, random });
  if (!target || !Object.hasOwn(target, 'state')) throw new TypeError('createTarget must return { state, dispose? }');
  try {
    const run = await runWorkload({ scenario: context => scenario({ ...context, seed, random }),
      state: target.state, profile, identity: { ...identity, seed } });
    const checked = await checkRun({ run, oracle });
    const result = { format: FORMAT, kind: 'explore', status: checked.status, seed,
      run, check: checked, walk: walk(run), shrink: null };
    if (checked.status === 'failed' && typeof replayCandidate === 'function') {
      result.shrink = await shrinkFailure({ trace: run.observations, replay: replayCandidate,
        createTarget, oracle, profile, seed, targetKind: firstFailure(checked), limits: shrink });
    }
    return deepFreeze(result);
  } finally { await target.dispose?.(); }
}

/**
 * Replay symbolic actions on a new disposable target. `rebuild` owns remapping
 * source IDs and refreshing versions/context; operation IDs from the old trace
 * are rejected if they appear in the rebuilt raw requests.
 */
export async function logicalReplay({ trace, createTarget, rebuild, profile, oracle,
  seed = 0, identity = {} } = {}) {
  validateTrace(trace);
  if (typeof createTarget !== 'function' || typeof rebuild !== 'function') throw new TypeError('logical replay needs createTarget and rebuild functions');
  if (typeof oracle !== 'function') throw new TypeError('logical replay needs a source-only oracle');
  const target = await createTarget({ seed, random: seeded(seed) });
  if (!target || !Object.hasOwn(target, 'state')) throw new TypeError('createTarget must return { state, dispose? }');
  try {
    const originalOperationIds = new Set(trace.map(operationId).filter(Boolean));
    const run = await runWorkload({ state: target.state, profile, identity: { ...identity, seed, replay: 'logical' },
      scenario: context => rebuild({ ...context, trace: clone(trace), seed, remapRequired: true }) });
    const reused = run.observations.map(operationId).filter(id => id && originalOperationIds.has(id));
    const originalReferences = new Set(trace.flatMap(identityReferences));
    const reusedReferences = run.observations.flatMap(identityReferences).filter(id => originalReferences.has(id));
    const obligations = [
      { name: 'logical-replay-fresh-operation-ids', status: reused.length ? 'failed' : 'passed',
        ...(reused.length ? { reason: 'rebuilt action reused an original operation ID' } : {}) },
      { name: 'logical-replay-remapped-record-ids', status: reusedReferences.length ? 'failed' : 'passed',
        ...(reusedReferences.length ? { reason: 'rebuilt request reused an original source identity' } : {}) },
    ];
    const checked = await checkRun({ run, oracle });
    obligations.push(...checked.obligations);
    const combined = resultFor(obligations, checked.costs);
    return deepFreeze({ format: FORMAT, kind: 'logical-replay', status: combined.status,
      sourceActionCount: trace.filter(row => row.action === true).length,
      remappedActions: run.observations.filter(row => row.action === true).length,
      run, check: combined, walk: walk(run), exactByteResume: false });
  } finally { await target.dispose?.(); }
}

/** Greedy bounded span deletion, accepting only the same named failure. */
export async function shrinkFailure({ trace, replay, createTarget, oracle, profile,
  seed = 0, targetKind, limits = {} } = {}) {
  validateTrace(trace);
  if (typeof replay !== 'function' || typeof createTarget !== 'function' || typeof oracle !== 'function') throw new TypeError('shrinking needs replay, createTarget and oracle functions');
  const maxAttempts = limits.maxAttempts ?? 32;
  const timeMs = limits.timeMs ?? 1_000;
  positiveInteger(maxAttempts, 'maxAttempts');
  positiveInteger(timeMs, 'timeMs');
  targetKind ??= 'source-oracle';
  let current = clone(trace), attempts = 0;
  const started = performance.now(), deadline = started + timeMs;
  const originalFailure = targetKind;
  attempts += 1;
  const baseline = await replayCandidate({ trace: current, replay, createTarget, oracle, profile, seed });
  if (!sameFailure(baseline, originalFailure)) return deepFreeze({ status: 'not-reproduced',
    originalTrace: clone(trace), minimizedTrace: current, originalActions: trace.length,
    minimizedActions: current.length, targetKind: originalFailure, maxAttempts, attempts,
    timeLimitMs: timeMs, elapsedMs: performance.now() - started,
    timeBoundReached: performance.now() >= deadline, sameFailureReproduced: false });
  let granularity = 2;
  while (current.length && attempts < maxAttempts && performance.now() < deadline) {
    const width = Math.max(1, Math.ceil(current.length / granularity));
    let reduced = false;
    for (let start = 0; start < current.length && attempts < maxAttempts && performance.now() < deadline; start += width) {
      attempts += 1;
      const candidate = current.slice(0, start).concat(current.slice(start + width));
      const result = await replayCandidate({ trace: candidate, replay, createTarget, oracle, profile, seed, attempt: attempts });
      if (sameFailure(result, originalFailure)) {
        current = candidate;
        granularity = Math.max(2, granularity - 1);
        reduced = true;
        break;
      }
    }
    if (!reduced) {
      if (granularity >= current.length) break;
      granularity = Math.min(current.length, granularity * 2);
    }
  }
  return deepFreeze({ status: current.length < trace.length ? 'minimized' : 'not-reduced',
    originalTrace: clone(trace), minimizedTrace: current, originalActions: trace.length,
    minimizedActions: current.length, targetKind: originalFailure, maxAttempts, attempts,
    timeLimitMs: timeMs, elapsedMs: performance.now() - started,
    timeBoundReached: performance.now() >= deadline, sameFailureReproduced: true });
}

async function replayCandidate({ trace, replay, createTarget, oracle, profile, seed }) {
  const target = await createTarget({ seed, random: seeded(seed), shrinking: true });
  if (!target || !Object.hasOwn(target, 'state')) throw new TypeError('createTarget must return { state, dispose? }');
  try {
    const run = await runWorkload({ state: target.state, profile, identity: { seed, shrinking: true },
      scenario: context => replay({ ...context, trace: clone(trace), seed, shrinking: true }) });
    const checked = await checkRun({ run, oracle });
    return { run, check: checked, kind: firstFailure(checked) };
  } finally { await target.dispose?.(); }
}

function validateExperiment({ seed, createTarget, scenario, profile, oracle }) {
  if (!(typeof seed === 'string' || Number.isSafeInteger(seed))) throw new TypeError('seed must be a string or safe integer');
  if (typeof createTarget !== 'function' || typeof scenario !== 'function' || typeof oracle !== 'function') throw new TypeError('explore needs createTarget, scenario and oracle functions');
  if (!profile || typeof profile !== 'object') throw new TypeError('explore needs a finite workload profile');
}
function validateTrace(trace) {
  if (!Array.isArray(trace) || trace.length > MAX_ACTIONS) throw new TypeError(`trace must contain at most ${MAX_ACTIONS} actions`);
  if (Buffer.byteLength(JSON.stringify(trace)) > MAX_TRACE_BYTES) throw new RangeError('trace exceeds 8 MiB');
}
function assertRun(run) { if (!run || run.format !== 'rebase-node-workload-1' || !Array.isArray(run.observations)) throw new TypeError('run must be a retained workload report'); }
function firstFailure(result) { return result.obligations.find(row => row.status === 'failed')?.name ?? 'source-oracle'; }
function sameFailure(result, kind) {
  return result?.run?.status === 'complete' && result.run.cancelled === false
    && result.run.timedOut === false && result.run.exhausted === true && result.run.unresolved === 0
    && result.check?.status === 'failed'
    && (result.kind === kind || result.check.obligations.some(row => row.name === kind && row.status === 'failed'));
}
function operationId(row) {
  const request = row?.request;
  return request?.request?.operation_id ?? request?.operation_id ?? null;
}
function identityReferences(row) {
  const values = [];
  const keys = new Set(['id', 'record', 'source', 'target', 'pool', 'parent', 'left', 'right', 'instrument', 'account']);
  const visit = value => {
    if (Array.isArray(value)) { for (const child of value) visit(child); return; }
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (keys.has(key) && typeof child === 'string') values.push(child);
      visit(child);
    }
  };
  visit(row?.request);
  return values;
}
function resultFor(obligations, costs) {
  const status = obligations.some(row => row.status === 'failed') ? 'failed'
    : obligations.some(row => row.status === 'incomplete') ? 'incomplete' : 'passed';
  return deepFreeze({ status, obligations: obligations.map(row => ({ ...row })), costs });
}
function clone(value) { return structuredClone(value); }
function deepFreeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) deepFreeze(child); Object.freeze(value); } return value; }
function positiveInteger(value, name) { if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`); }
function seeded(seed) {
  let state = typeof seed === 'number' ? seed >>> 0 : [...String(seed)].reduce((n, char) => Math.imul(n ^ char.charCodeAt(0), 16777619) >>> 0, 2166136261);
  if (!state) state = 0x9e3779b9;
  return () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 0x1_0000_0000; };
}
