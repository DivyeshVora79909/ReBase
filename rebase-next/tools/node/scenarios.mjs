const CHURN_DEFAULT = Object.freeze({ durationMs: 60_000, ratePerSecond: 10, maxActions: 1_000,
  concurrency: 1, maxPending: 1, maxObservations: 1_000, maxArtifactBytes: 4 * 1024 * 1024, sampleIntervalMs: 1_000 });
const OVERLOAD_DEFAULT = Object.freeze({ durationMs: 10_000, ratePerSecond: 128, maxActions: 768,
  concurrency: 8, maxPending: 8, maxObservations: 768, maxArtifactBytes: 8 * 1024 * 1024, sampleIntervalMs: 250 });
const FAULT_DEFAULT = Object.freeze({ durationMs: 30_000, ratePerSecond: 2, maxActions: 64,
  concurrency: 1, maxPending: 1, maxObservations: 64, maxArtifactBytes: 4 * 1024 * 1024, sampleIntervalMs: 250 });

export function churnProfile(overrides = {}) { return profile(CHURN_DEFAULT, overrides, 'churn'); }
export function overloadProfile(overrides = {}) { return profile(OVERLOAD_DEFAULT, overrides, 'overload'); }
export function faultProfile(overrides = {}) { return profile(FAULT_DEFAULT, overrides, 'fault'); }

/** Sequential bounded action source for caller-authored create/update/delete/archive churn. */
export function churnScenario({ actions, maxActions = 1_000 } = {}) {
  positiveInteger(maxActions, 'maxActions', 10_000);
  return async function* churn() {
    let count = 0;
    for await (const action of asAsync(actions)) {
      if (count >= maxActions) return;
      if (!['create', 'update', 'delete', 'archive', 'read', 'replay'].includes(action?.kind)) {
        throw new TypeError('churn actions must identify create, update, delete, archive, read, or replay');
      }
      validateMutationIntent(action);
      count += 1;
      yield action;
    }
  };
}

/**
 * Finite offered workload. The workload runner's concurrency/maxPending bounds
 * provide backpressure; this source never preloads or duplicates requests.
 */
export function overloadScenario({ actions, maxActions = 768 } = {}) {
  positiveInteger(maxActions, 'maxActions', 768);
  return async function* overload() {
    let count = 0;
    for await (const action of asAsync(actions)) {
      if (count >= maxActions) return;
      if (!['read', 'mutation', 'create', 'update', 'delete'].includes(action?.kind)) {
        throw new TypeError('overload actions must identify a read or bounded mutation');
      }
      validateMutationIntent(action);
      count += 1;
      yield action;
    }
  };
}

/**
 * Model a caller-owned service outage, the original write attempt, recovery,
 * then status reconciliation. Each phase is lazy and bounded. The lost reply
 * phase must carry the original immutable request descriptor; no retry is made.
 */
export function faultScenario({ before = [], outage = [], recovery = [], reconcile = [], maxActions = 64 } = {}) {
  positiveInteger(maxActions, 'maxActions', 64);
  return async function* fault() {
    let count = 0;
    for (const [phase, actions] of [['before', before], ['outage', outage], ['recovery', recovery], ['reconcile', reconcile]]) {
      for await (const action of asAsync(actions)) {
        if (count >= maxActions) return;
        if (phase === 'outage' && action?.mutation === true) validateMutationIntent(action);
        if (phase === 'reconcile' && action?.mutation === true && action?.request == null) {
          throw new TypeError('reconciliation must retain the exact original mutation request');
        }
        count += 1;
        yield Object.freeze({ ...action, phase });
      }
    }
  };
}

function profile(defaults, overrides, label) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) throw new TypeError(`${label} overrides must be an object`);
  const unknown = Object.keys(overrides).filter(key => !Object.hasOwn(defaults, key) && key !== 'setupMs');
  if (unknown.length) throw new TypeError(`${label} profile has unknown fields: ${unknown.join(', ')}`);
  const value = { ...defaults, ...overrides };
  const ceilings = { durationMs: 300_000, maxActions: defaults.maxActions, concurrency: 8, maxPending: 8,
    maxObservations: defaults.maxActions, maxArtifactBytes: 16 * 1024 * 1024, sampleIntervalMs: 300_000 };
  for (const key of Object.keys(ceilings)) positiveInteger(value[key], key, ceilings[key]);
  if (typeof value.ratePerSecond !== 'number' || !Number.isFinite(value.ratePerSecond) || value.ratePerSecond <= 0 || value.ratePerSecond > 10_000) throw new TypeError('ratePerSecond must be finite, positive, and at most 10000');
  if (value.setupMs !== undefined && (typeof value.setupMs !== 'number' || !Number.isFinite(value.setupMs) || value.setupMs < 0)) throw new TypeError('setupMs must be finite and nonnegative');
  if (value.maxPending > value.concurrency || value.maxObservations > value.maxActions || value.sampleIntervalMs > value.durationMs) throw new TypeError(`${label} profile bounds are inconsistent`);
  return Object.freeze(value);
}

function validateMutationIntent(action) {
  if (action?.mutation === true && (!action.request || typeof action.request !== 'object' || Array.isArray(action.request))) {
    throw new TypeError('mutating actions must retain their exact original request descriptor');
  }
}

function asAsync(value) {
  if (value?.[Symbol.asyncIterator]) return value;
  if (value?.[Symbol.iterator]) return { async *[Symbol.asyncIterator]() { yield* value; } };
  throw new TypeError('scenario actions must be an iterable or async iterable');
}

function positiveInteger(value, name, ceiling = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > ceiling) throw new TypeError(`${name} must be a positive safe integer no greater than ${ceiling}`);
}
