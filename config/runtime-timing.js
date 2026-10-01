const QUEUE_HORIZON_MS = 5 * 60 * 1000;
const DEFAULT_RECONCILE_INTERVAL_MS = 60 * 1000;

function surrealDuration(milliseconds) {
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 1) {
    throw new Error("Duration must be a positive safe integer in milliseconds");
  }
  for (const [unit, size] of [
    ["d", 24 * 60 * 60 * 1000],
    ["h", 60 * 60 * 1000],
    ["m", 60 * 1000],
    ["s", 1000],
    ["ms", 1],
  ]) {
    if (milliseconds % size === 0) return `${milliseconds / size}${unit}`;
  }
  throw new Error("Duration cannot be represented as SurrealQL duration");
}

module.exports = {
  DEFAULT_RECONCILE_INTERVAL_MS,
  QUEUE_HORIZON_MS,
  surrealDuration,
};
