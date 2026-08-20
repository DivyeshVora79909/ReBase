function recordIdString(value) {
  return String(value);
}

function clean(value, seen = new WeakSet()) {
  if (value == null || typeof value !== "object") return typeof value === "bigint" ? String(value) : value;
  if (value instanceof Date) return value.toISOString();
  if (value.constructor?.name?.startsWith("RecordId")) return recordIdString(value);
  if (["DateTime", "Decimal", "Uuid", "Duration"].some((name) => value.constructor?.name?.startsWith(name))) return String(value);
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => clean(item, seen));
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clean(item, seen)]));
  } finally {
    seen.delete(value);
  }
}

function queryResult(response) {
  if (!Array.isArray(response)) return clean(response);
  const last = response.at(-1);
  if (
    last
    && typeof last === "object"
    && !Array.isArray(last)
    && (last.status === "OK" || last.status === "ERR")
    && Object.prototype.hasOwnProperty.call(last, "result")
  ) return clean(last.result);
  return clean(last);
}

async function withTimeout(timeoutMs, callback) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error("Operation timed out");
      error.code = "OPERATION_TIMEOUT";
      error.retryable = true;
      controller.abort(error);
      reject(error);
    }, timeoutMs);
  });
  try {
    return await Promise.race([callback(controller.signal), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { clean, queryResult, recordIdString, withTimeout };
