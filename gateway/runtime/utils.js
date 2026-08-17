const crypto = require("node:crypto");

function surrealValueString(value) {
  return String(value);
}

// Keep Surreal's typed record literal intact so UUID and string record keys
// remain distinguishable when an ID crosses the HTTP or queue boundary.
function recordIdString(value) {
  return surrealValueString(value);
}

function clean(value, seen = new WeakSet()) {
  if (value == null || typeof value !== "object") return typeof value === "bigint" ? String(value) : value;
  if (value instanceof Date) return value.toISOString();
  if (value.constructor?.name?.startsWith("RecordId")) return recordIdString(value);
  if (["DateTime", "Decimal", "Uuid", "Duration"].some((name) => value.constructor?.name?.startsWith(name))) return surrealValueString(value);
  const visiting = seen instanceof WeakSet ? seen : new WeakSet();
  if (visiting.has(value)) return "[Circular]";
  visiting.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => clean(item, visiting));
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clean(item, visiting)]));
  } finally {
    visiting.delete(value);
  }
}

function queryResult(response) {
  if (!Array.isArray(response)) return clean(response);
  const last = response.at(-1);
  // Surreal's query envelope has a status alongside result. Records may also
  // legitimately contain a field named `result`, so that field alone is not
  // enough to identify an envelope.
  if (
    last &&
    typeof last === "object" &&
    !Array.isArray(last) &&
    (last.status === "OK" || last.status === "ERR") &&
    Object.prototype.hasOwnProperty.call(last, "result")
  ) return clean(last.result);
  return clean(last);
}

function requestId(value) {
  if (typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value)) return value;
  return crypto.randomUUID();
}

function sanitize(value, depth = 0) {
  if (depth > 5 || value == null) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitize(item, depth + 1));
  if (typeof value !== "object") {
    if (typeof value !== "string") return value;
    const redacted = value.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
    return redacted.length > 2048 ? `${redacted.slice(0, 2048)}...` : redacted;
  }
  const hidden = /authorization|bearer|token|password|secret|credential|api[_-]?key/i;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, hidden.test(key) ? "[REDACTED]" : sanitize(item, depth + 1)]));
}

function assertNoCredentials(value, path = "args", depth = 0) {
  if (depth > 10 || value == null || typeof value !== "object") return;
  const forbidden = /^(authorization|bearer|password|credentials?|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret|auth[_-]?token|secret(?:[_-]?key)?)$/i;
  for (const [key, item] of Object.entries(value)) {
    if (forbidden.test(key)) {
      const error = new Error(`Credential-shaped field is not allowed: ${path}.${key}`);
      error.code = "CREDENTIAL_INPUT_FORBIDDEN";
      throw error;
    }
    assertNoCredentials(item, `${path}.${key}`, depth + 1);
  }
}

function boundedData(value, maximumBytes = 64 * 1024) {
  const cleaned = sanitize(value);
  try {
    if (Buffer.byteLength(JSON.stringify(cleaned)) <= maximumBytes) return cleaned;
  } catch {}
  return { truncated: true };
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

module.exports = {
  assertNoCredentials,
  boundedData,
  clean,
  queryResult,
  requestId,
  recordIdString,
  sanitize,
  surrealValueString,
  withTimeout,
};
