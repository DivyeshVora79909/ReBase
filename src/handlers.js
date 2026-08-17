const fs = require("node:fs");
const path = require("node:path");

const CAPABILITY = /^[a-z][A-Za-z0-9]*$/;
const TABLE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MODES = new Set(["request", "job", "webhook"]);

function filesRecursive(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    return entry.isDirectory() ? filesRecursive(resolved) : [resolved];
  }).sort((left, right) => left.localeCompare(right));
}

function assertOnlyKeys(value, allowed, label) {
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw new Error(`Unknown ${label} property: ${unknown}`);
}

function normalizeTables(raw, capability, slot, availableTables) {
  const tables = typeof raw === "string" ? [raw] : raw;
  if (!Array.isArray(tables) || !tables.length) {
    throw new Error(`${capability}.${slot} requires at least one table`);
  }
  const unique = [...new Set(tables)];
  for (const table of unique) {
    if (!TABLE.test(table) || !availableTables.has(table)) {
      throw new Error(`Unknown record table ${table} in ${capability}.${slot}`);
    }
  }
  return unique;
}

function normalizeRecordSlot(raw, capability, slot, availableTables) {
  if (typeof raw === "string" || Array.isArray(raw)) {
    return {
      tables: normalizeTables(raw, capability, slot, availableTables),
      required: true,
      many: false,
    };
  }
  if (!raw || typeof raw !== "object") {
    throw new Error(`Invalid record slot ${capability}.${slot}`);
  }
  assertOnlyKeys(raw, new Set(["tables", "required", "many", "min", "max"]), `record slot ${capability}.${slot}`);
  const many = raw.many === true;
  const required = raw.required !== false;
  const normalized = {
    tables: normalizeTables(raw.tables, capability, slot, availableTables),
    required,
    many,
  };
  if (!many && (raw.min !== undefined || raw.max !== undefined)) {
    throw new Error(`${capability}.${slot} min/max require many: true`);
  }
  if (many) {
    const min = raw.min ?? (required ? 1 : 0);
    const max = raw.max ?? 100;
    if (!Number.isInteger(min) || min < 0 || !Number.isInteger(max) || max < 1 || min > max || max > 100) {
      throw new Error(`Invalid record cardinality for ${capability}.${slot}`);
    }
    normalized.min = min;
    normalized.max = max;
  }
  return normalized;
}

function normalizeHandler(filePath, edgeDir, availableTables) {
  const capability = path.basename(filePath, path.extname(filePath));
  if (!CAPABILITY.test(capability)) {
    throw new Error(`Edge handler filename must be camelCase: ${filePath}`);
  }
  const implementation = require(filePath);
  if (!implementation || typeof implementation !== "object") {
    throw new Error(`Edge handler must export an object: ${filePath}`);
  }
  const mode = implementation.mode;
  if (!MODES.has(mode)) throw new Error(`${capability} requires mode request, job, or webhook`);
  if (typeof implementation.execute !== "function") throw new Error(`${capability} must export execute()`);
  if (mode === "webhook" && typeof implementation.verify !== "function") {
    throw new Error(`${capability} webhook must export verify()`);
  }
  if (implementation.authorize !== undefined && typeof implementation.authorize !== "function") {
    throw new Error(`${capability}.authorize must be a function`);
  }
  const rawRecords = implementation.records ?? {};
  if (!rawRecords || typeof rawRecords !== "object" || Array.isArray(rawRecords)) {
    throw new Error(`${capability}.records must be an object`);
  }
  const records = {};
  for (const [slot, raw] of Object.entries(rawRecords)) {
    if (!/^[a-z][A-Za-z0-9]*$/.test(slot)) throw new Error(`Invalid record slot ${capability}.${slot}`);
    records[slot] = normalizeRecordSlot(raw, capability, slot, availableTables);
  }
  if (mode === "webhook" && Object.keys(records).length) {
    throw new Error(`${capability} webhook cannot declare authenticated record slots`);
  }
  const defaultTimeout = mode === "job" ? 60_000 : 10_000;
  const timeoutMs = implementation.timeoutMs ?? defaultTimeout;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) {
    throw new Error(`${capability}.timeoutMs must be between 1 and 300000`);
  }
  let maxAttempts;
  if (mode === "job") {
    maxAttempts = implementation.maxAttempts ?? 5;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 50) {
      throw new Error(`${capability}.maxAttempts must be between 1 and 50`);
    }
  }
  return Object.freeze({
    capability,
    file: path.relative(edgeDir, filePath).replaceAll(path.sep, "/"),
    implementation,
    maxAttempts,
    mode,
    records: Object.freeze(records),
    timeoutMs,
  });
}

class HandlerRegistry {
  #handlers;

  constructor(handlers) {
    this.#handlers = new Map(handlers.map((handler) => [handler.capability, handler]));
    this.capabilities = Object.freeze([...this.#handlers.keys()].sort());
    Object.freeze(this);
  }

  get(capability) {
    return this.#handlers.get(capability) || null;
  }

  list() {
    return this.capabilities.map((capability) => this.#handlers.get(capability));
  }
}

function discoverHandlers(edgeDir, availableTables) {
  const root = path.resolve(edgeDir);
  const handlers = filesRecursive(root)
    .filter((file) => file.endsWith(".js"))
    .map((file) => normalizeHandler(file, root, availableTables));
  const seen = new Set();
  for (const handler of handlers) {
    if (seen.has(handler.capability)) throw new Error(`Duplicate edge capability: ${handler.capability}`);
    seen.add(handler.capability);
  }
  return new HandlerRegistry(handlers);
}

module.exports = { HandlerRegistry, discoverHandlers, normalizeRecordSlot };
