const fs = require("node:fs");
const path = require("node:path");

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PROCESSES = new Set(["sync", "async"]);

function filesRecursive(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? filesRecursive(file) : [file];
  }).sort();
}

function normalizeHandler(file) {
  const implementation = require(file);
  const table = implementation?.table;
  if (!IDENTIFIER.test(table || "")) throw new Error(`Table handler requires a valid table name: ${file}`);
  if (!PROCESSES.has(implementation.process)) throw new Error(`${table} requires process sync or async`);
  if (typeof implementation.execute !== "function") throw new Error(`${table} requires execute()`);
  if (!Array.isArray(implementation.outputs) || !implementation.outputs.length) {
    throw new Error(`${table} requires a non-empty outputs array`);
  }
  const outputs = [...new Set(implementation.outputs)];
  if (outputs.length !== implementation.outputs.length || outputs.some((field) => !IDENTIFIER.test(field))) {
    throw new Error(`${table}.outputs contains an invalid or duplicate field`);
  }
  const timeoutMs = implementation.timeoutMs ?? (implementation.process === "sync" ? 10000 : 60000);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) {
    throw new Error(`${table}.timeoutMs must be between 1 and 300000`);
  }
  if (implementation.verify !== undefined && typeof implementation.verify !== "function") {
    throw new Error(`${table}.verify must be a function`);
  }
  if (implementation.webhook !== undefined && typeof implementation.webhook !== "function") {
    throw new Error(`${table}.webhook must be a function`);
  }
  if (implementation.webhook && !implementation.verify) {
    throw new Error(`${table}.webhook requires verify()`);
  }
  if (implementation.verify && !implementation.webhook) {
    throw new Error(`${table}.verify requires webhook()`);
  }
  return Object.freeze({
    file: path.relative(process.cwd(), file),
    implementation,
    outputs: Object.freeze(outputs),
    process: implementation.process,
    table,
    timeoutMs,
  });
}

function loadTableHandlers(directory) {
  const handlers = filesRecursive(path.resolve(directory))
    .filter((file) => file.endsWith(".js"))
    .map(normalizeHandler);
  const map = new Map();
  for (const handler of handlers) {
    if (map.has(handler.table)) throw new Error(`Duplicate table handler: ${handler.table}`);
    map.set(handler.table, handler);
  }
  return {
    get(table) { return map.get(table) || null; },
    list() { return [...map.values()]; },
    tables: [...map.keys()].sort(),
  };
}

function tableFromId(id) {
  const value = String(id || "");
  const separator = value.indexOf(":");
  if (separator < 1 || !IDENTIFIER.test(value.slice(0, separator))) return null;
  return value.slice(0, separator);
}

module.exports = { loadTableHandlers, normalizeHandler, tableFromId };
