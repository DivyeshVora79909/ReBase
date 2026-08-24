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

function normalizeImplementation(implementation, label, contracts = new Map()) {
  if (!(contracts instanceof Map)) contracts = new Map(Object.entries(contracts || {}));
  const aliases = implementation?.tables || implementation?.table;
  const tables = [...new Set(Array.isArray(aliases) ? aliases : [aliases])];
  if (!tables.length || tables.some((table) => !IDENTIFIER.test(table || ""))) {
    throw new Error(`Table handler requires a valid table or tables export: ${label}`);
  }
  if (typeof implementation.execute !== "function") throw new Error(`${tables[0]} requires execute()`);
  const contractValues = tables.map((table) => contracts.get(table)).filter(Boolean);
  if (contracts.size && contractValues.length !== tables.length) {
    throw new Error(`${tables[0]} handler has no compiled runtime contract`);
  }
  if (contractValues.length && implementation.process !== undefined) {
    throw new Error(`${tables[0]} must not duplicate the compiled process declaration`);
  }
  if (contractValues.length && implementation.outputs !== undefined) {
    throw new Error(`${tables[0]} must not duplicate compiled patch fields`);
  }
  if (contractValues.length && implementation.timeoutMs !== undefined) {
    throw new Error(`${tables[0]} must not duplicate the compiled timeout`);
  }
  const processType = implementation.process || contractValues[0]?.process;
  if (processType && !PROCESSES.has(processType)) throw new Error(`${tables[0]} requires process sync or async`);
  if (contractValues.some((contract) => contract.process !== processType)) {
    throw new Error(`${tables[0]} aliases must use one effect process`);
  }
  if (contractValues.length > 1) {
    const comparable = (contract) => JSON.stringify({
      process: contract.process,
      timeoutMs: contract.timeoutMs,
      inputFields: contract.inputFields,
      optionalInputs: contract.optionalInputs,
      patchFields: contract.patchFields,
      references: contract.references,
      providers: contract.providers,
      mutableInputs: contract.mutableInputs,
      schedule: contract.schedule,
      webhook: contract.webhook,
    });
    if (contractValues.some((contract) => comparable(contract) !== comparable(contractValues[0]))) {
      throw new Error(`${tables[0]} aliases must have equivalent compiled contracts`);
    }
  }
  const timeoutMs = implementation.timeoutMs ?? contractValues[0]?.timeoutMs ?? (processType === "sync" ? 10000 : 60000);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) {
    throw new Error(`${tables[0]}.timeoutMs must be between 1 and 300000`);
  }
  const verifyWebhook = implementation.verifyWebhook || implementation.verify;
  const correlateWebhook = implementation.correlateWebhook || implementation.webhook;
  if (verifyWebhook !== undefined && typeof verifyWebhook !== "function") {
    throw new Error(`${tables[0]}.verifyWebhook must be a function`);
  }
  if (correlateWebhook !== undefined && typeof correlateWebhook !== "function") {
    throw new Error(`${tables[0]}.correlateWebhook must be a function`);
  }
  if (correlateWebhook && !verifyWebhook) {
    throw new Error(`${tables[0]}.correlateWebhook requires verifyWebhook()`);
  }
  const contract = contractValues[0] || {};
  const immutableImplementation = Object.freeze(implementation);
  return Object.freeze({
    file: label,
    implementation: immutableImplementation,
    process: processType,
    table: tables[0],
    tables: Object.freeze([...new Set(tables)]),
    timeoutMs,
    contract,
    verifyWebhook,
    correlateWebhook,
    reconcile: implementation.reconcile,
  });
}

function normalizeHandler(file, contracts = new Map()) {
  return normalizeImplementation(require(file), path.relative(process.cwd(), file), contracts);
}

function createHandlerRegistry(handlers, contracts, { mutable = false } = {}) {
  const map = new Map();

  function add(handler, replace = false) {
    for (const table of handler.tables) {
      if (!replace && map.has(table)) throw new Error(`Duplicate table handler: ${table}`);
      map.set(table, handler);
    }
    return handler;
  }
  for (const handler of handlers) add(handler);

  return Object.freeze({
    contracts,
    frozen: !mutable,
    get(table) { return map.get(table) || null; },
    list() { return [...new Set(map.values())]; },
    get tables() { return [...map.keys()].sort(); },
    register(implementation, options = {}) {
      if (!mutable) throw new Error("Production handler directory is frozen");
      const handler = normalizeImplementation(implementation, options.label || "local-plugin", contracts);
      return add(handler, options.replace === true);
    },
    unregister(table) {
      if (!mutable) throw new Error("Production handler directory is frozen");
      const handler = map.get(table);
      if (!handler) return false;
      for (const alias of handler.tables) if (map.get(alias) === handler) map.delete(alias);
      return true;
    },
  });
}

function loadTableHandlers(directory, options = {}) {
  let contracts = options.contracts;
  if (!contracts && options.contractPath && fs.existsSync(options.contractPath)) {
    const parsed = JSON.parse(fs.readFileSync(options.contractPath, "utf8"));
    contracts = new Map(Object.entries(parsed.tables || {}));
  }
  if (!contracts) contracts = new Map();
  if (!(contracts instanceof Map)) contracts = new Map(Object.entries(contracts));
  const handlers = filesRecursive(path.resolve(directory))
    .filter((file) => file.endsWith(".js"))
    .map((file) => normalizeHandler(file, contracts));
  return createHandlerRegistry(handlers, contracts, { mutable: options.mutable === true });
}

function tableFromId(id) {
  const value = String(id || "");
  const separator = value.indexOf(":");
  if (separator < 1 || !IDENTIFIER.test(value.slice(0, separator))) return null;
  return value.slice(0, separator);
}

module.exports = {
  createHandlerRegistry,
  loadTableHandlers,
  normalizeHandler,
  normalizeImplementation,
  tableFromId,
};
