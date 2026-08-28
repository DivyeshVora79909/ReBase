const fs = require("node:fs");
const path = require("node:path");

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PROCESSES = new Set(["sync", "async"]);
const EVENTS = Object.freeze(["CREATE", "UPDATE", "DELETE"]);
const EVENT_SET = new Set(EVENTS);

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
      events: contract.events,
      timeoutMs: contract.timeoutMs,
      inputFields: contract.inputFields,
      optionalInputs: contract.optionalInputs,
      patchFields: contract.patchFields,
      references: contract.references,
      providers: contract.providers,
      mutableInputs: contract.mutableInputs,
      schedule: contract.schedule,
    });
    if (contractValues.some((contract) => comparable(contract) !== comparable(contractValues[0]))) {
      throw new Error(`${tables[0]} aliases must have equivalent compiled contracts`);
    }
  }
  const timeoutMs = implementation.timeoutMs ?? contractValues[0]?.timeoutMs ?? (processType === "sync" ? 10000 : 60000);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) {
    throw new Error(`${tables[0]}.timeoutMs must be between 1 and 300000`);
  }
  const contract = contractValues[0] || {};
  if (!implementation?.on || typeof implementation.on !== "object" || Array.isArray(implementation.on)) {
    throw new Error(`${tables[0]} requires an on event map`);
  }
  const exportedEvents = Object.keys(implementation.on).map((event) => event.toUpperCase());
  const invalidEvent = exportedEvents.find((event) => !EVENT_SET.has(event));
  if (invalidEvent) throw new Error(`${tables[0]} has an invalid event handler: ${invalidEvent}`);
  if (new Set(exportedEvents).size !== exportedEvents.length) {
    throw new Error(`${tables[0]} has duplicate event handlers`);
  }
  const declaredEvents = contract.events?.length ? contract.events : exportedEvents;
  const missingEvent = declaredEvents.find((event) => typeof implementation.on[event] !== "function");
  if (missingEvent) throw new Error(`${tables[0]} requires on.${missingEvent}()`);
  const undeclaredEvent = exportedEvents.find((event) => !declaredEvents.includes(event));
  if (contractValues.length && undeclaredEvent) {
    throw new Error(`${tables[0]}.on.${undeclaredEvent} is not declared by @rebase-events`);
  }
  if (implementation.reconcile !== undefined && typeof implementation.reconcile !== "function") {
    throw new Error(`${tables[0]}.reconcile must be a function`);
  }
  const on = Object.freeze(Object.fromEntries(declaredEvents.map((event) => [event, implementation.on[event]])));
  const immutableImplementation = Object.freeze({ ...implementation, on });
  return Object.freeze({
    file: label,
    implementation: immutableImplementation,
    process: processType,
    events: Object.freeze([...declaredEvents]),
    on,
    table: tables[0],
    tables: Object.freeze([...new Set(tables)]),
    timeoutMs,
    contract,
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
  EVENTS,
  createHandlerRegistry,
  loadTableHandlers,
  normalizeHandler,
  normalizeImplementation,
  tableFromId,
};
