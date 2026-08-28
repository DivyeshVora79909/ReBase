const fs = require("node:fs");
const path = require("node:path");

const PROVIDER = /^[a-z][a-z0-9_-]*$/;
const EVENT = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

function filesRecursive(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? filesRecursive(file) : [file];
  }).sort();
}

function normalizeImplementation(implementation, label) {
  const provider = String(implementation?.provider || "").trim().toLowerCase();
  if (!PROVIDER.test(provider)) throw new Error(`Webhook handler requires a valid provider export: ${label}`);
  if (!implementation?.on || typeof implementation.on !== "object" || Array.isArray(implementation.on)) {
    throw new Error(`${provider} webhook handler requires an on event map`);
  }
  const entries = Object.entries(implementation.on);
  if (!entries.length) throw new Error(`${provider} webhook handler requires at least one event`);
  for (const [event, handler] of entries) {
    if (!EVENT.test(event)) throw new Error(`${provider} has an invalid webhook event: ${event}`);
    if (typeof handler !== "function") throw new Error(`${provider}.${event} webhook handler must be a function`);
  }
  const on = Object.freeze(Object.fromEntries(entries));
  return Object.freeze({
    file: label,
    implementation: Object.freeze({ ...implementation, provider, on }),
    provider,
    events: Object.freeze(entries.map(([event]) => event).sort()),
    on,
  });
}

function normalizeContracts(contracts = {}) {
  return contracts instanceof Map ? contracts : new Map(Object.entries(contracts || {}));
}

function createWebhookRegistry(handlers, contracts = new Map(), { mutable = false } = {}) {
  const expected = normalizeContracts(contracts);
  const map = new Map();

  function add(handler, replace = false) {
    for (const event of handler.events) {
      const key = `${handler.provider}\u0000${event}`;
      if (!replace && map.has(key)) throw new Error(`Duplicate webhook handler: ${handler.provider}/${event}`);
      map.set(key, handler);
    }
    return handler;
  }
  for (const handler of handlers) add(handler);

  const actual = contractForHandlers([...new Set(map.values())]);
  if (expected.size) {
    for (const [provider, contract] of expected) {
      const wanted = [...(contract?.events || [])].sort();
      const found = actual[provider]?.events || [];
      if (JSON.stringify(found) !== JSON.stringify(wanted)) {
        throw new Error(`Webhook handler contract mismatch for ${provider}`);
      }
    }
    const extra = Object.keys(actual).find((provider) => !expected.has(provider));
    if (extra) throw new Error(`Webhook handler ${extra} has no compiled contract`);
  }

  return Object.freeze({
    contracts: expected,
    frozen: !mutable,
    get(provider, event) { return map.get(`${String(provider).toLowerCase()}\u0000${event}`) || null; },
    list() { return [...new Set(map.values())]; },
    get providers() { return [...new Set([...map.values()].map((handler) => handler.provider))].sort(); },
    contract() { return contractForHandlers([...new Set(map.values())]); },
    register(implementation, options = {}) {
      if (!mutable) throw new Error("Production webhook directory is frozen");
      return add(normalizeImplementation(implementation, options.label || "local-plugin"), options.replace === true);
    },
  });
}

function contractForHandlers(handlers) {
  const grouped = new Map();
  for (const handler of handlers) {
    if (!grouped.has(handler.provider)) grouped.set(handler.provider, new Set());
    for (const event of handler.events) grouped.get(handler.provider).add(event);
  }
  return Object.fromEntries([...grouped]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([provider, events]) => [provider, { events: [...events].sort() }]));
}

function loadWebhookHandlers(directory, options = {}) {
  const contracts = normalizeContracts(options.contracts);
  const handlers = filesRecursive(path.resolve(directory))
    .filter((file) => file.endsWith(".js"))
    .map((file) => normalizeImplementation(require(file), path.relative(process.cwd(), file)));
  return createWebhookRegistry(handlers, contracts, { mutable: options.mutable === true });
}

module.exports = {
  contractForHandlers,
  createWebhookRegistry,
  loadWebhookHandlers,
  normalizeImplementation,
};
