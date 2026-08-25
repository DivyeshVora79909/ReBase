const { createLocalProviders } = require("./local");
const { createRealProviders } = require("./real");

const DEFAULT_PROVIDER_ADAPTER = "local";
const PROVIDER_FACTORIES = Object.freeze({
  local: createLocalProviders,
  real: createRealProviders,
});

function assertProviderAdapter(adapter, label = "provider") {
  if (!adapter || typeof adapter !== "object" || Array.isArray(adapter)) {
    throw new Error(`${label} adapter must be an object`);
  }
  if (typeof adapter.kind !== "string" || !adapter.kind.trim()) {
    throw new Error(`${label} adapter requires a non-empty kind`);
  }
  if (typeof adapter.developmentOnly !== "boolean") {
    throw new Error(`${label} adapter requires developmentOnly boolean`);
  }
  if (typeof adapter.health !== "function") {
    throw new Error(`${label} adapter requires health()`);
  }
  return adapter;
}

function resolveProviderAdapter(selection = DEFAULT_PROVIDER_ADAPTER, options = {}) {
  if (selection && typeof selection === "object") {
    return assertProviderAdapter(selection);
  }

  const name = typeof selection === "string"
    ? selection.trim().toLowerCase()
    : null;
  const factory = name ? PROVIDER_FACTORIES[name] : selection;
  if (typeof factory !== "function") {
    throw new Error(`Unsupported provider adapter: ${String(selection)}`);
  }

  return assertProviderAdapter(factory(options), name || factory.name || "custom provider");
}

module.exports = {
  DEFAULT_PROVIDER_ADAPTER,
  assertProviderAdapter,
  createProviderAdapter: resolveProviderAdapter,
  resolveProviderAdapter,
};
