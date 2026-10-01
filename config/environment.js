const {
  DEFAULT_RECONCILE_INTERVAL_MS,
  QUEUE_HORIZON_MS,
} = require("./runtime-timing");

const DEFAULTS = Object.freeze({
  environment: "development",
  host: "127.0.0.1",
  port: 8788,
  connectTimeoutMs: 10000,
  reconcileIntervalMs: DEFAULT_RECONCILE_INTERVAL_MS,
  terminalTaskRetentionDays: 30,
  redisConnectTimeoutMs: 5000,
  queueStartupTimeoutMs: 10000,
  queueHealthTimeoutMs: 2000,
  queuePrefix: "rebase",
  bodyLimitBytes: 256 * 1024,
  requestTimeoutMs: 30000,
  authenticationChallengeTtlMs: 10 * 60 * 1000,
  authenticationRateLimitWindowMs: 15 * 60 * 1000,
  authenticationRateLimitIp: 10,
  authenticationRateLimitIdentifier: 3,
  debug: false,
});

const CONTEXT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CONTEXT_KEYS = ["namespace", "database"];

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireRecord(value, label) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain object`);
  }
  return value;
}

function assertOnlyKeys(value, allowed, label) {
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length) {
    throw new Error(`${label} has unsupported fields: ${unexpected.join(", ")}`);
  }
}

function envString(values, key, { secret = false } = {}) {
  const raw = values[key];
  if (raw === undefined || raw === null) return undefined;
  if (!["string", "number", "boolean"].includes(typeof raw)) {
    throw new Error(`${key} must be a string`);
  }
  const text = String(raw);
  if (!text.trim()) return undefined;
  return secret ? text : text.trim();
}

function requiredString(value, label, { allowWhitespace = false } = {}) {
  if (typeof value !== "string" || !value.length || (!allowWhitespace && !value.trim())) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function optionalString(value, label, options) {
  if (value === undefined || value === null) return undefined;
  return requiredString(value, label, options);
}

function envInteger(values, key, fallback, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  const raw = values[key];
  if (raw === undefined || raw === null) return fallback;
  const text = String(raw).trim();
  if (!/^-?\d+$/.test(text)) throw new Error(`${key} must be an integer`);
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new Error(`${key} must be between ${minimum} and ${maximum}`);
  }
  return number;
}

function envBoolean(values, key, fallback) {
  const raw = values[key];
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw === "boolean") return raw;
  const text = String(raw).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  throw new Error(`${key} must be true or false`);
}

function integer(value, label, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function validateUrl(value, label, protocols) {
  if (value === undefined) return undefined;
  const text = requiredString(value, label);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (!protocols.includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw new Error(`${label} must use ${protocols.join(" or ")} and contain a host without embedded credentials`);
  }
  if (url.hash) throw new Error(`${label} must not contain a fragment`);
  return text;
}

function context(value, label) {
  requireRecord(value, label);
  assertOnlyKeys(value, CONTEXT_KEYS, label);
  for (const key of CONTEXT_KEYS) {
    if (typeof value[key] !== "string" || !CONTEXT_NAME.test(value[key])) {
      throw new Error(`${label}.${key} must be a SurrealDB identifier`);
    }
  }
  return { namespace: value.namespace, database: value.database };
}

function contextKey(value) {
  return `${value.namespace}\u0000${value.database}`;
}

function parseContexts(raw) {
  if (raw === undefined || raw === null || raw === "") return [];
  let parsed;
  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new Error("REBASE_ALLOWED_CONTEXTS must be valid JSON");
  }
  if (!Array.isArray(parsed)) {
    throw new Error("REBASE_ALLOWED_CONTEXTS must be a JSON array");
  }
  const seen = new Set();
  return parsed.map((item, index) => {
    const parsedContext = context(item, `REBASE_ALLOWED_CONTEXTS[${index}]`);
    const key = contextKey(parsedContext);
    if (seen.has(key)) throw new Error("REBASE_ALLOWED_CONTEXTS must not contain duplicate contexts");
    seen.add(key);
    return parsedContext;
  });
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function validateConfiguration(configuration) {
  const input = requireRecord(configuration, "Configuration");
  assertOnlyKeys(
    input,
    ["environment", "server", "surreal", "runtime", "queue", "storage", "authentication", "webhooks"],
    "Configuration",
  );

  const environment = requiredString(input.environment, "NODE_ENV");
  if (!["development", "test", "production"].includes(environment)) {
    throw new Error("NODE_ENV must be development, test, or production");
  }

  const serverInput = requireRecord(input.server, "Configuration.server");
  assertOnlyKeys(serverInput, ["host", "port", "reconcileIntervalMs", "terminalTaskRetentionDays", "bodyLimitBytes", "requestTimeoutMs", "debug"], "Configuration.server");
  const server = {
    host: requiredString(serverInput.host, "REBASE_HTTP_HOST"),
    port: integer(serverInput.port, "REBASE_HTTP_PORT", 0, 65535),
    reconcileIntervalMs: integer(serverInput.reconcileIntervalMs, "REBASE_RECONCILE_INTERVAL_MS", 1000),
    terminalTaskRetentionDays: integer(serverInput.terminalTaskRetentionDays, "REBASE_TERMINAL_TASK_RETENTION_DAYS", 1, 3650),
    bodyLimitBytes: integer(serverInput.bodyLimitBytes, "REBASE_HTTP_BODY_LIMIT_BYTES", 1),
    requestTimeoutMs: integer(serverInput.requestTimeoutMs, "REBASE_HTTP_REQUEST_TIMEOUT_MS", 1),
    debug: serverInput.debug,
  };
  if (typeof server.debug !== "boolean") throw new Error("REBASE_HTTP_DEBUG must be a boolean");
  if (server.reconcileIntervalMs >= QUEUE_HORIZON_MS) {
    throw new Error(
      `REBASE_RECONCILE_INTERVAL_MS must be shorter than the ${QUEUE_HORIZON_MS}ms queue admission horizon`,
    );
  }

  const surrealInput = requireRecord(input.surreal, "Configuration.surreal");
  assertOnlyKeys(surrealInput, ["endpoint", "username", "password", "namespace", "database", "connectTimeoutMs", "defaultContext", "contexts"], "Configuration.surreal");
  const surreal = {
    endpoint: validateUrl(optionalString(surrealInput.endpoint, "SURREAL_ENDPOINT"), "SURREAL_ENDPOINT", ["ws:", "wss:", "http:", "https:"]),
    username: optionalString(surrealInput.username, "SURREAL_USERNAME"),
    password: optionalString(surrealInput.password, "SURREAL_PASSWORD", { allowWhitespace: true }),
    namespace: optionalString(surrealInput.namespace, "SURREAL_NAMESPACE"),
    database: optionalString(surrealInput.database, "SURREAL_DATABASE"),
    connectTimeoutMs: integer(surrealInput.connectTimeoutMs, "SURREAL_CONNECT_TIMEOUT_MS", 1),
  };
  const connectionFields = [surreal.endpoint, surreal.username, surreal.password];
  if (connectionFields.some(Boolean) && !connectionFields.every(Boolean)) {
    throw new Error("SURREAL_ENDPOINT, SURREAL_USERNAME, and SURREAL_PASSWORD must be provided together");
  }
  if (Boolean(surreal.namespace) !== Boolean(surreal.database)) {
    throw new Error("SURREAL_NAMESPACE and SURREAL_DATABASE must be provided together");
  }
  let defaultContext;
  if (surrealInput.defaultContext !== undefined && surrealInput.defaultContext !== null) {
    defaultContext = context(surrealInput.defaultContext, "Configuration.surreal.defaultContext");
  } else if (surreal.namespace && surreal.database) {
    defaultContext = { namespace: surreal.namespace, database: surreal.database };
  }
  if (
    surreal.namespace && surreal.database && defaultContext &&
    (surreal.namespace !== defaultContext.namespace || surreal.database !== defaultContext.database)
  ) {
    throw new Error("Configuration.surreal.defaultContext must match SURREAL_NAMESPACE and SURREAL_DATABASE");
  }
  const configuredContexts = surrealInput.contexts;
  if (!Array.isArray(configuredContexts)) throw new Error("Configuration.surreal.contexts must be an array");
  const contexts = configuredContexts.map((item, index) => context(item, `Configuration.surreal.contexts[${index}]`));
  const contextKeys = new Set();
  for (const item of contexts) {
    const key = contextKey(item);
    if (contextKeys.has(key)) throw new Error("Configuration.surreal.contexts must not contain duplicates");
    contextKeys.add(key);
  }
  if (defaultContext && !contextKeys.has(contextKey(defaultContext))) contexts.push(defaultContext);
  surreal.defaultContext = defaultContext;
  surreal.contexts = contexts;

  const runtimeInput = requireRecord(input.runtime, "Configuration.runtime");
  assertOnlyKeys(runtimeInput, ["url", "secret"], "Configuration.runtime");
  const runtime = {
    url: validateUrl(optionalString(runtimeInput.url, "REBASE_RUNTIME_URL"), "REBASE_RUNTIME_URL", ["http:", "https:"]),
    secret: optionalString(runtimeInput.secret, "REBASE_RUNTIME_SECRET", { allowWhitespace: true }),
  };
  if (Boolean(runtime.url) !== Boolean(runtime.secret)) {
    throw new Error("REBASE_RUNTIME_URL and REBASE_RUNTIME_SECRET must be provided together");
  }

  const queueInput = requireRecord(input.queue, "Configuration.queue");
  assertOnlyKeys(queueInput, ["prefix", "redis", "startupTimeoutMs", "healthTimeoutMs"], "Configuration.queue");
  const prefix = requiredString(queueInput.prefix, "REBASE_QUEUE_PREFIX");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(prefix)) throw new Error("REBASE_QUEUE_PREFIX contains unsupported characters");

  const redisInput = requireRecord(queueInput.redis, "Configuration.queue.redis");
  assertOnlyKeys(redisInput, ["url", "connectTimeoutMs"], "Configuration.queue.redis");
  const redis = {
    url: validateUrl(optionalString(redisInput.url, "REBASE_QUEUE_REDIS_URL"), "REBASE_QUEUE_REDIS_URL", ["redis:", "rediss:"]),
    connectTimeoutMs: integer(redisInput.connectTimeoutMs, "REBASE_QUEUE_REDIS_CONNECT_TIMEOUT_MS", 1),
  };

  const storageInput = requireRecord(input.storage, "Configuration.storage");
  assertOnlyKeys(storageInput, ["bucket"], "Configuration.storage");
  const storage = { bucket: optionalString(storageInput.bucket, "REBASE_STORAGE_BUCKET") };

  const authInput = requireRecord(input.authentication, "Configuration.authentication");
  assertOnlyKeys(authInput, ["payloadSecret", "challengeTtlMs", "rateLimits"], "Configuration.authentication");
  const limitsInput = requireRecord(authInput.rateLimits, "Configuration.authentication.rateLimits");
  assertOnlyKeys(limitsInput, ["windowMs", "ip", "identifier"], "Configuration.authentication.rateLimits");
  const authentication = {
    payloadSecret: optionalString(authInput.payloadSecret, "REBASE_AUTHENTICATION_PAYLOAD_SECRET", { allowWhitespace: true }),
    challengeTtlMs: integer(authInput.challengeTtlMs, "REBASE_AUTHENTICATION_CHALLENGE_TTL_MS", 60000, 86400000),
    rateLimits: {
      windowMs: integer(limitsInput.windowMs, "REBASE_AUTHENTICATION_RATE_LIMIT_WINDOW_MS", 1000),
      ip: integer(limitsInput.ip, "REBASE_AUTHENTICATION_RATE_LIMIT_IP", 1),
      identifier: integer(limitsInput.identifier, "REBASE_AUTHENTICATION_RATE_LIMIT_IDENTIFIER", 1),
    },
  };

  const webhooks = requireRecord(input.webhooks, "Configuration.webhooks");
  assertOnlyKeys(webhooks, [], "Configuration.webhooks");

  return deepFreeze({
    environment,
    server,
    surreal,
    runtime,
    queue: {
      prefix,
      redis,
      startupTimeoutMs: integer(queueInput.startupTimeoutMs, "REBASE_QUEUE_STARTUP_TIMEOUT_MS", 1),
      healthTimeoutMs: integer(queueInput.healthTimeoutMs, "REBASE_QUEUE_HEALTH_TIMEOUT_MS", 1),
    },
    storage,
    authentication,
    webhooks: {},
  });
}

function resolveConfiguration(values = process.env) {
  if (arguments.length > 1) {
    throw new Error("Configuration overrides are unsupported; resolve one process environment profile");
  }
  if (!isRecord(values)) throw new Error("Process environment must be an object");
  const selectedQueueDriver = envString(values, "REBASE_QUEUE_DRIVER");
  if (selectedQueueDriver && selectedQueueDriver !== "bullmq") {
    throw new Error("REBASE_QUEUE_DRIVER must be bullmq; the SQS driver was removed");
  }
  const environment = envString(values, "NODE_ENV") || DEFAULTS.environment;
  const namespace = envString(values, "SURREAL_NAMESPACE");
  const database = envString(values, "SURREAL_DATABASE");
  if (Boolean(namespace) !== Boolean(database)) {
    throw new Error("SURREAL_NAMESPACE and SURREAL_DATABASE must be provided together");
  }
  const runtimeUrl = envString(values, "REBASE_RUNTIME_URL");
  const runtimeSecret = envString(values, "REBASE_RUNTIME_SECRET", { secret: true });
  if (Boolean(runtimeUrl) !== Boolean(runtimeSecret)) {
    throw new Error("REBASE_RUNTIME_URL and REBASE_RUNTIME_SECRET must be provided together");
  }
  const defaultContext = namespace && database ? { namespace, database } : undefined;
  const contexts = parseContexts(envString(values, "REBASE_ALLOWED_CONTEXTS"));
  if (defaultContext && !contexts.some((item) => contextKey(item) === contextKey(defaultContext))) {
    contexts.push(defaultContext);
  }
  const configuration = {
    environment,
    server: {
      host: envString(values, "REBASE_HTTP_HOST") || DEFAULTS.host,
      port: envInteger(values, "REBASE_HTTP_PORT", DEFAULTS.port, 0, 65535),
      reconcileIntervalMs: envInteger(values, "REBASE_RECONCILE_INTERVAL_MS", DEFAULTS.reconcileIntervalMs, 1000),
      terminalTaskRetentionDays: envInteger(values, "REBASE_TERMINAL_TASK_RETENTION_DAYS", DEFAULTS.terminalTaskRetentionDays, 1, 3650),
      bodyLimitBytes: envInteger(values, "REBASE_HTTP_BODY_LIMIT_BYTES", DEFAULTS.bodyLimitBytes, 1),
      requestTimeoutMs: envInteger(values, "REBASE_HTTP_REQUEST_TIMEOUT_MS", DEFAULTS.requestTimeoutMs, 1),
      debug: envBoolean(values, "REBASE_HTTP_DEBUG", DEFAULTS.debug),
    },
    surreal: {
      endpoint: envString(values, "SURREAL_ENDPOINT"),
      username: envString(values, "SURREAL_USERNAME"),
      password: envString(values, "SURREAL_PASSWORD", { secret: true }),
      namespace,
      database,
      connectTimeoutMs: envInteger(values, "SURREAL_CONNECT_TIMEOUT_MS", DEFAULTS.connectTimeoutMs, 1),
      defaultContext,
      contexts,
    },
    runtime: { url: runtimeUrl, secret: runtimeSecret },
    queue: {
      prefix: envString(values, "REBASE_QUEUE_PREFIX") || DEFAULTS.queuePrefix,
      redis: {
        url: envString(values, "REBASE_QUEUE_REDIS_URL"),
        connectTimeoutMs: envInteger(values, "REBASE_QUEUE_REDIS_CONNECT_TIMEOUT_MS", DEFAULTS.redisConnectTimeoutMs, 1),
      },
      startupTimeoutMs: envInteger(values, "REBASE_QUEUE_STARTUP_TIMEOUT_MS", DEFAULTS.queueStartupTimeoutMs, 1),
      healthTimeoutMs: envInteger(values, "REBASE_QUEUE_HEALTH_TIMEOUT_MS", DEFAULTS.queueHealthTimeoutMs, 1),
    },
    storage: { bucket: envString(values, "REBASE_STORAGE_BUCKET") },
    authentication: {
      payloadSecret: envString(values, "REBASE_AUTHENTICATION_PAYLOAD_SECRET", { secret: true }),
      challengeTtlMs: envInteger(values, "REBASE_AUTHENTICATION_CHALLENGE_TTL_MS", DEFAULTS.authenticationChallengeTtlMs, 60000, 86400000),
      rateLimits: {
        windowMs: envInteger(values, "REBASE_AUTHENTICATION_RATE_LIMIT_WINDOW_MS", DEFAULTS.authenticationRateLimitWindowMs, 1000),
        ip: envInteger(values, "REBASE_AUTHENTICATION_RATE_LIMIT_IP", DEFAULTS.authenticationRateLimitIp, 1),
        identifier: envInteger(values, "REBASE_AUTHENTICATION_RATE_LIMIT_IDENTIFIER", DEFAULTS.authenticationRateLimitIdentifier, 1),
      },
    },
    webhooks: {},
  };
  return validateConfiguration(configuration);
}

function contextFromConfiguration(configuration) {
  return configuration?.surreal?.defaultContext;
}

function assertConfiguredContext(configuration, selectedContext) {
  const config = validateConfiguration(configuration);
  const selected = context(selectedContext, "Selected context");
  if (!config.surreal.contexts.some((item) => contextKey(item) === contextKey(selected))) {
    throw new Error(`Context ${selected.namespace}/${selected.database} is not configured in this process profile`);
  }
  return selected;
}

function assertConnectionConfiguration(configuration, { requireContext = true } = {}) {
  const config = validateConfiguration(configuration);
  const surreal = config.surreal;
  const missing = [];
  if (!surreal.endpoint) missing.push("SURREAL_ENDPOINT");
  if (!surreal.username) missing.push("SURREAL_USERNAME");
  if (!surreal.password) missing.push("SURREAL_PASSWORD");
  if (requireContext && !surreal.defaultContext && !surreal.contexts.length) {
    missing.push("SURREAL_NAMESPACE and SURREAL_DATABASE (or REBASE_ALLOWED_CONTEXTS)");
  }
  if (missing.length) throw new Error(`Missing configuration: ${missing.join(", ")}`);
  return config;
}

module.exports = {
  DEFAULTS,
  QUEUE_HORIZON_MS,
  assertConfiguredContext,
  assertConnectionConfiguration,
  contextFromConfiguration,
  parseContexts,
  resolveConfiguration,
  validateConfiguration,
};
