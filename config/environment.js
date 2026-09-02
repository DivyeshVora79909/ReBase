const fs = require("node:fs");
const path = require("node:path");

const DEFAULTS = Object.freeze({
  environment: "development",
  host: "127.0.0.1",
  port: 8788,
  connectTimeoutMs: 10000,
  reconcileIntervalMs: 30 * 60 * 1000,
  redisConnectTimeoutMs: 5000,
  queueStartupTimeoutMs: 10000,
  queueHealthTimeoutMs: 2000,
  queuePrefix: "rebase",
  bodyLimitBytes: 256 * 1024,
  requestTimeoutMs: 30000,
  platformEmailFrom: "ReBase <onboarding@resend.dev>",
  recoveryRateLimitWindowMs: 15 * 60 * 1000,
  recoveryRateLimitIp: 10,
  recoveryRateLimitIdentifier: 3,
  recoveryInviteTtlMs: 24 * 60 * 60 * 1000,
  queueDriver: "bullmq",
  debug: false,
});

function stripQuotes(value) {
  const text = String(value || "").trim();
  if (text.length < 2) return text;
  const quote = text[0];
  if (quote !== '"' && quote !== "'") return text;
  let escaped = false;
  for (let index = 1; index < text.length; index += 1) {
    if (text[index] === quote && !escaped) {
      const trailing = text.slice(index + 1).trim();
      if (trailing && !trailing.startsWith("#")) return text;
      const content = text.slice(1, index);
      if (quote === "'") return content.replace(/\\'/g, "'");
      return content
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t")
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, "\\");
    }
    escaped = text[index] === "\\" && !escaped;
    if (text[index] !== "\\") escaped = false;
  }
  return text;
}

function parseEnvFile(source) {
  const values = {};
  for (const rawLine of String(source || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(
      line,
    );
    if (!match) continue;
    let value = match[2].trim();
    if (!value.startsWith("'") && !value.startsWith('"')) {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    values[match[1]] = stripQuotes(value);
  }
  return values;
}

function envFileArgument(argv = []) {
  const args = [];
  let file;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--env-file") {
      if (argv[index + 1] === undefined)
        throw new Error("Missing value for --env-file");
      file = argv[++index];
      continue;
    }
    if (String(argument).startsWith("--env-file=")) {
      file = String(argument).slice("--env-file=".length);
      if (!file) throw new Error("--env-file requires a path");
      continue;
    }
    args.push(argument);
  }
  return { args, file };
}

function loadEnvironment(
  argv = [],
  { cwd = process.cwd(), baseEnv = process.env } = {},
) {
  const parsed = envFileArgument(argv);
  let fileValues = {};
  let file = null;
  if (parsed.file) {
    file = path.resolve(cwd, parsed.file);
    if (!fs.existsSync(file))
      throw new Error(`Environment file not found: ${file}`);
    fileValues = parseEnvFile(fs.readFileSync(file, "utf8"));
  }
  return {
    values: { ...(baseEnv || {}), ...fileValues },
    args: parsed.args,
    file,
  };
}

function value(values, overrides, key, overrideKey = key) {
  return overrides?.[overrideKey] ?? values?.[key];
}

function numberValue(values, overrides, key, overrideKey, fallback) {
  const raw = value(values, overrides, key, overrideKey);
  if (raw === undefined || raw === null || raw === "") return fallback;
  const result = Number(raw);
  return Number.isFinite(result) ? result : fallback;
}

function booleanValue(values, overrides, key, overrideKey, fallback) {
  const raw = value(values, overrides, key, overrideKey);
  if (raw === undefined || raw === null || raw === "") return fallback;
  if (typeof raw === "boolean") return raw;
  return /^(1|true|yes|on)$/i.test(String(raw));
}

function parseContexts(raw) {
  if (!raw) return [];
  let parsed;
  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new Error("REBASE_ALLOWED_CONTEXTS must be valid JSON");
  }
  if (!Array.isArray(parsed))
    throw new Error("REBASE_ALLOWED_CONTEXTS must be a JSON array");
  return parsed.map((context) => {
    if (!context?.namespace || !context?.database) {
      throw new Error(
        "Every REBASE_ALLOWED_CONTEXTS entry requires namespace and database",
      );
    }
    return {
      namespace: String(context.namespace),
      database: String(context.database),
    };
  });
}

function pair(
  values,
  overrides,
  leftKey,
  rightKey,
  leftOverride,
  rightOverride,
) {
  const left = value(values, overrides, leftKey, leftOverride);
  const right = value(values, overrides, rightKey, rightOverride);
  return {
    left: left ? String(left) : undefined,
    right: right ? String(right) : undefined,
  };
}

function resolveConfiguration(values = {}, overrides = {}) {
  const recoveryOverrides = overrides.accounts?.recovery || overrides.recovery || overrides;
  const environment = String(
    value(values, overrides, "NODE_ENV", "environment") || DEFAULTS.environment,
  );
  const surrealPair = pair(
    values,
    overrides,
    "SURREAL_NAMESPACE",
    "SURREAL_DATABASE",
    "namespace",
    "database",
  );
  const runtimePair = pair(
    values,
    overrides,
    "REBASE_RUNTIME_URL",
    "REBASE_RUNTIME_SECRET",
    "runtimeUrl",
    "runtimeSecret",
  );
  const defaultContext =
    overrides.defaultContext ||
    (surrealPair.left && surrealPair.right
      ? { namespace: surrealPair.left, database: surrealPair.right }
      : undefined);
  const configuredContexts =
    overrides.contexts ||
    parseContexts(value(values, overrides, "REBASE_ALLOWED_CONTEXTS", "contexts"));
  const contexts = [...configuredContexts];
  if (
    defaultContext &&
    !contexts.some(
      (item) =>
        item.namespace === defaultContext.namespace &&
        item.database === defaultContext.database,
    )
  ) {
    contexts.push(defaultContext);
  }
  return {
    environment,
    server: {
      host: String(
        value(values, overrides, "REBASE_HTTP_HOST", "hostname") || DEFAULTS.host,
      ),
      port: numberValue(
        values,
        overrides,
        "REBASE_HTTP_PORT",
        "port",
        DEFAULTS.port,
      ),
      reconcileIntervalMs: numberValue(
        values,
        overrides,
        "REBASE_RECONCILE_INTERVAL_MS",
        "reconcileIntervalMs",
        DEFAULTS.reconcileIntervalMs,
      ),
      bodyLimitBytes: numberValue(
        values,
        overrides,
        "REBASE_HTTP_BODY_LIMIT_BYTES",
        "bodyLimitBytes",
        DEFAULTS.bodyLimitBytes,
      ),
      requestTimeoutMs: numberValue(
        values,
        overrides,
        "REBASE_HTTP_REQUEST_TIMEOUT_MS",
        "requestTimeoutMs",
        DEFAULTS.requestTimeoutMs,
      ),
      debug: booleanValue(
        values,
        overrides,
        "REBASE_HTTP_DEBUG",
        "debug",
        DEFAULTS.debug,
      ),
    },
    surreal: {
      endpoint: value(values, overrides, "SURREAL_ENDPOINT", "endpoint"),
      username: value(values, overrides, "SURREAL_USERNAME", "username"),
      password: value(values, overrides, "SURREAL_PASSWORD", "password"),
      namespace: surrealPair.left,
      database: surrealPair.right,
      connectTimeoutMs: numberValue(
        values,
        overrides,
        "SURREAL_CONNECT_TIMEOUT_MS",
        "connectTimeoutMs",
        DEFAULTS.connectTimeoutMs,
      ),
      defaultContext,
      contexts,
    },
    runtime: { url: runtimePair.left, secret: runtimePair.right },
    queue: {
      driver: String(
        value(values, overrides, "REBASE_QUEUE_DRIVER", "queueDriver") ||
          DEFAULTS.queueDriver,
      ),
      prefix: String(
        value(values, overrides, "REBASE_QUEUE_PREFIX", "queuePrefix") ||
          DEFAULTS.queuePrefix,
      ),
      redis: {
        url: value(values, overrides, "REBASE_QUEUE_REDIS_URL", "redisUrl"),
        connectTimeoutMs: numberValue(
          values,
          overrides,
          "REBASE_QUEUE_REDIS_CONNECT_TIMEOUT_MS",
          "redisConnectTimeoutMs",
          DEFAULTS.redisConnectTimeoutMs,
        ),
      },
      startupTimeoutMs: numberValue(
        values,
        overrides,
        "REBASE_QUEUE_STARTUP_TIMEOUT_MS",
        "queueStartupTimeoutMs",
        DEFAULTS.queueStartupTimeoutMs,
      ),
      healthTimeoutMs: numberValue(
        values,
        overrides,
        "REBASE_QUEUE_HEALTH_TIMEOUT_MS",
        "queueHealthTimeoutMs",
        DEFAULTS.queueHealthTimeoutMs,
      ),
      sqs: {
        region: value(values, overrides, "AWS_REGION", "awsRegion"),
        endpoint: value(values, overrides, "SQS_ENDPOINT", "sqsEndpoint"),
        queueUrls: Object.fromEntries(
          ["task", "schedule", "webhook"].map((lane) => [
            lane,
            value(
              values,
              overrides,
              `REBASE_SQS_${lane.toUpperCase()}_QUEUE_URL`,
              `sqs${lane}QueueUrl`,
            ),
          ]),
        ),
        deadLetterQueueUrls: Object.fromEntries(
          ["task", "schedule", "webhook"].map((lane) => [
            lane,
            value(
              values,
              overrides,
              `REBASE_SQS_DEAD_LETTER_${lane.toUpperCase()}_QUEUE_URL`,
              `sqsDeadLetter${lane}QueueUrl`,
            ),
          ]),
        ),
      },
    },
    storage: {
      bucket: value(values, overrides, "REBASE_STORAGE_BUCKET", "storageBucket"),
    },
    platformEmail: {
      resendApiKey: overrides.platformEmail?.resendApiKey ?? value(
        values,
        overrides,
        "REBASE_PLATFORM_EMAIL_RESEND_API_KEY",
        "platformEmailResendApiKey",
      ),
      from: overrides.platformEmail?.from ?? String(
        value(values, overrides, "REBASE_PLATFORM_EMAIL_FROM", "platformEmailFrom")
          || DEFAULTS.platformEmailFrom,
      ),
    },
    accounts: {
      recovery: {
        windowMs: numberValue(
          values,
          recoveryOverrides,
          "REBASE_RECOVERY_RATE_LIMIT_WINDOW_MS",
          "windowMs",
          DEFAULTS.recoveryRateLimitWindowMs,
        ),
        ip: numberValue(
          values,
          recoveryOverrides,
          "REBASE_RECOVERY_RATE_LIMIT_IP",
          "ip",
          DEFAULTS.recoveryRateLimitIp,
        ),
        identifier: numberValue(
          values,
          recoveryOverrides,
          "REBASE_RECOVERY_RATE_LIMIT_IDENTIFIER",
          "identifier",
          DEFAULTS.recoveryRateLimitIdentifier,
        ),
        inviteTtlMs: numberValue(
          values,
          recoveryOverrides,
          "REBASE_RECOVERY_INVITE_TTL_MS",
          "inviteTtlMs",
          DEFAULTS.recoveryInviteTtlMs,
        ),
      },
    },
    webhooks: {},
  };
}

function contextFromConfiguration(config) {
  return config?.surreal?.defaultContext;
}

function assertConnectionConfiguration(config, { requireContext = true } = {}) {
  const surreal = config?.surreal || {};
  const missing = [];
  if (!surreal.endpoint) missing.push("SURREAL_ENDPOINT");
  if (!surreal.username) missing.push("SURREAL_USERNAME");
  if (!surreal.password) missing.push("SURREAL_PASSWORD");
  if (requireContext && !surreal.defaultContext && !surreal.contexts?.length) {
    missing.push("SURREAL_NAMESPACE and SURREAL_DATABASE (or REBASE_ALLOWED_CONTEXTS)");
  }
  if (missing.length)
    throw new Error(`Missing configuration: ${missing.join(", ")}`);
  return config;
}

module.exports = {
  DEFAULTS,
  assertConnectionConfiguration,
  contextFromConfiguration,
  envFileArgument,
  loadEnvironment,
  parseContexts,
  parseEnvFile,
  resolveConfiguration,
};
