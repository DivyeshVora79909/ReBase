#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { once } = require("node:events");
const { serve } = require("@hono/node-server");
const { createAccountService } = require("./accounts");
const { createRuntimeApp } = require("./app");
const {
  createSurrealStoreDirectory,
  fixedStoreDirectory,
} = require("./directory");
const { loadTableHandlers } = require("./handlers");
const { createOAuthVerifier } = require("./oauth");
const { createMemoryRateLimiter, createRedisRateLimiter } = require("./rate-limit");
const { createResendPlatformEmailAdapter } = require("./providers/resend-platform-email.adapter");
const { createWebhookRouteCodec } = require("./webhook-routes");
const { loadWebhookHandlers } = require("./webhooks");
const { createAdapters, createWebhookAdapters } = require("./providers");
const { createQueue } = require("./queues");
const { createReconciler } = require("./reconciler");
const { createRuntime } = require("./runtime");
const { createTableStore } = require("./store");
const {
  loadEnvironment,
  resolveConfiguration,
  assertConnectionConfiguration,
} = require("../config/environment");

function readContracts(projectDir) {
  const contractPath = path.join(projectDir, "runtime-contracts.json");
  if (!fs.existsSync(contractPath))
    throw new Error(`Missing compiled runtime contract: ${contractPath}`);
  const parsed = JSON.parse(fs.readFileSync(contractPath, "utf8"));
  return {
    contractPath,
    contracts: new Map(Object.entries(parsed.tables || {})),
    principals: parsed.principals,
    webhookContracts: new Map(Object.entries(parsed.webhooks || {})),
  };
}

async function startServer(options = {}) {
  const config = options.config || resolveConfiguration({}, options);
  const databaseOptions = options.databaseOptions || {};
  const optionContext = options.defaultContext || (
    options.namespace && options.database
      ? { namespace: options.namespace, database: options.database }
      : undefined
  );
  const connectionConfig = {
    ...config,
    surreal: {
      ...config.surreal,
      ...databaseOptions,
      endpoint: options.endpoint ?? databaseOptions.endpoint ?? config.surreal.endpoint,
      username: options.username ?? databaseOptions.username ?? config.surreal.username,
      password: options.password ?? databaseOptions.password ?? config.surreal.password,
      defaultContext: optionContext || config.surreal.defaultContext,
    },
  };
  if (!options.stores && !options.database) assertConnectionConfiguration(connectionConfig);
  const environment = options.environment || config.environment;
  const allowBearer =
    environment === "production"
      ? false
      : (options.allowBearer ?? environment === "development");
  const runtimeSecret = options.runtimeSecret || config.runtime.secret;
  if (!runtimeSecret) throw new Error("REBASE_RUNTIME_SECRET is required");
  const hostname = options.hostname || config.server.host;
  const port = Number(options.port ?? config.server.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new Error("REBASE_HTTP_PORT must be a valid TCP port");
  const projectDir =
    options.projectDir || path.resolve("build", options.project || "test");
  const loaded = options.contracts
    ? {
        contracts: options.contracts,
        contractPath: options.contractPath,
        principals: options.principals,
        webhookContracts: options.webhookContracts || new Map(),
      }
    : readContracts(projectDir);
  const handlers =
    options.handlers ||
    loadTableHandlers(path.join(projectDir, "table-handlers"), loaded);
  const webhooks = options.webhooks || loadWebhookHandlers(
    path.join(projectDir, "webhook-handlers"),
    { contracts: loaded.webhookContracts },
  );
  const sendPlatformEmail = options.sendPlatformEmail === undefined
    ? (config.platformEmail?.resendApiKey
        ? createResendPlatformEmailAdapter({
            apiKey: config.platformEmail.resendApiKey,
            from: config.platformEmail.from,
            fetch: options.fetch,
          })
        : null)
    : options.sendPlatformEmail;
  const oauth = options.oauth || createOAuthVerifier(options.oauthProviders, {
    onError: options.onOAuthError,
  });
  const storageBucket = options.storageBucket ?? config.storage?.bucket;
  const adapters = options.adapters || createAdapters({
    ...(options.adapterOptions || {}),
    fetch: options.fetch,
    storageBucket,
    overrides: options.adapterOverrides,
  });
  const webhookAdapters = options.webhookAdapters || createWebhookAdapters({
    overrides: options.webhookAdapterOverrides,
  });
  const queueOptions = options.queueOptions || {};
  const queue = options.queue || createQueue({
    driver: options.queueDriver ?? queueOptions.driver ?? config.queue.driver,
    bullmq: {
      ...config.queue,
      ...config.queue.redis,
      ...queueOptions,
      ...(options.queueOptions?.bullmq || {}),
    },
    sqs: {
      ...config.queue.sqs,
      ...queueOptions,
      ...(options.queueOptions?.sqs || {}),
    },
  });
  const stores =
    options.stores ||
    (options.database
      ? fixedStoreDirectory(
          options.database.store || createTableStore(options.database),
          options.database,
        )
      : createSurrealStoreDirectory({
          databaseOptions: {
            ...connectionConfig.surreal,
            ...databaseOptions,
          },
        }));
  const runtimeOptions = { ...(options.runtimeOptions || {}) };
  let defaultContext = options.defaultContext || {
    namespace: options.namespace ?? config.surreal.defaultContext?.namespace,
    database: options.database ?? config.surreal.defaultContext?.database,
  };
  const configuredContexts = [...(options.contexts ?? config.surreal.contexts ?? [])];
  if (defaultContext.namespace && defaultContext.database && !configuredContexts.some(
    (context) => context.namespace === defaultContext.namespace
      && context.database === defaultContext.database,
  )) {
    configuredContexts.push(defaultContext);
  }
  if (
    (!defaultContext.namespace || !defaultContext.database) &&
    configuredContexts.length === 1
  ) {
    defaultContext = configuredContexts[0];
  }
  if (environment === "production" && !configuredContexts.length) {
    if (!options.queue) await queue.close().catch(() => {});
    if (!options.stores) await stores.close?.().catch(() => {});
    throw new Error(
      "At least one configured namespace/database context is required in production",
    );
  }
  let rateLimiter = options.rateLimiter;
  let ownsRateLimiter = false;
  if (rateLimiter === undefined && sendPlatformEmail) {
    if (config.queue.redis.url) {
      rateLimiter = createRedisRateLimiter({
        url: config.queue.redis.url,
        prefix: `${config.queue.prefix}:anonymous`,
        connectTimeoutMs: config.queue.redis.connectTimeoutMs,
      });
    } else if (environment !== "production") {
      rateLimiter = createMemoryRateLimiter();
    } else {
      if (!options.queue) await queue.close().catch(() => {});
      if (!options.stores) await stores.close?.().catch(() => {});
      throw new Error("REBASE_QUEUE_REDIS_URL is required for production account recovery rate limiting");
    }
    ownsRateLimiter = true;
  }
  if (sendPlatformEmail && !loaded.principals?.user && !options.accounts) {
    if (ownsRateLimiter) await rateLimiter.close?.().catch(() => {});
    if (!options.queue) await queue.close().catch(() => {});
    if (!options.stores) await stores.close?.().catch(() => {});
    throw new Error("Compiled principal metadata is required for account recovery");
  }
  const accounts = options.accounts || (loaded.principals?.user
    ? createAccountService({
        stores,
        principals: loaded.principals,
        allowedContexts: configuredContexts,
        sendEmail: sendPlatformEmail,
        rateLimiter,
        inviteTtlMs: config.accounts?.recovery?.inviteTtlMs,
        rateLimits: config.accounts?.recovery,
        onError: options.onRecoveryError,
      })
    : null);
  runtimeOptions.allowedContexts ||= configuredContexts;
  const routeCodec = options.routeCodec || createWebhookRouteCodec(runtimeSecret);
  const runtime = createRuntime({
    handlers,
    webhooks,
    adapters,
    webhookAdapters,
    queue,
    stores,
    contracts: loaded.contracts,
    routeCodec,
    options: runtimeOptions,
  });
  const workerStops = [];
  let reconciler;
  let stopReconciler;
  let server;
  let app;
  try {
    for (const lane of ["task", "schedule", "webhook"]) {
      workerStops.push(
        await queue.start(lane, (delivery) => runtime.consume(lane, delivery)),
      );
    }
    reconciler = createReconciler({
      runtime,
      contexts: configuredContexts,
      intervalMs:
        options.reconcileIntervalMs ?? config.server.reconcileIntervalMs,
      onError: options.onReconcileError,
    });
    stopReconciler = reconciler.start({
      immediate: options.reconcileOnStartup !== false,
    });
    app = createRuntimeApp({
      handlers,
      webhooks,
      adapters,
      webhookAdapters,
      adapterConfiguration: {
        storageBucket,
        requiresStorageBucket: options.adapters === undefined,
      },
      accounts,
      oauth,
      queue,
      runtime,
      runtimeSecret,
      defaultContext,
      readinessContexts: configuredContexts,
      allowBearer,
      bodyLimitBytes: options.bodyLimitBytes ?? config.server.bodyLimitBytes,
      requestTimeoutMs: options.requestTimeoutMs ?? config.server.requestTimeoutMs,
      debug: options.debug ?? config.server.debug,
    });
    server = serve({ fetch: app.fetch, hostname, port });
    if (!server.listening)
      await Promise.race([
        once(server, "listening"),
        once(server, "error").then(([error]) => Promise.reject(error)),
      ]);
  } catch (error) {
    await stopReconciler?.().catch(() => {});
    await Promise.all(workerStops.map((stop) => stop?.().catch(() => {})));
    if (ownsRateLimiter) await rateLimiter.close?.().catch(() => {});
    if (!options.queue) await queue.close().catch(() => {});
    if (!options.stores) await stores.close?.().catch(() => {});
    throw error;
  }
  const listeningPort = server.address().port;
  let closing = null;
  const close = () => {
    if (closing) return closing;
    closing = (async () => {
      await new Promise((resolve) => server.close(resolve));
      await stopReconciler?.();
      await Promise.all(workerStops.map((stop) => stop?.()));
      if (ownsRateLimiter) await rateLimiter.close?.();
      if (!options.queue) await queue.close();
      if (!options.stores) await stores.close?.();
    })();
    return closing;
  };
  return {
    app,
    accounts,
    close,
    contracts: loaded.contracts,
    handlers,
    webhooks,
    hostname,
    oauth,
    adapters,
    webhookAdapters,
    sendPlatformEmail,
    port: listeningPort,
    queue,
    rateLimiter,
    reconciler,
    runtime,
    stores,
    server,
  };
}

if (require.main === module) {
  const loaded = loadEnvironment(process.argv.slice(2));
  const config = resolveConfiguration(loaded.values);
  startServer({ config })
    .then((server) => {
      const shutdown = async (signal) => {
        try {
          await server.close();
          process.exitCode = 0;
        } catch (error) {
          console.error(error);
          process.exitCode = 1;
        } finally {
          if (signal) process.exit();
        }
      };
      process.once("SIGTERM", () => shutdown("SIGTERM"));
      process.once("SIGINT", () => shutdown("SIGINT"));
      console.log(
        `ReBase runtime listening on http://${server.hostname}:${server.port}`,
      );
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}

module.exports = { readContracts, startServer };
