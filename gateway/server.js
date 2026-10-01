#!/usr/bin/env node

const fs = require("node:fs");
const { createServer } = require("node:http");
const path = require("node:path");
const { once } = require("node:events");
const { createAuthenticationService } = require("./authentication");
const { createAuthenticationPayloadCipher } = require("./authentication-payload");
const { createRuntimeApp } = require("./app");
const {
  createSurrealStoreDirectory,
  fixedStoreDirectory,
} = require("./directory");
const { loadTableHandlers } = require("./handlers");
const { createOAuthVerifier } = require("./oauth");
const { createMemoryRateLimiter, createRedisRateLimiter } = require("./rate-limit");
const { createWebhookRouteCodec } = require("./webhook-routes");
const { loadWebhookHandlers } = require("./webhooks");
const { createAdapters, createWebhookAdapters } = require("./providers");
const { createQueue } = require("./queues");
const { createReconciler } = require("./reconciler");
const { createRuntime } = require("./runtime");
const { createTableStore } = require("./store");
const {
  resolveConfiguration,
  assertConnectionConfiguration,
  validateConfiguration,
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
  for (const key of [
    "environment",
    "allowBearer",
    "endpoint",
    "username",
    "password",
    "databaseOptions",
    "namespace",
    "defaultContext",
    "contexts",
    "runtimeSecret",
    "hostname",
    "port",
    "queueDriver",
    "queueOptions",
    "storageBucket",
    "authenticationPayloadSecret",
    "reconcileIntervalMs",
    "bodyLimitBytes",
    "requestTimeoutMs",
    "debug",
  ]) {
    if (Object.hasOwn(options, key)) {
      throw new Error(`${key} is process-profile configuration and cannot be overridden`);
    }
  }
  const config = validateConfiguration(options.config || resolveConfiguration(process.env));
  if (!options.stores && !options.database) assertConnectionConfiguration(config);
  const connectionConfig = config;
  const environment = config.environment;
  const allowBearer = environment === "development";
  const runtimeSecret = config.runtime.secret;
  if (!runtimeSecret) throw new Error("REBASE_RUNTIME_SECRET is required");
  const hostname = config.server.host;
  const port = config.server.port;
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
  const authenticationPayloadSecret = config.authentication.payloadSecret;
  if (loaded.principals?.user && environment === "production"
    && !authenticationPayloadSecret && !options.authenticationPayloadCipher) {
    throw new Error("REBASE_AUTHENTICATION_PAYLOAD_SECRET is required in production");
  }
  if (loaded.principals?.user && environment === "production"
    && authenticationPayloadSecret && Buffer.byteLength(String(authenticationPayloadSecret)) < 32) {
    throw new Error("REBASE_AUTHENTICATION_PAYLOAD_SECRET must be at least 32 bytes in production");
  }
  const authenticationPayloadCipher = options.authenticationPayloadCipher
    || createAuthenticationPayloadCipher(authenticationPayloadSecret || runtimeSecret);
  const oauth = options.oauth || createOAuthVerifier(options.oauthProviders, {
    onError: options.onOAuthError,
  });
  const storageBucket = config.storage.bucket;
  const adapterSet = options.adapters || createAdapters({
    ...(options.adapterOptions || {}),
    fetch: options.fetch,
    storageBucket,
    authenticationPayloadCipher,
    overrides: options.adapterOverrides,
  });
  const adapters = Object.freeze({
    ...adapterSet,
    openAuthenticationPayload: adapterSet.openAuthenticationPayload || authenticationPayloadCipher.open,
  });
  const webhookAdapters = options.webhookAdapters || createWebhookAdapters({
    overrides: options.webhookAdapterOverrides,
  });
  const queue = options.queue || createQueue({
    bullmq: {
      url: config.queue.redis.url,
      prefix: config.queue.prefix,
      connectTimeoutMs: config.queue.redis.connectTimeoutMs,
      startupTimeoutMs: config.queue.startupTimeoutMs,
      healthTimeoutMs: config.queue.healthTimeoutMs,
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
          databaseOptions: connectionConfig.surreal,
        }));
  const runtimeOptions = { ...(options.runtimeOptions || {}) };
  let defaultContext = config.surreal.defaultContext || {};
  const configuredContexts = [...config.surreal.contexts];
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
  if (rateLimiter === undefined && loaded.principals?.user) {
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
      throw new Error("REBASE_QUEUE_REDIS_URL is required for production authentication rate limiting");
    }
    ownsRateLimiter = true;
  }
  const authentication = options.authentication || (loaded.principals?.user
    ? createAuthenticationService({
        stores,
        principals: loaded.principals,
        allowedContexts: configuredContexts,
        sealAuthenticationPayload: authenticationPayloadCipher.seal,
        rateLimiter,
        challengeTtlMs: config.authentication?.challengeTtlMs,
        rateLimits: config.authentication?.rateLimits,
        onError: options.onAuthenticationError,
      })
    : null);
  runtimeOptions.allowedContexts = configuredContexts;
  runtimeOptions.terminalTaskRetentionMs = config.server.terminalTaskRetentionDays * 24 * 60 * 60 * 1000;
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
    workerStops.push(await queue.start((delivery) => runtime.consume(delivery)));
    reconciler = createReconciler({
      runtime,
      contexts: configuredContexts,
      intervalMs: config.server.reconcileIntervalMs,
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
      authentication,
      oauth,
      queue,
      runtime,
      runtimeSecret,
      defaultContext,
      readinessContexts: configuredContexts,
      allowBearer,
      // Generated SurrealDB events authenticate with the shared runtime secret.
      allowInternalBearer: true,
      bodyLimitBytes: config.server.bodyLimitBytes,
      requestTimeoutMs: config.server.requestTimeoutMs,
      debug: config.server.debug,
    });
    server = createServer(app);
    server.requestTimeout = config.server.requestTimeoutMs;
    server.headersTimeout = Math.max(1000, Math.min(60000, server.requestTimeout));
    server.keepAliveTimeout = 5000;
    server.listen(port, hostname);
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
    authentication,
    close,
    contracts: loaded.contracts,
    handlers,
    webhooks,
    hostname,
    oauth,
    adapters,
    webhookAdapters,
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
  const applicationArgs = process.argv.slice(2);
  if (applicationArgs.length) {
    console.error(
      `Unexpected runtime arguments: ${applicationArgs.join(" ")}. Use Node options before gateway/server.js; configuration is read from process.env.`,
    );
    process.exitCode = 1;
  } else {
    const config = resolveConfiguration(process.env);
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
}

module.exports = { readContracts, startServer };
