#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { once } = require("node:events");
const { serve } = require("@hono/node-server");
const { createRuntimeApp } = require("./app");
const {
  createSurrealStoreDirectory,
  fixedStoreDirectory,
} = require("./directory");
const { loadTableHandlers } = require("./handlers");
const {
  DEFAULT_PROVIDER_ADAPTER,
  resolveProviderAdapter,
} = require("./providers");
const { createQueue } = require("./queues");
const { createReconciler } = require("./reconciler");
const { createRuntime } = require("./runtime");
const { createTableStore } = require("./store");

function readContracts(projectDir) {
  const contractPath = path.join(projectDir, "runtime-contracts.json");
  if (!fs.existsSync(contractPath))
    throw new Error(`Missing compiled runtime contract: ${contractPath}`);
  const parsed = JSON.parse(fs.readFileSync(contractPath, "utf8"));
  return {
    contractPath,
    contracts: new Map(Object.entries(parsed.tables || {})),
  };
}

function contextsFromEnvironment(value = process.env.REBASE_CONTEXTS) {
  if (!value) return [];
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("REBASE_CONTEXTS must be valid JSON");
  }
  if (!Array.isArray(parsed))
    throw new Error("REBASE_CONTEXTS must be a JSON array");
  return parsed.map((context) => {
    if (!context?.namespace || !context?.database)
      throw new Error(
        "Every REBASE_CONTEXTS entry requires namespace and database",
      );
    return {
      namespace: String(context.namespace),
      database: String(context.database),
    };
  });
}

async function startServer(options = {}) {
  const environment =
    options.environment || process.env.NODE_ENV || "development";
  const allowBearer =
    environment === "production"
      ? false
      : (options.allowBearer ?? environment === "development");
  const wakeSecret = options.wakeSecret || process.env.REBASE_WAKE_SECRET;
  if (!wakeSecret) throw new Error("REBASE_WAKE_SECRET is required");
  const hostname = options.hostname || process.env.HOST || "127.0.0.1";
  const port = Number(options.port ?? process.env.REBASE_PORT ?? 8788);
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new Error("REBASE_PORT must be a valid TCP port");
  const projectDir =
    options.projectDir || path.resolve("build", options.project || "test");
  const loaded = options.contracts
    ? { contracts: options.contracts, contractPath: options.contractPath }
    : readContracts(projectDir);
  const handlers =
    options.handlers ||
    loadTableHandlers(path.join(projectDir, "table-handlers"), loaded);
  const providerSelection =
    options.providers ??
    options.provider ??
    process.env.REBASE_PROVIDER ??
    DEFAULT_PROVIDER_ADAPTER;
  const providers = resolveProviderAdapter(
    providerSelection,
    options.providerOptions,
  );
  if (environment === "production" && providers.developmentOnly) {
    throw new Error("Development-only providers are not allowed in production");
  }
  const queue = options.queue || createQueue(options.queueOptions || {});
  const stores =
    options.stores ||
    (options.database
      ? fixedStoreDirectory(
          options.database.store || createTableStore(options.database),
          options.database,
        )
      : createSurrealStoreDirectory({
          databaseOptions: options.databaseOptions,
        }));
  const runtimeOptions = { ...(options.runtimeOptions || {}) };
  let defaultContext = options.defaultContext || {
    namespace: process.env.REBASE_NAMESPACE,
    database: process.env.REBASE_DATABASE,
  };
  const configuredContexts =
    options.contexts ||
    contextsFromEnvironment() ||
    (defaultContext.namespace && defaultContext.database
      ? [defaultContext]
      : []);
  if (
    !configuredContexts.length &&
    defaultContext.namespace &&
    defaultContext.database
  )
    configuredContexts.push(defaultContext);
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
  runtimeOptions.allowedContexts ||= configuredContexts;
  const runtime = createRuntime({
    handlers,
    providers,
    queue,
    stores,
    contracts: loaded.contracts,
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
        options.reconcileIntervalMs ||
        Number(process.env.REBASE_RECONCILE_INTERVAL_MS) ||
        30 * 60 * 1000,
      onError: options.onReconcileError,
    });
    stopReconciler = reconciler.start({
      immediate: options.reconcileOnStartup !== false,
    });
    app = createRuntimeApp({
      handlers,
      providers,
      queue,
      runtime,
      wakeSecret,
      defaultContext,
      readinessContexts: configuredContexts,
      resolveWebhookContext: options.resolveWebhookContext,
      allowBearer,
      bodyLimitBytes: options.bodyLimitBytes,
      requestTimeoutMs: options.requestTimeoutMs,
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
      if (!options.queue) await queue.close();
      if (!options.stores) await stores.close?.();
    })();
    return closing;
  };
  return {
    app,
    close,
    contracts: loaded.contracts,
    handlers,
    hostname,
    port: listeningPort,
    queue,
    reconciler,
    runtime,
    stores,
    server,
  };
}

if (require.main === module) {
  startServer()
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

module.exports = { contextsFromEnvironment, readContracts, startServer };
