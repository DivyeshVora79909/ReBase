#!/usr/bin/env node

const { serve } = require("@hono/node-server");
const { createApp, defaultPaths } = require("./app");
const { createQueue } = require("./queues");
const { createLocalProviders } = require("./providers/local");
const { DatabaseRuntime } = require("./runtime/database");
const { createExecutor } = require("./runtime/executor");
const { loadHandlers } = require("./runtime/handlers");
const { createOutboxRelay } = require("./runtime/outbox");
const { createWorker } = require("./worker");

async function startServer(options = {}) {
  const paths = { ...defaultPaths(options.project), ...options.paths };
  const ownsDatabase = !options.database;
  const ownsQueue = !options.queue;
  let database = options.database;
  let queue = options.queue;
  let relay;
  let stopConsumer;
  let interval;
  let server;
  let closing;

  async function close() {
    if (closing) return closing;
    closing = (async () => {
      if (interval) clearInterval(interval);
      const tasks = [];
      if (server?.listening) {
        tasks.push(new Promise((resolve) => {
          server.close(resolve);
          server.closeIdleConnections?.();
          server.closeAllConnections?.();
        }));
      }
      if (relay) tasks.push(relay.close());
      if (stopConsumer) tasks.push(Promise.resolve().then(() => stopConsumer()));
      if (ownsQueue && queue?.close) tasks.push(queue.close());
      if (ownsDatabase && database?.close) tasks.push(database.close());
      const results = await Promise.allSettled(tasks);
      const failure = results.find((result) => result.status === "rejected");
      if (failure) throw failure.reason;
    })();
    return closing;
  }

  try {
    const handlers = options.handlers || loadHandlers(paths.projectDir);
    database ||= await DatabaseRuntime.connect(options.databaseOptions);
    queue ||= createQueue(options.queueOptions);
    const providers = options.providers || createLocalProviders(options.providerOptions);
    const executor = options.executor || createExecutor({ database, handlers, providers });
    relay = createOutboxRelay({ database, queue, batchSize: options.outboxBatchSize || 50 });
    const worker = createWorker({ database, handlers, providers, executor });
    stopConsumer = await queue.start(worker.consume);
    const intervalMs = options.outboxIntervalMs || 1000;
    interval = setInterval(() => relay.runOnce().catch((error) => console.error(`Outbox relay failed: ${error.message}`)), intervalMs);
    interval.unref?.();
    const app = createApp({ database, handlers, providers, outboxRelay: relay, executor });
    const requestedPort = Number(options.port ?? process.env.PORT ?? 8787);
    const hostname = options.hostname || process.env.HOST || "127.0.0.1";
    const address = await new Promise((resolve, reject) => {
      const onError = (error) => reject(error);
      server = serve({ fetch: app.fetch, port: requestedPort, hostname }, (info) => {
        server.off("error", onError);
        resolve(info);
      });
      server.once("error", onError);
    });
    return {
      app,
      close,
      database,
      handlers,
      hostname,
      port: address.port,
      queue,
      relay,
      server,
      worker,
    };
  } catch (error) {
    await close().catch((cleanupError) => {
      if (error && typeof error === "object") error.cleanupError = cleanupError;
    });
    throw error;
  }
}

if (require.main === module) {
  startServer().then((runtime) => {
    console.log(`ReBase gateway listening on http://${runtime.hostname}:${runtime.port}`);
    const shutdown = async () => {
      try {
        await runtime.close();
      } finally {
        process.exit(0);
      }
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  }).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { startServer };
