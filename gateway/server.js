#!/usr/bin/env node

const path = require("node:path");
const { once } = require("node:events");
const { serve } = require("@hono/node-server");
const { createRuntimeApp } = require("./app");
const { createSurrealStoreDirectory, fixedStoreDirectory } = require("./directory");
const { loadTableHandlers } = require("./handlers");
const { createLocalProviders } = require("./providers/local");
const { createQueue } = require("./queues");
const { createRuntime } = require("./runtime");
const { createTableStore } = require("./store");

async function startServer(options = {}) {
  const projectDir = options.projectDir || path.resolve("build", options.project || "test");
  const handlers = options.handlers || loadTableHandlers(path.join(projectDir, "table-handlers"));
  const queue = options.queue || createQueue(options.queueOptions);
  const providers = options.providers || createLocalProviders(options.providerOptions);
  const stores = options.stores || (options.database
    ? fixedStoreDirectory(options.database.store || createTableStore(options.database), options.database)
    : createSurrealStoreDirectory({ databaseOptions: options.databaseOptions }));
  const runtime = createRuntime({ handlers, providers, queue, stores });
  const stop = await queue.start(runtime.consume);
  const app = createRuntimeApp({
    handlers,
    runtime,
    wakeSecret: options.wakeSecret || process.env.REBASE_WAKE_SECRET,
    defaultContext: options.defaultContext,
  });
  const hostname = options.hostname || process.env.HOST || "127.0.0.1";
  const port = Number(options.port ?? process.env.REBASE_PORT ?? 8788);
  const server = serve({ fetch: app.fetch, hostname, port });
  if (!server.listening) await once(server, "listening");
  const listeningPort = server.address().port;
  return {
    app,
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      await stop?.();
      if (!options.queue) await queue.close?.();
      if (!options.stores) await stores.close?.();
    },
    handlers,
    hostname,
    port: listeningPort,
    queue,
    runtime,
    stores,
    server,
  };
}

if (require.main === module) {
  startServer().then((server) => {
    console.log(`ReBase runtime listening on http://${server.hostname}:${server.port}`);
  }).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { startServer };
