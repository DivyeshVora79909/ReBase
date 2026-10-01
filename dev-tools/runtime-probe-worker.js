#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { Surreal } = require("surrealdb");
const { loadTableHandlers } = require("../gateway/handlers");
const { createAdapters } = require("../gateway/providers");
const { createRuntime } = require("../gateway/runtime");
const { createTableStore } = require("../gateway/store");

async function main() {
  const required = [
    "SURREAL_ENDPOINT",
    "SURREAL_USERNAME",
    "SURREAL_PASSWORD",
    "SURREAL_NAMESPACE",
    "SURREAL_DATABASE",
    "REBASE_WORKER_PROVIDER_URL",
  ];
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length) throw new Error(`Missing worker probe settings: ${missing.join(", ")}`);

  const projectDirectory = path.resolve(__dirname, "../build/test");
  const runtimeContracts = JSON.parse(fs.readFileSync(path.join(projectDirectory, "runtime-contracts.json"), "utf8"));
  const contracts = new Map(Object.entries(runtimeContracts.tables || {}));
  const handlers = loadTableHandlers(path.join(projectDirectory, "table-handlers"), { contracts });
  const db = new Surreal();
  await db.connect(process.env.SURREAL_ENDPOINT);
  await db.signin({ username: process.env.SURREAL_USERNAME, password: process.env.SURREAL_PASSWORD });
  await db.use({ namespace: process.env.SURREAL_NAMESPACE, database: process.env.SURREAL_DATABASE });

  const runtime = createRuntime({
    database: createTableStore({ db }),
    handlers,
    contracts,
    adapters: createAdapters({ brevoEndpoint: process.env.REBASE_WORKER_PROVIDER_URL }),
    queue: { async publish() { return { queued: true, jobId: "runtime-probe-worker" }; } },
    options: {
      leaseMs: Number(process.env.REBASE_WORKER_LEASE_MS || 750),
      allowedContexts: [{
        namespace: process.env.SURREAL_NAMESPACE,
        database: process.env.SURREAL_DATABASE,
      }],
    },
  });

  process.send?.({ type: "ready" });
  process.on("message", async (message) => {
    if (message?.type !== "run" || typeof message.taskId !== "string") return;
    try {
      const result = await runtime.execute({
        namespace: process.env.SURREAL_NAMESPACE,
        database: process.env.SURREAL_DATABASE,
        id: message.taskId,
      });
      process.send?.({ type: "done", result });
    } catch (error) {
      process.send?.({ type: "error", message: String(error?.message || error) });
    }
  });
}

main().catch((error) => {
  process.send?.({ type: "error", message: String(error?.stack || error) });
  process.exitCode = 1;
});
