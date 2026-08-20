const { RuntimeError, runtimeError } = require("./errors");
const { tableFromId } = require("./handlers");
const { withTimeout } = require("./utils");

const TERMINAL_STATES = new Set(["succeeded", "failed", "cancelled"]);

function createRuntime({ database, stores, queue, handlers, providers }) {
  const directory = stores || {
    async forContext() { return database.store || database; },
  };

  function storeFor(namespace, databaseName) {
    return directory.forContext(namespace, databaseName);
  }

  function resolve(id) {
    const table = tableFromId(id);
    const handler = table && handlers.get(table);
    if (!table || !handler) throw new RuntimeError("TABLE_HANDLER_NOT_FOUND", `No handler for ${table || id}`, 404);
    return { table, handler };
  }

  function boundedPatch(handler, value, maximumBytes = 64 * 1024) {
    const patch = value && typeof value === "object" && !Array.isArray(value) ? value : {};
    const unknown = Object.keys(patch).find((field) => !handler.outputs.includes(field));
    if (unknown) throw new RuntimeError("PATCH_FIELD_FORBIDDEN", `Handler cannot patch ${unknown}`, 500);
    if (Buffer.byteLength(JSON.stringify(patch)) > maximumBytes) {
      throw new RuntimeError("PATCH_TOO_LARGE", "Handler patch is too large", 500);
    }
    return structuredClone(patch);
  }

  function failurePatch(handler, error) {
    const patch = {};
    if (handler.outputs.includes("effect_state")) patch.effect_state = error.retryable ? "waiting" : "failed";
    if (handler.outputs.includes("error_code")) patch.error_code = error.code || "TABLE_HANDLER_FAILED";
    if (handler.outputs.includes("error_message")) patch.error_message = error.message;
    return patch;
  }

  async function invoke(handler, method, input) {
    const fn = handler.implementation[method] || handler.implementation.execute;
    return withTimeout(handler.timeoutMs, (signal) => fn({ ...input, signal }));
  }

  async function sync({ namespace, database: databaseName, id, event = "CREATE", record }) {
    const { table, handler } = resolve(id);
    if (handler.process !== "sync") throw new RuntimeError("TABLE_PROCESS_MISMATCH", `${table} is not synchronous`, 409);
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new RuntimeError("SYNC_SNAPSHOT_REQUIRED", "A synchronous snapshot is required", 400);
    }
    if (String(record.id) !== String(id)) throw new RuntimeError("SYNC_SNAPSHOT_MISMATCH", "Snapshot ID does not match the locator", 400);
    const store = await storeFor(namespace, databaseName);
    const result = await invoke(handler, "execute", {
      context: { namespace, database: databaseName, event, id: String(id), table },
      record,
      load: store.load,
      providers,
    });
    return boundedPatch(handler, result?.patch || {});
  }

  async function asyncEffect({ namespace, database: databaseName, id }, { recoverProcessing = false } = {}) {
    const { table, handler } = resolve(id);
    if (handler.process !== "async") throw new RuntimeError("TABLE_PROCESS_MISMATCH", `${table} is not asynchronous`, 409);
    const store = await storeFor(namespace, databaseName);
    let record = await store.load(id);
    if (!record) return { state: "missing", id: String(id), table };
    if (TERMINAL_STATES.has(record.effect_state)) return { state: "terminal", id: String(id), table };
    if (["pending", "waiting"].includes(record.effect_state)) {
      record = await store.claim(id);
      if (!record) return { state: "claimed", id: String(id), table };
    } else if (record.effect_state === "processing" && !recoverProcessing) {
      return { state: "processing", id: String(id), table };
    }
    const result = await invoke(handler, "execute", {
      context: { namespace, database: databaseName, event: "ASYNC", id: String(id), table },
      record,
      load: store.load,
      providers,
    });
    const patch = boundedPatch(handler, result?.patch || {});
    if (Object.keys(patch).length) await store.patch(id, patch);
    return { state: "handled", id: String(id), table, patch };
  }

  async function enqueue(locator) {
    if (!queue) throw new Error("Runtime queue is not configured");
    return queue.publish({ namespace: locator.namespace, database: locator.database, id: String(locator.id) });
  }

  async function consume(delivery) {
    const envelope = delivery.envelope || delivery;
    let handler;
    try {
      handler = resolve(envelope.id).handler;
      await asyncEffect(envelope, { recoverProcessing: Number(delivery.attempts || 1) > 1 });
      return { action: "ack" };
    } catch (error) {
      if (process.env.REBASE_RUNTIME_DEBUG) console.error("runtime consume failed", error);
      const normalized = runtimeError(error);
      const store = await storeFor(envelope.namespace, envelope.database).catch(() => null);
      const current = store ? await store.load(envelope.id).catch(() => null) : null;
      if (handler && current?.effect_state && !TERMINAL_STATES.has(current.effect_state)) {
        const patch = failurePatch(handler, normalized);
        if (Object.keys(patch).length) await store.patch(envelope.id, patch).catch(() => {});
      }
      if (normalized.retryable) return { action: "retry", delaySeconds: normalized.delaySeconds || 0 };
      return { action: "dead-letter", reason: normalized.code || "TABLE_HANDLER_FAILED" };
    }
  }

  async function reconcile({ namespace, database: databaseName } = {}) {
    const store = await storeFor(namespace, databaseName);
    const tables = handlers.list().filter((handler) => handler.process === "async").map((handler) => handler.table);
    const ids = await store.pending(tables);
    for (const id of ids) await enqueue({ namespace, database: databaseName, id });
    return { queued: ids.length, ids };
  }

  async function webhook({ namespace, database: databaseName, table, payload, request, rawBody }) {
    const handler = handlers.get(table);
    if (!handler?.implementation.webhook) throw new RuntimeError("TABLE_WEBHOOK_NOT_FOUND", `No webhook for ${table}`, 404);
    const verified = await handler.implementation.verify({ request, rawBody, payload, providers });
    if (!verified) throw new RuntimeError("INVALID_WEBHOOK", "Invalid webhook signature or payload", 401);
    const effectiveNamespace = verified.namespace || verified.context?.namespace || namespace;
    const effectiveDatabase = verified.database || verified.context?.database || databaseName;
    if (!effectiveNamespace || !effectiveDatabase) {
      throw new RuntimeError("WEBHOOK_CONTEXT_REQUIRED", "Webhook database context is required", 400);
    }
    const store = await storeFor(effectiveNamespace, effectiveDatabase);
    const patch = (id, value) => {
      if (tableFromId(id) !== table) {
        throw new RuntimeError("WEBHOOK_RECORD_TABLE_MISMATCH", "Webhook record does not match the route table", 400);
      }
      return store.patch(id, boundedPatch(handler, value));
    };
    return invoke(handler, "webhook", {
      context: { namespace: effectiveNamespace, database: effectiveDatabase, table },
      payload: verified.payload ?? verified.args ?? payload,
      verification: verified,
      load: store.load,
      patch,
      providers,
    });
  }

  return { asyncEffect, consume, enqueue, reconcile, sync, webhook, stores: directory };
}

module.exports = { createRuntime };
