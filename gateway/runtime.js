const crypto = require("node:crypto");
const { RuntimeError, runtimeError } = require("./errors");
const { tableFromId } = require("./handlers");
const { assertLocator, locatorKey } = require("./queues/port");
const { withTimeout } = require("./utils");
const { nextCronDate, isExhausted, normalizeSchedule, occurrenceContent, planOccurrence } = require("./scheduler");

const LANES = new Set(["task", "schedule", "webhook"]);
const HANDLER_OUTCOMES = new Set(["success", "retry", "failed", "ambiguous", "ignore"]);

function createRuntime({ database, stores, queue, handlers, webhooks, adapters, webhookAdapters, contracts, routeCodec, options = {} }) {
  const directory = stores || {
    async forContext() { return database.store || database; },
  };
  const contractMap = contracts || handlers.contracts || new Map();
  const maxPatchBytes = options.maxPatchBytes || 64 * 1024;
  const leaseMs = options.leaseMs || 120000;
  const maxCatchUpOccurrences = options.maxCatchUpOccurrences || 100;
  const allowedContexts = options.allowedContexts
    ? new Set(options.allowedContexts.map((value) => `${value.namespace}\u0000${value.database}`))
    : null;

  function assertContext(namespace, databaseName) {
    if (!namespace || !databaseName) throw new RuntimeError("INVALID_CONTEXT", "Namespace and database are required", 400);
    if (allowedContexts && !allowedContexts.has(`${namespace}\u0000${databaseName}`)) {
      throw new RuntimeError("CONTEXT_NOT_ALLOWED", "The runtime is not configured for this database context", 403);
    }
  }

  function storeFor(namespace, databaseName) {
    assertContext(namespace, databaseName);
    return directory.forContext(namespace, databaseName);
  }

  function resolve(id) {
    const table = tableFromId(id);
    const handler = table && handlers.get(table);
    if (!table || !handler) throw new RuntimeError("TABLE_HANDLER_NOT_FOUND", `No handler for ${table || id}`, 404);
    const contract = contractMap instanceof Map ? contractMap.get(table) : contractMap.tables?.[table];
    const resolvedContract = contract || handler.contract || {};
    const scopedAdapters = {};
    for (const name of resolvedContract.adapters || []) {
      if (typeof adapters?.[name] !== "function") {
        throw new RuntimeError("ADAPTER_NOT_FOUND", `Required adapter is unavailable: ${name}`, 503);
      }
      scopedAdapters[name] = adapters[name];
    }
    return {
      table,
      handler,
      contract: resolvedContract,
      adapters: Object.freeze(scopedAdapters),
    };
  }

  function boundedPatch(contract, value) {
    const patch = value && typeof value === "object" && !Array.isArray(value) ? value : {};
    const allowed = new Set(contract.patchFields || []);
    const unknown = Object.keys(patch).find((field) => !allowed.has(field) || field.startsWith("rebase_"));
    if (unknown) throw new RuntimeError("PATCH_FIELD_FORBIDDEN", `Handler cannot patch ${unknown}`, 500);
    if (Buffer.byteLength(JSON.stringify(patch)) > maxPatchBytes) {
      throw new RuntimeError("PATCH_TOO_LARGE", "Handler patch is too large", 500);
    }
    return structuredClone(patch);
  }

  function resultOutcome(result) {
    if (result == null || typeof result !== "object" || Array.isArray(result)) {
      throw new RuntimeError("INVALID_HANDLER_RESULT", "Handler must return an outcome object", 500);
    }
    const outcome = result?.outcome || "success";
    if (!HANDLER_OUTCOMES.has(outcome)) {
      throw new RuntimeError("INVALID_HANDLER_OUTCOME", `Handler returned unsupported outcome: ${outcome}`, 500);
    }
    return outcome;
  }

  function retryDelay(value, fallback) {
    const delay = value == null ? fallback : Number(value);
    if (!Number.isFinite(delay) || delay < 0 || delay > 30 * 86400 * 1000) {
      throw new RuntimeError("INVALID_RETRY_DELAY", "Handler retry delay is invalid", 500);
    }
    return Math.max(1000, Math.floor(delay));
  }

  function scopedLoad(store, record, contract) {
    const allowed = new Set();
    function allowReferences(value, valueContract) {
      for (const reference of valueContract?.references || []) {
        const referenced = value?.[reference.field];
        const values = reference.array ? (Array.isArray(referenced) ? referenced : []) : [referenced];
        for (const id of values) if (id != null) allowed.add(String(id));
      }
    }
    allowReferences(record, contract);
    return async (id) => {
      const key = String(id);
      if (!allowed.has(key)) {
        throw new RuntimeError("REFERENCE_LOAD_FORBIDDEN", "Handler can load only declared record references", 500);
      }
      const loaded = await store.load(key);
      const table = tableFromId(key);
      const loadedContract = contractMap instanceof Map ? contractMap.get(table) : contractMap.tables?.[table];
      allowReferences(loaded, loadedContract);
      return loaded;
    };
  }

  function validateRecordShape(record, contract) {
    const optional = new Set(contract.optionalInputs || []);
    for (const field of contract.inputFields || []) {
      if (!optional.has(field) && !(field in (record || {}))) {
        throw new RuntimeError("EFFECT_INPUT_MISSING", `Effect input is missing: ${field}`, 500);
      }
    }
    return record;
  }

  function errorRecord(error) {
    return {
      code: String(error?.code || "TABLE_HANDLER_FAILED"),
      message: String(error?.message || "Handler failed").slice(0, 2000),
      retryable: error?.retryable === true,
    };
  }

  function assertEvent(contract, event) {
    const normalized = String(event || "").toUpperCase();
    if (!(contract.events || []).includes(normalized)) {
      throw new RuntimeError("TABLE_EVENT_NOT_SUPPORTED", `The table does not handle ${normalized || "this event"}`, 409);
    }
    return normalized;
  }

  function routeTools(context, record, contract) {
    return Object.freeze({
      seal(provider, { config } = {}) {
        if (!routeCodec) throw new RuntimeError("WEBHOOK_ROUTING_UNAVAILABLE", "Webhook routing is not configured", 503);
        const configId = String(config || "");
        const declaredReference = (contract.references || []).some((reference) => {
          const value = record?.[reference.field];
          return reference.array
            ? (Array.isArray(value) && value.some((item) => String(item) === configId))
            : String(value || "") === configId;
        });
        if (!declaredReference) {
          throw new RuntimeError("WEBHOOK_CONFIG_FORBIDDEN", "Webhook route config must be a declared record reference", 500);
        }
        return routeCodec.seal({
          provider,
          namespace: context.namespace,
          database: context.database,
          config: configId,
          id: context.id,
        });
      },
    });
  }

  async function invoke(fn, handler, input) {
    if (typeof fn !== "function") throw new RuntimeError("HANDLER_METHOD_MISSING", "Handler method is missing", 500);
    return withTimeout(input.timeoutMs || handler.timeoutMs, (signal) => fn({ ...input, signal }));
  }

  async function sync({ namespace, database: databaseName, id, event, before = null, after = null }) {
    assertContext(namespace, databaseName);
    const { table, handler, contract, adapters: scopedAdapters } = resolve(id);
    if (contract.process !== "sync" && handler.process !== "sync") {
      throw new RuntimeError("TABLE_PROCESS_MISMATCH", `${table} is not synchronous`, 409);
    }
    const normalizedEvent = assertEvent(contract, event);
    const record = normalizedEvent === "DELETE" ? before : after;
    const validSnapshot = record && typeof record === "object" && !Array.isArray(record)
      && String(record.id) === String(id)
      && (before == null || (typeof before === "object" && !Array.isArray(before) && String(before.id) === String(id)))
      && (after == null || (typeof after === "object" && !Array.isArray(after) && String(after.id) === String(id)));
    if (!validSnapshot || (normalizedEvent === "CREATE" && before != null) || (normalizedEvent === "DELETE" && after != null)) {
      throw new RuntimeError("SYNC_SNAPSHOT_REQUIRED", "Matching before/after snapshots are required", 400);
    }
    const store = await storeFor(namespace, databaseName);
    try {
      validateRecordShape(record, contract);
      const context = { namespace, database: databaseName, event: normalizedEvent, id: String(id), table };
      const result = await invoke(handler.on[normalizedEvent], handler, {
        context,
        record,
        before,
        after,
        load: scopedLoad(store, record, contract),
        adapters: scopedAdapters,
        routes: routeTools(context, record, contract),
        trigger: "sync",
      });
      return { outcome: resultOutcome(result), patch: boundedPatch(contract, result?.patch || {}) };
    } catch (error) {
      const normalized = runtimeError(error);
      return { outcome: normalized.retryable ? "ambiguous" : "failed", patch: {}, error: errorRecord(normalized) };
    }
  }

  async function enqueue(lane, locator, options = {}) {
    if (!LANES.has(lane)) throw new RuntimeError("INVALID_QUEUE_LANE", `Invalid lane: ${lane}`, 400);
    if (!queue) throw new Error("Runtime queue is not configured");
    const normalized = assertLocator(locator);
    assertContext(normalized.namespace, normalized.database);
    const { handler, contract } = resolve(normalized.id);
    assertEvent(contract, "CREATE");
    if (contract.process !== "async") {
      throw new RuntimeError("TABLE_PROCESS_MISMATCH", "Only asynchronous effects can use this queue lane", 409);
    }
    if (lane === "schedule" && !contract.schedule) {
      throw new RuntimeError("SCHEDULE_NOT_SUPPORTED", "The effect table has no schedule contract", 409);
    }
    if (lane === "webhook" && typeof handler.reconcile !== "function") {
      throw new RuntimeError("WEBHOOK_NOT_SUPPORTED", "The effect table has no reconciliation handler", 409);
    }
    return queue.publish(lane, normalized, options);
  }

  async function execute(locator, delivery = {}) {
    const normalizedLocator = assertLocator(locator);
    const { namespace, database: databaseName, id } = normalizedLocator;
    assertContext(namespace, databaseName);
    const { table, handler, contract, adapters: scopedAdapters } = resolve(id);
    if (contract.process !== "async" && handler.process !== "async") {
      throw new RuntimeError("TABLE_PROCESS_MISMATCH", `${table} is not asynchronous`, 409);
    }
    const normalizedEvent = assertEvent(contract, "CREATE");
    const store = await storeFor(namespace, databaseName);
    const record = await store.load(id);
    if (!record) return { action: "ack", state: "missing", id, table };
    if (record.rebase_cancel_requested === true) return { action: "ack", state: "cancelled", id, table };
    if (record.rebase_outcome) return { action: "ack", state: "terminal", id, table };
    validateRecordShape(record, contract);
    const token = crypto.randomUUID();
    const claimed = await store.claim(id, { token, leaseUntil: Date.now() + leaseMs, outcome: record.rebase_outcome || "pending" });
    if (!claimed) return { action: "ack", state: "busy", id, table };
    try {
      const context = { namespace, database: databaseName, event: normalizedEvent, id: String(id), table };
      const result = await invoke(handler.on[normalizedEvent], handler, {
        context,
        record: claimed,
        load: scopedLoad(store, claimed, contract),
        adapters: scopedAdapters,
        routes: routeTools(context, claimed, contract),
        trigger: "task",
        attempts: delivery.attempts,
      });
      const outcome = resultOutcome(result);
      const patch = boundedPatch(contract, result?.patch || {});
      if (outcome === "retry") {
        if (delivery.maxAttempts && delivery.attempts >= delivery.maxAttempts) {
          const finalized = await store.finalize(id, token, patch, contract.patchFields, "failed", errorRecord(result.error));
          if (!finalized) return { action: "ack", state: "stale" };
          return { action: "dead-letter", reason: result.error?.code || "RETRY_EXHAUSTED" };
        }
        const delayMs = retryDelay(result.retryAfterMs, 1000);
        const retried = await store.retry(id, token, Date.now() + delayMs, errorRecord(result.error), "pending");
        return retried ? { action: "retry", delayMs, state: "waiting" } : { action: "ack", state: "stale" };
      }
      if (outcome === "ambiguous") {
        const delayMs = retryDelay(result.retryAfterMs, 300000);
        const finalized = await store.ambiguous(id, token, patch, contract.patchFields, Date.now() + delayMs, errorRecord(result.error));
        if (!finalized) return { action: "ack", state: "stale" };
        await enqueue("webhook", normalizedLocator, { delayMs });
        return { action: "ack", state: "ambiguous" };
      }
      if (outcome === "ignore") {
        const finalized = await store.finalize(id, token, {}, contract.patchFields, "succeeded");
        return finalized ? { action: "ack", state: "ignored" } : { action: "ack", state: "stale" };
      }
      if (outcome === "failed") {
        const finalized = await store.finalize(id, token, patch, contract.patchFields, "failed", errorRecord(result.error));
        if (!finalized) return { action: "ack", state: "stale" };
        return { action: "dead-letter", reason: result.error?.code || "HANDLER_FAILED" };
      }
      const finalized = await store.finalize(id, token, patch, contract.patchFields, "succeeded");
      return finalized ? { action: "ack", state: "succeeded", patch } : { action: "ack", state: "stale" };
    } catch (error) {
      const normalized = runtimeError(error);
      const details = errorRecord(normalized);
      if (normalized.retryable) {
        if (delivery.maxAttempts && delivery.attempts >= delivery.maxAttempts) {
          const finalized = await store.finalize(id, token, {}, contract.patchFields, "failed", details).catch(() => null);
          if (!finalized) return { action: "ack", state: "stale" };
          return { action: "dead-letter", reason: normalized.code || "RETRY_EXHAUSTED" };
        }
        const delayMs = retryDelay(Number(normalized.delaySeconds || 0) * 1000, 1000);
        const retried = await store.retry(id, token, Date.now() + delayMs, details, "pending").catch(() => null);
        return retried ? { action: "retry", delayMs } : { action: "ack", state: "stale" };
      }
      const finalized = await store.finalize(id, token, {}, contract.patchFields, "failed", details).catch(() => null);
      if (!finalized) return { action: "ack", state: "stale" };
      return { action: "dead-letter", reason: normalized.code || "TABLE_HANDLER_FAILED" };
    }
  }

  async function schedule(locator) {
    const normalizedLocator = assertLocator(locator);
    const { namespace, database: databaseName, id } = normalizedLocator;
    assertContext(namespace, databaseName);
    const { handler, contract } = resolve(id);
    if (contract.process !== "async") throw new RuntimeError("TABLE_PROCESS_MISMATCH", "Only asynchronous effects can be scheduled", 409);
    const store = await storeFor(namespace, databaseName);
    const record = await store.load(id);
    if (!record || !record.schedule) return { action: "ack", state: "inactive" };
    if (record.rebase_cancel_requested === true) {
      if (!record.rebase_schedule_finished_at) await store.finishSchedule(id, { cancelled: true });
      await queue.removeSchedule?.(`schedule:${locatorKey(normalizedLocator)}`);
      return { action: "ack", state: "cancelled" };
    }
    if (record.rebase_outcome) return { action: "ack", state: "inactive" };
    try {
      normalizeSchedule(record.schedule);
    } catch (error) {
      await store.failSchedule(id, errorRecord(error));
      return { action: "dead-letter", reason: error.code || "INVALID_SCHEDULE" };
    }
    const index = Number(record.rebase_schedule_index || 0);
    if (!record.rebase_schedule_next_at) {
      const firstAt = nextCronDate(record.schedule, record.created_at || new Date(), 0);
      const initialized = await store.initializeSchedule(id, firstAt);
      if (initialized) await queue.schedule(`schedule:${locatorKey(normalizedLocator)}`, normalizedLocator, firstAt);
      return { action: "ack", state: initialized ? "initialized" : "busy" };
    }
    const currentAt = record.rebase_schedule_next_at;
    if (new Date(currentAt).getTime() > Date.now()) {
      await queue.schedule(`schedule:${locatorKey(normalizedLocator)}`, normalizedLocator, currentAt);
      return { action: "ack", state: "waiting" };
    }
    if (isExhausted(record.schedule, index)) {
      await store.finishSchedule(id);
      return { action: "ack", state: "finished" };
    }
    const content = occurrenceContent(record, contract);
    const occurrences = [];
    let cursor = currentAt;
    let cursorIndex = index;
    let nextAt = new Date(currentAt);
    for (let count = 0; count < maxCatchUpOccurrences; count += 1) {
      const plan = planOccurrence(record.schedule, cursor, new Date(), cursorIndex);
      if (plan.reason === "future") {
        nextAt = plan.nextAt;
        break;
      }
      const finish = plan.emit && isExhausted(record.schedule, plan.nextIndex);
      const advanced = await store.advanceSchedule(id, {
        expectedAt: cursor,
        nextAt: plan.nextAt,
        nextIndex: plan.nextIndex,
        content,
        recordFields: contract.references,
        emit: plan.emit,
        finish,
      });
      if (!advanced?.source) {
        if (!occurrences.length) return { action: "ack", state: "busy" };
        break;
      }
      if (advanced.occurrence?.id) {
        const occurrenceId = String(advanced.occurrence.id);
        occurrences.push(occurrenceId);
        await enqueue("task", { namespace, database: databaseName, id: occurrenceId });
      }
      if (finish) return { action: "ack", state: "finished", occurrences };
      cursor = String(advanced.source.rebase_schedule_next_at || plan.nextAt.toISOString());
      cursorIndex = plan.nextIndex;
      nextAt = plan.nextAt;
      if (nextAt.getTime() > Date.now() || record.schedule.misfire !== "all") break;
    }
    await queue.schedule(`schedule:${locatorKey(normalizedLocator)}`, normalizedLocator, nextAt);
    return { action: "ack", state: occurrences.length ? "scheduled" : "advanced", occurrences };
  }

  async function webhook({ provider, request, rawBody }) {
    if (!routeCodec) throw new RuntimeError("WEBHOOK_ROUTING_UNAVAILABLE", "Webhook routing is not configured", 503);
    const adapter = webhookAdapters?.[provider];
    if (!adapter || typeof adapter.extractRoute !== "function" || typeof adapter.verify !== "function") {
      throw new RuntimeError("WEBHOOK_PROVIDER_NOT_FOUND", `No webhook provider for ${provider}`, 404);
    }
    const capsule = await adapter.extractRoute({ request, rawBody });
    const route = routeCodec.open(capsule);
    if (route.provider !== provider) throw new RuntimeError("WEBHOOK_PROVIDER_MISMATCH", "Webhook route provider mismatch", 403);
    assertContext(route.namespace, route.database);
    const store = await storeFor(route.namespace, route.database);
    const [config, record] = await Promise.all([store.load(route.config), store.load(route.id)]);
    if (!config || !record || String(record.config || "") !== route.config) {
      throw new RuntimeError("WEBHOOK_TARGET_NOT_FOUND", "Webhook target was not found", 404);
    }
    const verified = await adapter.verify({ request, rawBody, config, route });
    if (!verified) throw new RuntimeError("INVALID_WEBHOOK", "Invalid webhook signature or payload", 401);
    const handler = webhooks?.get(provider, verified.event);
    if (!handler) throw new RuntimeError("WEBHOOK_EVENT_NOT_FOUND", `No webhook handler for ${provider}/${verified.event}`, 404);
    return withTimeout(options.webhookTimeoutMs || 30000, (signal) => handler.on[verified.event]({
      context: { namespace: route.namespace, database: route.database, provider, event: verified.event },
      config,
      record,
      route,
      verified,
      store,
      signal,
    }));
  }

  async function reconcileWebhook(locator, delivery = {}) {
    const { namespace, database: databaseName, id } = locator;
    const { handler, contract, table, adapters: scopedAdapters } = resolve(id);
    if (typeof handler.reconcile !== "function") return { action: "ack", state: "recorded" };
    const store = await storeFor(namespace, databaseName);
    const record = await store.load(id);
    if (!record) return { action: "ack", state: "missing" };
    if (record.rebase_cancel_requested === true) return { action: "ack", state: "cancelled" };
    if (record.rebase_outcome !== "ambiguous") return { action: "ack", state: "recorded" };
    const token = crypto.randomUUID();
    const claimed = await store.claim(id, { token, leaseUntil: Date.now() + leaseMs, outcome: "ambiguous" });
    if (!claimed) return { action: "ack", state: "busy" };
    try {
      const context = { namespace, database: databaseName, event: "CREATE", id, table };
      const result = await invoke(handler.reconcile, handler, {
        context,
        record: claimed,
        load: scopedLoad(store, claimed, contract),
        adapters: scopedAdapters,
        routes: routeTools(context, claimed, contract),
        trigger: "webhook",
        attempts: delivery.attempts,
      });
      const outcome = resultOutcome(result);
      const patch = boundedPatch(contract, result?.patch || {});
      if (outcome === "success") {
        const finalized = await store.finalize(id, token, patch, contract.patchFields, "succeeded", null, "ambiguous");
        return finalized ? { action: "ack", state: "succeeded" } : { action: "ack", state: "stale" };
      }
      if (outcome === "failed") {
        const finalized = await store.finalize(
          id,
          token,
          patch,
          contract.patchFields,
          "failed",
          errorRecord(result.error),
          "ambiguous",
        );
        return finalized ? { action: "dead-letter", reason: result.error?.code || "RECONCILIATION_FAILED" } : { action: "ack", state: "stale" };
      }
      if (outcome === "ignore") {
        const finalized = await store.finalize(id, token, patch, contract.patchFields, "succeeded", null, "ambiguous");
        return finalized ? { action: "ack", state: "ignored" } : { action: "ack", state: "stale" };
      }
      const delayMs = retryDelay(result?.retryAfterMs, 30000);
      const retried = await store.retry(id, token, Date.now() + delayMs, errorRecord(result?.error), "ambiguous");
      if (!retried) return { action: "ack", state: "stale" };
      return delivery.maxAttempts && delivery.attempts >= delivery.maxAttempts
        ? { action: "dead-letter", reason: result?.error?.code || "RECONCILIATION_EXHAUSTED" }
        : { action: "retry", delayMs, state: outcome };
    } catch (error) {
      const normalized = runtimeError(error);
      const delayMs = retryDelay(Number(normalized.delaySeconds || 0) * 1000, 30000);
      const retried = await store.retry(id, token, Date.now() + delayMs, errorRecord(normalized), "ambiguous").catch(() => null);
      if (!retried) return { action: "ack", state: "stale" };
      return delivery.maxAttempts && delivery.attempts >= delivery.maxAttempts
        ? { action: "dead-letter", reason: normalized.code || "RECONCILIATION_EXHAUSTED" }
        : { action: "retry", delayMs };
    }
  }

  async function reconcile({ namespace, database: databaseName, lane = "task", deep = false } = {}) {
    assertContext(namespace, databaseName);
    if (!LANES.has(lane)) throw new RuntimeError("INVALID_QUEUE_LANE", `Invalid reconciliation lane: ${lane}`, 400);
    const tableNames = handlers.tables
      .filter((table) => {
        const handler = handlers.get(table);
        const contract = contractMap instanceof Map ? contractMap.get(table) : contractMap.tables?.[table];
        if (handler.process !== "async") return false;
        if (lane === "schedule") return Boolean(contract?.schedule);
        if (lane === "webhook") return Boolean(handler.reconcile);
        return true;
      })
      .sort();
    const store = await storeFor(namespace, databaseName);
    const ids = await store.pending(tableNames, lane, { deep: deep || lane === "schedule" });
    for (const id of ids) await enqueue(lane, { namespace, database: databaseName, id });
    return { queued: ids.length, ids, lane, deep };
  }

  async function consume(lane, delivery) {
    try {
      if (lane === "schedule") return schedule(delivery.locator);
      if (lane === "webhook") return reconcileWebhook(delivery.locator, delivery);
      return execute(delivery.locator, delivery);
    } catch (error) {
      const normalized = runtimeError(error);
      if (normalized.retryable || normalized.code === "INTERNAL_ERROR") {
        return { action: "retry", delayMs: Math.max(1000, Number(normalized.delaySeconds || 0) * 1000) };
      }
      return { action: "dead-letter", reason: normalized.code || "RUNTIME_FAILURE" };
    }
  }

  return {
    consume,
    enqueue,
    execute,
    reconcile,
    reconcileWebhook,
    schedule,
    stores: directory,
    sync,
    webhook,
  };
}

module.exports = { createRuntime };
