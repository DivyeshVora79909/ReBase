const crypto = require("node:crypto");
const { RuntimeError, runtimeError } = require("./errors");
const { tableFromId } = require("./handlers");
const {
  assertLocator,
  assertOperationEnvelope,
  operationEnvelope,
  receiptEnvelope,
  assertWorkEnvelope,
} = require("./queues/port");
const { withTimeout } = require("./utils");
const { SIDE_EFFECT_ADAPTERS, assertGrantAdapters } = require("../src/operation-adapters");
const { QUEUE_HORIZON_MS, surrealDuration } = require("../config/runtime-timing");

const HANDLER_OUTCOMES = new Set(["success", "retry", "failed", "ambiguous", "ignore"]);
const RECEIPT_TABLE = "rebase_webhook_receipt";

function createRuntime({ database, stores, queue, handlers, webhooks, adapters, webhookAdapters, contracts, routeCodec, options = {} }) {
  const directory = stores || {
    async forContext() { return database.store || database; },
  };
  const contractMap = contracts || handlers.contracts || new Map();
  const maxPatchBytes = options.maxPatchBytes || 64 * 1024;
  const leaseMs = options.leaseMs || 120000;
  const maxTaskAttempts = options.maxTaskAttempts || 5;
  const queueHorizonMs = options.queueHorizonMs || QUEUE_HORIZON_MS;
  const reconcilePageSize = options.reconcilePageSize || 100;
  const terminalTaskRetentionMs = options.terminalTaskRetentionMs === undefined
    ? 30 * 24 * 60 * 60 * 1000
    : options.terminalTaskRetentionMs;
  if (!Number.isSafeInteger(terminalTaskRetentionMs) || terminalTaskRetentionMs < 1) {
    throw new Error("Terminal task retention must be a positive safe integer in milliseconds");
  }
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
    if (resolvedContract.mode === "grant") {
      try {
        assertGrantAdapters(table, resolvedContract.adapters || []);
      } catch (error) {
        throw new RuntimeError("UNSAFE_GRANT_ADAPTER", error.message, 500);
      }
    }
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
    const sourceTable = tableFromId(String(record.id));
    const platformCredential = sourceTable === "send_brevo_email"
      ? "rebase_email_delivery_config:platform"
      : sourceTable === "send_twilio_sms"
        ? "rebase_sms_delivery_config:platform"
        : null;
    function allowReferences(value, valueContract) {
      for (const reference of valueContract?.references || []) {
        const referenced = value?.[reference.field];
        const values = reference.array ? (Array.isArray(referenced) ? referenced : []) : [referenced];
        for (const id of values) if (id != null) allowed.add(String(id));
      }
    }
    allowReferences(record, contract);
    if (platformCredential && record.config == null) allowed.add(platformCredential);
    return async (id) => {
      const key = String(id);
      if (!allowed.has(key)) {
        throw new RuntimeError("REFERENCE_LOAD_FORBIDDEN", "Handler can load only declared record references", 500);
      }
      const targetTable = tableFromId(key);
      if (targetTable === "rebase_email_delivery_config" || targetTable === "rebase_sms_delivery_config") {
        const owner = await store.execute("RETURN (SELECT VALUE owned_by FROM type::record($id))[0];", { id: key });
        if (!owner) {
          throw new RuntimeError("CREDENTIAL_USE_FORBIDDEN", "Delivery configuration is unavailable", 403);
        }
        if (key === platformCredential && record.config == null && String(owner) !== "rebase_group:root") {
          throw new RuntimeError("CREDENTIAL_USE_FORBIDDEN", "Platform delivery configuration is unavailable", 403);
        }
        if (sourceTable !== "authentication_delivery_task") {
          const creator = record.created_by ? String(record.created_by) : "";
          let authorized = false;
          if (!creator) {
            // A system connection may create a system-owned operation, but it
            // cannot use a tenant BYOC credential without an authenticated
            // source principal. Client-created rows always carry created_by.
            authorized = String(record.owned_by) === "rebase_group:root"
              && String(owner) === "rebase_group:root";
          } else if (creator.startsWith("rebase_user:")) {
            const actor = await store.execute("RETURN (SELECT z_access_index, permissions FROM type::record($id))[0];", { id: creator });
            authorized = Array.isArray(actor?.permissions)
              && actor.permissions.includes(`${sourceTable}_create`)
              && (String(owner) === "rebase_group:root"
                ? key === platformCredential && record.config == null
                : Array.isArray(actor?.z_access_index) && actor.z_access_index.includes(String(owner)));
          }
          if (!authorized) {
            throw new RuntimeError("CREDENTIAL_USE_FORBIDDEN", "Delivery configuration is not authorized", 403);
          }
        }
      }
      const loaded = await store.load(key);
      const loadedContract = contractMap instanceof Map ? contractMap.get(targetTable) : contractMap.tables?.[targetTable];
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

  function taskAdapters(adaptersForTask, markProviderStarted) {
    return Object.freeze(Object.fromEntries(Object.entries(adaptersForTask).map(([name, adapter]) => {
      if (!SIDE_EFFECT_ADAPTERS.has(name)) return [name, adapter];
      return [name, async (...args) => {
        if (!await markProviderStarted()) {
          throw new RuntimeError("TASK_LEASE_LOST", "Task lease was lost before provider work started", 409);
        }
        return adapter(...args);
      }];
    })));
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

  async function grant({ namespace, database: databaseName, id, event, before = null, after = null }) {
    assertContext(namespace, databaseName);
    const { table, handler, contract, adapters: scopedAdapters } = resolve(id);
    if (contract.mode !== "grant" || handler.mode !== "grant") {
      throw new RuntimeError("TABLE_MODE_MISMATCH", `${table} is not a grant operation`, 409);
    }
    const normalizedEvent = assertEvent(contract, event);
    const record = after;
    const validSnapshot = record && typeof record === "object" && !Array.isArray(record)
      && String(record.id) === String(id)
      && (before == null || (typeof before === "object" && !Array.isArray(before) && String(before.id) === String(id)))
      && String(after.id) === String(id);
    if (!validSnapshot
      || (normalizedEvent === "CREATE" && before != null)
      || (normalizedEvent === "UPDATE" && before == null)
      || normalizedEvent === "DELETE") {
      throw new RuntimeError("GRANT_SNAPSHOT_REQUIRED", "Matching before/after snapshots are required", 400);
    }
    const store = await storeFor(namespace, databaseName);
    try {
      validateRecordShape(record, contract);
      const context = { namespace, database: databaseName, event: normalizedEvent, id: String(id), table };
      const result = await invoke(handler.grant[normalizedEvent], handler, {
        context,
        record,
        before,
        after,
        load: scopedLoad(store, record, contract),
        adapters: scopedAdapters,
        trigger: "grant",
      });
      const outcome = resultOutcome(result);
      if (outcome !== "success" && outcome !== "failed") {
        throw new RuntimeError("INVALID_GRANT_OUTCOME", "Grant handlers may return only success or failed", 500);
      }
      return { outcome, patch: outcome === "success" ? boundedPatch(contract, result?.patch || {}) : {} };
    } catch (error) {
      const normalized = runtimeError(error);
      return { outcome: "failed", patch: {}, error: errorRecord(normalized) };
    }
  }

  async function enqueue(locator, options = {}) {
    if (!queue) throw new Error("Runtime queue is not configured");
    const normalized = assertLocator(locator);
    assertContext(normalized.namespace, normalized.database);
    const { table, handler, contract } = resolve(normalized.id);
    assertEvent(contract, "CREATE");
    if (!(contract.process === "async" || contract.mode === "queued" || contract.mode === "inline")) {
      throw new RuntimeError("TABLE_MODE_MISMATCH", "This operation cannot use the task queue", 409);
    }
    const store = await storeFor(normalized.namespace, normalized.database);
    const record = await store.load(normalized.id);
    if (!record) return { queued: false, state: "missing" };
    if (record.rebase_outcome && record.rebase_outcome !== "ambiguous") {
      return { queued: false, state: "terminal" };
    }
    if (record.rebase_outcome === "ambiguous" && typeof handler.reconcile !== "function") {
      return { queued: false, state: "uncertain" };
    }
    const leaseUntil = record.rebase_lease_until ? new Date(record.rebase_lease_until).getTime() : 0;
    const providerAttemptExpired = record.rebase_provider_started_at != null && leaseUntil <= Date.now();
    if (record.rebase_cancel_requested === true && record.rebase_outcome !== "ambiguous" && !providerAttemptExpired) {
      return { queued: false, state: "cancelled" };
    }
    const envelope = table === RECEIPT_TABLE
      ? receiptEnvelope(normalized, record.revision)
      : operationEnvelope(normalized, record);
    const executeAt = new Date(record.execute_at || 0).getTime();
    const wakeAt = record.rebase_wake_at ? new Date(record.rebase_wake_at).getTime() : 0;
    const dueAt = Math.max(Number.isFinite(executeAt) ? executeAt : 0, Number.isFinite(wakeAt) ? wakeAt : 0);
    const delayMs = Math.max(0, dueAt - Date.now());
    if (delayMs > queueHorizonMs) return { queued: false, state: "outside-horizon", dueAt };
    const { recovery: _recovery, delayMs: _delayMs, ...publishOptions } = options;
    return queue.publish(envelope, {
      ...publishOptions,
      priority: table === RECEIPT_TABLE ? 1 : Number(record.priority ?? 50),
      delayMs: Math.max(delayMs, Number(options.delayMs || 0)),
    });
  }

  async function execute(locatorOrEnvelope, delivery = {}) {
    const incomingEnvelope = delivery.envelope
      ? assertOperationEnvelope(delivery.envelope)
      : (locatorOrEnvelope?.version === 1 ? assertOperationEnvelope(locatorOrEnvelope) : null);
    const normalizedLocator = incomingEnvelope
      ? incomingEnvelope.locator
      : assertLocator(locatorOrEnvelope);
    const { namespace, database: databaseName, id } = normalizedLocator;
    assertContext(namespace, databaseName);
    const { table, handler, contract, adapters: scopedAdapters } = resolve(id);
    const taskMode = contract.mode === "inline" || contract.mode === "queued";
    if (!taskMode && contract.process !== "async" && handler.process !== "async") {
      throw new RuntimeError("TABLE_PROCESS_MISMATCH", `${table} is not an executable task`, 409);
    }
    const normalizedEvent = assertEvent(contract, "CREATE");
    const store = await storeFor(namespace, databaseName);
    const record = await store.load(id);
    if (!record) return { action: "ack", state: "missing", id, table };
    const envelope = incomingEnvelope || operationEnvelope(normalizedLocator, record);
    const identity = { executionId: envelope.executionId, revision: envelope.revision };
    if (String(record.execution_id || "").toLowerCase() !== identity.executionId
      || String(record.revision || "").toLowerCase() !== identity.revision) {
      return { action: "ack", state: "stale", id, table };
    }
    if (record.rebase_outcome === "ambiguous") return reconcileWebhook(envelope, delivery);
    const leaseUntil = record.rebase_lease_until ? new Date(record.rebase_lease_until).getTime() : 0;
    const providerAttemptExpired = record.rebase_provider_started_at != null && leaseUntil <= Date.now();
    if (record.rebase_cancel_requested === true && !providerAttemptExpired) return { action: "ack", state: "cancelled", id, table };
    if (record.rebase_outcome) return { action: "ack", state: "terminal", id, table };
    const executeAt = new Date(record.execute_at || 0).getTime();
    if (Number.isFinite(executeAt) && executeAt > Date.now()) return { action: "ack", state: "not-due", id, table };
    validateRecordShape(record, contract);
    const token = crypto.randomUUID();
    const claimed = await store.claim(id, {
      token,
      leaseUntil: Date.now() + leaseMs,
      outcome: record.rebase_outcome || "pending",
      ...identity,
    });
    if (!claimed) return { action: "ack", state: "busy", id, table };
    if (claimed.rebase_outcome === "ambiguous") {
      if (handler.reconcile) await enqueue(normalizedLocator).catch(() => null);
      return { action: "ack", state: "ambiguous", id, table };
    }
    try {
      const context = { namespace, database: databaseName, event: normalizedEvent, id: String(id), table };
      const method = taskMode ? handler.execute : handler.on[normalizedEvent];
      const result = await invoke(method, handler, {
        context,
        record: claimed,
        load: scopedLoad(store, claimed, contract),
        ...(table === RECEIPT_TABLE ? { store, webhooks } : {}),
        adapters: taskAdapters(scopedAdapters, async () => {
          const marked = await store.markProviderStarted(id, token, identity);
          if (marked) return true;
          const current = await store.load(id);
          if (current?.rebase_cancel_requested === true
            && String(current.rebase_lease_token || "").toLowerCase() === token.toLowerCase()) {
            throw new RuntimeError(
              "TASK_CANCELLED_BEFORE_PROVIDER_START",
              "Cancellation was requested before provider work started",
              409,
            );
          }
          return false;
        }),
        routes: routeTools(context, claimed, contract),
        trigger: delivery.trigger || "task",
        attempts: delivery.attempts,
      });
      const outcome = resultOutcome(result);
      const patch = boundedPatch(contract, result?.patch || {});
      if (outcome === "retry") {
        if (Number(claimed.rebase_attempt || 1) >= maxTaskAttempts) {
          const retryError = errorRecord(result.error || { code: "RETRY_EXHAUSTED", message: "Task retry limit reached" });
          const finalized = await store.finalize(id, token, patch, contract.patchFields, "failed", retryError, "pending", identity);
          if (!finalized) return { action: "ack", state: "stale" };
          return { action: "dead-letter", reason: retryError.code || "RETRY_EXHAUSTED" };
        }
        const delayMs = retryDelay(result.retryAfterMs, 1000);
        const retried = await store.retry(id, token, Date.now() + delayMs, errorRecord(result.error), "pending", identity);
        if (!retried) return { action: "ack", state: "stale" };
        if (retried.rebase_cancel_requested === true) return { action: "ack", state: "cancelled" };
        await enqueue(normalizedLocator).catch(() => null);
        return { action: "ack", state: "waiting", delayMs };
      }
      if (outcome === "ambiguous") {
        const delayMs = retryDelay(result.retryAfterMs, 300000);
        const finalized = await store.ambiguous(id, token, patch, contract.patchFields, Date.now() + delayMs, errorRecord(result.error), identity);
        if (!finalized) return { action: "ack", state: "stale" };
        if (handler.reconcile) await enqueue(normalizedLocator).catch(() => null);
        return { action: "ack", state: "ambiguous" };
      }
      if (outcome === "ignore") {
        const finalized = await store.finalize(id, token, {}, contract.patchFields, "succeeded", null, "pending", identity);
        return finalized ? { action: "ack", state: "ignored" } : { action: "ack", state: "stale" };
      }
      if (outcome === "failed") {
        const finalized = await store.finalize(id, token, patch, contract.patchFields, "failed", errorRecord(result.error), "pending", identity);
        if (!finalized) return { action: "ack", state: "stale" };
        return { action: "dead-letter", reason: result.error?.code || "HANDLER_FAILED" };
      }
      const finalized = await store.finalize(id, token, patch, contract.patchFields, "succeeded", null, "pending", identity);
      return finalized ? { action: "ack", state: "succeeded", patch } : { action: "ack", state: "stale" };
    } catch (error) {
      const normalized = runtimeError(error);
      const details = errorRecord(normalized);
      if (normalized.code === "TASK_CANCELLED_BEFORE_PROVIDER_START") {
        const cancelled = await store.retry(id, token, Date.now(), details, "pending", identity).catch(() => null);
        return cancelled?.rebase_cancel_requested === true
          ? { action: "ack", state: "cancelled", id, table }
          : { action: "ack", state: "stale", id, table };
      }
      if (normalized.retryable) {
        if (taskMode) {
          const delayMs = retryDelay(Number(normalized.delaySeconds || 0) * 1000, 300000);
          const ambiguous = await store.ambiguous(
            id,
            token,
            {},
            contract.patchFields,
            Date.now() + delayMs,
            details,
            identity,
          ).catch(() => null);
          if (!ambiguous) return { action: "ack", state: "stale" };
          if (handler.reconcile) await enqueue(normalizedLocator).catch(() => null);
          return { action: "ack", state: "ambiguous" };
        }
        if (Number(claimed.rebase_attempt || 1) >= maxTaskAttempts) {
          const finalized = await store.finalize(id, token, {}, contract.patchFields, "failed", details, "pending", identity).catch(() => null);
          if (!finalized) return { action: "ack", state: "stale" };
          return { action: "dead-letter", reason: normalized.code || "RETRY_EXHAUSTED" };
        }
        const delayMs = retryDelay(Number(normalized.delaySeconds || 0) * 1000, 1000);
        const retried = await store.retry(id, token, Date.now() + delayMs, details, "pending", identity).catch(() => null);
        if (!retried) return { action: "ack", state: "stale" };
        if (retried.rebase_cancel_requested === true) return { action: "ack", state: "cancelled" };
        await enqueue(normalizedLocator).catch(() => null);
        return { action: "ack", state: "waiting", delayMs };
      }
      const finalized = await store.finalize(id, token, {}, contract.patchFields, "failed", details, "pending", identity).catch(() => null);
      if (!finalized) return { action: "ack", state: "stale" };
      return { action: "dead-letter", reason: normalized.code || "TABLE_HANDLER_FAILED" };
    }
  }

  async function runInline(locator) {
    const normalized = assertLocator(locator);
    const { contract } = resolve(normalized.id);
    if (contract.mode !== "inline") {
      throw new RuntimeError("TABLE_MODE_MISMATCH", "Only inline operations can use this route", 409);
    }
    const result = await execute(normalized, { trigger: "inline" });
    return { action: result.action, state: result.state };
  }

  async function webhook({ provider, request, rawBody, routeCapsule }) {
    if (!routeCodec) throw new RuntimeError("WEBHOOK_ROUTING_UNAVAILABLE", "Webhook routing is not configured", 503);
    const adapter = webhookAdapters?.[provider];
    if (!adapter || typeof adapter.extractRoute !== "function" || typeof adapter.verify !== "function") {
      throw new RuntimeError("WEBHOOK_PROVIDER_NOT_FOUND", `No webhook provider for ${provider}`, 404);
    }
    const capsule = routeCapsule || await adapter.extractRoute({ request, rawBody });
    const route = routeCodec.open(capsule);
    if (route.provider !== provider) throw new RuntimeError("WEBHOOK_PROVIDER_MISMATCH", "Webhook route provider mismatch", 403);
    assertContext(route.namespace, route.database);
    const store = await storeFor(route.namespace, route.database);
    const configRoute = route.id === route.config && tableFromId(route.id) === `${provider}_config`;
    const config = await store.load(route.config);
    let record = configRoute ? null : await store.load(route.id);
    if (!config || (!configRoute && (!record || String(record.config || "") !== route.config))) {
      throw new RuntimeError("WEBHOOK_TARGET_NOT_FOUND", "Webhook target was not found", 404);
    }
    const verified = await adapter.verify({ request, rawBody, config, route });
    if (!verified) throw new RuntimeError("INVALID_WEBHOOK", "Invalid webhook signature or payload", 401);
    let resolvedRoute = route;
    if (configRoute) {
      const providerOrderId = String(verified.order?.id || verified.payment?.orderId || "");
      if (!providerOrderId) throw new RuntimeError("WEBHOOK_TARGET_NOT_FOUND", "Webhook has no provider order identity", 404);
      const matches = await store.execute(`
        SELECT * FROM razorpay_order
        WHERE config = type::record($config_id) AND provider_order_id = $provider_order_id
        LIMIT 2;
      `, { config_id: route.config, provider_order_id: providerOrderId });
      if (!Array.isArray(matches) || matches.length !== 1) {
        throw new RuntimeError("WEBHOOK_TARGET_NOT_FOUND", "Webhook order does not resolve uniquely in its configured context", 404);
      }
      [record] = matches;
      resolvedRoute = { ...route, id: String(record.id) };
    }
    const handler = webhooks?.get(provider, verified.event);
    if (!handler) throw new RuntimeError("WEBHOOK_EVENT_NOT_FOUND", `No webhook handler for ${provider}/${verified.event}`, 404);
    await withTimeout(options.webhookTimeoutMs || 30000, (signal) => handler.validate({
      context: { namespace: resolvedRoute.namespace, database: resolvedRoute.database, provider, event: verified.event },
      config, record, route: resolvedRoute, verified,
      signal,
    }));
    if (!verified.eventId) throw new RuntimeError("WEBHOOK_EVENT_ID_REQUIRED", "Verified webhook event has no identity", 400);
    const providerAccountId = `${provider}:${route.config}`;
    const payloadHash = crypto.createHash("sha256").update(rawBody).digest("hex");
    const receiptDigest = crypto.createHash("sha256")
      .update(`${providerAccountId}\u0000${verified.eventId}`)
      .digest("hex");
    const receiptId = `${RECEIPT_TABLE}:${receiptDigest}`;
    const receiptInput = {
      provider_account_id: providerAccountId,
      event_id: verified.eventId,
      provider,
      event: verified.event,
      config_id: resolvedRoute.config,
      target_id: resolvedRoute.id,
      payload_hash: payloadHash,
      normalized_payload: verified,
    };
    let receipt = await store.load(receiptId);
    let duplicate = Boolean(receipt);
    if (!receipt) {
      try {
        receipt = await store.createWebhookReceipt(receiptId, receiptInput);
      } catch (error) {
        receipt = await store.load(receiptId);
        if (!receipt) throw error;
        duplicate = true;
      }
    }
    if (!receipt || String(receipt.provider_account_id) !== providerAccountId
      || String(receipt.event_id) !== verified.eventId
      || String(receipt.provider) !== provider
      || String(receipt.event) !== verified.event
      || String(receipt.config_id) !== route.config
      || String(receipt.target_id) !== resolvedRoute.id
      || String(receipt.payload_hash) !== payloadHash) {
      throw new RuntimeError("WEBHOOK_EVENT_CONFLICT", "Webhook event identity was already used with different content", 409);
    }
    let queued = null;
    try {
      queued = await enqueue({ namespace: resolvedRoute.namespace, database: resolvedRoute.database, id: receiptId });
    } catch {
      // The committed receipt remains discoverable by bounded database reconciliation.
    }
    return { accepted: true, duplicate, receiptId, queued: queued?.queued === true };
  }

  async function createWebhookRoute({ provider, namespace, database: databaseName, config } = {}) {
    if (!routeCodec) throw new RuntimeError("WEBHOOK_ROUTING_UNAVAILABLE", "Webhook routing is not configured", 503);
    const normalizedProvider = String(provider || "").toLowerCase();
    if (normalizedProvider !== "razorpay") {
      throw new RuntimeError("WEBHOOK_ROUTE_UNSUPPORTED", "Config-bound target lookup is implemented for Razorpay only", 400);
    }
    if (!webhookAdapters?.[normalizedProvider] || !webhooks?.providers?.includes(normalizedProvider)) {
      throw new RuntimeError("WEBHOOK_PROVIDER_NOT_FOUND", `No webhook provider for ${normalizedProvider}`, 404);
    }
    const configId = String(config || "");
    if (tableFromId(configId) !== `${normalizedProvider}_config`) {
      throw new RuntimeError("WEBHOOK_CONFIG_INVALID", "Webhook route must name a matching provider config", 400);
    }
    const store = await storeFor(namespace, databaseName);
    if (!await store.load(configId)) throw new RuntimeError("WEBHOOK_CONFIG_NOT_FOUND", "Webhook config was not found", 404);
    const capsule = routeCodec.seal({
      provider: normalizedProvider,
      namespace,
      database: databaseName,
      config: configId,
      id: configId,
    });
    return {
      provider: normalizedProvider,
      capsule,
      path: `/webhooks/${encodeURIComponent(normalizedProvider)}/${encodeURIComponent(capsule)}`,
    };
  }

  async function reconcileWebhook(locatorOrEnvelope, delivery = {}) {
    const incomingEnvelope = delivery.envelope
      ? assertOperationEnvelope(delivery.envelope)
      : (locatorOrEnvelope?.version === 1 ? assertOperationEnvelope(locatorOrEnvelope) : null);
    const locator = incomingEnvelope ? incomingEnvelope.locator : assertLocator(locatorOrEnvelope);
    const { namespace, database: databaseName, id } = locator;
    const { handler, contract, table, adapters: scopedAdapters } = resolve(id);
    if (typeof handler.reconcile !== "function") return { action: "ack", state: "recorded" };
    const store = await storeFor(namespace, databaseName);
    const record = await store.load(id);
    if (!record) return { action: "ack", state: "missing" };
    const envelope = incomingEnvelope || operationEnvelope(locator, record);
    const identity = { executionId: envelope.executionId, revision: envelope.revision };
    if (String(record.execution_id || "").toLowerCase() !== identity.executionId
      || String(record.revision || "").toLowerCase() !== identity.revision) {
      return { action: "ack", state: "stale" };
    }
    if (record.rebase_outcome !== "ambiguous") return { action: "ack", state: "recorded" };
    const token = crypto.randomUUID();
    const claimed = await store.claim(id, { token, leaseUntil: Date.now() + leaseMs, outcome: "ambiguous", ...identity });
    if (!claimed) return { action: "ack", state: "busy" };
    try {
      const context = { namespace, database: databaseName, event: "CREATE", id, table };
      const result = await invoke(handler.reconcile, handler, {
        context,
        record: claimed,
        load: scopedLoad(store, claimed, contract),
        ...(table === RECEIPT_TABLE ? { store, webhooks } : {}),
        adapters: taskAdapters(scopedAdapters, async () => Boolean(
          await store.markProviderStarted(id, token, identity, "ambiguous"),
        )),
        routes: routeTools(context, claimed, contract),
        trigger: "webhook",
        attempts: delivery.attempts,
      });
      const outcome = resultOutcome(result);
      const patch = boundedPatch(contract, result?.patch || {});
      if (outcome === "success") {
        const finalized = await store.finalize(id, token, patch, contract.patchFields, "succeeded", null, "ambiguous", identity);
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
          identity,
        );
        return finalized ? { action: "dead-letter", reason: result.error?.code || "RECONCILIATION_FAILED" } : { action: "ack", state: "stale" };
      }
      if (outcome === "ignore") {
        const finalized = await store.finalize(id, token, patch, contract.patchFields, "succeeded", null, "ambiguous", identity);
        return finalized ? { action: "ack", state: "ignored" } : { action: "ack", state: "stale" };
      }
      const delayMs = retryDelay(result?.retryAfterMs, outcome === "ambiguous" ? 15 * 60 * 1000 : 30000);
      const retried = await store.retry(id, token, Date.now() + delayMs, errorRecord(result?.error), "ambiguous", identity);
      if (!retried) return { action: "ack", state: "stale" };
      await enqueue(locator).catch(() => null);
      return { action: "ack", state: "waiting", delayMs, previous: outcome };
    } catch (error) {
      const normalized = runtimeError(error);
      const delayMs = retryDelay(Number(normalized.delaySeconds || 0) * 1000, 15 * 60 * 1000);
      const retried = await store.retry(id, token, Date.now() + delayMs, errorRecord(normalized), "ambiguous", identity).catch(() => null);
      if (!retried) return { action: "ack", state: "stale" };
      await enqueue(locator).catch(() => null);
      return { action: "ack", state: "waiting", delayMs };
    }
  }

  async function reconcile({ namespace, database: databaseName } = {}) {
    assertContext(namespace, databaseName);
    const tableNames = handlers.tables
      .filter((table) => {
        const handler = handlers.get(table);
        const contract = contractMap instanceof Map ? contractMap.get(table) : contractMap.tables?.[table];
        const mode = contract?.mode;
        return handler.process === "async" || mode === "queued" || mode === "inline";
      })
      .sort();
    const store = await storeFor(namespace, databaseName);
    let page = null;
    if (tableNames.length) {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const cursor = await store.loadReconciliationCursor();
        const offset = Number(cursor.table_offset || 0) % tableNames.length;
        const orderedTables = [...tableNames.slice(offset), ...tableNames.slice(0, offset)];
        const candidate = await store.pendingPage(orderedTables, {
          cursors: cursor.cursors || {},
          highWater: cursor.high_water || {},
          ambiguousTables: tableNames.filter((table) => typeof handlers.get(table)?.reconcile === "function"),
          pageSize: reconcilePageSize,
          horizon: surrealDuration(queueHorizonMs),
        });
        const advanced = await store.compareAndSetReconciliationCursor({
          expectedVersion: Number(cursor.version || 0),
          cursors: candidate.cursors,
          highWater: candidate.highWater,
          retentionCursors: cursor.retention_cursors || {},
          retentionHighWater: cursor.retention_high_water || {},
          tableOffset: (offset + 1) % tableNames.length,
        });
        if (advanced) {
          page = candidate;
          break;
        }
      }
    } else {
      page = { ids: [] };
    }
    if (!page) {
      return {
        queued: 0,
        ids: [],
        queuedIds: [],
        deferred: [{ state: "cursor-contention" }],
        pageSize: reconcilePageSize,
        horizonMs: queueHorizonMs,
        morePending: false,
      };
    }
    const queuedIds = [];
    const deferred = [];
    for (const id of page.ids) {
      try {
        const result = await enqueue({ namespace, database: databaseName, id });
        if (result?.queued === true || result?.duplicate === true) queuedIds.push(id);
        else deferred.push({ id, state: result?.state || "not-queued" });
      } catch (error) {
        deferred.push({ id, state: "publish-error", error: String(error?.message || error).slice(0, 500) });
      }
    }
    let purged = [];
    let retentionDeferred;
    const retentionTables = tableNames.filter((table) => table !== RECEIPT_TABLE);
    if (retentionTables.length) {
      let candidate = null;
      const cutoff = new Date(Date.now() - terminalTaskRetentionMs);
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const cursor = await store.loadReconciliationCursor();
        const offset = Number(cursor.table_offset || 0) % retentionTables.length;
        const orderedTables = [...retentionTables.slice(offset), ...retentionTables.slice(0, offset)];
        const retention = await store.expiredTerminalPage(orderedTables, {
          cursors: cursor.retention_cursors || {},
          highWater: cursor.retention_high_water || {},
          cutoff,
          pageSize: reconcilePageSize,
        });
        const advanced = await store.compareAndSetReconciliationCursor({
          expectedVersion: Number(cursor.version || 0),
          cursors: cursor.cursors || {},
          highWater: cursor.high_water || {},
          retentionCursors: retention.cursors,
          retentionHighWater: retention.highWater,
          tableOffset: (offset + 1) % retentionTables.length,
        });
        if (advanced) {
          candidate = retention;
          break;
        }
      }
      if (!candidate) {
        retentionDeferred = "cursor-contention";
      } else {
        purged = await store.deleteExpiredTerminalRows(candidate.rows, cutoff);
      }
    }
    return {
      queued: queuedIds.length,
      ids: page.ids,
      queuedIds,
      deferred,
      pageSize: reconcilePageSize,
      horizonMs: queueHorizonMs,
      morePending: Object.keys(page.cursors || {}).some((table) => (
        Boolean(page.cursors[table]) && Boolean(page.highWater?.[table])
      )),
      purged: purged.length,
      ...(retentionDeferred ? { retentionDeferred } : {}),
    };
  }

  async function consume(delivery) {
    try {
      const envelope = assertWorkEnvelope(delivery.envelope || delivery);
      if (envelope.kind === "receipt") {
        if (tableFromId(envelope.locator.id) !== RECEIPT_TABLE) {
          return { action: "dead-letter", reason: "INVALID_RECEIPT_TABLE" };
        }
        const store = await storeFor(envelope.locator.namespace, envelope.locator.database);
        const record = await store.load(envelope.locator.id);
        if (!record) return { action: "ack", state: "missing" };
        if (String(record.revision || "").toLowerCase() !== envelope.revision) {
          return { action: "ack", state: "stale" };
        }
        const operationHint = operationEnvelope(envelope.locator, record);
        return execute(operationHint, { ...delivery, envelope: operationHint });
      }
      return execute(envelope, delivery);
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
    createWebhookRoute,
    enqueue,
    execute,
    grant,
    reconcile,
    reconcileWebhook,
    runInline,
    stores: directory,
    sync,
    webhook,
  };
}

module.exports = { createRuntime };
