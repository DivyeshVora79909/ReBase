const crypto = require("node:crypto");
const { Hono } = require("hono");
const { bodyLimit } = require("hono/body-limit");
const { RuntimeError, publicError } = require("./errors");
const { LANES, assertLocator } = require("./queues/port");

function safeEqual(left, right) {
  const actual = Buffer.from(String(left || ""));
  const expected = Buffer.from(String(right || ""));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function verifyInternal(request, rawBody, secret, options = {}) {
  if (!secret) throw new Error("Runtime wake secret is not configured");
  const bearer = request.headers.get("authorization");
  if (options.allowBearer !== false && bearer === `Bearer ${secret}`) return true;
  const timestamp = request.headers.get("x-rebase-timestamp") || "";
  const supplied = (request.headers.get("x-rebase-signature") || "").replace(/^sha256=/i, "");
  const timestampMs = Number(timestamp);
  const normalizedTimestampMs = timestampMs > 0 && timestampMs < 1e12 ? timestampMs * 1000 : timestampMs;
  const replayWindowMs = options.replayWindowMs || 5 * 60 * 1000;
  if (!Number.isFinite(normalizedTimestampMs) || Math.abs(Date.now() - normalizedTimestampMs) > replayWindowMs) return false;
  const expected = crypto.createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");
  return safeEqual(supplied, expected);
}

async function readBody(c, maximumBytes) {
  const declared = Number(c.req.header("content-length") || 0);
  if (declared > maximumBytes) throw new RuntimeError("BODY_TOO_LARGE", "Request body is too large", 413);
  const bytes = Buffer.from(await c.req.raw.arrayBuffer());
  if (bytes.byteLength > maximumBytes) throw new RuntimeError("BODY_TOO_LARGE", "Request body is too large", 413);
  return bytes.toString("utf8");
}

function requireJsonContentType(c) {
  const contentType = c.req.header("content-type") || "";
  if (!isJsonContentType(contentType)) {
    throw new RuntimeError("UNSUPPORTED_MEDIA_TYPE", "JSON content type is required", 415);
  }
}

function isJsonContentType(contentType) {
  return /^application\/json(?:\s*;|$)/i.test(String(contentType || ""));
}

function parseJson(rawBody, code = "INVALID_JSON") {
  try {
    return rawBody ? JSON.parse(rawBody) : {};
  } catch {
    throw new RuntimeError(code, "Invalid JSON body", 400);
  }
}

function withRequestTimeout(timeoutMs, operation) {
  let timer;
  const timeout = new Promise((_, reject) => {
    const error = new RuntimeError("REQUEST_TIMEOUT", "Request timed out", 504, { retryable: true });
    timer = setTimeout(() => reject(error), timeoutMs);
    timer.unref?.();
  });
  return Promise.race([operation(), timeout]).finally(() => clearTimeout(timer));
}

function createRuntimeApp({
  runtime,
  handlers,
  webhooks,
  queue,
  providers,
  wakeSecret,
  defaultContext = {},
  readinessContexts = [],
  bodyLimitBytes = 256 * 1024,
  requestTimeoutMs = 30000,
  allowBearer = true,
  debug = false,
}) {
  if (!Number.isInteger(bodyLimitBytes) || bodyLimitBytes < 1024) throw new Error("bodyLimitBytes must be at least 1024 bytes");
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 300000) throw new Error("requestTimeoutMs must be between 1 and 300000ms");
  const app = new Hono();
  const webhookProviders = webhooks?.providers || [];
  const webhookRouting = webhookProviders.every((provider) => (
    typeof providers?.webhooks?.[provider]?.extractRoute === "function"
    && typeof providers?.webhooks?.[provider]?.verify === "function"
  ));
  app.use("*", bodyLimit({
    maxSize: bodyLimitBytes,
    onError() { throw new RuntimeError("BODY_TOO_LARGE", "Request body is too large", 413); },
  }));

  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/readyz", async (c) => {
    const queueHealth = await queue.health();
    const contexts = readinessContexts.length
      ? readinessContexts
      : (defaultContext.namespace && defaultContext.database ? [defaultContext] : []);
    let surreal = contexts.length > 0;
    const surrealErrors = [];
    try {
      for (const context of contexts) {
        const store = await runtime.stores.forContext(context.namespace, context.database);
        if (!await store.health()) surreal = false;
      }
    } catch (error) {
      surreal = false;
      surrealErrors.push(error.message);
    }
    if (!contexts.length) surrealErrors.push("No readiness database context configured");
    const contracts = handlers.tables.every((table) => {
      const contract = handlers.contracts?.get(table) || handlers.get(table)?.contract;
      return Boolean(handlers.get(table)?.process && contract?.patchFields);
    });
    const requiredProviders = [...new Set(handlers.tables.flatMap((table) => (
      handlers.contracts?.get(table)?.providers || handlers.get(table)?.contract?.providers || []
    )))].sort();
    let providerHealth;
    try {
      providerHealth = typeof providers?.health === "function"
        ? await providers.health({ required: requiredProviders, webhookProviders })
        : { ok: requiredProviders.every((name) => providers?.[name]), missing: requiredProviders.filter((name) => !providers?.[name]) };
    } catch (error) {
      providerHealth = { ok: false, error: error.message, missing: requiredProviders };
    }
    const workers = LANES.every((lane) => queueHealth.lanes?.[lane] === true);
    const ok = queueHealth.ok && workers && surreal && contracts && providerHealth.ok && webhookRouting;
    return c.json({
      ok,
      queue: { ...queueHealth, workers },
      surreal,
      surrealErrors,
      contexts,
      handlers: { ok: contracts, tables: handlers.tables },
      providers: providerHealth,
      webhooks: { ok: Boolean(webhookRouting), providers: webhookProviders },
    }, ok ? 200 : 503);
  });

  app.post("/internal/sync", async (c) => {
    requireJsonContentType(c);
    const rawBody = await readBody(c, bodyLimitBytes);
    if (!verifyInternal(c.req.raw, rawBody, wakeSecret, { allowBearer })) {
      throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
    }
    const result = await withRequestTimeout(requestTimeoutMs, () => runtime.sync(parseJson(rawBody)));
    return c.json(result, result.outcome === "success" ? 200 : 409);
  });

  app.post("/internal/wake/:lane", async (c) => {
    const lane = c.req.param("lane");
    if (!LANES.includes(lane)) throw new RuntimeError("INVALID_QUEUE_LANE", "Invalid queue lane", 404);
    requireJsonContentType(c);
    const rawBody = await readBody(c, bodyLimitBytes);
    if (!verifyInternal(c.req.raw, rawBody, wakeSecret, { allowBearer })) {
      throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
    }
    const locator = assertLocator(parseJson(rawBody));
    const result = await withRequestTimeout(requestTimeoutMs, () => runtime.enqueue(lane, locator));
    return c.json({ ok: true, queued: result }, 202);
  });

  app.post("/webhooks/:provider", async (c) => {
    const rawBody = await readBody(c, bodyLimitBytes);
    const provider = c.req.param("provider").toLowerCase();
    if (!webhooks?.providers?.includes(provider)) {
      throw new RuntimeError("WEBHOOK_PROVIDER_NOT_FOUND", `No webhook handler for ${provider}`, 404);
    }
    if (!webhookRouting) throw new RuntimeError("WEBHOOK_PROVIDER_UNAVAILABLE", "Webhook provider is unavailable", 503);
    const result = await withRequestTimeout(requestTimeoutMs, () => runtime.webhook({
      provider,
      request: c.req.raw,
      rawBody,
    }));
    return c.json({ ok: true, data: result }, 200);
  });

  app.notFound((c) => c.json({ ok: false, error: { code: "NOT_FOUND", message: "Route not found" } }, 404));
  app.onError((error, c) => {
    if (debug) console.error("runtime app error", error.stack || error);
    const response = publicError(error);
    return c.json(response.body, response.status);
  });
  return app;
}

module.exports = {
  createRuntimeApp,
  isJsonContentType,
  parseJson,
  readBody,
  requireJsonContentType,
  verifyInternal,
};
