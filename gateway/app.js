const crypto = require("node:crypto");
const { RuntimeError, publicError } = require("./errors");
const { assertLocator } = require("./queues/port");

function header(request, name) {
  const headers = request?.headers;
  const value = typeof headers?.get === "function"
    ? headers.get(name)
    : headers?.[String(name).toLowerCase()];
  if (Array.isArray(value)) return value.join(", ");
  return value == null ? null : String(value);
}

function safeEqual(left, right) {
  const actual = Buffer.from(String(left || ""));
  const expected = Buffer.from(String(right || ""));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function verifyInternal(request, rawBody, secret, options = {}) {
  if (!secret) throw new Error("Runtime wake secret is not configured");
  const bearer = header(request, "authorization");
  if (options.allowBearer !== false && bearer === `Bearer ${secret}`) return true;
  const timestamp = header(request, "x-rebase-timestamp") || "";
  const supplied = (header(request, "x-rebase-signature") || "").replace(/^sha256=/i, "");
  const timestampMs = Number(timestamp);
  const normalizedTimestampMs = timestampMs > 0 && timestampMs < 1e12 ? timestampMs * 1000 : timestampMs;
  const replayWindowMs = options.replayWindowMs || 5 * 60 * 1000;
  if (!Number.isFinite(normalizedTimestampMs) || Math.abs(Date.now() - normalizedTimestampMs) > replayWindowMs) return false;
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody || ""));
  const signedBytes = Buffer.concat([Buffer.from(`${timestamp}.`), body]);
  const expected = crypto.createHmac("sha256", secret).update(signedBytes).digest("hex");
  return safeEqual(supplied, expected);
}

function bodyTooLarge() {
  return new RuntimeError("BODY_TOO_LARGE", "Request body is too large", 413);
}

function readBody(request, maximumBytes) {
  const declared = Number(header(request, "content-length") || 0);
  if (declared > maximumBytes) {
    request.resume?.();
    throw bodyTooLarge();
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    let oversized = false;
    let settled = false;
    const cleanup = () => {
      request.removeListener("data", onData);
      request.removeListener("end", onEnd);
      request.removeListener("error", onError);
      request.removeListener("aborted", onAborted);
    };
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve(result);
    };
    const onData = (chunk) => {
      if (oversized) return;
      length += chunk.length;
      if (length > maximumBytes) {
        oversized = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(oversized ? bodyTooLarge() : null, Buffer.concat(chunks, length));
    const onError = (error) => finish(error);
    const onAborted = () => finish(new RuntimeError("REQUEST_ABORTED", "Request body was interrupted", 400));
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

function isJsonContentType(contentType) {
  return /^application\/json(?:\s*;|$)/i.test(String(contentType || ""));
}

function requireJsonContentType(request) {
  if (!isJsonContentType(header(request, "content-type"))) {
    throw new RuntimeError("UNSUPPORTED_MEDIA_TYPE", "JSON content type is required", 415);
  }
}

function parseJson(rawBody, code = "INVALID_JSON") {
  try {
    const text = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody || "");
    return text ? JSON.parse(text) : {};
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

function requestClientAddress(request, { trustProxy = false } = {}) {
  if (trustProxy) {
    const proxyAddress = header(request, "x-real-ip")
      || header(request, "x-forwarded-for")?.split(",", 1)[0]?.trim();
    if (proxyAddress) return proxyAddress;
  }
  return request?.socket?.remoteAddress || "unknown";
}

function requestView(request) {
  return {
    method: request.method,
    url: request.url,
    headers: Object.freeze({ get: (name) => header(request, name) }),
  };
}

function sendJson(response, status, value, headers = {}) {
  if (response.destroyed || response.writableEnded) return;
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "content-type": "application/json; charset=UTF-8",
    "content-length": body.byteLength,
    ...headers,
  });
  response.end(body);
}

function requestPath(request) {
  try {
    return new URL(request.url || "/", "http://runtime.local").pathname;
  } catch {
    throw new RuntimeError("INVALID_URL", "Invalid request URL", 400);
  }
}

function decodeSegment(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new RuntimeError("INVALID_URL", "Invalid request path", 400);
  }
}

function createRuntimeApp({
  runtime,
  handlers,
  webhooks,
  queue,
  adapters,
  webhookAdapters,
  adapterConfiguration = {},
  authentication,
  oauth,
  runtimeSecret,
  defaultContext = {},
  readinessContexts = [],
  bodyLimitBytes = 256 * 1024,
  requestTimeoutMs = 30000,
  allowBearer = true,
  allowInternalBearer = allowBearer,
  trustProxy = false,
  debug = false,
}) {
  if (!Number.isInteger(bodyLimitBytes) || bodyLimitBytes < 1024) throw new Error("bodyLimitBytes must be at least 1024 bytes");
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 300000) throw new Error("requestTimeoutMs must be between 1 and 300000ms");
  const webhookProviders = webhooks?.providers || [];
  const webhookRouting = webhookProviders.every((provider) => (
    typeof webhookAdapters?.[provider]?.extractRoute === "function"
    && typeof webhookAdapters?.[provider]?.verify === "function"
  ));

  async function readiness() {
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
      const handler = handlers.get(table);
      return Boolean((handler?.process || handler?.mode) && Array.isArray(contract?.patchFields));
    });
    const requiredAdapters = [...new Set(handlers.tables.flatMap((table) => (
      handlers.contracts?.get(table)?.adapters || handlers.get(table)?.contract?.adapters || []
    )))].sort();
    const missingAdapters = requiredAdapters.filter((name) => typeof adapters?.[name] !== "function");
    const needsStorageBucket = requiredAdapters.some((name) => (
      name === "createS3UploadGrant" || name === "createS3AccessGrant"
      || name === "deleteS3Object" || name === "purgeS3Object"
    ));
    const missingConfiguration = needsStorageBucket && adapterConfiguration.requiresStorageBucket
      && !adapterConfiguration.storageBucket
      ? ["REBASE_STORAGE_BUCKET"]
      : [];
    const adapterHealth = {
      ok: missingAdapters.length === 0 && missingConfiguration.length === 0,
      required: requiredAdapters,
      missing: missingAdapters,
      missingConfiguration,
    };
    const authenticationHealth = typeof authentication?.health === "function"
      ? await authentication.health()
      : { ok: true, enabled: false };
    const oauthHealth = typeof oauth?.health === "function"
      ? await oauth.health()
      : { ok: true, configuredProviders: [] };
    const workers = queueHealth.worker === true;
    const ok = queueHealth.ok && workers && surreal && contracts && adapterHealth.ok
      && webhookRouting && authenticationHealth.ok && oauthHealth.ok;
    return {
      ok,
      queue: { ...queueHealth, workers },
      surreal,
      surrealErrors,
      contexts,
      handlers: { ok: contracts, tables: handlers.tables },
      adapters: adapterHealth,
      webhooks: { ok: Boolean(webhookRouting), providers: webhookProviders },
      authentication: authenticationHealth,
      oauth: oauthHealth,
    };
  }

  async function readJsonBody(request) {
    requireJsonContentType(request);
    return parseJson(await readBody(request, bodyLimitBytes));
  }

  async function handle(request, response) {
    try {
      const method = String(request.method || "GET").toUpperCase();
      const pathname = requestPath(request);
      if (method === "GET" && pathname === "/healthz") {
        return sendJson(response, 200, { ok: true });
      }
      if (method === "GET" && pathname === "/readyz") {
        const result = await withRequestTimeout(requestTimeoutMs, readiness);
        return sendJson(response, result.ok ? 200 : 503, result);
      }
      if (method === "POST" && pathname === "/anonymous/authentication/challenges") {
        const body = await readJsonBody(request);
        if (!authentication?.requestChallenge) {
          throw new RuntimeError("AUTHENTICATION_DELIVERY_UNAVAILABLE", "Authentication delivery is not configured", 503);
        }
        const result = await withRequestTimeout(requestTimeoutMs, () => authentication.requestChallenge({
          namespace: body.namespace,
          database: body.database,
          identifier: body.identifier,
          channel: body.channel,
          clientAddress: requestClientAddress(request, { trustProxy }),
        }));
        if (result.rateLimited) {
          const retryAfter = Math.max(1, Math.ceil(result.retryAfterMs / 1000));
          return sendJson(response, 429, {
            ok: false,
            error: { code: "RATE_LIMITED", message: "Too many authentication requests" },
          }, { "retry-after": String(retryAfter) });
        }
        return sendJson(response, 202, { ok: true });
      }
      if (method === "POST" && pathname === "/internal/oauth") {
        requireJsonContentType(request);
        const rawBody = await readBody(request, bodyLimitBytes);
        if (!verifyInternal(request, rawBody, runtimeSecret, { allowBearer })) {
          throw new RuntimeError("INVALID_OAUTH_AUTH", "Invalid internal OAuth authentication", 401);
        }
        const body = parseJson(rawBody);
        const result = typeof oauth?.verify === "function"
          ? await withRequestTimeout(requestTimeoutMs, () => oauth.verify(body.provider, body.token))
          : { verified: false };
        return sendJson(response, 200, result?.verified === true && result.email
          ? { verified: true, email: result.email }
          : { verified: false });
      }
      if (method === "POST" && pathname === "/internal/sync") {
        requireJsonContentType(request);
        const rawBody = await readBody(request, bodyLimitBytes);
        if (!verifyInternal(request, rawBody, runtimeSecret, { allowBearer: allowInternalBearer })) {
          throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
        }
        const result = await withRequestTimeout(requestTimeoutMs, () => runtime.sync(parseJson(rawBody)));
        return sendJson(response, result.outcome === "success" ? 200 : 409, result);
      }
      if (method === "POST" && pathname === "/internal/grant") {
        requireJsonContentType(request);
        const rawBody = await readBody(request, bodyLimitBytes);
        if (!verifyInternal(request, rawBody, runtimeSecret, { allowBearer: allowInternalBearer })) {
          throw new RuntimeError("INVALID_GRANT_AUTH", "Invalid internal grant authentication", 401);
        }
        const result = await withRequestTimeout(requestTimeoutMs, () => runtime.grant(parseJson(rawBody)));
        return sendJson(response, result.outcome === "success" ? 200 : 409, result);
      }
      if (method === "POST" && pathname === "/internal/webhook-route") {
        requireJsonContentType(request);
        const rawBody = await readBody(request, bodyLimitBytes);
        if (!verifyInternal(request, rawBody, runtimeSecret, { allowBearer: allowInternalBearer })) {
          throw new RuntimeError("INVALID_WEBHOOK_ROUTE_AUTH", "Invalid internal webhook-route authentication", 401);
        }
        const result = await withRequestTimeout(requestTimeoutMs, () => runtime.createWebhookRoute(parseJson(rawBody)));
        return sendJson(response, 200, result);
      }
      if (method === "POST" && pathname === "/internal/inline") {
        requireJsonContentType(request);
        const rawBody = await readBody(request, bodyLimitBytes);
        if (!verifyInternal(request, rawBody, runtimeSecret, { allowBearer: allowInternalBearer })) {
          throw new RuntimeError("INVALID_INLINE_AUTH", "Invalid internal inline-operation authentication", 401);
        }
        const locator = assertLocator(parseJson(rawBody));
        const result = await withRequestTimeout(requestTimeoutMs, () => runtime.runInline(locator));
        return sendJson(response, result.state === "succeeded" ? 200 : 202, { ok: true, state: result.state });
      }
      if (method === "POST" && pathname === "/internal/wake/task") {
        requireJsonContentType(request);
        const rawBody = await readBody(request, bodyLimitBytes);
        if (!verifyInternal(request, rawBody, runtimeSecret, { allowBearer: allowInternalBearer })) {
          throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
        }
        const locator = assertLocator(parseJson(rawBody));
        const result = await withRequestTimeout(requestTimeoutMs, () => runtime.enqueue(locator));
        return sendJson(response, 202, { ok: true, queued: result });
      }
      const webhookMatch = /^\/webhooks\/([^/]+)(?:\/([^/]+))?$/.exec(pathname);
      if (method === "POST" && webhookMatch) {
        const rawBody = await readBody(request, bodyLimitBytes);
        const provider = decodeSegment(webhookMatch[1]).toLowerCase();
        if (!webhooks?.providers?.includes(provider)) {
          throw new RuntimeError("WEBHOOK_PROVIDER_NOT_FOUND", `No webhook handler for ${provider}`, 404);
        }
        if (!webhookRouting) throw new RuntimeError("WEBHOOK_PROVIDER_UNAVAILABLE", "Webhook provider is unavailable", 503);
        const result = await withRequestTimeout(requestTimeoutMs, () => runtime.webhook({
          provider,
          request: requestView(request),
          routeCapsule: webhookMatch[2] ? decodeSegment(webhookMatch[2]) : undefined,
          rawBody,
        }));
        return sendJson(response, 200, { ok: true, data: result });
      }
      return sendJson(response, 404, { ok: false, error: { code: "NOT_FOUND", message: "Route not found" } });
    } catch (error) {
      if (debug) console.error("runtime app error", error.stack || error);
      const result = publicError(error);
      return sendJson(response, result.status, result.body);
    }
  }

  return handle;
}

module.exports = {
  createRuntimeApp,
  isJsonContentType,
  parseJson,
  readBody,
  requireJsonContentType,
  requestClientAddress,
  verifyInternal,
};
