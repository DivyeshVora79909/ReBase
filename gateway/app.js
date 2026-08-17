const crypto = require("node:crypto");
const path = require("node:path");
const { Hono } = require("hono");
const { bodyLimit } = require("hono/body-limit");
const { createExecutor } = require("./runtime/executor");
const { hasCapability } = require("./runtime/access");
const { GatewayError, publicError } = require("./runtime/errors");
const { requestId } = require("./runtime/utils");

function bearerToken(header) {
  const match = /^Bearer\s+(.+)$/i.exec(header || "");
  return match?.[1];
}

function jsonBody(c) {
  return c.req.json().catch(() => {
    throw new GatewayError("INVALID_JSON", "Invalid JSON body", 400);
  });
}

function createApp({ database, handlers, providers, outboxRelay, executor }) {
  const edge = executor || createExecutor({ database, handlers, providers });
  const app = new Hono();

  app.use("*", async (c, next) => {
    c.set("requestId", requestId(c.req.header("x-request-id")));
    c.header("x-request-id", c.get("requestId"));
    await next();
  });

  app.use("/v1/*", bodyLimit({
    maxSize: 1024 * 1024,
    onError: (c) => c.json({
      ok: false,
      error: { code: "BODY_TOO_LARGE", message: "Request body is too large" },
      requestId: c.get("requestId"),
    }, 413),
  }));

  async function caller(c) {
    const actorId = await database.authenticate(bearerToken(c.req.header("authorization")));
    c.set("actor", actorId);
    return actorId;
  }

  async function auth(c) {
    return database.actor(await caller(c));
  }

  app.get("/healthz", (c) => c.json({ ok: true, handlers: handlers.capabilities.length }));

  app.post("/v1/edge/:capability", async (c) => {
    const capability = c.req.param("capability");
    c.set("capability", capability);
    const handler = handlers.get(capability);
    if (!handler || handler.mode === "webhook") {
      throw new GatewayError("UNKNOWN_EDGE", "Unknown edge function", 404);
    }
    const current = await auth(c);
    if (!hasCapability(current, capability)) throw new GatewayError("FORBIDDEN", "Forbidden", 403);
    const body = await jsonBody(c);
    const allowed = new Set(["args", "records", "requestId"]);
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((key) => !allowed.has(key))) {
      throw new GatewayError("EDGE_REQUEST_INVALID", "Invalid edge request", 400);
    }
    const args = body.args ?? {};
    const recordIds = body.records ?? {};
    const correlationId = requestId(body.requestId || c.get("requestId"));
    const actorId = String(current.id);
    const started = Date.now();

    if (handler.mode === "job") {
      const prepared = await edge.prepare({ caller: actorId, handler, args, recordIds, auth: current });
      const job = await database.createJob({
        caller: actorId,
        capability,
        args: prepared.args,
        records: prepared.recordIds,
        requestId: correlationId,
        maxAttempts: handler.maxAttempts,
      });
      if (outboxRelay) outboxRelay.runOnce().catch((error) => console.error(`Outbox relay failed: ${error.message}`));
      const id = String(job.id);
      await database.log({ requestId: correlationId, jobId: id, capability, actor: actorId, phase: "gateway", outcome: "queued" });
      return c.json({
        ok: true,
        data: { jobId: id, status: job.status, statusUrl: `/v1/jobs/${encodeURIComponent(id)}` },
        requestId: correlationId,
      }, 202);
    }

    const data = await edge.execute({
      caller: actorId,
      handler,
      args,
      recordIds,
      auth: current,
      execution: { requestId: correlationId },
    });
    await database.log({
      requestId: correlationId,
      capability,
      actor: actorId,
      phase: "gateway",
      outcome: "succeeded",
      durationMs: Date.now() - started,
    });
    return c.json({ ok: true, data, requestId: correlationId });
  });

  app.get("/v1/jobs/:job", async (c) => {
    const actorId = await caller(c);
    const job = await database.job(actorId, decodeURIComponent(c.req.param("job")));
    return c.json({ ok: true, data: job, requestId: c.get("requestId") });
  });

  app.post("/v1/jobs/:job/cancel", async (c) => {
    const actorId = await caller(c);
    const job = await database.cancelJob(actorId, decodeURIComponent(c.req.param("job")));
    return c.json({ ok: true, data: job, requestId: c.get("requestId") });
  });

  app.post("/v1/webhooks/:capability", async (c) => {
    const capability = c.req.param("capability");
    const handler = handlers.get(capability);
    if (!handler || handler.mode !== "webhook") {
      throw new GatewayError("UNKNOWN_WEBHOOK", "Unknown webhook", 404);
    }
    c.set("capability", capability);
    const rawBody = await c.req.text();
    const verified = await handler.implementation.verify({ request: c.req.raw, rawBody, providers });
    if (!verified || typeof verified !== "object" || verified.args === undefined) {
      throw new GatewayError("INVALID_WEBHOOK", "Invalid webhook signature or payload", 401);
    }
    const providerEventId = verified.eventId
      ? String(verified.eventId)
      : crypto.createHash("sha256").update(rawBody).digest("hex");
    const provider = verified.provider ? String(verified.provider) : null;
    const dedupeKey = crypto.createHash("sha256").update(`${capability}\n${providerEventId}`).digest("hex");
    const leaseOwner = crypto.randomUUID();
    const claim = await database.claimWebhook({ dedupeKey, capability, provider, providerEventId, leaseOwner });
    if (!claim.claimed) {
      if (claim.receipt?.status !== "succeeded") {
        throw new GatewayError("WEBHOOK_IN_PROGRESS", "Webhook is already being processed", 503, {
          retryable: true,
          delaySeconds: 5,
        });
      }
      return c.json({ ok: true, data: { duplicate: true, eventId: providerEventId }, requestId: c.get("requestId") });
    }
    try {
      const data = await edge.executeWebhook({
        handler,
        args: verified.args,
        execution: {
          requestId: c.get("requestId"),
          provider,
          providerEventId,
          verification: verified,
        },
      });
      await database.finishWebhook(dedupeKey, leaseOwner, "succeeded", data || {}, null);
      await database.log({
        capability,
        provider,
        phase: "webhook",
        outcome: "succeeded",
        data: { eventId: providerEventId },
      });
      return c.json({ ok: true, data, requestId: c.get("requestId") });
    } catch (error) {
      const normalized = publicError(error, c.get("requestId"));
      await database.finishWebhook(dedupeKey, leaseOwner, "failed", null, normalized.body.error);
      throw error;
    }
  });

  app.onError(async (error, c) => {
    const response = publicError(error, c.get("requestId") || requestId());
    await database.log({
      requestId: c.get("requestId"),
      capability: c.get("capability") || "httpRequest",
      actor: c.get("actor"),
      phase: "gateway",
      outcome: "failed",
      errorCode: response.body.error.code,
    });
    return c.json(response.body, response.status);
  });

  app.notFound((c) => c.json({
    ok: false,
    error: { code: "NOT_FOUND", message: "Not found" },
    requestId: c.get("requestId") || requestId(),
  }, 404));

  return app;
}

function defaultPaths(project = process.env.REBASE_PROJECT || "test") {
  const root = path.resolve(__dirname, "..");
  return { projectDir: path.join(root, "build", project) };
}

module.exports = { bearerToken, createApp, defaultPaths };
