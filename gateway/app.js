const crypto = require("node:crypto");
const { Hono } = require("hono");
const { RuntimeError, publicError } = require("./errors");

function verifyInternal(request, rawBody, secret) {
  if (!secret) throw new Error("Runtime wake secret is not configured");
  const bearer = request.headers.get("authorization");
  if (bearer === `Bearer ${secret}`) return true;
  const timestamp = request.headers.get("x-rebase-timestamp") || "";
  const signature = request.headers.get("x-rebase-signature") || "";
  if (!timestamp || !signature || Math.abs(Date.now() - Number(timestamp)) > 300000) return false;
  const expected = crypto.createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");
  const actual = Buffer.from(signature);
  const wanted = Buffer.from(expected);
  return actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted);
}

function parseJson(rawBody, code = "INVALID_JSON") {
  try {
    return rawBody ? JSON.parse(rawBody) : {};
  } catch {
    throw new RuntimeError(code, "Invalid JSON body", 400);
  }
}

function createRuntimeApp({ runtime, handlers, wakeSecret, defaultContext = {} }) {
  const app = new Hono();
  app.get("/healthz", (c) => c.json({ ok: true, tables: handlers.tables }));

  app.post("/internal/sync", async (c) => {
    const rawBody = await c.req.text();
    if (!verifyInternal(c.req.raw, rawBody, wakeSecret)) throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
    return c.json({ ok: true, patch: await runtime.sync(parseJson(rawBody)) });
  });

  app.post("/internal/async", async (c) => {
    const rawBody = await c.req.text();
    if (!verifyInternal(c.req.raw, rawBody, wakeSecret)) throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
    return c.json({ ok: true, queued: await runtime.enqueue(parseJson(rawBody)) }, 202);
  });

  app.post("/internal/reconcile", async (c) => {
    const rawBody = await c.req.text();
    if (!verifyInternal(c.req.raw, rawBody, wakeSecret)) throw new RuntimeError("INVALID_WAKE_AUTH", "Invalid internal wake authentication", 401);
    return c.json({ ok: true, ...(await runtime.reconcile(parseJson(rawBody))) });
  });

  app.post("/webhooks/:table", async (c) => {
    const table = c.req.param("table");
    const rawBody = await c.req.text();
    const payload = parseJson(rawBody, "INVALID_WEBHOOK");
    const result = await runtime.webhook({
      namespace: defaultContext.namespace,
      database: defaultContext.database,
      table,
      payload,
      rawBody,
      request: c.req.raw,
    });
    return c.json({ ok: true, data: result || {} });
  });

  app.onError((error, c) => {
    const response = publicError(error);
    return c.json(response.body, response.status);
  });
  return app;
}

module.exports = { createRuntimeApp, verifyInternal };
