const crypto = require("node:crypto");
const { RuntimeError } = require("./errors");
const { tableFromId } = require("./handlers");

const VERSION = "v1";
const PURPOSE = Buffer.from("rebase:webhook-route:v1", "utf8");

function routeKey(secret) {
  if (!secret) throw new Error("Webhook route secret is required");
  return Buffer.from(crypto.hkdfSync("sha256", String(secret), Buffer.alloc(0), PURPOSE, 32));
}

function assertRoute(route) {
  const normalized = {
    provider: String(route?.provider || "").toLowerCase(),
    namespace: String(route?.namespace || ""),
    database: String(route?.database || ""),
    config: String(route?.config || ""),
    id: String(route?.id || ""),
  };
  if (
    !/^[a-z][a-z0-9_-]*$/.test(normalized.provider)
    || !normalized.namespace
    || !normalized.database
    || !tableFromId(normalized.config)
    || !tableFromId(normalized.id)
  ) {
    throw new RuntimeError("INVALID_WEBHOOK_ROUTE", "Webhook route is invalid", 400);
  }
  return normalized;
}

function createWebhookRouteCodec(secret) {
  const key = routeKey(secret);

  function seal(route) {
    const value = assertRoute(route);
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(PURPOSE);
    const plaintext = Buffer.from(JSON.stringify({
      p: value.provider,
      n: value.namespace,
      d: value.database,
      c: value.config,
      i: value.id,
    }));
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return `${VERSION}.${Buffer.concat([nonce, cipher.getAuthTag(), encrypted]).toString("base64url")}`;
  }

  function open(token) {
    try {
      const value = String(token || "");
      if (!value.startsWith(`${VERSION}.`) || value.length > 2048) throw new Error("invalid token");
      const packed = Buffer.from(value.slice(VERSION.length + 1), "base64url");
      if (packed.length < 29) throw new Error("invalid token");
      const nonce = packed.subarray(0, 12);
      const tag = packed.subarray(12, 28);
      const encrypted = packed.subarray(28);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
      decipher.setAAD(PURPOSE);
      decipher.setAuthTag(tag);
      const payload = JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"));
      return assertRoute({
        provider: payload.p,
        namespace: payload.n,
        database: payload.d,
        config: payload.c,
        id: payload.i,
      });
    } catch (error) {
      if (error instanceof RuntimeError) throw error;
      throw new RuntimeError("INVALID_WEBHOOK_ROUTE", "Webhook route is invalid", 401);
    }
  }

  return Object.freeze({ open, seal });
}

module.exports = { assertRoute, createWebhookRouteCodec };
