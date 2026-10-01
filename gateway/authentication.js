const crypto = require("node:crypto");
const { RuntimeError } = require("./errors");

const IDENTITY_TABLES = Object.freeze({
  email: "authentication_email",
  phone: "authentication_phone",
});

function identifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) {
    throw new Error(`Invalid authentication table identifier: ${value}`);
  }
  return value;
}

function contextKey(namespace, database) {
  return `${namespace}\u0000${database}`;
}

function contextPart(value, label) {
  if (typeof value !== "string" || !value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new RuntimeError("INVALID_AUTHENTICATION_REQUEST", `${label} is invalid`, 400);
  }
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function normalizeEmail(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return normalized && normalized.length <= 320 && normalized.includes("@") && !/\s/.test(normalized)
    ? normalized
    : null;
}

function normalizePhone(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return /^\+[1-9][0-9]{7,14}$/.test(normalized) ? normalized : null;
}

function normalizeUsername(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9_.-]{8,31}$/.test(normalized) ? normalized : null;
}

function inferChannel(value) {
  if (normalizeEmail(value)) return "email";
  if (normalizePhone(value)) return "phone";
  return null;
}

function normalizeIdentifier(value, channel) {
  const normalized = channel === "phone" ? normalizePhone(value) : normalizeEmail(value);
  if (!normalized) {
    throw new RuntimeError(
      "INVALID_AUTHENTICATION_REQUEST",
      channel === "phone" ? "A valid E.164 phone number is required" : "A valid email address is required",
      400,
    );
  }
  return normalized;
}

function randomCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function challengeMessage(identity, context, code, ttlMs, channel, expiresAt) {
  const name = String(identity.name || "there");
  const expires = new Date(expiresAt).toISOString();
  const text = [
    `Hello ${name},`,
    "",
    `Your ReBase ${channel} verification code is ${code}.`,
    `It expires at ${expires}.`,
    "",
    `Namespace: ${context.namespace}`,
    `Database: ${context.database}`,
    "",
    "If you did not request this code, you can ignore this message.",
  ].join("\n");
  const html = `<p>Hello ${escapeHtml(name)},</p>
<p>Your ReBase ${escapeHtml(channel)} verification code is <strong>${escapeHtml(code)}</strong>.</p>
<p>It expires at ${escapeHtml(expires)}.</p>
<p>Namespace: <code>${escapeHtml(context.namespace)}</code><br>Database: <code>${escapeHtml(context.database)}</code></p>
<p>If you did not request this code, you can ignore this message.</p>`;
  if (channel === "phone") {
    return {
      body: `ReBase verification code: ${code}. Expires in ${Math.max(1, Math.ceil(ttlMs / 60000))} minutes.`,
    };
  }
  return {
    subject: "Your ReBase verification code",
    text,
    html,
  };
}

function validatePositiveInteger(value, name, minimum = 1) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum) throw new Error(`${name} must be a positive integer`);
  return number;
}

function unavailableError(code = "AUTHENTICATION_UNAVAILABLE", cause) {
  const timeout = cause?.code === "REQUEST_TIMEOUT" || cause?.code === "OPERATION_TIMEOUT";
  return new RuntimeError(
    timeout ? "AUTHENTICATION_TIMEOUT" : code,
    timeout ? "Authentication service timed out" : "Authentication service is temporarily unavailable",
    timeout ? 504 : 503,
    { retryable: true, cause },
  );
}

function createAuthenticationService(options = {}) {
  if (!options.stores?.forContext) throw new Error("Authentication requires a store directory");
  const userTable = identifier(options.principals?.user || "user");
  const allowedContexts = options.allowedContexts
    ? new Set(options.allowedContexts.map((context) => contextKey(
        contextPart(context?.namespace, "Namespace"),
        contextPart(context?.database, "Database"),
      )))
    : null;
  const sealAuthenticationPayload = typeof options.sealAuthenticationPayload === "function"
    ? options.sealAuthenticationPayload
    : null;
  const rateLimiter = options.rateLimiter || null;
  const generateCode = options.generateCode || randomCode;
  if (typeof generateCode !== "function") throw new Error("Authentication code generator must be a function");
  const challengeTtlMs = validatePositiveInteger(
    options.challengeTtlMs ?? 10 * 60 * 1000,
    "Authentication challenge TTL",
  );
  if (challengeTtlMs < 60_000 || challengeTtlMs > 24 * 60 * 60 * 1000) {
    throw new Error("Authentication challenge TTL must be between one minute and one day");
  }
  // The attempt ceiling is part of the database access-method contract. Keep
  // one source of truth so a runtime option cannot silently weaken it.
  const rateLimits = {
    windowMs: validatePositiveInteger(options.rateLimits?.windowMs ?? 15 * 60 * 1000, "Authentication rate-limit window"),
    ip: validatePositiveInteger(options.rateLimits?.ip ?? 10, "Authentication IP rate limit"),
    identifier: validatePositiveInteger(options.rateLimits?.identifier ?? 3, "Authentication identifier rate limit"),
  };

  async function limit(clientAddress, context, channel, accountIdentifier) {
    if (!rateLimiter) return null;
    try {
      const [ip, account] = await Promise.all([
        rateLimiter.consume(`authentication:ip:${digest(clientAddress || "unknown")}`, {
          limit: rateLimits.ip,
          windowMs: rateLimits.windowMs,
        }),
        rateLimiter.consume(`authentication:account:${digest(`${contextKey(context.namespace, context.database)}\u0000${channel}\u0000${accountIdentifier}`)}`, {
          limit: rateLimits.identifier,
          windowMs: rateLimits.windowMs,
        }),
      ]);
      if (ip.allowed && account.allowed) return null;
      return Math.max(ip.retryAfterMs, account.retryAfterMs);
    } catch (error) {
      reportError({
        code: "AUTHENTICATION_RATE_LIMIT_UNAVAILABLE",
        channel,
        namespace: context.namespace,
        database: context.database,
        cause: error,
      });
      throw unavailableError("AUTHENTICATION_RATE_LIMIT_UNAVAILABLE", error);
    }
  }

  function reportError(details) {
    try {
      options.onError?.({
        code: String(details?.code || "AUTHENTICATION_FAILURE"),
        channel: details?.channel,
        namespace: details?.namespace,
        database: details?.database,
      });
    } catch {
      // Error hooks are observational and must not change the request result.
    }
  }

  async function findIdentity(store, channel, accountIdentifier) {
    const table = IDENTITY_TABLES[channel];
    const field = channel === "phone" ? "number" : "address";
    return store.execute(`
      RETURN (SELECT id, principal, ${field}, revision,
        principal.name AS name,
        principal.authentication_revision AS principal_revision,
        '${channel}' AS channel,
        priority
        FROM ${table}
        WHERE ${field} = $identifier AND principal.login_access = true)[0];
    `, { identifier: accountIdentifier });
  }

  async function findUsernameIdentities(store, accountIdentifier) {
    return store.execute(`
      LET $principal = (SELECT VALUE id FROM ${userTable}
        WHERE username = $identifier AND login_access = true)[0];
      RETURN {
        principal: $principal,
        email: (SELECT id, principal, address, revision,
          principal.name AS name,
          principal.authentication_revision AS principal_revision,
          'email' AS channel, priority
          FROM authentication_email
          WHERE principal = $principal AND principal.login_access = true
          ORDER BY priority DESC, id ASC),
        phone: (SELECT id, principal, number, revision,
          principal.name AS name,
          principal.authentication_revision AS principal_revision,
          'phone' AS channel, priority
          FROM authentication_phone
          WHERE principal = $principal AND principal.login_access = true
          ORDER BY priority DESC, id ASC)
      };
    `, { identifier: accountIdentifier });
  }

  async function findDeliveryPolicy(store) {
    return store.execute(`
      RETURN (SELECT email_configuration, phone_configuration
        FROM rebase_authentication_delivery_policy:default)[0];
    `);
  }

  async function enqueueChallenge(store, identity, channel, configuration, code, expiresAt, context) {
    const deliveryNonce = crypto.randomUUID();
    const challengeId = `authentication_challenge:${digest(identity.id)}`;
    const message = challengeMessage(identity, context, code, challengeTtlMs, channel, expiresAt);
    const payloadCiphertext = sealAuthenticationPayload(message);
    if (typeof payloadCiphertext !== "string" || !payloadCiphertext) {
      throw new Error("Authentication payload sealer returned an invalid ciphertext");
    }
    return store.execute(`
      BEGIN TRANSACTION;
      LET $current_challenge = (SELECT VALUE <string>id FROM authentication_challenge
        WHERE target = type::record($target))[0];
      LET $challenge_id = $current_challenge ?? $new_challenge_id;
      UPSERT type::record($challenge_id) SET
        principal = type::record($principal),
        target = type::record($target),
        principal_revision = $principal_revision,
        target_revision = $target_revision,
        code_hash = crypto::argon2::generate($code),
        attempts = 0,
        expires_at = type::datetime($expires_at),
        consumed_at = NONE,
        delivery_nonce = type::uuid($delivery_nonce);
      CREATE ONLY authentication_delivery_task SET
        configuration = type::record($configuration),
        principal = type::record($principal),
        target = type::record($target),
        challenge = type::record($challenge_id),
        channel = $channel,
        principal_revision = $principal_revision,
        target_revision = $target_revision,
        delivery_nonce = type::uuid($delivery_nonce),
        payload_ciphertext = $payload_ciphertext;
      COMMIT TRANSACTION;
      RETURN true;
    `, {
      new_challenge_id: challengeId,
      principal: String(identity.principal),
      target: String(identity.id),
      configuration: String(configuration),
      principal_revision: Number(identity.principal_revision),
      target_revision: Number(identity.revision),
      code,
      expires_at: new Date(expiresAt).toISOString(),
      delivery_nonce: deliveryNonce,
      channel,
      payload_ciphertext: payloadCiphertext,
    });
  }

  async function requestChallenge({
    namespace,
    database,
    identifier: rawIdentifier,
    channel: requestedChannel,
    clientAddress,
  }) {
    namespace = contextPart(namespace, "Namespace");
    database = contextPart(database, "Database");
    const inferred = inferChannel(rawIdentifier);
    let channel = String(requestedChannel || inferred || "").trim().toLowerCase();
    if (channel !== "username" && !IDENTITY_TABLES[channel]) {
      if (!requestedChannel && normalizeUsername(rawIdentifier)) channel = "username";
      else throw new RuntimeError("INVALID_AUTHENTICATION_REQUEST", "Channel must be email, phone, or username", 400);
    }
    const accountIdentifier = channel === "username"
      ? normalizeUsername(rawIdentifier)
      : normalizeIdentifier(rawIdentifier, channel);
    if (!accountIdentifier) {
      throw new RuntimeError(
        "INVALID_AUTHENTICATION_REQUEST",
        channel === "username" ? "A valid username is required" : "A valid email address or phone number is required",
        400,
      );
    }
    if (!rateLimiter || !sealAuthenticationPayload) {
      throw new RuntimeError(
        "AUTHENTICATION_DELIVERY_UNAVAILABLE",
        "Authentication recovery is not configured",
        503,
      );
    }
    const context = { namespace, database };
    const retryAfterMs = await limit(clientAddress, context, channel, accountIdentifier);
    if (retryAfterMs != null) return { accepted: false, rateLimited: true, retryAfterMs };
    if (allowedContexts && !allowedContexts.has(contextKey(namespace, database))) {
      return { accepted: true, delivered: false };
    }
    try {
      const store = await options.stores.forContext(namespace, database);
      const policy = await findDeliveryPolicy(store);
      if (!policy) return { accepted: true, delivered: false };
      const deliveryConfigurations = {
        email: policy.email_configuration ? String(policy.email_configuration) : null,
        phone: policy.phone_configuration ? String(policy.phone_configuration) : null,
      };
      let identity;
      if (channel === "username") {
        const candidates = await findUsernameIdentities(store, accountIdentifier);
        const selected = [
          ...(deliveryConfigurations.email ? (candidates?.email || []) : []),
          ...(deliveryConfigurations.phone ? (candidates?.phone || []) : []),
        ].sort((left, right) => Number(right.priority || 0) - Number(left.priority || 0)
          || String(left.id).localeCompare(String(right.id)));
        identity = selected[0];
        channel = identity?.channel || channel;
      } else {
        identity = await findIdentity(store, channel, accountIdentifier);
      }
      if (!identity?.id || identity.principal_revision == null || identity.revision == null) {
        return { accepted: true, delivered: false };
      }
      const configuration = deliveryConfigurations[channel];
      if (!configuration) return { accepted: true, delivered: false };
      if (!await store.load(configuration)) return { accepted: true, delivered: false };
      const code = String(generateCode());
      if (!/^[0-9]{6}$/.test(code)) throw new Error("Authentication code generator returned an invalid code");
      const expiresAt = Date.now() + challengeTtlMs;
      await enqueueChallenge(store, identity, channel, configuration, code, expiresAt, context);
      return { accepted: true, queued: true, channel };
    } catch (error) {
      reportError({
        code: String(error?.code || "AUTHENTICATION_DELIVERY_FAILED"),
        channel,
        namespace,
        database,
        cause: error,
      });
      throw unavailableError("AUTHENTICATION_DELIVERY_UNAVAILABLE", error);
    }
  }

  return Object.freeze({
    enabled: Boolean(sealAuthenticationPayload && rateLimiter),
    channels: Object.freeze({ email: Boolean(sealAuthenticationPayload), phone: Boolean(sealAuthenticationPayload) }),
    async health() {
      if (!sealAuthenticationPayload) return { ok: true, enabled: false, channels: { email: false, phone: false } };
      if (!rateLimiter) return { ok: false, enabled: true, channels: { email: true, phone: true }, error: "rate limiter unavailable" };
      let limiter = { ok: true };
      try {
        if (typeof rateLimiter.health === "function") limiter = await rateLimiter.health();
      } catch {
        limiter = { ok: false };
      }
      return {
        ok: limiter.ok !== false,
        enabled: true,
        channels: { email: true, phone: true },
        rateLimit: limiter,
      };
    },
    requestChallenge,
  });
}

module.exports = {
  IDENTITY_TABLES,
  contextPart,
  createAuthenticationService,
  inferChannel,
  normalizeEmail,
  normalizeIdentifier,
  normalizePhone,
  normalizeUsername,
  randomCode,
  unavailableError,
};
