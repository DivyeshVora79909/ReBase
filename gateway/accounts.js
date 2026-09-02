const crypto = require("node:crypto");
const { RuntimeError } = require("./errors");

function identifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) throw new Error(`Invalid principal table: ${value}`);
  return value;
}

function normalizedIdentifier(value) {
  if (typeof value !== "string") throw new RuntimeError("INVALID_RECOVERY_REQUEST", "A recovery identifier is required", 400);
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > 320) {
    throw new RuntimeError("INVALID_RECOVERY_REQUEST", "A valid recovery identifier is required", 400);
  }
  return normalized;
}

function contextKey(namespace, database) {
  return `${namespace}\u0000${database}`;
}

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
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

function recoveryMessage(record, context) {
  const name = String(record.name || "there");
  const invite = String(record.invite_token);
  const namespace = String(context.namespace);
  const database = String(context.database);
  const expiresAt = new Date(record.invite_expires_at).toISOString();
  const text = [
    `Hello ${name},`,
    "",
    "Use this one-time invite token to set a new password for your existing ReBase account:",
    invite,
    "",
    `Namespace: ${namespace}`,
    `Database: ${database}`,
    `Expires: ${expiresAt}`,
    "",
    "If you did not request this, your current password remains valid and you can ignore this email.",
  ].join("\n");
  const html = `<p>Hello ${escapeHtml(name)},</p>
<p>Use this one-time invite token to set a new password for your existing ReBase account:</p>
<p><code>${escapeHtml(invite)}</code></p>
<p>Namespace: <code>${escapeHtml(namespace)}</code><br>Database: <code>${escapeHtml(database)}</code><br>Expires: ${escapeHtml(expiresAt)}</p>
<p>If you did not request this, your current password remains valid and you can ignore this email.</p>`;
  return {
    to: [String(record.email)],
    subject: "Reset your ReBase account password",
    text,
    html,
  };
}

function createAccountService(options = {}) {
  if (!options.stores?.forContext) throw new Error("Account recovery requires a store directory");
  const userTable = identifier(options.principals?.user);
  const allowedContexts = options.allowedContexts
    ? new Set(options.allowedContexts.map((context) => contextKey(context.namespace, context.database)))
    : null;
  const sendEmail = options.sendEmail || null;
  const rateLimiter = options.rateLimiter || null;
  const inviteTtlMs = Number(options.inviteTtlMs || 24 * 60 * 60 * 1000);
  const rateLimits = {
    windowMs: Number(options.rateLimits?.windowMs || 15 * 60 * 1000),
    ip: Number(options.rateLimits?.ip || 10),
    identifier: Number(options.rateLimits?.identifier || 3),
  };
  if (!Number.isInteger(inviteTtlMs) || inviteTtlMs < 60_000 || inviteTtlMs > 7 * 24 * 60 * 60 * 1000) {
    throw new Error("Recovery invite TTL must be between one minute and seven days");
  }
  if (!Number.isInteger(rateLimits.windowMs) || rateLimits.windowMs < 1000) {
    throw new Error("Recovery rate-limit window must be at least one second");
  }
  if (!Number.isInteger(rateLimits.ip) || rateLimits.ip < 1
      || !Number.isInteger(rateLimits.identifier) || rateLimits.identifier < 1) {
    throw new Error("Recovery rate limits must be positive integers");
  }

  async function limit(clientAddress, context, accountIdentifier) {
    if (!rateLimiter) return null;
    const [ip, account] = await Promise.all([
      rateLimiter.consume(`recovery:ip:${digest(clientAddress || "unknown")}`, {
        limit: rateLimits.ip,
        windowMs: rateLimits.windowMs,
      }),
      rateLimiter.consume(`recovery:account:${digest(`${contextKey(context.namespace, context.database)}\u0000${accountIdentifier}`)}`, {
        limit: rateLimits.identifier,
        windowMs: rateLimits.windowMs,
      }),
    ]);
    if (ip.allowed && account.allowed) return null;
    return Math.max(ip.retryAfterMs, account.retryAfterMs);
  }

  return Object.freeze({
    enabled: Boolean(sendEmail && rateLimiter),
    async requestRecovery({ namespace, database, identifier: rawIdentifier, clientAddress }) {
      if (typeof namespace !== "string" || !namespace || typeof database !== "string" || !database) {
        throw new RuntimeError("INVALID_RECOVERY_REQUEST", "Namespace and database are required", 400);
      }
      const accountIdentifier = normalizedIdentifier(rawIdentifier);
      if (!sendEmail || !rateLimiter) {
        throw new RuntimeError("ACCOUNT_RECOVERY_UNAVAILABLE", "Account recovery is not configured", 503);
      }
      const retryAfterMs = await limit(clientAddress, { namespace, database }, accountIdentifier);
      if (retryAfterMs != null) return { accepted: false, rateLimited: true, retryAfterMs };
      if (allowedContexts && !allowedContexts.has(contextKey(namespace, database))) {
        return { accepted: true, delivered: false };
      }
      try {
        const store = await options.stores.forContext(namespace, database);
        const record = await store.execute(`
          RETURN (UPDATE ${userTable}
            SET invite_expires_at = type::datetime($invite_expires_at)
            WHERE login_access = true
              AND (email = $identifier OR username = $identifier)
            RETURN AFTER)[0];
        `, {
          identifier: accountIdentifier,
          invite_expires_at: new Date(Date.now() + inviteTtlMs).toISOString(),
        });
        if (!record?.email || !record?.invite_token || !record?.invite_expires_at) {
          return { accepted: true, delivered: false };
        }
        await sendEmail(recoveryMessage(record, { namespace, database }));
        return { accepted: true, delivered: true };
      } catch (error) {
        options.onError?.({
          code: String(error?.code || "ACCOUNT_RECOVERY_FAILED"),
          namespace,
          database,
        });
        return { accepted: true, delivered: false };
      }
    },
    async health() {
      if (!sendEmail || !rateLimiter) return { ok: true, enabled: false };
      const limiter = typeof rateLimiter.health === "function"
        ? await rateLimiter.health()
        : { ok: true };
      return { ok: limiter.ok !== false, enabled: true, email: { ok: true }, rateLimit: limiter };
    },
  });
}

module.exports = {
  createAccountService,
  normalizedIdentifier,
  recoveryMessage,
};
