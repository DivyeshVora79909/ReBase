const crypto = require("node:crypto");

const DEFAULT_EMAIL_TABLES = Object.freeze({ email_brevo_config: "brevo" });

function createLocalProviders(options = {}) {
  const emailTables = { ...DEFAULT_EMAIL_TABLES, ...(options.emailTables || {}) };
  async function resolveSecret(reference) {
    if (!reference) return null;
    if (typeof options.resolveSecret === "function") return options.resolveSecret(reference);
    if (Object.prototype.hasOwnProperty.call(options.secrets || {}, reference)) return options.secrets[reference];
    if (String(reference).startsWith("env:")) return process.env[String(reference).slice(4)] || null;
    return null;
  }
  function verifyWebhook(request, rawBody, secret) {
    const signature = request.headers.get("x-rebase-signature");
    if (!secret || !signature) return false;
    const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
    const actualBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    if (actualBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) return false;
    let payload;
    try { payload = JSON.parse(rawBody); } catch { return false; }
    const eventId = request.headers.get("x-rebase-event-id") || payload.id;
    return eventId ? {
      args: payload,
      eventId: String(eventId),
      provider: String(payload.provider || "local"),
    } : false;
  }
  return {
    storage: {
      async createAccessGrant({ config, objectKey, expiresIn, id }) {
        const seconds = Math.max(1, Number(expiresIn || config.default_expiry_seconds || 900));
        const token = crypto.createHash("sha256").update(`${String(id)}\n${String(objectKey)}\n${seconds}`).digest("hex");
        return {
          provider: config.provider || "local-storage",
          accessUrl: `https://storage.local/access/${encodeURIComponent(String(objectKey))}?token=${token}`,
          accessToken: token,
          expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
          expiresIn: seconds,
        };
      },
      async verifyWebhook({ request, rawBody }) {
        return verifyWebhook(
          request,
          rawBody,
          options.storageWebhookSecret || options.webhookSecret || process.env.REBASE_STORAGE_WEBHOOK_SECRET,
        );
      },
    },
    email: {
      async verifyWebhook({ request, rawBody }) {
        return verifyWebhook(request, rawBody, options.webhookSecret || process.env.REBASE_EMAIL_WEBHOOK_SECRET);
      },
      forTable(table) {
        const provider = emailTables[table];
        if (!provider) throw new Error(`Unsupported email resource table: ${table}`);
        return {
          async sendMessage({ config, message, idempotencyKey }) {
            if (config.api_secret_ref) await resolveSecret(config.api_secret_ref);
            const messageId = idempotencyKey
              ? crypto.createHash("sha256").update(String(idempotencyKey)).digest("hex").slice(0, 24)
              : crypto.randomUUID();
            return { provider, messageId, accepted: [message?.to].flat().filter(Boolean) };
          },
          async sendCampaign({ config, campaign, idempotencyKey }) {
            if (config.api_secret_ref) await resolveSecret(config.api_secret_ref);
            const campaignId = crypto.createHash("sha256").update(String(idempotencyKey)).digest("hex").slice(0, 24);
            return { provider, campaignId, idempotencyKey, recipients: campaign?.recipients?.length || 0 };
          },
        };
      },
      forResource(resource) {
        const table = String(resource?.id || "").split(":", 1)[0];
        return this.forTable(table);
      },
    },
  };
}

module.exports = { createLocalProviders };
