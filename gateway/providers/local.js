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
  return {
    email: {
      async verifyWebhook({ request, rawBody }) {
        const secret = options.webhookSecret || process.env.REBASE_EMAIL_WEBHOOK_SECRET;
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
      },
      forTable(table) {
        const provider = emailTables[table];
        if (!provider) throw new Error(`Unsupported email resource table: ${table}`);
        return {
          async sendMessage({ config, message }) {
            if (config.api_secret_ref) await resolveSecret(config.api_secret_ref);
            return { provider, messageId: crypto.randomUUID(), accepted: [message?.to].flat().filter(Boolean) };
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
