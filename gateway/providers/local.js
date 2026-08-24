const crypto = require("node:crypto");

const DEFAULT_EMAIL_TABLES = Object.freeze({ email_brevo_config: "brevo" });

function createLocalProviders(options = {}) {
  const emailTables = { ...DEFAULT_EMAIL_TABLES, ...(options.emailTables || {}) };
  const emailWebhookSecret = options.emailWebhookSecret || options.webhookSecret || process.env.REBASE_EMAIL_WEBHOOK_SECRET;
  const storageWebhookSecret = options.storageWebhookSecret || options.webhookSecret || process.env.REBASE_STORAGE_WEBHOOK_SECRET;
  function verifyWebhook(request, rawBody, secret) {
    const signature = (request.headers.get("x-rebase-signature") || "").replace(/^sha256=/i, "");
    if (!secret || !signature) return false;
    const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
    const actualBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    if (actualBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) return false;
    let payload;
    try { payload = JSON.parse(rawBody); } catch { return false; }
    const eventId = request.headers.get("x-rebase-event-id") || payload.event_id || payload.id;
    const account = request.headers.get("x-rebase-account") || payload.account;
    const orderedAt = request.headers.get("x-rebase-event-at") || payload.timestamp || payload.created_at;
    const orderedAtMs = new Date(orderedAt).getTime();
    const replayWindowMs = options.webhookReplayWindowMs || 5 * 60 * 1000;
    if (!orderedAt || Number.isNaN(orderedAtMs) || Math.abs(Date.now() - orderedAtMs) > replayWindowMs) return false;
    return eventId && account ? {
      args: payload,
      account: String(account),
      eventId: String(eventId),
      orderedAt: new Date(orderedAtMs).toISOString(),
      provider: String(payload.provider || "local"),
    } : false;
  }
  const providers = {
    kind: "local",
    developmentOnly: true,
    async health({ required = [], webhookProviders = [] } = {}) {
      const missing = required.filter((name) => !providers[name]);
      const configuration = [];
      if (webhookProviders.includes("local") || webhookProviders.includes("email")) {
        if (!emailWebhookSecret) configuration.push("emailWebhookSecret");
      }
      if (webhookProviders.includes("storage") && !storageWebhookSecret) {
        configuration.push("storageWebhookSecret");
      }
      return {
        ok: missing.length === 0 && configuration.length === 0,
        provider: "local",
        developmentOnly: true,
        missing,
        missingConfiguration: configuration,
      };
    },
    storage: {
      async createAccessGrant({ config, objectKey, expiresIn, id }) {
        const seconds = Math.max(1, Number(expiresIn || config.default_expiry_seconds || 900));
        const token = crypto.createHash("sha256")
          .update(`${String(id)}\n${String(objectKey)}\n${seconds}`)
          .digest("hex");
        return {
          provider: config.provider || "local-storage",
          accessUrl: `https://storage.local/access/${encodeURIComponent(String(objectKey))}?token=${token}`,
          accessToken: token,
          expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
          expiresIn: seconds,
        };
      },
      async verifyWebhook({ request, rawBody }) {
        return verifyWebhook(request, rawBody, storageWebhookSecret);
      },
    },
    email: {
      async verifyWebhook({ request, rawBody }) {
        return verifyWebhook(request, rawBody, emailWebhookSecret);
      },
      forTable(table) {
        const provider = emailTables[table];
        if (!provider) throw new Error(`Unsupported email resource table: ${table}`);
        return {
          async sendMessage({ config, message, idempotencyKey }) {
            const messageId = idempotencyKey
              ? crypto.createHash("sha256").update(String(idempotencyKey)).digest("hex").slice(0, 24)
              : crypto.randomUUID();
            return { provider, messageId, accepted: [message?.to].flat().filter(Boolean) };
          },
          async sendCampaign({ config, campaign, idempotencyKey }) {
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
  return providers;
}

module.exports = { createLocalProviders };
