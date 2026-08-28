const crypto = require("node:crypto");
const { createRazorpayWebhookAdapter } = require("./razorpay");

const DEFAULT_EMAIL_TABLES = Object.freeze({ email_brevo_config: "brevo" });

function createLocalProviders(options = {}) {
  const emailTables = {
    ...DEFAULT_EMAIL_TABLES,
    ...(options.emailTables || {}),
  };
  const providers = {
    kind: "local",
    developmentOnly: true,
    async health({ required = [], webhookProviders = [] } = {}) {
      const missing = required.filter((name) => !providers[name]);
      const missingWebhooks = webhookProviders.filter((name) => !providers.webhooks?.[name]);
      return {
        ok: missing.length === 0 && missingWebhooks.length === 0,
        provider: "local",
        developmentOnly: true,
        missing,
        missingWebhooks,
      };
    },
    storage: {
      async createUploadGrant({ config, objectKey, contentType, contentLength, expiresIn, id }) {
        const seconds = Math.max(1, Number(expiresIn || config.default_expiry_seconds || 900));
        const token = crypto
          .createHash("sha256")
          .update(`${String(id)}\n${String(objectKey)}\n${String(contentType)}\n${Number(contentLength)}\n${seconds}`)
          .digest("hex");
        return {
          provider: config.provider || "local-storage",
          uploadUrl: `https://storage.local/upload/${encodeURIComponent(String(objectKey))}?token=${token}`,
          headers: { "content-type": contentType, "content-length": String(contentLength) },
          expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
          expiresIn: seconds,
        };
      },
      async createAccessGrant({ config, objectKey, expiresIn, id }) {
        const seconds = Math.max(
          1,
          Number(expiresIn || config.default_expiry_seconds || 900),
        );
        const token = crypto
          .createHash("sha256")
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
      async deleteObject() {
        return { deleted: true };
      },
    },
    payment: {
      forResource() {
        return {
          async createOrder({ amount, currency, receipt }) {
            return {
              provider: "razorpay",
              id: `order_${crypto.createHash("sha256").update(receipt).digest("hex").slice(0, 18)}`,
              amount,
              amountPaid: 0,
              amountDue: amount,
              attempts: 0,
              currency,
              receipt,
              status: "created",
              createdAt: new Date().toISOString(),
            };
          },
        };
      },
    },
    email: {
      forTable(table) {
        const provider = emailTables[table];
        if (!provider)
          throw new Error(`Unsupported email resource table: ${table}`);
        return {
          async sendMessage({ config, message, idempotencyKey }) {
            const messageId = idempotencyKey
              ? crypto
                  .createHash("sha256")
                  .update(String(idempotencyKey))
                  .digest("hex")
                  .slice(0, 24)
              : crypto.randomUUID();
            return {
              provider,
              messageId,
              accepted: [message?.to].flat().filter(Boolean),
            };
          },
        };
      },
      forResource(resource) {
        const table = String(resource?.id || "").split(":", 1)[0];
        return this.forTable(table);
      },
    },
    webhooks: {
      razorpay: createRazorpayWebhookAdapter(),
    },
  };
  return providers;
}

module.exports = { createLocalProviders };
