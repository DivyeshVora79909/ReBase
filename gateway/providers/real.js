const crypto = require("node:crypto");
const { GetObjectCommand, S3Client } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const DEFAULT_EMAIL_TABLES = Object.freeze({ email_brevo_config: "brevo" });
const DEFAULT_BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email";

function providerError(code, message, status, retryable = false, cause) {
  const error = new Error(message, { cause });
  error.code = code;
  error.status = status;
  error.retryable = retryable;
  return error;
}

async function responseBody(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text.slice(0, 500) };
  }
}

function verifyHmacWebhook(request, rawBody, secret, provider) {
  const signature = (request.headers.get("x-rebase-signature") || "").replace(
    /^sha256=/i,
    "",
  );
  if (!secret || !signature) return false;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");
  const actual = Buffer.from(signature, "utf8");
  const wanted = Buffer.from(expected, "utf8");
  if (
    actual.length !== wanted.length ||
    !crypto.timingSafeEqual(actual, wanted)
  )
    return false;
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return false;
  }
  const eventId =
    request.headers.get("x-rebase-event-id") || payload.event_id || payload.id;
  const account = request.headers.get("x-rebase-account") || payload.account;
  const orderedAt =
    request.headers.get("x-rebase-event-at") ||
    payload.timestamp ||
    payload.created_at;
  const orderedAtMs = new Date(orderedAt).getTime();
  const replayWindowMs = 5 * 60 * 1000;
  if (
    !eventId ||
    !account ||
    !orderedAt ||
    Number.isNaN(orderedAtMs) ||
    Math.abs(Date.now() - orderedAtMs) > replayWindowMs
  )
    return false;
  return {
    args: payload,
    account: String(account),
    eventId: String(eventId),
    orderedAt: new Date(orderedAtMs).toISOString(),
    provider,
  };
}

function createRealProviders(options = {}) {
  const emailTables = {
    ...DEFAULT_EMAIL_TABLES,
    ...(options.emailTables || {}),
  };
  const fetchImpl = options.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function")
    throw new Error("The real provider requires global fetch");
  const brevoEndpoint = options.brevoEndpoint || DEFAULT_BREVO_ENDPOINT;

  const providers = {
    kind: "real",
    developmentOnly: false,
    async health({ required = [] } = {}) {
      const missing = required.filter((name) => !providers[name]);
      return {
        ok: missing.length === 0,
        provider: "real",
        developmentOnly: false,
        missing,
        missingConfiguration: [],
      };
    },
    storage: {
      async createAccessGrant({ config, objectKey, expiresIn }) {
        const seconds = expiresIn || config.default_expiry_seconds;
        const client = new S3Client({
          region: config.region,
          endpoint: config.endpoint,
          forcePathStyle: true,
          credentials: {
            accessKeyId: config.access_key_id,
            secretAccessKey: config.secret_access_key,
          },
        });
        try {
          const accessUrl = await getSignedUrl(
            client,
            new GetObjectCommand({ Bucket: config.bucket, Key: objectKey }),
            { expiresIn: seconds },
          );
          return {
            provider: String(config.provider || "s3"),
            accessUrl,
            accessToken: accessUrl,
            expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
            expiresIn: seconds,
          };
        } finally {
          client.destroy?.();
        }
      },
      async verifyWebhook({ request, rawBody }) {
        return verifyHmacWebhook(
          request,
          rawBody,
          options.storageWebhookSecret,
          "backblaze-b2",
        );
      },
    },
    email: {
      async verifyWebhook({ request, rawBody }) {
        return verifyHmacWebhook(
          request,
          rawBody,
          options.emailWebhookSecret,
          "brevo",
        );
      },
      forTable(table) {
        const provider = emailTables[table];
        if (!provider)
          throw new Error(`Unsupported email resource table: ${table}`);
        return {
          async sendMessage({ config, message, idempotencyKey, signal }) {
            const recipients = message.to.map((email) => ({ email }));
            const body = {
              sender: { email: config.from_email, name: config.from_name },
              to: recipients,
              subject: message.subject,
            };
            if (message.html) body.htmlContent = message.html;
            if (message.text) body.textContent = message.text;
            if (config.reply_to) body.replyTo = { email: config.reply_to };
            let response;
            try {
              response = await fetchImpl(brevoEndpoint, {
                method: "POST",
                headers: {
                  accept: "application/json",
                  "content-type": "application/json",
                  "api-key": config.api_key,
                  ...(idempotencyKey
                    ? { "idempotency-key": String(idempotencyKey) }
                    : {}),
                },
                body: JSON.stringify(body),
                signal,
              });
            } catch (error) {
              throw providerError(
                "BREVO_UNAVAILABLE",
                "Brevo request failed",
                503,
                true,
                error,
              );
            }
            const payload = await responseBody(response);
            if (!response.ok) {
              const retryable =
                response.status === 408 ||
                response.status === 429 ||
                response.status >= 500;
              throw providerError(
                "BREVO_REQUEST_FAILED",
                `Brevo request failed with HTTP ${response.status}`,
                response.status >= 400 ? response.status : 502,
                retryable,
              );
            }
            const messageId = payload.messageId || payload.message_id;
            if (!messageId)
              throw providerError(
                "BREVO_RESPONSE_INVALID",
                "Brevo response did not contain a message ID",
                502,
                true,
              );
            return {
              provider: "brevo",
              messageId: String(messageId),
              accepted: message.to,
            };
          },
        };
      },
      forResource(resource) {
        return this.forTable(String(resource?.id || "").split(":", 1)[0]);
      },
    },
  };
  return providers;
}

module.exports = { createRealProviders };
