const { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { createRazorpayWebhookAdapter } = require("./razorpay");

const DEFAULT_EMAIL_TABLES = Object.freeze({ email_brevo_config: "brevo" });
const DEFAULT_BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email";
const DEFAULT_RAZORPAY_ENDPOINT = "https://api.razorpay.com/v1";

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

function createRealProviders(options = {}) {
  const emailTables = {
    ...DEFAULT_EMAIL_TABLES,
    ...(options.emailTables || {}),
  };
  const fetchImpl = options.fetch || globalThis.fetch;
  if (typeof fetchImpl !== "function")
    throw new Error("The real provider requires global fetch");
  const brevoEndpoint = options.brevoEndpoint || DEFAULT_BREVO_ENDPOINT;
  const razorpayEndpoint = options.razorpayEndpoint || DEFAULT_RAZORPAY_ENDPOINT;
  const storageBucket = String(options.storageBucket || "").trim();

  function requireStorageBucket() {
    if (!storageBucket) {
      throw providerError(
        "STORAGE_BUCKET_NOT_CONFIGURED",
        "REBASE_STORAGE_BUCKET is required",
        503,
      );
    }
    return storageBucket;
  }

  function storageClient(config) {
    return new S3Client({
      region: config.region,
      endpoint: config.endpoint,
      forcePathStyle: true,
      credentials: {
        accessKeyId: config.access_key_id,
        secretAccessKey: config.secret_access_key,
      },
    });
  }

  const providers = {
    kind: "real",
    developmentOnly: false,
    async health({ required = [] } = {}) {
      const missing = required.filter((name) => !providers[name]);
      const missingConfiguration = required.includes("storage") && !storageBucket
        ? ["REBASE_STORAGE_BUCKET"]
        : [];
      return {
        ok: missing.length === 0 && missingConfiguration.length === 0,
        provider: "real",
        developmentOnly: false,
        missing,
        missingConfiguration,
      };
    },
    storage: {
      async createUploadGrant({ config, objectKey, contentType, contentLength, expiresIn }) {
        const seconds = expiresIn || config.default_expiry_seconds;
        const bucket = requireStorageBucket();
        const client = storageClient(config);
        try {
          const uploadUrl = await getSignedUrl(
            client,
            new PutObjectCommand({
              Bucket: bucket,
              Key: objectKey,
              ContentType: contentType,
              ContentLength: contentLength,
            }),
            { expiresIn: seconds },
          );
          return {
            provider: String(config.provider || "s3"),
            uploadUrl,
            headers: {
              "content-type": contentType,
            },
            expiresAt: new Date(Date.now() + seconds * 1000).toISOString(),
            expiresIn: seconds,
          };
        } finally {
          client.destroy?.();
        }
      },
      async createAccessGrant({ config, objectKey, expiresIn, fileName }) {
        const seconds = expiresIn || config.default_expiry_seconds;
        const bucket = requireStorageBucket();
        const client = storageClient(config);
        try {
          const accessUrl = await getSignedUrl(
            client,
            new GetObjectCommand({
              Bucket: bucket,
              Key: objectKey,
              ...(fileName ? {
                ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`,
              } : {}),
            }),
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
      async deleteObject({ config, objectKey, signal }) {
        const bucket = requireStorageBucket();
        const client = storageClient(config);
        try {
          await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: objectKey }), { abortSignal: signal });
          return { deleted: true };
        } finally {
          client.destroy?.();
        }
      },
    },
    payment: {
      forResource(config) {
        return {
          async createOrder({ amount, currency, receipt, notes, signal }) {
            let response;
            try {
              response = await fetchImpl(`${razorpayEndpoint}/orders`, {
                method: "POST",
                headers: {
                  authorization: `Basic ${Buffer.from(`${config.key_id}:${config.key_secret}`).toString("base64")}`,
                  "content-type": "application/json",
                },
                body: JSON.stringify({ amount, currency, receipt, notes }),
                signal,
              });
            } catch (error) {
              throw providerError("RAZORPAY_UNAVAILABLE", "Razorpay request failed", 503, true, error);
            }
            const payload = await responseBody(response);
            if (!response.ok) {
              const retryable = response.status === 408 || response.status === 429 || response.status >= 500;
              throw providerError(
                "RAZORPAY_REQUEST_FAILED",
                `Razorpay request failed with HTTP ${response.status}`,
                response.status >= 400 ? response.status : 502,
                retryable,
              );
            }
            if (!payload.id || !payload.status || !payload.receipt) {
              throw providerError("RAZORPAY_RESPONSE_INVALID", "Razorpay response was incomplete", 502, true);
            }
            return {
              provider: "razorpay",
              id: String(payload.id),
              amount: Number(payload.amount),
              amountPaid: Number(payload.amount_paid),
              amountDue: Number(payload.amount_due),
              attempts: Number(payload.attempts),
              currency: String(payload.currency),
              receipt: String(payload.receipt),
              status: String(payload.status),
              createdAt: payload.created_at ? new Date(Number(payload.created_at) * 1000).toISOString() : null,
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
    webhooks: {
      razorpay: createRazorpayWebhookAdapter(),
    },
  };
  return providers;
}

module.exports = { createRealProviders };
