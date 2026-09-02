const { RuntimeError } = require("../errors");

const RESEND_EMAIL_ENDPOINT = "https://api.resend.com/emails";
const DEFAULT_PLATFORM_EMAIL_FROM = "ReBase <onboarding@resend.dev>";

function createResendPlatformEmailAdapter(options = {}) {
  const request = options.fetch || globalThis.fetch;
  if (typeof request !== "function") throw new Error("Resend email requires a fetch implementation");
  const endpoint = options.endpoint || RESEND_EMAIL_ENDPOINT;
  const from = options.from || DEFAULT_PLATFORM_EMAIL_FROM;

  return async function sendResendPlatformEmail(message) {
    const response = await request(endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${options.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: Array.isArray(message.to) ? message.to : [message.to],
        subject: message.subject,
        ...(message.html == null ? {} : { html: message.html }),
        ...(message.text == null ? {} : { text: message.text }),
      }),
      signal: message.signal,
    });
    if (!response.ok) {
      throw new RuntimeError("PLATFORM_EMAIL_FAILED", "Platform email delivery failed", 503, {
        retryable: response.status === 429 || response.status >= 500,
      });
    }
    const result = await response.json().catch(() => ({}));
    return { id: result.id ? String(result.id) : undefined, provider: "resend" };
  };
}

module.exports = {
  DEFAULT_PLATFORM_EMAIL_FROM,
  RESEND_EMAIL_ENDPOINT,
  createResendPlatformEmailAdapter,
};
