const { adapterError, isRetryableStatus, responseBody } = require("./http");

const RESEND_EMAIL_ENDPOINT = "https://api.resend.com/emails";
const DEFAULT_PLATFORM_EMAIL_FROM = "ReBase <onboarding@resend.dev>";

function createResendPlatformEmailAdapter(options = {}) {
  const request = options.fetch || globalThis.fetch;
  if (typeof request !== "function") throw new Error("Resend email requires a fetch implementation");
  const endpoint = options.endpoint || RESEND_EMAIL_ENDPOINT;
  const from = options.from || DEFAULT_PLATFORM_EMAIL_FROM;

  return async function sendResendPlatformEmail(message) {
    let response;
    try {
      response = await request(endpoint, {
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
    } catch (error) {
      throw adapterError("PLATFORM_EMAIL_UNAVAILABLE", "Platform email request failed", 503, true, error);
    }

    let result;
    try {
      result = await responseBody(response);
    } catch (error) {
      throw adapterError("PLATFORM_EMAIL_RESPONSE_INVALID", "Platform email response could not be read", 502, true, error);
    }
    if (!response.ok) {
      const error = adapterError(
        "PLATFORM_EMAIL_FAILED",
        `Platform email request failed with HTTP ${response.status}`,
        response.status >= 400 ? response.status : 502,
        isRetryableStatus(response.status),
      );
      error.providerCode = result.code ?? result.name;
      error.providerMessage = result.message;
      throw error;
    }
    if (!result.id) {
      throw adapterError("PLATFORM_EMAIL_RESPONSE_INVALID", "Platform email response did not contain a message ID", 502, true);
    }
    return { id: String(result.id), provider: "resend" };
  };
}

module.exports = {
  DEFAULT_PLATFORM_EMAIL_FROM,
  RESEND_EMAIL_ENDPOINT,
  createResendPlatformEmailAdapter,
};
