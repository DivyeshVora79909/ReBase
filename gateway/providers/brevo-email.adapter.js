const { adapterError, isRetryableStatus, responseBody } = require("./http");

const BREVO_EMAIL_ENDPOINT = "https://api.brevo.com/v3/smtp/email";

function createBrevoEmailAdapter(options = {}) {
  const request = options.fetch || globalThis.fetch;
  if (typeof request !== "function") throw new Error("Brevo email requires a fetch implementation");
  const endpoint = options.endpoint || BREVO_EMAIL_ENDPOINT;

  return async function sendBrevoEmail({
    apiKey,
    fromEmail,
    fromName,
    replyTo,
    to,
    subject,
    html,
    text,
    idempotencyKey,
    signal,
  }) {
    const body = {
      sender: { email: fromEmail, name: fromName },
      to: to.map((email) => ({ email })),
      subject,
    };
    if (html) body.htmlContent = html;
    if (text) body.textContent = text;
    if (replyTo) body.replyTo = { email: replyTo };

    let response;
    try {
      response = await request(endpoint, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "api-key": apiKey,
          ...(idempotencyKey ? { "idempotency-key": String(idempotencyKey) } : {}),
        },
        body: JSON.stringify(body),
        signal,
      });
    } catch (error) {
      throw adapterError("BREVO_UNAVAILABLE", "Brevo request failed", 503, true, error);
    }

    const payload = await responseBody(response);
    if (!response.ok) {
      throw adapterError(
        "BREVO_REQUEST_FAILED",
        `Brevo request failed with HTTP ${response.status}`,
        response.status >= 400 ? response.status : 502,
        isRetryableStatus(response.status),
      );
    }
    const messageId = payload.messageId || payload.message_id;
    if (!messageId) {
      throw adapterError("BREVO_RESPONSE_INVALID", "Brevo response did not contain a message ID", 502, true);
    }
    return { provider: "brevo", messageId: String(messageId), accepted: to };
  };
}

module.exports = { BREVO_EMAIL_ENDPOINT, createBrevoEmailAdapter };
