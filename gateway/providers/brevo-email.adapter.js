const { adapterError, isRetryableStatus, responseBody } = require("./http");

const BREVO_EMAIL_ENDPOINT = "https://api.brevo.com/v3/smtp/email";
const BREVO_EMAIL_EVENTS_ENDPOINT = "https://api.brevo.com/v3/smtp/statistics/events";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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
    reconciliationTag,
    signal,
  }) {
    const normalizedIdempotencyKey = idempotencyKey == null ? null : String(idempotencyKey);
    if (normalizedIdempotencyKey && !UUID_PATTERN.test(normalizedIdempotencyKey)) {
      throw adapterError(
        "BREVO_IDEMPOTENCY_KEY_INVALID",
        "Brevo idempotency keys must be UUIDs",
        400,
        false,
      );
    }
    const body = {
      sender: { email: fromEmail, name: fromName },
      to: to.map((email) => ({ email })),
      subject,
    };
    if (html) body.htmlContent = html;
    if (text) body.textContent = text;
    if (replyTo) body.replyTo = { email: replyTo };
    if (reconciliationTag) body.tags = [String(reconciliationTag)];
    if (normalizedIdempotencyKey) {
      body.headers = { ...(body.headers || {}), idempotencyKey: normalizedIdempotencyKey };
    }

    let response;
    try {
      response = await request(endpoint, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "api-key": apiKey,
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

function createBrevoEmailEventsAdapter(options = {}) {
  const request = options.fetch || globalThis.fetch;
  if (typeof request !== "function") throw new Error("Brevo email events require a fetch implementation");
  const endpoint = options.eventsEndpoint || BREVO_EMAIL_EVENTS_ENDPOINT;

  return async function getBrevoEmailEvents({ apiKey, email, tag, signal }) {
    const url = new URL(endpoint);
    url.searchParams.set("days", "90");
    url.searchParams.set("limit", "5000");
    url.searchParams.set("email", String(email));
    url.searchParams.set("tags", JSON.stringify([String(tag)]));

    let response;
    try {
      response = await request(url, {
        method: "GET",
        headers: { accept: "application/json", "api-key": apiKey },
        signal,
      });
    } catch (error) {
      throw adapterError("BREVO_UNAVAILABLE", "Brevo event lookup failed", 503, true, error);
    }
    const payload = await responseBody(response);
    if (!response.ok) {
      throw adapterError(
        "BREVO_EVENT_LOOKUP_FAILED",
        `Brevo event lookup failed with HTTP ${response.status}`,
        response.status >= 400 ? response.status : 502,
        isRetryableStatus(response.status),
      );
    }
    if (!Array.isArray(payload.events)) {
      throw adapterError("BREVO_EVENT_RESPONSE_INVALID", "Brevo event response did not contain events", 502, true);
    }
    return payload.events.map((event) => ({
      email: String(event.email || "").toLowerCase(),
      event: String(event.event || "").toLowerCase(),
      messageId: event.messageId == null ? "" : String(event.messageId),
      tags: [...new Set([...(Array.isArray(event.tags) ? event.tags : []), ...(event.tag == null ? [] : [event.tag])].map(String))],
    }));
  };
}

module.exports = { BREVO_EMAIL_ENDPOINT, BREVO_EMAIL_EVENTS_ENDPOINT, createBrevoEmailAdapter, createBrevoEmailEventsAdapter };
