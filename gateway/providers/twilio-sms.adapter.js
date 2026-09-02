const { adapterError, isRetryableStatus, responseBody } = require("./http");

const TWILIO_MESSAGES_ENDPOINT = "https://api.twilio.com/2010-04-01/Accounts";

function createTwilioSmsAdapter(options = {}) {
  const request = options.fetch || globalThis.fetch;
  if (typeof request !== "function") throw new Error("Twilio SMS requires a fetch implementation");
  const accountSid = options.accountSid ? String(options.accountSid) : "";
  const apiKeySid = options.apiKeySid ? String(options.apiKeySid) : "";
  const apiKeySecret = options.apiKeySecret ? String(options.apiKeySecret) : "";
  const authToken = options.authToken ? String(options.authToken) : "";
  const from = options.from ? String(options.from) : "";
  const endpoint = String(options.endpoint || TWILIO_MESSAGES_ENDPOINT).replace(/\/+$/, "");

  return async function sendTwilioSms({ to, body, statusCallback, signal }) {
    const username = apiKeySid && apiKeySecret ? apiKeySid : accountSid;
    const password = apiKeySid && apiKeySecret ? apiKeySecret : authToken;
    if (!username || !password || !accountSid || !from) {
      throw adapterError("TWILIO_NOT_CONFIGURED", "Twilio SMS credentials or sender are not configured", 503, false);
    }
    const form = new URLSearchParams({
      To: String(to),
      From: from,
      Body: String(body),
    });
    if (statusCallback) form.set("StatusCallback", String(statusCallback));
    let response;
    try {
      response = await request(`${endpoint}/${encodeURIComponent(accountSid)}/Messages.json`, {
        method: "POST",
        headers: {
          authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        },
        body: form,
        signal,
      });
    } catch (error) {
      throw adapterError("TWILIO_UNAVAILABLE", "Twilio SMS request failed", 503, true, error);
    }
    const payload = await responseBody(response);
    if (!response.ok) {
      const error = adapterError(
        "TWILIO_REQUEST_FAILED",
        payload.message || `Twilio SMS request failed with HTTP ${response.status}`,
        response.status >= 400 ? response.status : 502,
        isRetryableStatus(response.status),
      );
      error.providerCode = payload.code ?? payload.error_code;
      error.providerMessage = payload.message || payload.error_message;
      throw error;
    }
    if (!payload.sid) {
      throw adapterError("TWILIO_RESPONSE_INVALID", "Twilio SMS response did not contain a message SID", 502, true);
    }
    return {
      provider: "twilio",
      messageId: String(payload.sid),
      status: payload.status ? String(payload.status) : undefined,
      to: payload.to ? String(payload.to) : String(to),
      from: payload.from ? String(payload.from) : from,
    };
  };
}

module.exports = { TWILIO_MESSAGES_ENDPOINT, createTwilioSmsAdapter };
