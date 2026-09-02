const { adapterError, isRetryableStatus, responseBody } = require("./http");

const RAZORPAY_API_ENDPOINT = "https://api.razorpay.com/v1";

function createRazorpayOrderAdapter(options = {}) {
  const request = options.fetch || globalThis.fetch;
  if (typeof request !== "function") throw new Error("Razorpay orders require a fetch implementation");
  const endpoint = options.endpoint || RAZORPAY_API_ENDPOINT;

  return async function createRazorpayOrder({
    keyId,
    keySecret,
    amount,
    currency,
    receipt,
    notes,
    signal,
  }) {
    let response;
    try {
      response = await request(`${endpoint}/orders`, {
        method: "POST",
        headers: {
          authorization: `Basic ${Buffer.from(`${keyId}:${keySecret}`).toString("base64")}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ amount, currency, receipt, notes }),
        signal,
      });
    } catch (error) {
      throw adapterError("RAZORPAY_UNAVAILABLE", "Razorpay request failed", 503, true, error);
    }
    const payload = await responseBody(response);
    if (!response.ok) {
      throw adapterError(
        "RAZORPAY_REQUEST_FAILED",
        `Razorpay request failed with HTTP ${response.status}`,
        response.status >= 400 ? response.status : 502,
        isRetryableStatus(response.status),
      );
    }
    if (!payload.id || !payload.status || !payload.receipt) {
      throw adapterError("RAZORPAY_RESPONSE_INVALID", "Razorpay response was incomplete", 502, true);
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
  };
}

module.exports = { RAZORPAY_API_ENDPOINT, createRazorpayOrderAdapter };
