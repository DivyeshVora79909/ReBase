const { parseJson, verifyHmacSha256 } = require("./signatures");

function invalid(code, message, status = 400) {
  return Object.assign(new Error(message), { code, status });
}

function entity(payload, name) {
  return payload?.payload?.[name]?.entity || null;
}

function routeFromPayload(payload) {
  const order = entity(payload, "order");
  const payment = entity(payload, "payment");
  return order?.notes?.rebase_route || payment?.notes?.rebase_route || null;
}

function timestamp(value) {
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? new Date(seconds * 1000).toISOString() : null;
}

function createRazorpayWebhookAdapter() {
  return Object.freeze({
    extractRoute({ rawBody }) {
      const payload = parseJson(rawBody);
      const route = payload && routeFromPayload(payload);
      if (!route) throw invalid("RAZORPAY_ROUTE_REQUIRED", "Razorpay webhook route is missing");
      return String(route);
    },

    verify({ request, rawBody, config }) {
      if (!verifyHmacSha256(rawBody, request.headers.get("x-razorpay-signature"), config.webhook_secret)) return false;
      const payload = parseJson(rawBody);
      const order = entity(payload, "order");
      const payment = entity(payload, "payment");
      const eventId = request.headers.get("x-razorpay-event-id");
      if (!payload?.event || !eventId || !order?.id || !payment?.id || !payment?.order_id) return false;
      return {
        event: String(payload.event),
        eventId: String(eventId),
        createdAt: timestamp(payload.created_at),
        order: {
          id: String(order.id),
          amount: Number(order.amount),
          currency: String(order.currency || ""),
          status: String(order.status || ""),
          createdAt: timestamp(order.created_at),
        },
        payment: {
          id: String(payment.id),
          orderId: String(payment.order_id),
          amount: Number(payment.amount),
          currency: String(payment.currency || ""),
          status: String(payment.status || ""),
          method: payment.method == null ? null : String(payment.method),
          createdAt: timestamp(payment.created_at),
          errorCode: payment.error_code == null ? null : String(payment.error_code),
          errorDescription: payment.error_description == null ? null : String(payment.error_description),
        },
      };
    },
  });
}

module.exports = { createRazorpayWebhookAdapter, routeFromPayload };
