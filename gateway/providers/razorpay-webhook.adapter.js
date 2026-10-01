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

function integer(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : null;
}

function createRazorpayWebhookAdapter() {
  return Object.freeze({
    extractRoute({ rawBody, routeCapsule }) {
      if (routeCapsule) return String(routeCapsule);
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
      const refund = entity(payload, "refund");
      const eventId = request.headers.get("x-razorpay-event-id");
      if (!payload?.event || !eventId || !payment?.id || !payment?.order_id) return false;
      if (payload.event === "order.paid" && !order?.id) return false;
      const eventCreatedAt = timestamp(payload.created_at);
      if (["order.paid", "payment.authorized", "payment.captured", "payment.failed"].includes(payload.event)
        && !eventCreatedAt) return false;
      if (payload.event === "refund.processed"
        && (!eventCreatedAt || !refund?.id || !refund?.payment_id || !integer(refund.amount)
          || !timestamp(refund.created_at) || integer(payment.amount_refunded) === null)) return false;
      return {
        event: String(payload.event),
        eventId: String(eventId),
        createdAt: eventCreatedAt,
        order: order ? {
          id: String(order.id),
          amount: Number(order.amount),
          currency: String(order.currency || ""),
          status: String(order.status || ""),
          createdAt: timestamp(order.created_at),
        } : null,
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
          amountRefunded: integer(payment.amount_refunded) ?? 0,
        },
        refund: refund ? {
          id: String(refund.id),
          paymentId: String(refund.payment_id || ""),
          amount: integer(refund.amount),
          currency: String(refund.currency || ""),
          status: String(refund.status || ""),
          createdAt: timestamp(refund.created_at),
        } : null,
      };
    },
  });
}

module.exports = { createRazorpayWebhookAdapter, routeFromPayload };
