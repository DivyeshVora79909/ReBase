function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

module.exports = {
  provider: "razorpay",
  on: {
    async "order.paid"({ route, record, verified, store, signal }) {
      if (verified.order.id !== String(record.provider_order_id || "")) {
        throw invalid("RAZORPAY_ORDER_MISMATCH", "Webhook order does not match the local order");
      }
      if (verified.payment.orderId !== verified.order.id) {
        throw invalid("RAZORPAY_PAYMENT_ORDER_MISMATCH", "Webhook payment does not belong to the order");
      }
      if (
        verified.order.amount !== Number(record.amount_paise)
        || verified.order.currency !== String(record.currency)
        || verified.payment.amount !== Number(record.amount_paise)
        || verified.payment.currency !== String(record.currency)
      ) {
        throw invalid("RAZORPAY_AMOUNT_MISMATCH", "Webhook amount or currency does not match the order");
      }
      const result = await store.execute(`
        BEGIN TRANSACTION;
        LET $payment = UPSERT ONLY razorpay_payment SET
          owned_by = type::record($owned_by),
          order = type::record($order_id),
          provider_payment_id = $payment_id,
          status = $status,
          amount_paise = $amount,
          currency = $currency,
          method = IF $method = NULL THEN NONE ELSE $method END,
          provider_created_at = type::datetime($created_at),
          error_code = IF $error_code = NULL THEN NONE ELSE $error_code END,
          error_description = IF $error_description = NULL THEN NONE ELSE $error_description END
        WHERE provider_payment_id = $payment_id AND order = type::record($order_id)
        RETURN AFTER;
        IF $payment = NONE { THROW 'RAZORPAY_PAYMENT_NOT_PERSISTED'; };
        UPDATE type::record($order_id) SET status = $order_status;
        COMMIT TRANSACTION;
        RETURN { ok: true, payment: $payment };
      `, {
        payment_id: verified.payment.id,
        status: verified.payment.status,
        amount: verified.payment.amount,
        currency: verified.payment.currency,
        method: verified.payment.method,
        created_at: verified.payment.createdAt || verified.createdAt,
        error_code: verified.payment.errorCode,
        error_description: verified.payment.errorDescription,
        owned_by: record.owned_by,
        order_id: route.id,
        order_status: verified.order.status,
      });
      return { outcome: "success", result };
    },
  },
};
