function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

function validatePayment({ event, record, verified }) {
  const expectedStatus = {
    "order.paid": "captured",
    "payment.authorized": "authorized",
    "payment.captured": "captured",
    "payment.failed": "failed",
    "refund.processed": "captured",
  }[event];
  if (!expectedStatus) throw invalid("RAZORPAY_EVENT_UNSUPPORTED", `Unsupported Razorpay event ${event}`);
  if (verified.payment.orderId !== String(record.provider_order_id || "")) {
    throw invalid("RAZORPAY_PAYMENT_ORDER_MISMATCH", "Webhook payment does not belong to the local order");
  }
  if (
    verified.payment.amount !== Number(record.amount_paise)
    || verified.payment.currency !== String(record.currency)
  ) {
    throw invalid("RAZORPAY_AMOUNT_MISMATCH", "Webhook amount or currency does not match the order");
  }
  if (verified.payment.status !== expectedStatus) {
    throw invalid("RAZORPAY_PAYMENT_PHASE_MISMATCH", `${event} requires a ${expectedStatus} payment snapshot`);
  }
  if (event === "refund.processed") {
    const { refund } = verified;
    if (!refund || !refund.id || refund.paymentId !== verified.payment.id
      || refund.status !== "processed" || refund.currency !== verified.payment.currency
      || !Number.isSafeInteger(refund.amount) || refund.amount <= 0
      || refund.amount > verified.payment.amount
      || !Number.isSafeInteger(verified.payment.amountRefunded)
      || verified.payment.amountRefunded < refund.amount
      || verified.payment.amountRefunded > verified.payment.amount) {
      throw invalid("RAZORPAY_REFUND_MISMATCH", "Processed refund does not match its captured payment snapshot");
    }
  }
  if (event === "order.paid") {
    if (verified.order?.id !== String(record.provider_order_id || "")) {
      throw invalid("RAZORPAY_ORDER_MISMATCH", "Webhook order does not match the local order");
    }
    if (
      verified.order.amount !== Number(record.amount_paise)
      || verified.order.currency !== String(record.currency)
      || verified.order.status !== "paid"
    ) {
      throw invalid("RAZORPAY_ORDER_PAID_PHASE_MISMATCH", "order.paid requires a matching paid order snapshot");
    }
  }
  return true;
}

async function applyPaymentSnapshot({ route, record, verified, receipt, store, orderPaid }) {
  const result = await store.execute(`
    BEGIN TRANSACTION;
    LET $receipt = UPDATE type::record($receipt_id) SET applied_at = time::now()
      WHERE provider_account_id = $provider_account_id
        AND event_id = $event_id AND payload_hash = $payload_hash
        AND rebase_lease_token = type::uuid($lease_token)
        AND rebase_lease_until > time::now()
        AND execution_id = type::uuid($execution_id)
        AND revision = type::uuid($revision)
        AND (($expected_outcome = 'pending' AND rebase_outcome = NONE)
          OR ($expected_outcome = 'ambiguous' AND rebase_outcome = 'ambiguous'))
      RETURN AFTER;
    IF $receipt = NONE OR array::len(array::flatten([$receipt])) = 0 {
      THROW 'RAZORPAY_RECEIPT_LEASE_LOST';
    };
    LET $payment = UPSERT ONLY razorpay_payment SET
      owned_by = type::record($owned_by),
      order = type::record($order_id),
      provider_payment_id = $payment_id,
      status = IF status = 'refunded' THEN status
        ELSE (IF $amount_refunded != NONE AND $amount_refunded >= $amount THEN 'refunded'
        ELSE (IF (provider_event_at != NONE AND type::datetime($event_at) < provider_event_at AND $status != 'refunded')
          OR (status = 'captured' AND $status != 'refunded')
          OR (status = 'authorized' AND ($status = 'created' OR $status = 'failed'))
          OR (status = 'failed' AND $status = 'authorized'
            AND provider_event_at != NONE AND type::datetime($event_at) <= provider_event_at)
          THEN status ELSE $status END) END) END,
      amount_paise = $amount,
      amount_refunded_paise = IF $amount_refunded = NONE
        THEN (IF amount_refunded_paise = NONE THEN 0 ELSE amount_refunded_paise END)
        ELSE (IF amount_refunded_paise = NONE OR $amount_refunded > amount_refunded_paise
          THEN $amount_refunded ELSE amount_refunded_paise END) END,
      currency = $currency,
      method = IF $method = NULL THEN NONE ELSE $method END,
      provider_created_at = type::datetime($created_at),
      provider_event_at = IF status = 'refunded'
        OR (provider_event_at != NONE AND type::datetime($event_at) < provider_event_at AND $status != 'refunded')
        OR (status = 'captured' AND $status != 'refunded')
        OR (status = 'authorized' AND ($status = 'created' OR $status = 'failed'))
        OR (status = 'failed' AND $status = 'authorized'
          AND provider_event_at != NONE AND type::datetime($event_at) <= provider_event_at)
        THEN provider_event_at ELSE type::datetime($event_at) END,
      error_code = IF $error_code = NULL THEN NONE ELSE $error_code END,
      error_description = IF $error_description = NULL THEN NONE ELSE $error_description END
    WHERE provider_payment_id = $payment_id AND order = type::record($order_id)
    RETURN AFTER;
    IF $payment = NONE OR array::len(array::flatten([$payment])) = 0 {
      THROW 'RAZORPAY_PAYMENT_NOT_PERSISTED';
    };
    IF $order_paid = true {
      UPDATE type::record($order_id) SET status = 'paid' WHERE status != 'paid';
    };
    COMMIT TRANSACTION;
    RETURN { ok: true, payment: $payment, applied_at: $receipt.applied_at };
  `, {
    receipt_id: receipt.id,
    provider_account_id: receipt.provider_account_id,
    event_id: receipt.event_id,
    payload_hash: receipt.payload_hash,
    lease_token: receipt.rebase_lease_token,
    execution_id: receipt.execution_id,
    revision: receipt.revision,
    expected_outcome: receipt.rebase_outcome === "ambiguous" ? "ambiguous" : "pending",
    payment_id: verified.payment.id,
    status: verified.payment.status,
    amount: verified.payment.amount,
    currency: verified.payment.currency,
    amount_refunded: verified.payment.amountRefunded,
    method: verified.payment.method,
    created_at: verified.payment.createdAt || verified.createdAt,
    event_at: verified.createdAt,
    error_code: verified.payment.errorCode,
    error_description: verified.payment.errorDescription,
    owned_by: record.owned_by,
    order_id: route.id,
    order_paid: orderPaid,
  });
  return { outcome: "success", result };
}

module.exports = {
  provider: "razorpay",
  validate(input) {
    return validatePayment({ ...input, event: input.verified.event });
  },
  on: {
    async "order.paid"(input) {
      return applyPaymentSnapshot({ ...input, orderPaid: true });
    },
    async "payment.authorized"(input) {
      return applyPaymentSnapshot({ ...input, orderPaid: false });
    },
    async "payment.captured"(input) {
      return applyPaymentSnapshot({ ...input, orderPaid: true });
    },
    async "payment.failed"(input) {
      return applyPaymentSnapshot({ ...input, orderPaid: false });
    },
    async "refund.processed"(input) {
      return applyPaymentSnapshot({ ...input, orderPaid: false });
    },
  },
};
