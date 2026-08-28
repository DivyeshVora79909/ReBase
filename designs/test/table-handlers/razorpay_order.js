const crypto = require("node:crypto");

function receipt(context) {
  return `rb_${crypto
    .createHash("sha256")
    .update(`${context.namespace}\u0000${context.database}\u0000${context.id}`)
    .digest("hex")
    .slice(0, 32)}`;
}

module.exports = {
  table: "razorpay_order",
  on: {
    async CREATE({ context, record, load, providers, routes, signal }) {
      const config = await load(record.config);
      const providerReceipt = receipt(context);
      const route = routes.seal("razorpay", { config: record.config });
      const order = await providers.payment.forResource(config).createOrder({
        amount: record.amount_paise,
        currency: record.currency,
        receipt: providerReceipt,
        notes: { rebase_route: route },
        signal,
      });
      return {
        patch: {
          provider_order_id: order.id,
          receipt: order.receipt,
          status: order.status,
          provider_created_at: order.createdAt,
        },
        outcome: "success",
      };
    },
  },
};
