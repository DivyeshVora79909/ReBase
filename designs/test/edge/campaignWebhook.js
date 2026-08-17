function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

module.exports = {
  mode: "webhook",
  timeoutMs: 10_000,

  async verify({ request, rawBody, providers }) {
    return providers.email.verifyWebhook({ request, rawBody });
  },

  async execute({ args, execution }) {
    const type = String(args?.type || "").trim();
    if (!type) throw invalid("WEBHOOK_TYPE_REQUIRED", "Webhook type is required");
    return {
      accepted: true,
      eventId: execution.providerEventId,
      type,
    };
  },
};
