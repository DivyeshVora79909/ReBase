function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

module.exports = {
  table: "send_brevo_email",

  async execute({ record, load, providers, signal }) {
    const config = await load(record.config);
    const provider = providers.email.forResource(config);
    const result = await provider.sendMessage({
      config,
      idempotencyKey: String(record.id),
      message: { to: record.to, subject: record.subject, html: record.html, text: record.text },
      signal,
    });
    return {
      patch: {
        provider_reference: result.messageId,
        provider_state: "accepted",
        result: { provider: result.provider, accepted: result.accepted },
      },
      outcome: "success",
    };
  },

  async verifyWebhook({ request, rawBody, providers }) {
    const verified = await providers.email.verifyWebhook({ request, rawBody });
    return verified ? { ...verified, payload: verified.args } : false;
  },

  async correlateWebhook({ verified }) {
    const payload = verified?.payload;
    if (!payload?.id) throw invalid("WEBHOOK_ID_REQUIRED", "Webhook effect id is required");
    return {
      id: payload.id,
      patch: { provider_state: String(payload.status || payload.type || "updated") },
    };
  },
};
