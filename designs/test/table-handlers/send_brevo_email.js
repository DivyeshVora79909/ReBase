function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

module.exports = {
  table: "send_brevo_email",
  process: "async",
  timeoutMs: 30000,
  outputs: ["effect_state", "provider_reference", "provider_state", "result", "error_code", "error_message"],

  async execute({ record, load, providers, context }) {
    const config = await load(record.config);
    if (!config) throw invalid("CONFIG_UNAVAILABLE", "Email configuration is unavailable");
    const provider = providers.email.forResource(config);
    const result = await provider.sendMessage({
      config,
      idempotencyKey: String(record.id),
      message: { to: record.to, subject: record.subject, html: record.html, text: record.text },
    });
    return {
      patch: {
        effect_state: "succeeded",
        provider_reference: result.messageId,
        provider_state: "accepted",
        result: { provider: result.provider, accepted: result.accepted },
      },
      context,
    };
  },

  async verify({ request, rawBody, providers }) {
    const verified = await providers.email.verifyWebhook({ request, rawBody });
    return verified ? {
      ...verified,
      database: verified.args.database,
      namespace: verified.args.namespace,
      payload: verified.args,
    } : false;
  },

  async webhook({ payload, patch }) {
    if (!payload?.id) throw invalid("WEBHOOK_ID_REQUIRED", "Webhook effect id is required");
    return patch(payload.id, {
      provider_state: String(payload.status || payload.type || "updated"),
    });
  },
};
