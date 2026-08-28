module.exports = {
  table: "send_brevo_email",
  on: {
    async CREATE({ record, load, providers, signal }) {
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
  },
};
