module.exports = {
  table: "send_brevo_email",
  on: {
    async CREATE({ record, load, adapters, signal }) {
      const config = await load(record.config);
      const result = await adapters.sendBrevoEmail({
        apiKey: config.api_key,
        fromEmail: config.from_email,
        fromName: config.from_name,
        replyTo: config.reply_to,
        to: record.to,
        subject: record.subject,
        html: record.html,
        text: record.text,
        idempotencyKey: String(record.id),
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
