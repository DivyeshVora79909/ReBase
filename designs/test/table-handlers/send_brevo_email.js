module.exports = {
  table: "send_brevo_email",
  async reconcile({ record, load, adapters }) {
    const config = await load(record.config || "rebase_email_delivery_config:platform");
    const tag = `rebase_${String(record.execution_id).toLowerCase()}`;
    const recipients = [...new Set((record.to || []).map((email) => String(email).toLowerCase()))];
    const matches = await Promise.all(recipients.map(async (email) => {
      const events = await adapters.getBrevoEmailEvents({ apiKey: config.api_key, email, tag });
      return events.find((event) => event.email === email && event.tags.includes(tag) && event.messageId);
    }));
    if (recipients.length > 0 && matches.every(Boolean)) {
      return {
        outcome: "success",
        patch: {
          provider_reference: matches[0].messageId,
          provider_state: "accepted",
          result: { provider: "brevo", accepted: recipients },
        },
      };
    }
    return { outcome: "ambiguous", retryAfterMs: 15 * 60 * 1000 };
  },
  on: {
    async CREATE({ record, load, adapters, signal }) {
      const config = await load(record.config || "rebase_email_delivery_config:platform");
      const result = await adapters.sendBrevoEmail({
        apiKey: config.api_key,
        fromEmail: config.from_email,
        fromName: config.from_name,
        replyTo: config.reply_to,
        to: record.to,
        subject: record.subject,
        html: record.html,
        text: record.text,
        idempotencyKey: String(record.execution_id),
        reconciliationTag: `rebase_${String(record.execution_id).toLowerCase()}`,
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
