function sameRecord(left, right) {
  return left != null && right != null && String(left) === String(right);
}

async function reconcileBrevoEmail({ record, load, adapters }) {
  const [configuration, target] = await Promise.all([load(record.configuration), load(record.target)]);
  if (!configuration || !target || record.channel !== "email") return { outcome: "ambiguous", retryAfterMs: 15 * 60 * 1000 };
  const email = String(target.address || "").toLowerCase();
  const tag = `rebase_${String(record.execution_id).toLowerCase()}`;
  const events = await adapters.getBrevoEmailEvents({ apiKey: configuration.api_key, email, tag });
  const match = events.find((event) => event.email === email && event.tags.includes(tag) && event.messageId);
  return match
    ? { outcome: "success", patch: { provider_reference: match.messageId } }
    : { outcome: "ambiguous", retryAfterMs: 15 * 60 * 1000 };
}

function createAuthenticationDeliveryHandler() {
  return Object.freeze({
    table: "authentication_delivery_task",
    reconcile: reconcileBrevoEmail,
    async execute({ context, record, load, adapters }) {
      const [configuration, principal, target, challenge] = await Promise.all([
        load(record.configuration),
        load(record.principal),
        load(record.target),
        load(record.challenge),
      ]);
      const now = Date.now();
      if (!configuration || !principal || !target || !challenge
        || principal.login_access !== true
        || !sameRecord(principal.id, record.principal)
        || !sameRecord(target.principal, record.principal)
        || Number(principal.authentication_revision) !== Number(record.principal_revision)
        || Number(target.revision) !== Number(record.target_revision)
        || !sameRecord(challenge.principal, record.principal)
        || !sameRecord(challenge.target, record.target)
        || Number(challenge.principal_revision) !== Number(record.principal_revision)
        || Number(challenge.target_revision) !== Number(record.target_revision)
        || String(challenge.delivery_nonce) !== String(record.delivery_nonce)
        || challenge.consumed_at != null
        || !Number.isFinite(Date.parse(challenge.expires_at))
        || Date.parse(challenge.expires_at) <= now) {
        return { outcome: "ignore" };
      }

      const message = await adapters.openAuthenticationPayload(record.payload_ciphertext);
      if (!message || typeof message !== "object" || Array.isArray(message)) {
        throw new Error("Authentication delivery payload is invalid");
      }
      if (record.channel === "email"
        && String(configuration.id).startsWith("rebase_email_delivery_config:")
        && String(target.id).startsWith("authentication_email:")) {
        const result = await adapters.sendBrevoEmail({
          apiKey: configuration.api_key,
          fromEmail: configuration.from_email,
          fromName: configuration.from_name,
          replyTo: configuration.reply_to || undefined,
          to: [target.address],
          subject: message.subject,
          text: message.text,
          html: message.html,
          idempotencyKey: String(record.execution_id),
          reconciliationTag: `rebase_${String(record.execution_id).toLowerCase()}`,
        });
        return { patch: { provider_reference: result?.messageId || result?.id || null } };
      }
      if (record.channel === "phone"
        && String(configuration.id).startsWith("rebase_sms_delivery_config:")
        && String(target.id).startsWith("authentication_phone:")) {
        const result = await adapters.sendTwilioSms({
          configuration,
          to: target.number,
          body: message.body,
        });
        return { patch: { provider_reference: result?.messageId || result?.id || null } };
      }
      return { outcome: "ignore" };
    },
  });
}

module.exports = createAuthenticationDeliveryHandler();
