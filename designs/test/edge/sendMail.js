function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

function messageArgs(args) {
  const message = args?.message;
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    throw invalid("MESSAGE_REQUIRED", "message is required");
  }
  const recipients = [message.to].flat().filter((value) => typeof value === "string" && value.trim());
  if (!recipients.length) throw invalid("RECIPIENT_REQUIRED", "At least one recipient is required");
  const subject = String(message.subject || "").trim();
  if (!subject) throw invalid("SUBJECT_REQUIRED", "Subject is required");
  return { ...message, subject, to: recipients };
}

module.exports = {
  mode: "request",
  records: { config: "email_brevo_config" },
  timeoutMs: 10_000,

  async execute({ args, records, providers, signal }) {
    const provider = providers.email.forResource(records.config);
    return provider.sendMessage({
      config: records.config,
      message: messageArgs(args),
      signal,
    });
  },
};
