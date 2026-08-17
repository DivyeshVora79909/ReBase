function invalid(code, message) {
  return Object.assign(new Error(message), { code, status: 400 });
}

module.exports = {
  mode: "job",
  records: {
    config: "email_brevo_config",
    profile: "email_campaign_profile",
  },
  timeoutMs: 60_000,
  maxAttempts: 5,

  async authorize({ records }) {
    return String(records.profile.config) === String(records.config.id);
  },

  async execute({ args, records, providers, signal, execution }) {
    if (args?.campaign !== undefined && (!args.campaign || typeof args.campaign !== "object" || Array.isArray(args.campaign))) {
      throw invalid("CAMPAIGN_INVALID", "campaign must be an object");
    }
    const provider = providers.email.forResource(records.config);
    return provider.sendCampaign({
      config: records.config,
      campaign: {
        ...(args.campaign || {}),
        recipients: records.profile.recipients,
        template: {
          subject: records.profile.subject,
          html: records.profile.html,
          text: records.profile.text,
        },
      },
      idempotencyKey: execution.idempotencyKey,
      signal,
    });
  },
};
