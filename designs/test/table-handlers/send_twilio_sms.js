module.exports = {
  table: "send_twilio_sms",
  on: {
    async CREATE({ record, load, adapters, signal }) {
      const configuration = await load(record.config || "rebase_sms_delivery_config:platform");
      const result = await adapters.sendTwilioSms({
        configuration,
        to: record.to,
        body: record.body,
        signal,
      });
      return { patch: { provider_reference: result.messageId }, outcome: "success" };
    },
  },
};
