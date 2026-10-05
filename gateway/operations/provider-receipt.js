function failure(code, message) {
  return { outcome: "failed", error: { code, message } };
}

async function applyProviderReceipt({ context, record, webhooks, store }) {
  if (record.applied_at) return { outcome: "success" };
  const handler = webhooks?.get(record.provider, record.event);
  if (!handler || typeof handler.on[record.event] !== "function") {
    return failure("WEBHOOK_HANDLER_MISSING", `No handler for ${record.provider}/${record.event}`);
  }
  const [config, target] = await Promise.all([
    store.load(record.config_id),
    store.load(record.target_id),
  ]);
  if (!config || !target) return failure("WEBHOOK_TARGET_NOT_FOUND", "Receipt configuration or target no longer exists");
  if (!record.tenant || String(config.tenant) !== String(record.tenant)
    || String(target.tenant) !== String(record.tenant)) {
    return failure('WEBHOOK_TENANT_MISMATCH', 'Receipt configuration and target must remain in its tenant');
  }
  const route = {
    provider: record.provider,
    tenant: String(record.tenant),
    config: record.config_id,
    id: record.target_id,
  };
  const result = await handler.on[record.event]({
    context: { ...context, provider: record.provider, event: record.event },
    config,
    record: target,
    route,
    verified: record.normalized_payload,
    receipt: record,
    store,
  });
  return result;
}

module.exports = Object.freeze({
  table: "rebase_webhook_receipt",
  async execute(input) {
    return applyProviderReceipt(input);
  },
  async reconcile(input) {
    return applyProviderReceipt(input);
  },
});
