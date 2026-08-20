module.exports = {
  table: "file_access_grant",
  process: "sync",
  timeoutMs: 10000,
  outputs: ["effect_state", "access_url", "access_token", "expires_at", "provider_reference", "provider_state", "object_size", "object_etag", "completed_at"],

  async execute({ record, load, providers }) {
    const config = await load(record.storage_config);
    if (!config) throw Object.assign(new Error("Storage configuration is unavailable"), { code: "CONFIG_UNAVAILABLE", status: 400 });
    const grant = await providers.storage.createAccessGrant({
      config,
      objectKey: record.object_key,
      expiresIn: record.expires_in,
      id: record.id,
    });
    return {
      patch: {
        effect_state: "succeeded",
        access_url: grant.accessUrl,
        access_token: grant.accessToken,
        expires_at: grant.expiresAt,
        provider_reference: grant.accessToken.slice(0, 24),
        provider_state: "issued",
      },
    };
  },

  async verify({ request, rawBody, providers }) {
    const verified = await providers.storage.verifyWebhook({ request, rawBody });
    return verified ? {
      ...verified,
      database: verified.args.database,
      namespace: verified.args.namespace,
      payload: verified.args,
    } : false;
  },

  async webhook({ payload, load, patch }) {
    if (!payload?.id) throw Object.assign(new Error("Webhook effect id is required"), { code: "WEBHOOK_ID_REQUIRED", status: 400 });
    const size = Number(payload.size);
    if (!Number.isSafeInteger(size) || size < 0) {
      throw Object.assign(new Error("Webhook object size is invalid"), { code: "WEBHOOK_SIZE_INVALID", status: 400 });
    }
    if (typeof payload.etag !== "string" || !payload.etag) {
      throw Object.assign(new Error("Webhook object ETag is required"), { code: "WEBHOOK_ETAG_REQUIRED", status: 400 });
    }
    const current = await load(payload.id);
    if (!current) throw Object.assign(new Error("File access grant is unavailable"), { code: "GRANT_UNAVAILABLE", status: 404 });
    const completedAt = payload.completed_at ? new Date(payload.completed_at) : new Date();
    if (Number.isNaN(completedAt.getTime())) {
      throw Object.assign(new Error("Webhook completion time is invalid"), { code: "WEBHOOK_TIME_INVALID", status: 400 });
    }
    return patch(payload.id, {
      provider_state: String(payload.status || "stored"),
      object_size: size,
      object_etag: payload.etag,
      completed_at: current.completed_at ? new Date(current.completed_at) : completedAt,
    });
  },
};
