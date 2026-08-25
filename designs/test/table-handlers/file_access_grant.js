module.exports = {
  table: "file_access_grant",

  async execute({ record, load, providers, signal }) {
    const config = await load(record.storage_config);
    const grant = await providers.storage.createAccessGrant({
      config,
      objectKey: record.object_key,
      expiresIn: record.expires_in,
      id: record.id,
      signal,
    });
    return {
      patch: {
        access_url: grant.accessUrl,
        access_token: grant.accessToken,
        expires_at: grant.expiresAt,
        provider_reference: grant.accessToken.slice(0, 24),
        provider_state: "issued",
      },
      outcome: "success",
    };
  },
};
