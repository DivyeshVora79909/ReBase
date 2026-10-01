module.exports = {
  table: "test_attachment_cleanup",
  async execute({ record, load, adapters, signal, context }) {
    const config = await load(record.storage_config);
    await adapters.purgeS3Object({
      ...storageArguments(config),
      objectKey: record.object_key,
      taskId: context.id,
      signal,
    });
    return { outcome: "success", patch: {} };
  },
  async reconcile({ record, load, adapters, signal, context }) {
    const config = await load(record.storage_config);
    const input = {
      ...storageArguments(config),
      objectKey: record.object_key,
      taskId: context.id,
      signal,
    };
    await adapters.purgeS3Object(input);
    return { outcome: "success", patch: {} };
  },
};

function storageArguments(config) {
  return {
    provider: config.provider,
    accessKeyId: config.access_key_id,
    secretAccessKey: config.secret_access_key,
    endpoint: config.endpoint,
    region: config.region,
  };
}
