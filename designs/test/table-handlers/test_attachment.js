const crypto = require("node:crypto");

function objectKey(context) {
  const scope = crypto
    .createHash("sha256")
    .update(`${context.namespace}\u0000${context.database}`)
    .digest("hex")
    .slice(0, 24);
  const record = crypto
    .createHash("sha256")
    .update(String(context.id))
    .digest("hex")
    .slice(0, 32);
  return `rebase/${scope}/${context.table}/${record}`;
}

module.exports = {
  table: "test_attachment",
  on: {
    async CREATE(input) {
      return issueAccess(input, objectKey(input.context));
    },
    async UPDATE(input) {
      return issueAccess(input, input.before.object_key);
    },
    async DELETE({ before, load, adapters, signal }) {
      const config = await load(before.storage_config);
      await adapters.deleteS3Object({
        ...storageArguments(config),
        objectKey: before.object_key,
        signal,
      });
      return { outcome: "success", patch: {} };
    },
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

async function issueAccess({ record, load, adapters, signal }, key) {
  const config = await load(record.storage_config);
  const grant = record.access_mode === "download"
    ? await adapters.createS3AccessGrant({
        ...storageArguments(config),
        objectKey: key,
        fileName: record.file_name,
        expiresIn: record.access_duration,
        signal,
      })
    : await adapters.createS3UploadGrant({
        ...storageArguments(config),
        objectKey: key,
        contentType: record.media_type,
        contentLength: record.byte_length_limit,
        expiresIn: record.access_duration,
        signal,
      });
  return {
    patch: {
      object_key: key,
      access_url: grant.uploadUrl || grant.accessUrl,
      access_headers: grant.headers || {},
      access_expires_at: grant.expiresAt,
    },
    outcome: "success",
  };
}
