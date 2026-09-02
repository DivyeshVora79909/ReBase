const { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { adapterError } = require("./http");

function createS3StorageAdapters(options = {}) {
  const bucket = String(options.bucket || "").trim();
  const createClient = options.createClient || ((configuration) => new S3Client(configuration));
  const signUrl = options.getSignedUrl || getSignedUrl;

  function storageBucket() {
    if (!bucket) {
      throw adapterError("STORAGE_BUCKET_NOT_CONFIGURED", "REBASE_STORAGE_BUCKET is required", 503);
    }
    return bucket;
  }

  function clientFor({ endpoint, region, accessKeyId, secretAccessKey }) {
    return createClient({
      region,
      endpoint,
      forcePathStyle: true,
      credentials: { accessKeyId, secretAccessKey },
    });
  }

  async function createS3UploadGrant(input) {
    const client = clientFor(input);
    try {
      const uploadUrl = await signUrl(client, new PutObjectCommand({
        Bucket: storageBucket(),
        Key: input.objectKey,
        ContentType: input.contentType,
        ContentLength: input.contentLength,
      }), { expiresIn: input.expiresIn });
      return {
        provider: String(input.provider || "s3"),
        uploadUrl,
        headers: { "content-type": input.contentType },
        expiresAt: new Date(Date.now() + input.expiresIn * 1000).toISOString(),
        expiresIn: input.expiresIn,
      };
    } finally {
      client.destroy?.();
    }
  }

  async function createS3AccessGrant(input) {
    const client = clientFor(input);
    try {
      const accessUrl = await signUrl(client, new GetObjectCommand({
        Bucket: storageBucket(),
        Key: input.objectKey,
        ...(input.fileName ? {
          ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(input.fileName)}`,
        } : {}),
      }), { expiresIn: input.expiresIn });
      return {
        provider: String(input.provider || "s3"),
        accessUrl,
        accessToken: accessUrl,
        expiresAt: new Date(Date.now() + input.expiresIn * 1000).toISOString(),
        expiresIn: input.expiresIn,
      };
    } finally {
      client.destroy?.();
    }
  }

  async function deleteS3Object(input) {
    const client = clientFor(input);
    try {
      await client.send(new DeleteObjectCommand({
        Bucket: storageBucket(),
        Key: input.objectKey,
      }), { abortSignal: input.signal });
      return { deleted: true };
    } finally {
      client.destroy?.();
    }
  }

  return Object.freeze({ createS3AccessGrant, createS3UploadGrant, deleteS3Object });
}

module.exports = { createS3StorageAdapters };
