const {
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
} = require("@aws-sdk/client-s3");
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

  async function purgeS3Object(input) {
    const client = clientFor(input);
    const key = String(input.objectKey);
    const deletedVersions = new Set();
    let totalDeleted = 0;
    try {
      const bucket = storageBucket();
      const versionPrefix = { Bucket: bucket, Prefix: key, MaxKeys: 1000 };
      while (true) {
        let KeyMarker;
        let VersionIdMarker;
        let deletedPage = false;
        while (!deletedPage) {
          const page = await client.send(new ListObjectVersionsCommand({
            ...versionPrefix,
            ...(KeyMarker ? { KeyMarker } : {}),
            ...(VersionIdMarker ? { VersionIdMarker } : {}),
          }), { abortSignal: input.signal });
          const entries = [
            ...(page.Versions || []),
            ...(page.DeleteMarkers || []),
          ].filter((entry) => entry.Key === key).slice(0, 1000);
          if (entries.length) {
            const objects = entries.map((entry) => {
              if (entry.VersionId == null) {
                throw adapterError(
                  "STORAGE_VERSION_ID_MISSING",
                  "S3 returned a version without a version ID; refusing a non-versioned delete",
                  502,
                  true,
                );
              }
              const versionId = String(entry.VersionId);
              if (deletedVersions.has(versionId)) {
                throw adapterError(
                  "STORAGE_PURGE_NOT_CONVERGED",
                  "S3 continues to list versions after deletion",
                  503,
                  true,
                );
              }
              return { Key: key, VersionId: versionId };
            });
            const result = await client.send(new DeleteObjectsCommand({
              Bucket: bucket,
              Delete: { Objects: objects },
            }), { abortSignal: input.signal });
            if (result.Errors?.length) {
              throw adapterError(
                "STORAGE_VERSION_PURGE_PARTIAL",
                `S3 could not delete ${result.Errors.length} object version(s)`,
                503,
                true,
              );
            }
            if (result.Deleted?.length !== objects.length) {
              throw adapterError(
                "STORAGE_VERSION_PURGE_INCOMPLETE",
                "S3 did not confirm deletion of every listed object version",
                503,
                true,
              );
            }
            for (const object of objects) deletedVersions.add(object.VersionId);
            totalDeleted += objects.length;
            deletedPage = true;
            continue;
          }
          if (!page.IsTruncated) {
            return { deleted: totalDeleted > 0, versionsDeleted: totalDeleted };
          }
          const nextKeyMarker = page.NextKeyMarker;
          const nextVersionIdMarker = page.NextVersionIdMarker;
          if (!nextKeyMarker && !nextVersionIdMarker) {
            throw adapterError(
              "STORAGE_VERSION_PAGINATION_INVALID",
              "S3 truncated a version listing without a continuation marker",
              502,
              true,
            );
          }
          if (nextKeyMarker === KeyMarker && nextVersionIdMarker === VersionIdMarker) {
            throw adapterError(
              "STORAGE_VERSION_PAGINATION_STALLED",
              "S3 version-list pagination did not advance",
              502,
              true,
            );
          }
          KeyMarker = nextKeyMarker;
          VersionIdMarker = nextVersionIdMarker;
        }
      }
    } finally {
      client.destroy?.();
    }
  }

  async function headS3Object(input) {
    const client = clientFor(input);
    try {
      await client.send(new HeadObjectCommand({
        Bucket: storageBucket(),
        Key: input.objectKey,
      }), { abortSignal: input.signal });
      return { exists: true };
    } catch (error) {
      const status = Number(error?.$metadata?.httpStatusCode || error?.statusCode || error?.status);
      if (status === 404 || ["NotFound", "NoSuchKey"].includes(error?.name || error?.code)) {
        return { exists: false };
      }
      throw error;
    } finally {
      client.destroy?.();
    }
  }

  return Object.freeze({ createS3AccessGrant, createS3UploadGrant, deleteS3Object, headS3Object, purgeS3Object });
}

module.exports = { createS3StorageAdapters };
