const { createBrevoEmailAdapter } = require("./brevo-email.adapter");
const { createRazorpayOrderAdapter } = require("./razorpay-order.adapter");
const { createRazorpayWebhookAdapter } = require("./razorpay-webhook.adapter");
const { createS3StorageAdapters } = require("./s3-storage.adapter");

const ADAPTER_NAMES = Object.freeze([
  "sendBrevoEmail",
  "createS3UploadGrant",
  "createS3AccessGrant",
  "deleteS3Object",
  "createRazorpayOrder",
]);

function assertFunctionOverrides(overrides = {}) {
  for (const [name, adapter] of Object.entries(overrides)) {
    if (!ADAPTER_NAMES.includes(name)) throw new Error(`Unknown adapter override: ${name}`);
    if (typeof adapter !== "function") throw new Error(`Adapter override ${name} must be a function`);
  }
  return overrides;
}

function createAdapters(options = {}) {
  const storage = createS3StorageAdapters({
    bucket: options.storageBucket,
    createClient: options.createS3Client,
    getSignedUrl: options.getSignedUrl,
  });
  return Object.freeze({
    sendBrevoEmail: createBrevoEmailAdapter({ fetch: options.fetch, endpoint: options.brevoEndpoint }),
    ...storage,
    createRazorpayOrder: createRazorpayOrderAdapter({ fetch: options.fetch, endpoint: options.razorpayEndpoint }),
    ...assertFunctionOverrides(options.overrides),
  });
}

function createWebhookAdapters(options = {}) {
  const adapters = {
    razorpay: createRazorpayWebhookAdapter(),
    ...(options.overrides || {}),
  };
  for (const [provider, adapter] of Object.entries(adapters)) {
    if (typeof adapter?.extractRoute !== "function" || typeof adapter?.verify !== "function") {
      throw new Error(`Webhook adapter ${provider} requires extractRoute() and verify()`);
    }
  }
  return Object.freeze(adapters);
}

module.exports = { ADAPTER_NAMES, createAdapters, createWebhookAdapters };
