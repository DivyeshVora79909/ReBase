const GRANT_ADAPTERS = new Set([
  "createS3AccessGrant",
  "createS3UploadGrant",
]);

const SIDE_EFFECT_ADAPTERS = new Set([
  "createRazorpayOrder",
  "deleteS3Object",
  "purgeS3Object",
  "sendBrevoEmail",
  "sendTwilioSms",
]);

function assertGrantAdapters(table, adapters = []) {
  const unsafe = adapters.find((name) => !GRANT_ADAPTERS.has(name));
  if (unsafe) {
    throw new Error(`${table}: adapter ${unsafe} is not permitted for a grant operation`);
  }
}

module.exports = { SIDE_EFFECT_ADAPTERS, assertGrantAdapters };
