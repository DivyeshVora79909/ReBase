#!/usr/bin/env node

const assert = require("node:assert/strict");
const { ADAPTER_NAMES, createAdapters } = require("../gateway/providers");
const { createResendPlatformEmailAdapter } = require("../gateway/providers/resend-platform-email.adapter");

async function main() {
  const requests = [];
  const signed = [];
  const clients = [];
  const fetch = async (url, options) => {
    requests.push({ url: String(url), options });
    if (String(url).endsWith("/orders")) {
      return new Response(JSON.stringify({
        id: "order_probe",
        amount: 12500,
        amount_paid: 0,
        amount_due: 12500,
        attempts: 0,
        currency: "INR",
        receipt: "rb_probe",
        status: "created",
        created_at: 1_700_000_000,
      }), { status: 200 });
    }
    return new Response(JSON.stringify({ message_id: "message_probe" }), { status: 201 });
  };
  const adapters = createAdapters({
    fetch,
    storageBucket: "shared-probe-bucket",
    createS3Client(configuration) {
      const client = {
        configuration,
        commands: [],
        destroyed: false,
        async send(command) { this.commands.push(command); return {}; },
        destroy() { this.destroyed = true; },
      };
      clients.push(client);
      return client;
    },
    async getSignedUrl(client, command, options) {
      signed.push({ client, command, options });
      return `https://signed.invalid/${command.input.Bucket}/${command.input.Key}`;
    },
  });

  assert(Object.isFrozen(adapters));
  assert.deepEqual(Object.keys(adapters).sort(), [...ADAPTER_NAMES].sort());
  const email = await adapters.sendBrevoEmail({
    apiKey: "database-brevo-key",
    fromEmail: "from@example.com",
    fromName: "Probe",
    replyTo: "reply@example.com",
    to: ["to@example.com"],
    subject: "Adapter probe",
    text: "Body",
    idempotencyKey: "send_brevo_email:probe",
  });
  assert.deepEqual(email, {
    provider: "brevo",
    messageId: "message_probe",
    accepted: ["to@example.com"],
  });
  assert.equal(requests[0].options.headers["api-key"], "database-brevo-key");
  assert.equal(requests[0].options.headers["idempotency-key"], "send_brevo_email:probe");
  assert.deepEqual(JSON.parse(requests[0].options.body).replyTo, { email: "reply@example.com" });

  const order = await adapters.createRazorpayOrder({
    keyId: "database-key-id",
    keySecret: "database-key-secret",
    amount: 12500,
    currency: "INR",
    receipt: "rb_probe",
    notes: { rebase_route: "sealed-route" },
  });
  assert.equal(order.id, "order_probe");
  assert.equal(order.createdAt, "2023-11-14T22:13:20.000Z");
  assert.equal(requests[1].options.headers.authorization, `Basic ${Buffer.from("database-key-id:database-key-secret").toString("base64")}`);
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    amount: 12500,
    currency: "INR",
    receipt: "rb_probe",
    notes: { rebase_route: "sealed-route" },
  });

  const storageInput = {
    provider: "s3-compatible",
    accessKeyId: "database-storage-id",
    secretAccessKey: "database-storage-secret",
    endpoint: "https://storage.invalid",
    region: "probe-1",
    objectKey: "rebase/context/test_attachment/record",
    expiresIn: 60,
  };
  const upload = await adapters.createS3UploadGrant({
    ...storageInput,
    contentType: "text/plain",
    contentLength: 12,
  });
  const access = await adapters.createS3AccessGrant({ ...storageInput, fileName: "probe.txt" });
  await adapters.deleteS3Object(storageInput);
  assert.equal(upload.provider, "s3-compatible");
  assert.equal(access.provider, "s3-compatible");
  assert(signed.every(({ command }) => command.input.Bucket === "shared-probe-bucket"));
  assert.equal(signed[0].command.input.ContentLength, 12);
  assert.match(signed[1].command.input.ResponseContentDisposition, /probe\.txt/);
  assert.equal(clients[2].commands[0].input.Bucket, "shared-probe-bucket");
  assert(clients.every((client) => client.destroyed));
  assert.deepEqual(clients[0].configuration.credentials, {
    accessKeyId: "database-storage-id",
    secretAccessKey: "database-storage-secret",
  });

  const retrying = createAdapters({
    storageBucket: "probe",
    fetch: async () => new Response(JSON.stringify({ message: "busy" }), { status: 429 }),
  });
  await assert.rejects(
    retrying.sendBrevoEmail({
      apiKey: "key", fromEmail: "from@example.com", fromName: "Probe",
      to: ["to@example.com"], subject: "Retry", text: "Body",
    }),
    (error) => error.code === "BREVO_REQUEST_FAILED" && error.retryable === true,
  );
  await assert.rejects(
    retrying.createRazorpayOrder({
      keyId: "key", keySecret: "secret", amount: 100, currency: "INR", receipt: "receipt", notes: {},
    }),
    (error) => error.code === "RAZORPAY_REQUEST_FAILED" && error.retryable === true,
  );

  const override = async () => ({ messageId: "mocked" });
  const overridden = createAdapters({ overrides: { sendBrevoEmail: override } });
  assert.equal(overridden.sendBrevoEmail, override);
  assert.throws(() => createAdapters({ overrides: { arbitraryCode: async () => {} } }), /Unknown adapter override/);
  assert.throws(() => createAdapters({ overrides: { sendBrevoEmail: {} } }), /must be a function/);

  const platformRequests = [];
  const sendPlatformEmail = createResendPlatformEmailAdapter({
    apiKey: "platform-resend-key",
    fetch: async (url, options) => {
      platformRequests.push({ url, options });
      return new Response(JSON.stringify({ id: "platform-message" }), { status: 200 });
    },
  });
  assert.deepEqual(await sendPlatformEmail({
    to: ["owner@example.com"], subject: "Recovery", text: "Token",
  }), { id: "platform-message", provider: "resend" });
  assert.equal(platformRequests[0].options.headers.authorization, "Bearer platform-resend-key");
  assert.equal(JSON.parse(platformRequests[0].options.body).from, "ReBase <onboarding@resend.dev>");

  console.log("adapters: static registry, flat mappings, normalization, retries, shared bucket, and overrides passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`adapters: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
