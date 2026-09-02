#!/usr/bin/env node

const assert = require("node:assert/strict");
const { ADAPTER_NAMES, createAdapters } = require("../gateway/providers");
const { createPlatformEmail, createPlatformSms } = require("../gateway/server");
const { createResendPlatformEmailAdapter } = require("../gateway/providers/resend-platform-email.adapter");
const { createTwilioSmsAdapter } = require("../gateway/providers/twilio-sms.adapter");

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
  await assert.rejects(
    createResendPlatformEmailAdapter({
      apiKey: "platform-resend-key",
      fetch: async () => { throw new Error("network down"); },
    })({ to: ["owner@example.com"], subject: "Unavailable", text: "Token" }),
    (error) => error.code === "PLATFORM_EMAIL_UNAVAILABLE" && error.retryable === true && error.status === 503,
  );
  await assert.rejects(
    createResendPlatformEmailAdapter({
      apiKey: "platform-resend-key",
      fetch: async () => new Response(JSON.stringify({ error: "bad request" }), { status: 400 }),
    })({ to: ["owner@example.com"], subject: "Rejected", text: "Token" }),
    (error) => error.code === "PLATFORM_EMAIL_FAILED" && error.retryable === false && error.status === 400,
  );
  await assert.rejects(
    createResendPlatformEmailAdapter({
      apiKey: "platform-resend-key",
      fetch: async () => new Response("{}", { status: 200 }),
    })({ to: ["owner@example.com"], subject: "Malformed", text: "Token" }),
    (error) => error.code === "PLATFORM_EMAIL_RESPONSE_INVALID" && error.retryable === true,
  );

  const twilioRequests = [];
  const sendTwilioSms = createTwilioSmsAdapter({
    accountSid: "AC123",
    apiKeySid: "SK123",
    apiKeySecret: "twilio-api-secret",
    authToken: "account-token-not-used",
    from: "+17372508034",
    fetch: async (url, options) => {
      twilioRequests.push({ url, options });
      return new Response(JSON.stringify({
        sid: "SM123", status: "queued", to: "+917990910580", from: "+17372508034",
      }), { status: 201, headers: { "content-type": "application/json" } });
    },
  });
  assert.deepEqual(await sendTwilioSms({
    to: "+917990910580",
    body: "sms_appointment_reminders",
    statusCallback: "https://runtime.invalid/twilio/status",
  }), {
    provider: "twilio",
    messageId: "SM123",
    status: "queued",
    to: "+917990910580",
    from: "+17372508034",
  });
  assert.equal(twilioRequests[0].url, "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json");
  assert.equal(
    twilioRequests[0].options.headers.authorization,
    `Basic ${Buffer.from("SK123:twilio-api-secret").toString("base64")}`,
  );
  assert.equal(twilioRequests[0].options.headers["content-type"], "application/x-www-form-urlencoded");
  assert.deepEqual(Object.fromEntries(new URLSearchParams(String(twilioRequests[0].options.body))), {
    To: "+917990910580",
    From: "+17372508034",
    Body: "sms_appointment_reminders",
    StatusCallback: "https://runtime.invalid/twilio/status",
  });

  const accountAuthRequests = [];
  const accountAuthSms = createTwilioSmsAdapter({
    accountSid: "AC456",
    authToken: "account-token",
    from: "+17372508034",
    fetch: async (url, options) => {
      accountAuthRequests.push({ url, options });
      return new Response(JSON.stringify({ sid: "SM456" }), { status: 201 });
    },
  });
  await accountAuthSms({ to: "+917990910580", body: "sms_2fa" });
  assert.equal(
    accountAuthRequests[0].options.headers.authorization,
    `Basic ${Buffer.from("AC456:account-token").toString("base64")}`,
  );

  const twilioRetry = createTwilioSmsAdapter({
    accountSid: "AC123", authToken: "token", from: "+17372508034",
    fetch: async () => new Response(JSON.stringify({ code: 20429, message: "rate limited" }), { status: 429 }),
  });
  await assert.rejects(
    twilioRetry({ to: "+917990910580", body: "sms_2fa" }),
    (error) => error.code === "TWILIO_REQUEST_FAILED" && error.retryable === true && error.providerCode === 20429,
  );
  await assert.rejects(
    createTwilioSmsAdapter({ accountSid: "AC123", from: "+17372508034", fetch: async () => new Response("{}") })({
      to: "+917990910580", body: "sms_2fa",
    }),
    (error) => error.code === "TWILIO_NOT_CONFIGURED" && error.status === 503,
  );

  assert.equal(createPlatformEmail({ resendApiKey: "   " }), null);
  const factoryEmailRequests = [];
  const factoryEmail = createPlatformEmail({
    resendApiKey: "  platform-key  ",
    from: "  ReBase <onboarding@resend.dev>  ",
  }, {
    fetch: async (url, options) => {
      factoryEmailRequests.push({ url, options });
      return new Response(JSON.stringify({ id: "factory-email" }), { status: 200 });
    },
  });
  assert(factoryEmail);
  await factoryEmail({ to: ["probe@example.com"], subject: "Factory", text: "Body" });
  assert.equal(factoryEmailRequests[0].options.headers.authorization, "Bearer platform-key");
  assert.equal(JSON.parse(factoryEmailRequests[0].options.body).from, "ReBase <onboarding@resend.dev>");

  assert.equal(createPlatformSms({}, { fetch }), null);
  assert.throws(
    () => createPlatformSms({ accountSid: "AC123", from: "+10000000000" }, { fetch }),
    /Incomplete Twilio SMS configuration.*AUTH_TOKEN/,
  );
  assert.throws(
    () => createPlatformSms({ accountSid: "AC123", apiKeySid: "SK123", from: "+10000000000" }, { fetch }),
    /Incomplete Twilio SMS configuration.*API_KEY_SECRET/,
  );
  const factorySmsRequests = [];
  const factorySms = createPlatformSms({
    accountSid: " AC123 ",
    authToken: " account-token ",
    from: " +10000000000 ",
  }, {
    fetch: async (url, options) => {
      factorySmsRequests.push({ url, options });
      return new Response(JSON.stringify({ sid: "factory-sms", status: "queued" }), { status: 201 });
    },
  });
  assert(factorySms);
  await factorySms({ to: "+917990910580", body: "Factory" });
  assert.equal(factorySmsRequests[0].options.headers.authorization,
    `Basic ${Buffer.from("AC123:account-token").toString("base64")}`);

  console.log("adapters: static registry, flat mappings, normalization, retries, shared bucket, overrides, and platform factories passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`adapters: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
