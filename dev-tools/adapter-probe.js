#!/usr/bin/env node

const assert = require("node:assert/strict");
const { ADAPTER_NAMES, createAdapters } = require("../gateway/providers");
const { createTwilioSmsAdapter } = require("../gateway/providers/twilio-sms.adapter");
const brevoEmailHandler = require("../designs/test/table-handlers/send_brevo_email");

async function main() {
  const requests = [];
  const signed = [];
  const clients = [];
  let versionedObjects = [];
  let headMissing = false;
  let brevoEvents = [{
    email: "to@example.com",
    event: "request",
    messageId: "message_probe",
    tags: ["rebase_c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f"],
  }];
  const fetch = async (url, options) => {
    requests.push({ url: String(url), options });
    if (String(url).includes("/smtp/statistics/events")) {
      return new Response(JSON.stringify({ events: brevoEvents }), { status: 200 });
    }
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
        async send(command) {
          this.commands.push(command);
          if (command.constructor.name === "ListObjectVersionsCommand") {
            const candidates = versionedObjects.filter((entry) => entry.Key.startsWith(command.input.Prefix));
            const page = candidates.slice(0, command.input.MaxKeys || 1000);
            const isTruncated = candidates.length > page.length;
            const last = page.at(-1);
            return {
              Versions: page.filter((entry) => !entry.DeleteMarker),
              DeleteMarkers: page.filter((entry) => entry.DeleteMarker),
              IsTruncated: isTruncated,
              ...(isTruncated ? {
                NextKeyMarker: last.Key,
                NextVersionIdMarker: last.VersionId,
              } : {}),
            };
          }
          if (command.constructor.name === "DeleteObjectsCommand") {
            const objects = command.input.Delete.Objects;
            versionedObjects = versionedObjects.filter((entry) => !objects.some((object) =>
              object.Key === entry.Key && object.VersionId === entry.VersionId));
            return { Deleted: objects };
          }
          if (headMissing && command.constructor.name === "HeadObjectCommand") {
            throw Object.assign(new Error("Missing object"), {
              name: "NotFound",
              $metadata: { httpStatusCode: 404 },
            });
          }
          return {};
        },
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
    idempotencyKey: "c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f",
    reconciliationTag: "rebase_c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f",
  });
  assert.deepEqual(email, {
    provider: "brevo",
    messageId: "message_probe",
    accepted: ["to@example.com"],
  });
  assert.equal(requests[0].options.headers["api-key"], "database-brevo-key");
  assert.equal(requests[0].options.headers["idempotency-key"], undefined);
  const emailBody = JSON.parse(requests[0].options.body);
  assert.deepEqual(emailBody.replyTo, { email: "reply@example.com" });
  assert.equal(emailBody.headers.idempotencyKey, "c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f");
  assert.deepEqual(emailBody.tags, ["rebase_c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f"]);
  await assert.rejects(adapters.sendBrevoEmail({ to: [], idempotencyKey: "send_brevo_email:probe" }), /UUID/);
  const emailEvents = await adapters.getBrevoEmailEvents({
    apiKey: "database-brevo-key",
    email: "to@example.com",
    tag: "rebase_c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f",
  });
  assert.deepEqual(emailEvents, [{
    email: "to@example.com",
    event: "request",
    messageId: "message_probe",
    tags: ["rebase_c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f"],
  }]);
  const eventRequest = requests[1];
  const eventUrl = new URL(eventRequest.url);
  assert.equal(eventRequest.options.method, "GET");
  assert.equal(eventRequest.options.headers["api-key"], "database-brevo-key");
  assert.equal(eventUrl.searchParams.get("days"), "90");
  assert.equal(eventUrl.searchParams.get("limit"), "5000");
  assert.equal(eventUrl.searchParams.get("email"), "to@example.com");
  assert.deepEqual(JSON.parse(eventUrl.searchParams.get("tags")), ["rebase_c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f"]);
  const reconcileRecord = {
    execution_id: "c3d4e5f6-a7b8-4c3d-8e4f-5a6b7c8d9e0f",
    config: "rebase_email_delivery_config:probe",
    to: ["to@example.com"],
  };
  const reconcile = (events) => brevoEmailHandler.reconcile({
    record: reconcileRecord,
    async load() { return { api_key: "database-brevo-key" }; },
    adapters: { async getBrevoEmailEvents() { return events; } },
  });
  assert.deepEqual(await reconcile(emailEvents), {
    outcome: "success",
    patch: {
      provider_reference: "message_probe",
      provider_state: "accepted",
      result: { provider: "brevo", accepted: ["to@example.com"] },
    },
  });
  assert.deepEqual(await reconcile([]), { outcome: "ambiguous", retryAfterMs: 900000 });

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
  assert.equal(requests[2].options.headers.authorization, `Basic ${Buffer.from("database-key-id:database-key-secret").toString("base64")}`);
  assert.deepEqual(JSON.parse(requests[2].options.body), {
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
  assert.deepEqual(await adapters.headS3Object(storageInput), { exists: true });
  headMissing = true;
  assert.deepEqual(await adapters.headS3Object(storageInput), { exists: false });
  versionedObjects = [
    ...Array.from({ length: 1002 }, (_, index) => ({
      Key: storageInput.objectKey,
      VersionId: `version-${String(index).padStart(4, "0")}`,
    })),
    { Key: storageInput.objectKey, VersionId: "delete-marker", DeleteMarker: true },
    { Key: `${storageInput.objectKey}-neighbor`, VersionId: "neighbor-version" },
  ];
  const purge = await adapters.purgeS3Object(storageInput);
  assert.deepEqual(purge, { deleted: true, versionsDeleted: 1003 });
  assert.deepEqual(versionedObjects, [{
    Key: `${storageInput.objectKey}-neighbor`,
    VersionId: "neighbor-version",
  }]);
  assert.equal(upload.provider, "s3-compatible");
  assert.equal(access.provider, "s3-compatible");
  assert(signed.every(({ command }) => command.input.Bucket === "shared-probe-bucket"));
  assert.equal(signed[0].command.input.ContentLength, 12);
  assert.match(signed[1].command.input.ResponseContentDisposition, /probe\.txt/);
  assert.equal(clients[2].commands[0].input.Bucket, "shared-probe-bucket");
  assert.equal(clients[3].commands[0].input.Key, storageInput.objectKey);
  assert.equal(clients[4].commands[0].input.Key, storageInput.objectKey);
  const purgeCommands = clients[5].commands;
  const purgeBatches = purgeCommands.filter((command) => command.constructor.name === "DeleteObjectsCommand");
  assert.deepEqual(purgeCommands.filter((command) => command.constructor.name === "ListObjectVersionsCommand")
    .map((command) => command.input.Prefix), [storageInput.objectKey, storageInput.objectKey, storageInput.objectKey]);
  assert.deepEqual(purgeBatches.map((command) => command.input.Delete.Objects.length), [1000, 3]);
  assert(purgeBatches.every((command) => command.input.Delete.Objects.every((object) => object.Key === storageInput.objectKey)));
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

  const twilioRequests = [];
  const sendTwilioSms = createTwilioSmsAdapter({
    fetch: async (url, options) => {
      twilioRequests.push({ url, options });
      return new Response(JSON.stringify({
        sid: "SM123", status: "queued", to: "+917990910580", from: "+17372508034",
      }), { status: 201, headers: { "content-type": "application/json" } });
    },
  });
  assert.deepEqual(await sendTwilioSms({
    configuration: {
      account_sid: "AC123", api_key_sid: "SK123", api_key_secret: "twilio-api-secret",
      auth_token: "account-token-not-used", from_number: "+17372508034",
    },
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
    fetch: async (url, options) => {
      accountAuthRequests.push({ url, options });
      return new Response(JSON.stringify({ sid: "SM456" }), { status: 201 });
    },
  });
  await accountAuthSms({
    configuration: { account_sid: "AC456", auth_token: "account-token", from_number: "+17372508034" },
    to: "+917990910580", body: "sms_2fa",
  });
  assert.equal(
    accountAuthRequests[0].options.headers.authorization,
    `Basic ${Buffer.from("AC456:account-token").toString("base64")}`,
  );

  const twilioRetry = createTwilioSmsAdapter({
    fetch: async () => new Response(JSON.stringify({ code: 20429, message: "rate limited" }), { status: 429 }),
  });
  await assert.rejects(
    twilioRetry({
      configuration: { account_sid: "AC123", auth_token: "token", from_number: "+17372508034" },
      to: "+917990910580", body: "sms_2fa",
    }),
    (error) => error.code === "TWILIO_REQUEST_FAILED" && error.retryable === true && error.providerCode === 20429,
  );
  await assert.rejects(
    createTwilioSmsAdapter({ fetch: async () => new Response("{}") })({
      to: "+917990910580", body: "sms_2fa",
    }),
    (error) => error.code === "TWILIO_NOT_CONFIGURED" && error.status === 503,
  );

  console.log("adapters: static registry, flat mappings, normalization, retries, shared bucket, dynamic Twilio credentials, and overrides passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`adapters: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
