#!/usr/bin/env node

const assert = require("node:assert/strict");
const { Readable } = require("node:stream");
const {
  contextPart,
  createAuthenticationService: createService,
  inferChannel,
  normalizeEmail,
  normalizePhone,
  normalizeUsername,
} = require("../gateway/authentication");
const { createMockOAuthAdapter, createOAuthVerifier } = require("../gateway/oauth");
const { createMemoryRateLimiter } = require("../gateway/rate-limit");
const { createAuthenticationPayloadCipher } = require("../gateway/authentication-payload");
const { createRuntimeApp } = require("../gateway/app");

function fakeDirectory({ mode = "identity", identity = {} } = {}) {
  let calls = 0;
  let transaction = null;
  const store = {
    async execute(statement, variables = {}) {
      calls += 1;
      if (mode === "store-error") throw new Error("database unavailable");
      if (statement.includes("rebase_authentication_delivery_policy:default")) {
        if (mode === "no-policy") return null;
        return {
          email_configuration: "rebase_email_delivery_config:probe",
          phone_configuration: "rebase_sms_delivery_config:probe",
        };
      }
      if (statement.includes("RETURN {")) {
        if (mode === "missing") return { principal: null, email: [], phone: [] };
        return {
          principal: identity.principal || "rebase_user:probe",
          email: identity.channel === "phone" ? [] : [identity],
          phone: identity.channel === "phone" ? [identity] : [],
        };
      }
      if (statement.includes("FROM authentication_email")) {
        return mode === "missing" ? null : identity;
      }
      if (statement.includes("BEGIN TRANSACTION")) {
        transaction = { statement, variables };
        return true;
      }
      return null;
    },
    async load(id) {
      if (mode === "missing-config") return null;
      return String(id).startsWith("rebase_") ? { id } : null;
    },
  };
  return {
    store,
    get calls() { return calls; },
    get transaction() { return transaction; },
    async forContext() {
      if (mode === "store-error") throw new Error("database unavailable");
      return store;
    },
  };
}

function serviceOptions(directory, overrides = {}) {
  return {
    stores: directory,
    principals: { user: "rebase_user" },
    allowedContexts: [{ namespace: "probe", database: "auth" }],
    rateLimiter: createMemoryRateLimiter(),
    rateLimits: { windowMs: 1000, ip: 10, identifier: 3 },
    challengeTtlMs: 60000,
    generateCode: () => "123456",
    ...overrides,
  };
}

async function main() {
  assert.equal(normalizeEmail("  User@Example.COM "), "user@example.com");
  assert.equal(normalizePhone(" +917990910580 "), "+917990910580");
  assert.equal(normalizeUsername(" User_Name1 "), "user_name1");
  assert.equal(inferChannel("user@example.com"), "email");
  assert.equal(inferChannel("+917990910580"), "phone");
  assert.equal(inferChannel("user_name1"), null);
  assert.equal(contextPart("tenant", "Namespace"), "tenant");
  assert.throws(() => contextPart("bad\nvalue", "Namespace"), /invalid/i);

  const messages = [];
  const cipher = createAuthenticationPayloadCipher("authentication-probe-payload-secret-32-bytes");
  const directory = fakeDirectory({
    identity: {
      id: "authentication_email:probe",
      principal: "rebase_user:probe",
      address: "probe@example.com",
      revision: 1,
      principal_revision: 1,
      channel: "email",
      priority: 0,
      name: "Probe",
    },
  });
  const service = createService(serviceOptions(directory, {
    sealAuthenticationPayload(message) { messages.push(message); return cipher.seal(message); },
  }));
  const delivered = await service.requestChallenge({
    namespace: "probe",
    database: "auth",
    identifier: "probe_user",
    clientAddress: "192.0.2.1",
    recipient: "attacker@example.net",
    to: ["attacker@example.net"],
    identity: "authentication_email:attacker",
    target: "authentication_phone:attacker",
    config: "rebase_email_delivery_config:attacker",
    configuration: "rebase_sms_delivery_config:attacker",
  });
  assert.deepEqual(delivered, { accepted: true, queued: true, channel: "email" });
  assert.equal(messages.length, 1);
  assert.match(messages[0].text, /123456/);
  assert.equal(directory.transaction.variables.channel, "email");
  assert.equal(directory.transaction.variables.configuration, "rebase_email_delivery_config:probe");
  assert.equal(directory.transaction.variables.target, "authentication_email:probe");
  assert.match(directory.transaction.statement, /BEGIN TRANSACTION[\s\S]*UPSERT[\s\S]*CREATE ONLY authentication_delivery_task[\s\S]*COMMIT TRANSACTION/);
  assert.equal(directory.transaction.variables.payload_ciphertext.includes("123456"), false);
  assert.match(cipher.open(directory.transaction.variables.payload_ciphertext).text, /123456/);
  assert.equal(directory.transaction.variables.principal, "rebase_user:probe");

  let routedChallenge;
  const app = createRuntimeApp({
    authentication: {
      async requestChallenge(input) {
        routedChallenge = input;
        return { accepted: true, queued: true, channel: "email" };
      },
    },
  });
  const requestBody = JSON.stringify({
    namespace: "probe",
    database: "auth",
    identifier: "probe@example.com",
    channel: "email",
    recipient: "attacker@example.net",
    to: ["attacker@example.net"],
    identity: "authentication_email:attacker",
    target: "authentication_phone:attacker",
    config: "rebase_email_delivery_config:attacker",
    configuration: "rebase_sms_delivery_config:attacker",
    clientAddress: "198.51.100.77",
  });
  const request = Readable.from([Buffer.from(requestBody)]);
  request.method = "POST";
  request.url = "/anonymous/authentication/challenges";
  request.headers = {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(requestBody)),
  };
  request.socket = { remoteAddress: "192.0.2.8" };
  const response = {
    writableEnded: false,
    writeHead(statusCode, headers) { this.statusCode = statusCode; this.headers = headers; },
    end(body) { this.body = String(body); this.writableEnded = true; },
  };
  await app(request, response);
  assert.equal(response.statusCode, 202);
  assert.deepEqual(routedChallenge, {
    namespace: "probe",
    database: "auth",
    identifier: "probe@example.com",
    channel: "email",
    clientAddress: "192.0.2.8",
  });

  const missingDirectory = fakeDirectory({ mode: "missing" });
  const missingService = createService(serviceOptions(missingDirectory, {
    sealAuthenticationPayload: cipher.seal,
  }));
  assert.deepEqual(await missingService.requestChallenge({
    namespace: "probe", database: "auth", identifier: "missing@example.com", clientAddress: "192.0.2.2",
  }), { accepted: true, delivered: false });

  const disallowedDirectory = fakeDirectory({ mode: "missing" });
  const disallowedService = createService(serviceOptions(disallowedDirectory, {
    sealAuthenticationPayload: cipher.seal,
  }));
  assert.deepEqual(await disallowedService.requestChallenge({
    namespace: "other", database: "auth", identifier: "probe@example.com", clientAddress: "192.0.2.3",
  }), { accepted: true, delivered: false });
  assert.equal(disallowedDirectory.calls, 0);

  const unavailableDirectory = fakeDirectory({ mode: "store-error" });
  const unavailableService = createService(serviceOptions(unavailableDirectory, {
    sealAuthenticationPayload: cipher.seal,
  }));
  await assert.rejects(
    unavailableService.requestChallenge({ namespace: "probe", database: "auth", identifier: "probe@example.com", clientAddress: "192.0.2.4" }),
    (error) => error.status === 503 && error.code === "AUTHENTICATION_DELIVERY_UNAVAILABLE",
  );

  const noLimiter = createService({
    stores: directory,
    principals: { user: "rebase_user" },
    sealAuthenticationPayload: cipher.seal,
  });
  await assert.rejects(
    noLimiter.requestChallenge({ namespace: "probe", database: "auth", identifier: "probe@example.com" }),
    (error) => error.status === 503,
  );

  await assert.rejects(
    service.requestChallenge({ namespace: "probe", database: "auth", identifier: "bad", clientAddress: "192.0.2.6" }),
    (error) => error.status === 400,
  );

  const oauthErrors = [];
  const oauth = createOAuthVerifier({
    mock: createMockOAuthAdapter({ token: "User@Example.COM" }),
    failing: async () => { throw Object.assign(new Error("provider error"), { code: "OAUTH_DOWN" }); },
  }, { onError: (error) => oauthErrors.push(error) });
  assert.deepEqual(await oauth.verify("mock", "token"), { verified: true, email: "user@example.com" });
  assert.deepEqual(await oauth.verify("unknown", "token"), { verified: false });
  assert.deepEqual(await oauth.verify("failing", "token"), { verified: false });
  assert.equal(oauthErrors[0].code, "OAUTH_DOWN");
  const hookFailure = createOAuthVerifier({
    failing: async () => { throw new Error("provider error"); },
  }, { onError: () => { throw new Error("observer error"); } });
  assert.deepEqual(await hookFailure.verify("failing", "token"), { verified: false });
  assert.throws(() => createOAuthVerifier({ invalid: null }), /must be a function/);

  const noPolicyDirectory = fakeDirectory({ mode: "no-policy", identity: {
    id: "authentication_email:probe", principal: "rebase_user:probe", revision: 1, principal_revision: 1,
  } });
  const noPolicyService = createService(serviceOptions(noPolicyDirectory, { sealAuthenticationPayload: cipher.seal }));
  assert.deepEqual(await noPolicyService.requestChallenge({
    namespace: "probe", database: "auth", identifier: "probe@example.com", clientAddress: "192.0.2.7",
  }), { accepted: true, delivered: false });
  assert.equal(noPolicyDirectory.transaction, null);

  console.log("authentication: normalization, context isolation, generic responses, fixed target/config routing, encrypted atomic queueing, failure mapping, and OAuth allowlist passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`authentication: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
