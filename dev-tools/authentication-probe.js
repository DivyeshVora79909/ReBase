#!/usr/bin/env node

const assert = require("node:assert/strict");
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

function fakeDirectory({ mode = "identity", identity = {} } = {}) {
  let challengeWrites = 0;
  let calls = 0;
  const store = {
    async execute(statement) {
      calls += 1;
      if (mode === "store-error") throw new Error("database unavailable");
      if (statement.includes("RETURN {")) {
        if (mode === "missing") return { principal: null, email: [], phone: [] };
        return {
          principal: identity.principal || "user:probe",
          email: identity.channel === "phone" ? [] : [identity],
          phone: identity.channel === "phone" ? [identity] : [],
        };
      }
      if (statement.includes("FROM authentication_email")) {
        return mode === "missing" ? null : identity;
      }
      if (statement.includes("RETURN (UPDATE authentication_challenge")) return null;
      if (statement.includes("CREATE authentication_challenge")) {
        challengeWrites += 1;
        return { id: `authentication_challenge:probe_${challengeWrites}` };
      }
      return null;
    },
  };
  return {
    store,
    get calls() { return calls; },
    async forContext() {
      if (mode === "store-error") throw new Error("database unavailable");
      return store;
    },
  };
}

function serviceOptions(directory, overrides = {}) {
  return {
    stores: directory,
    principals: { user: "user" },
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
  const directory = fakeDirectory({
    identity: {
      id: "authentication_email:probe",
      principal: "user:probe",
      address: "probe@example.com",
      revision: 1,
      principal_revision: 1,
      channel: "email",
      priority: 0,
      name: "Probe",
    },
  });
  const service = createService(serviceOptions(directory, {
    sendEmail: async (message) => { messages.push(message); },
  }));
  const delivered = await service.requestChallenge({
    namespace: "probe",
    database: "auth",
    identifier: "probe_user",
    clientAddress: "192.0.2.1",
  });
  assert.deepEqual(delivered, { accepted: true, delivered: true, channel: "email" });
  assert.equal(messages.length, 1);
  assert.match(messages[0].text, /123456/);
  assert.deepEqual(messages[0].to, ["probe@example.com"]);

  const missingDirectory = fakeDirectory({ mode: "missing" });
  const missingService = createService(serviceOptions(missingDirectory, {
    sendEmail: async () => { throw new Error("must not deliver"); },
  }));
  assert.deepEqual(await missingService.requestChallenge({
    namespace: "probe", database: "auth", identifier: "missing@example.com", clientAddress: "192.0.2.2",
  }), { accepted: true, delivered: false });

  const disallowedDirectory = fakeDirectory({ mode: "missing" });
  const disallowedService = createService(serviceOptions(disallowedDirectory, {
    sendEmail: async () => { throw new Error("must not deliver"); },
  }));
  assert.deepEqual(await disallowedService.requestChallenge({
    namespace: "other", database: "auth", identifier: "probe@example.com", clientAddress: "192.0.2.3",
  }), { accepted: true, delivered: false });
  assert.equal(disallowedDirectory.calls, 0);

  const failedService = createService(serviceOptions(directory, {
    sendEmail: async () => { throw Object.assign(new Error("provider down"), { code: "PROVIDER_DOWN" }); },
  }));
  await assert.rejects(
    failedService.requestChallenge({ namespace: "probe", database: "auth", identifier: "probe@example.com", clientAddress: "192.0.2.4" }),
    (error) => error.status === 503 && error.code === "AUTHENTICATION_DELIVERY_UNAVAILABLE",
  );

  const unavailableDirectory = fakeDirectory({ mode: "store-error" });
  const unavailableService = createService(serviceOptions(unavailableDirectory, {
    sendEmail: async () => {},
  }));
  await assert.rejects(
    unavailableService.requestChallenge({ namespace: "probe", database: "auth", identifier: "probe@example.com", clientAddress: "192.0.2.5" }),
    (error) => error.status === 503 && error.code === "AUTHENTICATION_DELIVERY_UNAVAILABLE",
  );

  const noLimiter = createService({
    stores: directory,
    principals: { user: "user" },
    sendEmail: async () => {},
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

  console.log("authentication: normalization, context isolation, generic responses, failure mapping, and OAuth allowlist passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`authentication: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
