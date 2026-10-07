#!/usr/bin/env node
"use strict";

// A software authenticator supplies real P-256 signatures to SimpleWebAuthn.
// This verifies backend cryptography and durable claims, not browser/device UX.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { loadMaterials } = require("../compiler/materials");
const { generateBundle } = require("../compiler/pipeline");
const path = require("node:path");
const { Readable } = require("node:stream");
const { Surreal } = require("surrealdb");
const { isoCBOR } = require("@simplewebauthn/server/helpers");
const { start, client, applySchema } = require("../temporal-tree/harness");
const { signIn } = require("./tenant-auth-probe");
const { createTableStore } = require("../../gateway/store");
const { createMemoryRateLimiter } = require("../../gateway/rate-limit");
const { createAuthenticationService } = require("../../gateway/authentication");
const { createAuthenticationPayloadCipher } = require("../../gateway/authentication-payload");
const { createPasskeyService } = require("../../gateway/passkeys");
const { createRuntimeApp } = require("../../gateway/app");

const rpId = "example.test";
const origin = "https://app.example.test";
const digest = value => crypto.createHash("sha256").update(value).digest();

function authenticator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicKey.export({ format: "jwk" });
  const credential = crypto.randomBytes(32);
  const id = credential.toString("base64url");
  const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
  let userHandle;
  return {
    id,
    registration(options) {
      userHandle = options.user.id;
      const length = Buffer.alloc(2); length.writeUInt16BE(credential.length);
      const authData = Buffer.concat([digest(rpId), Buffer.from([0x45]), Buffer.alloc(4),
        Buffer.alloc(16), length, credential, Buffer.from(cose)]);
      const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }));
      const attestation = isoCBOR.encode(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
      return { id, rawId: id, type: "public-key", authenticatorAttachment: "platform",
        response: { clientDataJSON: clientData.toString("base64url"), attestationObject: Buffer.from(attestation).toString("base64url"), transports: ["internal"] },
        clientExtensionResults: { credProps: { rk: true } } };
    },
    assertion(options, counter, overrides = {}) {
      const count = Buffer.alloc(4); count.writeUInt32BE(counter);
      const authData = Buffer.concat([digest(overrides.rpId || rpId), Buffer.from([overrides.flags ?? 0x05]), count]);
      const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: overrides.challenge || options.challenge,
        origin: overrides.origin || origin, crossOrigin: false }));
      const signature = crypto.sign("sha256", Buffer.concat([authData, digest(clientData)]), privateKey);
      if (overrides.badSignature) signature[signature.length - 1] ^= 1;
      return { id, rawId: id, type: "public-key", authenticatorAttachment: "platform",
        response: { clientDataJSON: clientData.toString("base64url"), authenticatorData: authData.toString("base64url"),
          signature: signature.toString("base64url"), userHandle }, clientExtensionResults: {} };
    },
  };
}

async function exchange(url, tenant, exchangeToken) {
  const response = await fetch(`${url}/signin`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ ns: "temporal_probe", db: "fixture", ac: "account_passkey", tenant, exchange_token: exchangeToken }) });
  return (await response.json()).token || null;
}

async function request(app, pathname, body, token) {
  const bytes = Buffer.from(JSON.stringify(body));
  const incoming = Readable.from([bytes]);
  incoming.method = "POST";
  incoming.url = pathname;
  incoming.headers = { "content-type": "application/json", "content-length": String(bytes.length),
    ...(token ? { authorization: `Bearer ${token}` } : {}) };
  incoming.socket = { remoteAddress: "192.0.2.1" };
  const response = { writableEnded: false,
    writeHead(status) { this.status = status; }, end(value) { this.body = JSON.parse(value); this.writableEnded = true; } };
  await app(incoming, response);
  return response;
}

async function main() {
  const server = await start();
  const q = client(server.url);
  const db = new Surreal();
  try {
    await q("DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;");
    const materials = loadMaterials({ groups: [{ name: 'framework', roots: [path.join(__dirname, '../../framework')] }] });
    await applySchema(q, generateBundle(materials).bundle);
    const tenantA = (await q("CREATE rebase_tenant SET name='UUID tenant';"))[0].id;
    const tenantAlternative = tenantA.replace(/u'([^']+)'$/, 'u"$1"');
    assert.notEqual(tenantA, tenantAlternative);
    await q(`CREATE rebase_tenant:b SET name='B';
      CREATE rebase_user:admin SET name='Admin',username='admin_user',parents=[${tenantA}],
        password=crypto::argon2::generate('tenant-probe-password');
      CREATE authentication_email:admin SET owned_by=rebase_user:admin,address='admin@example.test';
      UPDATE authentication_email:admin SET verified_revision=revision;`);
    const token = await signIn(server.url, tenantA, "admin@example.test");
    assert(token);
    await db.connect(`${server.url.replace("http:", "ws:")}/rpc`);
    await db.signin({ username: "root", password: "root" });
    await db.use({ namespace: "temporal_probe", database: "fixture" });
    const store = createTableStore(db);
    const rateKeys = [];
    const memoryLimiter = createMemoryRateLimiter();
    const rateLimiter = { consume(key, options) { rateKeys.push(key); return memoryLimiter.consume(key, options); } };
    const service = createPasskeyService({ stores: { async forContext() { return store; } },
      defaultContext: { namespace: "temporal_probe", database: "fixture" }, endpoint: server.url,
      rpId, origins: [origin], rateLimiter });
    const actor = client(server.url, "fixture", token);
    const device = authenticator();
    const input = { tenant: tenantAlternative, token, clientAddress: "192.0.2.1" };
    const rejected = error => error?.status === 401;
    const app = createRuntimeApp({ passkeys: service });
    assert.equal((await request(app, "/authentication/passkeys/registration/options",
      { tenant: tenantA, token })).status, 401, "a body token cannot replace the Authorization header");
    assert.equal((await request(app, "/authentication/passkeys/registration/options",
      { tenant: "rebase_tenant:b" }, token)).status, 401);
    assert.equal((await request(app, "/authentication/passkeys/registration/options",
      { tenant: tenantAlternative, namespace: "attacker", database: "attacker", token: "forged" }, token)).status, 200,
    "the route uses the native bearer token and configured design");
    await assert.rejects(service.registrationOptions({ ...input, tenant: "rebase_tenant:b" }), rejected);
    await assert.rejects(service.registrationOptions({ ...input, token: "forged" }), rejected);
    await service.authenticationOptions({ ...input, tenant: tenantA });
    await service.authenticationOptions({ ...input, tenant: tenantAlternative });
    assert.equal(rateKeys.at(-1), rateKeys.at(-2), 'equivalent UUID tenant spellings must share the passkey rate limit');
    await q(`CREATE rebase_email_delivery_config:auth SET owned_by=${tenantA},api_key='probe',from_email='sender@example.test',from_name='Sender';
      CREATE rebase_authentication_delivery_policy:auth SET tenant=${tenantA},email_configuration=rebase_email_delivery_config:auth;`);
    const authentication = createAuthenticationService({ stores: { async forContext() { return store; } },
      defaultContext: { namespace: 'temporal_probe', database: 'fixture' }, rateLimiter,
      sealAuthenticationPayload: createAuthenticationPayloadCipher('probe-authentication-payload-secret-32-bytes').seal });
    for (const tenant of [tenantA, tenantAlternative]) {
      const result = await authentication.requestChallenge({ tenant, identifier: 'admin@example.test', clientAddress: '192.0.2.9' });
      assert.equal(result.queued, true);
    }
    const accountKeys = rateKeys.filter(key => key.startsWith('authentication:account:'));
    assert.equal(accountKeys.at(-1), accountKeys.at(-2), 'equivalent UUID tenant spellings must share the identity rate limit');
    const registration = await service.registrationOptions(input);
    assert.equal(registration.options.authenticatorSelection.userVerification, "required");
    const registrationResponse = device.registration(registration.options);
    const registered = await service.register({ ...input, challengeId: registration.challengeId, response: registrationResponse });
    assert.equal(registered.verified, true);
    await assert.rejects(service.register({ ...input, challengeId: registration.challengeId, response: registrationResponse }), rejected);
    const publicCredential = (await actor(`SELECT * FROM ${registered.id};`))[0];
    assert.equal(publicCredential.owned_by, "rebase_user:admin");
    assert.equal(publicCredential.tenant, tenantA);
    assert.equal(publicCredential.public_key, undefined);
    await actor(`UPDATE ${registered.id} SET sign_count=999;`);
    assert.equal(await q(`RETURN ${registered.id}.sign_count;`), 0);

    for (const invalid of [{ origin: "https://evil.example.test" }, { rpId: "evil.test" },
      { challenge: "wrong-challenge" }, { flags: 0x01 }, { badSignature: true }]) {
      const attempt = await service.authenticationOptions(input);
      await assert.rejects(service.authenticate({ ...input, challengeId: attempt.challengeId,
        response: device.assertion(attempt.options, 1, invalid) }), rejected);
    }
    const wrongTenant = await service.authenticationOptions({ ...input, tenant: "rebase_tenant:b" });
    await assert.rejects(service.authenticate({ ...input, tenant: "rebase_tenant:b", challengeId: wrongTenant.challengeId,
      response: device.assertion(wrongTenant.options, 1) }), rejected);

    const login = await service.authenticationOptions(input);
    const accepted = await service.authenticate({ ...input, challengeId: login.challengeId, response: device.assertion(login.options, 1) });
    assert.equal(accepted.verified, true);
    assert.equal(await exchange(server.url, "rebase_tenant:b", accepted.exchangeToken), null);
    const raced = await Promise.all([exchange(server.url, tenantA, accepted.exchangeToken), exchange(server.url, tenantA, accepted.exchangeToken)]);
    assert.equal(raced.filter(Boolean).length, 1, "one-use exchange must have exactly one winner");
    const passkeyActor = client(server.url, "fixture", raced.find(Boolean));
    assert.equal(await passkeyActor("RETURN <string>$auth;"), "rebase_user:admin");
    assert.equal(await q(`RETURN ${registered.id}.sign_count;`), 1);

    const replay = await service.authenticationOptions(input);
    await assert.rejects(service.authenticate({ ...input, challengeId: replay.challengeId, response: device.assertion(replay.options, 1) }), rejected);
    await q("DELETE authentication_email:admin;");
    assert(await signIn(server.url, tenantA, "admin_user"), "a verified passkey satisfies the username identity gate");
    const finalLogin = await service.authenticationOptions(input);
    const finalExchange = await service.authenticate({ ...input, challengeId: finalLogin.challengeId, response: device.assertion(finalLogin.options, 2) });
    await passkeyActor(`DELETE ${registered.id};`);
    assert.equal(await exchange(server.url, tenantA, finalExchange.exchangeToken), null);
    assert.equal(await signIn(server.url, tenantA, "admin_user"), null);
    const report = { realP256Verification: true, rpOriginChallengeUserVerification: true, recentNativeSession: true,
      tenantIsolation: true, canonicalUuidTenantRateLimits: true, httpBearerBoundary: true,
      counterReplayDenied: true, concurrentExchangeOneWinner: true, revocation: true,
      scope: "Software authenticator and disposable SurrealDB; browser/device UX and live deployment not tested." };
    console.log(`passkeys: ${JSON.stringify(report)}`);
    return report;
  } finally { await db.close().catch(() => {}); await server.close(); }
}

if (require.main === module) main().catch(error => {
  console.error(`passkeys: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
module.exports = { main, authenticator };
