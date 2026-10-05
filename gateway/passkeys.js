"use strict";

const crypto = require("node:crypto");
const webauthn = require("@simplewebauthn/server");
const { RuntimeError } = require("./errors");
const { contextPart, resolveTenant } = require("./authentication");

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const EXCHANGE_TTL_MS = 60 * 1000;
const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const userHandle = id => crypto.createHash("sha256").update(String(id)).digest();
const rejected = () => new RuntimeError("PASSKEY_AUTHENTICATION_FAILED", "Passkey verification failed", 401);

function relyingParty(rpId, origins) {
  if (typeof rpId !== "string" || !/^[a-z0-9.-]+$/.test(rpId) || !Array.isArray(origins) || origins.length === 0) {
    throw new Error("Passkeys require an explicit RP ID and allowed origins");
  }
  const allowed = [...new Set(origins.map(value => {
    const origin = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
    if (origin.origin !== value || origin.username || origin.password
      || (origin.protocol !== "https:" && !(local && origin.protocol === "http:"))
      || (origin.hostname !== rpId && !origin.hostname.endsWith(`.${rpId}`))) {
      throw new Error("Passkey origins must be HTTPS origins within the RP ID (HTTP localhost is allowed)");
    }
    return origin.origin;
  }))];
  return { rpId, origins: allowed };
}

// Verify record tokens with SurrealDB itself, using a separate HTTP request.
// The trusted store connection is never switched into a user's session.
function createRecordSessionVerifier({ endpoint, defaultContext, fetchImpl = fetch }) {
  const url = new URL(endpoint);
  if (url.protocol === "ws:") url.protocol = "http:";
  else if (url.protocol === "wss:") url.protocol = "https:";
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Invalid SurrealDB passkey endpoint");
  url.pathname = `${url.pathname.replace(/\/rpc\/?$/, "").replace(/\/$/, "")}/sql`;
  return async token => {
    if (typeof token !== "string" || !token || token.length > 16384) throw rejected();
    const response = await fetchImpl(url, {
      method: "POST", signal: AbortSignal.timeout(10000),
      headers: { Authorization: `Bearer ${token}`, "surreal-ns": defaultContext.namespace,
        "surreal-db": defaultContext.database, Accept: "application/json" },
      body: "RETURN { id: <string>$auth, tenant: <string>$auth.tenant, login_access: $auth.login_access, issued_at: $token.iat };",
    });
    if (!response.ok) throw rejected();
    const results = await response.json();
    if (!Array.isArray(results) || results.some(row => row.status !== "OK")) throw rejected();
    const session = results.at(-1)?.result;
    if (!session?.id?.startsWith("rebase_user:") || session.login_access !== true) throw rejected();
    return session;
  };
}

function createPasskeyService(options = {}) {
  const { rpId, origins } = relyingParty(options.rpId, options.origins);
  if (!options.stores?.forContext || !options.rateLimiter?.consume) {
    throw new Error("Passkeys require the design store and a rate limiter");
  }
  const design = {
    namespace: contextPart(options.defaultContext?.namespace, "Design namespace"),
    database: contextPart(options.defaultContext?.database, "Design database"),
  };
  const verifySession = options.verifySession || createRecordSessionVerifier({
    endpoint: options.endpoint, defaultContext: design,
  });
  const api = options.webauthn || webauthn;
  const now = options.now || Date.now;
  const getStore = () => options.stores.forContext(design.namespace, design.database);

  async function tenantStore(rawTenant) {
    const store = await getStore();
    const tenant = await resolveTenant(store, rawTenant);
    if (!tenant) throw rejected();
    return { store, tenant };
  }

  async function limit(tenant, clientAddress) {
    let result;
    try {
      result = await options.rateLimiter.consume(`passkey:${hash(`${design.namespace}\0${design.database}\0${tenant}\0${clientAddress || "unknown"}`)}`, {
        limit: 30, windowMs: 15 * 60 * 1000,
      });
    } catch (cause) {
      throw new RuntimeError("AUTHENTICATION_RATE_LIMIT_UNAVAILABLE", "Authentication service is temporarily unavailable", 503, { cause });
    }
    if (!result.allowed) throw new RuntimeError("RATE_LIMITED", "Too many authentication requests", 429);
  }

  async function currentPrincipal(store, tenant, token) {
    const session = await verifySession(token);
    if (String(session.tenant) !== tenant || !Number.isFinite(session.issued_at)
      || session.issued_at < Math.floor(now() / 1000) - 600) {
      throw new RuntimeError("RECENT_AUTHENTICATION_REQUIRED", "Sign in again before enrolling a passkey", 401);
    }
    const principal = await store.execute(`RETURN (SELECT *, <string>tenant AS tenant
      FROM type::record($id))[0];`, { id: session.id });
    if (!principal || String(principal.tenant) !== tenant || principal.login_access !== true) throw rejected();
    return principal;
  }

  async function saveChallenge(store, tenant, purpose, challenge, principal) {
    const id = `authentication_passkey_challenge:c_${hash(challenge)}`;
    await store.execute(`
      BEGIN TRANSACTION;
      LET $expired = (SELECT VALUE id FROM authentication_passkey_challenge
        WHERE tenant = type::record($tenant) AND expires_at < time::now() LIMIT 100);
      DELETE $expired;
      CREATE ONLY type::record($id) SET tenant = type::record($tenant),
        owned_by = IF $principal = NONE THEN NONE ELSE type::record($principal) END,
        principal_revision = $principal_revision, purpose = $purpose, challenge = $challenge,
        expires_at = type::datetime($expires_at);
      COMMIT TRANSACTION;
      RETURN true;
    `, { id, tenant, purpose, challenge, principal: principal ? String(principal.id) : undefined,
      principal_revision: principal?.authentication_revision,
      expires_at: new Date(now() + CHALLENGE_TTL_MS).toISOString() });
    return id;
  }

  async function claimChallenge(store, tenant, id, purpose, principal) {
    if (typeof id !== "string" || !/^authentication_passkey_challenge:c_[a-f0-9]{64}$/.test(id)) throw rejected();
    const challenge = await store.execute(`
      RETURN (UPDATE type::record($id) SET claimed_at = time::now()
        WHERE tenant = type::record($tenant) AND purpose = $purpose
          AND claimed_at = NONE AND expires_at >= time::now()
          AND ($principal = NONE OR (owned_by = type::record($principal)
            AND principal_revision = $principal_revision)) RETURN AFTER)[0];
    `, { id, tenant, purpose, principal: principal ? String(principal.id) : undefined,
      principal_revision: principal?.authentication_revision });
    if (!challenge) throw rejected();
    return challenge;
  }

  async function registrationOptions({ tenant: rawTenant, token, clientAddress }) {
    const { store, tenant } = await tenantStore(rawTenant);
    await limit(tenant, clientAddress);
    const principal = await currentPrincipal(store, tenant, token);
    const credentials = await store.execute(`SELECT credential_id, transports FROM authentication_passkey
      WHERE owned_by = type::record($principal) AND rp_id = $rp_id;`, { principal: String(principal.id), rp_id: rpId });
    const publicKey = await api.generateRegistrationOptions({
      rpName: options.rpName || "ReBase", rpID: rpId, userID: userHandle(principal.id),
      userName: principal.username || String(principal.id), userDisplayName: principal.name,
      attestationType: "none", timeout: CHALLENGE_TTL_MS,
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      excludeCredentials: (credentials || []).map(credential => ({ id: credential.credential_id, transports: credential.transports })),
    });
    const challengeId = await saveChallenge(store, tenant, "registration", publicKey.challenge, principal);
    return { challengeId, options: publicKey };
  }

  async function register({ tenant: rawTenant, token, challengeId, response, clientAddress }) {
    const { store, tenant } = await tenantStore(rawTenant);
    await limit(tenant, clientAddress);
    const principal = await currentPrincipal(store, tenant, token);
    const challenge = await claimChallenge(store, tenant, challengeId, "registration", principal);
    let verification;
    try {
      verification = await api.verifyRegistrationResponse({ response, expectedChallenge: challenge.challenge,
        expectedOrigin: origins, expectedRPID: rpId, requireUserVerification: true });
    } catch { throw rejected(); }
    if (!verification.verified || !verification.registrationInfo?.credential) throw rejected();
    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    const identity = `authentication_passkey:p_${hash(`${tenant}\0${credential.id}`)}`;
    await store.execute(`
      BEGIN TRANSACTION;
      LET $principal_row = (SELECT * FROM type::record($principal))[0];
      IF $principal_row.tenant != type::record($tenant) OR !$principal_row.login_access
        OR $principal_row.authentication_revision != $principal_revision { THROW 'ERR_PASSKEY_PRINCIPAL_CHANGED'; };
      CREATE ONLY type::record($identity) SET owned_by = type::record($principal),
        credential_id = $credential_id, public_key = $public_key, user_handle = $user_handle,
        rp_id = $rp_id, sign_count = $counter, transports = $transports,
        device_type = $device_type, backed_up = $backed_up;
      COMMIT TRANSACTION;
      RETURN true;
    `, { identity, principal: String(principal.id), tenant, principal_revision: principal.authentication_revision,
      credential_id: credential.id, public_key: Buffer.from(credential.publicKey).toString("base64url"),
      user_handle: userHandle(principal.id).toString("base64url"), rp_id: rpId, counter: credential.counter,
      transports: credential.transports || [], device_type: credentialDeviceType, backed_up: credentialBackedUp });
    return { verified: true, id: identity };
  }

  async function authenticationOptions({ tenant: rawTenant, clientAddress }) {
    const { store, tenant } = await tenantStore(rawTenant);
    await limit(tenant, clientAddress);
    const publicKey = await api.generateAuthenticationOptions({
      rpID: rpId, userVerification: "required", timeout: CHALLENGE_TTL_MS,
    });
    const challengeId = await saveChallenge(store, tenant, "authentication", publicKey.challenge);
    return { challengeId, options: publicKey };
  }

  async function authenticate({ tenant: rawTenant, challengeId, response, clientAddress }) {
    const { store, tenant } = await tenantStore(rawTenant);
    await limit(tenant, clientAddress);
    const challenge = await claimChallenge(store, tenant, challengeId, "authentication");
    if (!response || typeof response.id !== "string" || response.id.length > 2048) throw rejected();
    const credential = await store.execute(`RETURN (SELECT *, owned_by.authentication_revision AS principal_revision
      FROM authentication_passkey WHERE tenant = type::record($tenant) AND credential_id = $credential_id
        AND rp_id = $rp_id AND owned_by.login_access = true)[0];`, { tenant, credential_id: response.id, rp_id: rpId });
    if (!credential || (response.response?.userHandle != null && response.response.userHandle !== credential.user_handle)) throw rejected();
    let verification;
    try {
      verification = await api.verifyAuthenticationResponse({ response, expectedChallenge: challenge.challenge,
        expectedOrigin: origins, expectedRPID: rpId, requireUserVerification: true,
        credential: { id: credential.credential_id, publicKey: Buffer.from(credential.public_key, "base64url"),
          counter: Number(credential.sign_count), transports: credential.transports } });
    } catch { throw rejected(); }
    if (!verification.verified) throw rejected();
    const exchangeToken = crypto.randomBytes(32).toString("base64url");
    const exchangeId = `authentication_passkey_exchange:x_${hash(exchangeToken)}`;
    const expiresAt = new Date(now() + EXCHANGE_TTL_MS).toISOString();
    const info = verification.authenticationInfo;
    await store.execute(`
      BEGIN TRANSACTION;
      LET $current = (SELECT * FROM type::record($credential))[0];
      IF $current = NONE OR $current.tenant != type::record($tenant)
        OR !$current.owned_by.login_access OR $current.sign_count != $old_counter
        OR $current.owned_by.authentication_revision != $principal_revision { THROW 'ERR_PASSKEY_CREDENTIAL_CHANGED'; };
      UPDATE $current.id SET sign_count = $counter, backed_up = $backed_up;
      LET $expired = (SELECT VALUE id FROM authentication_passkey_exchange
        WHERE tenant = type::record($tenant) AND expires_at < time::now() LIMIT 100);
      DELETE $expired;
      CREATE ONLY type::record($exchange_id) SET owned_by = $current.owned_by,
        target = $current.id, principal_revision = $principal_revision,
        expires_at = type::datetime($expires_at);
      COMMIT TRANSACTION;
      RETURN true;
    `, { credential: String(credential.id), tenant, old_counter: Number(credential.sign_count),
      principal_revision: Number(credential.principal_revision), counter: info.newCounter,
      backed_up: info.credentialBackedUp, exchange_id: exchangeId, expires_at: expiresAt });
    return { verified: true, exchangeToken, expiresAt };
  }

  return Object.freeze({ enabled: true, registrationOptions, register, authenticationOptions, authenticate,
    async health() { return { ok: true, enabled: true, rpId }; } });
}

module.exports = { createPasskeyService, createRecordSessionVerifier, relyingParty };
