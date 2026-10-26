import { createHmac, generateKeyPairSync, randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { startFakeProvider } from '../fake-provider.mjs';

const TENANT = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const METHODS = ['service.start', 'service.stop', 'identity.issue'];
const EVENT_LIMIT = 8192;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Sign the provider's exact HTTP body bytes. JSON serialization is the caller's
 * choice and happens before this function; the same bytes must be sent later.
 */
export function signFakeIngressHeaders({ secret, account, event, timestamp, body }) {
  if (!Buffer.isBuffer(secret) || secret.byteLength < 32 || secret.byteLength > 128) {
    throw new TypeError('secret must be a Buffer containing 32 to 128 raw bytes');
  }
  if (typeof account !== 'string' || typeof event !== 'string' || typeof timestamp !== 'string') {
    throw new TypeError('account, event and timestamp must be strings');
  }
  if (!/^[A-Za-z0-9-]{1,128}$/.test(account) || !UUID.test(event)
    || event === '00000000-0000-0000-0000-000000000000'
    || !/^(0|[1-9][0-9]*)$/.test(timestamp) || !Number.isSafeInteger(Number(timestamp))) {
    throw new TypeError('account, event and timestamp must use ingress wire forms');
  }
  if (!(Buffer.isBuffer(body) || body instanceof Uint8Array)) throw new TypeError('body must contain exact request bytes');
  const bytes = Buffer.from(body);
  const signature = createHmac('sha256', secret)
    .update(Buffer.from(`${account}\n${event}\n${timestamp}\n`, 'utf8'))
    .update(bytes)
    .digest('hex');
  return Object.freeze({
    'content-type': 'application/json',
    'x-fake-account': account,
    'x-fake-event': event,
    'x-fake-timestamp': timestamp,
    'x-fake-signature': signature,
  });
}

/** Send one bounded webhook request. This function never retries an unknown outcome. */
export function postFakeIngress({ endpoint, secret, account = 'fake-account-1', event, timestamp, body, timeoutMs = 5000 } = {}) {
  if (typeof endpoint !== 'string') return Promise.reject(new TypeError('endpoint must be a URL string'));
  let base;
  try { base = new URL(endpoint); }
  catch { return Promise.reject(new TypeError('endpoint must be an HTTP(S) URL')); }
  if (!['http:', 'https:'].includes(base.protocol) || !base.hostname || base.username || base.password
    || base.search || base.hash || !['/', '/rpc'].includes(base.pathname)) {
    return Promise.reject(new TypeError('endpoint must be an HTTP(S) origin or native /rpc URL without credentials, query or fragment'));
  }
  const target = new URL('/effects/fake', base.origin);
  if (!(Buffer.isBuffer(body) || body instanceof Uint8Array) || body.byteLength > EVENT_LIMIT * 2) {
    return Promise.reject(new TypeError('body must contain at most 16384 exact request bytes'));
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    return Promise.reject(new TypeError('timeoutMs must be an integer in [1, 30000]'));
  }
  const bytes = Buffer.from(body);
  const headers = signFakeIngressHeaders({ secret, account, event, timestamp, body: bytes });
  const transport = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => request.destroy(new Error('Webhook request timed out')), timeoutMs);
    const request = transport.request(target, {
      method: 'POST',
      headers: { ...headers, 'content-length': bytes.byteLength, accept: 'application/json' },
      agent: false,
    }, response => {
      const chunks = [];
      let received = 0;
      response.on('data', chunk => {
        received += chunk.byteLength;
        if (received > EVENT_LIMIT) {
          response.destroy(new Error('Webhook response exceeds 8192 bytes'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', error => { clearTimeout(deadline); reject(error); });
      response.on('end', () => {
        clearTimeout(deadline);
        const raw = Buffer.concat(chunks, received);
        let value;
        try { value = JSON.parse(raw.toString('utf8')); }
        catch { return reject(new Error('Webhook returned a non-JSON response')); }
        resolve(Object.freeze({ status: response.statusCode ?? 0, value }));
      });
    });
    request.on('error', error => { clearTimeout(deadline); reject(error); });
    request.end(bytes);
  });
}

/** Run the complete local provider callback path against an owned native host. */
export async function runN6SignedIngress({ binary, directory, tenant = TENANT, actor = ACTOR } = {}) {
  for (const [name, value] of Object.entries({ binary, directory })) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) throw new TypeError(`${name} must be an explicit absolute path`);
  }
  await mkdir(directory, { mode: 0o700 });
  let provider;
  let native;
  let service;
  try {
    const secret = Buffer.alloc(32, 0x6e);
    const secretPath = path.join(directory, 'ingress.secret');
    await writeFile(secretPath, secret, { mode: 0o600, flag: 'wx' });
    provider = await startFakeProvider({ directory: path.join(directory, 'provider') });
    const pair = generateKeyPairSync('ed25519');
    const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: 'n6-ingress-example', audience: 'n6-ingress-example',
      public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
    const storePath = path.join(directory, 'effect-demo.redb');
    const configFor = target => resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'effect-demo', backend: { kind: 'redb', cluster_file: null }, target, operator_methods: METHODS,
    } }, runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5000, diagnosticBytes: 4096 } } });
    native = await openNative(configFor({ mode: 'create', path: storePath, tenant, actor }));
    const operator = openOperator(native, { scope: native.scope, methods: METHODS });
    const serviceConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10,
      effects: { endpoint: provider.endpoint, mode: 'disabled', ingress_secret_file: secretPath } };
    service = await operator.startService({ config: serviceConfig });
    const token = (await operator.issueIdentity({ identity, privateKeyPem, request: {
      tenant, actor, epoch: 0, ttl: 120, key_id: 'local',
    } })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    const account = randomUUID();
    const dispatch = randomUUID();
    const plan = await client.prepare({ model: native.scope.model, commands: [
      { op: 'create', id: account, contract: 101, fields: { balance: '12' } },
      { op: 'create', id: dispatch, contract: 205,
        fields: { account, units: '3', execute_at: null, not_after: null } },
    ], returning: [] });
    const committed = await client.execute(plan);
    const store = native.scope.store;
    const execution = committed.result.executions[0].execution_id;
    const outcome = { execution_id: execution, account: 'fake-account-1', action: 1,
      units: '3', phase: 'succeeded', receipt: randomUUID() };
    const event = randomUUID();
    const timestamp = String(Date.now());
    const body = Buffer.from(JSON.stringify({ execution_id: execution, outcome }), 'utf8');
    const accepted = await postFakeIngress({ endpoint: service.endpoint, secret, event, timestamp, body });
    if (accepted.status !== 200 || accepted.value.duplicate !== false) throw new Error('Native signed ingress did not accept the first event');

    await operator.stopService({ service: service.service });
    service = null;
    await native.close();
    native = null;
    native = await openNative(configFor({ mode: 'open', path: storePath, expect_store: store }));
    const restartedOperator = openOperator(native, { scope: native.scope, methods: METHODS });
    service = await restartedOperator.startService({ config: { ...serviceConfig, effects: { ...serviceConfig.effects, mode: 'reconcile' } } });
    const restartedToken = (await restartedOperator.issueIdentity({ identity, privateKeyPem, request: {
      tenant, actor, epoch: 0, ttl: 120, key_id: 'local',
    } })).token;
    const restartedClient = connect({ endpoint: service.endpoint, credential: restartedToken });
    const applied = await waitFor(async () => {
      const status = await restartedClient.call('effects.status', { model: native.scope.model, execution_id: execution });
      return status.application === 'applied' ? status : null;
    });
    if ((await restartedClient.call('records.get', { model: native.scope.model, id: account })).input.balance !== '9') {
      throw new Error('Signed ingress application did not update the account once');
    }
    return Object.freeze({ execution, event, accepted: accepted.value, phase: applied.phase,
      application: applied.application, balance: '9' });
  } finally {
    if (native) {
      try { if (service) await native.stopService({ service: service.service }); } catch {}
      await native.close().catch(() => {});
    }
    try { await provider?.close(); } catch {}
    try { await rm(directory, { recursive: true, force: true }); } catch {}
  }
}

async function waitFor(check) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for durable signed event application');
}
