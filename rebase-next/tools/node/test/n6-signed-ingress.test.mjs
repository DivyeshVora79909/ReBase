import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { startFakeProvider } from '../fake-provider.mjs';
import { postFakeIngress, runN6SignedIngress } from '../examples/n6-signed-ingress.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N6_BINARY ?? process.env.REBASE_NODE_N5_BINARY
  ?? path.join(repositoryRoot, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const tenant = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const methods = ['service.start', 'service.stop', 'identity.issue'];

test('example startup failure releases owned resources and preserves an existing caller directory',
  { concurrency: false }, async () => {
    const parent = await mkdtemp(path.join(os.tmpdir(), 'rebase-n6-ingress-cleanup-'));
    const owned = path.join(parent, 'owned');
    const existing = path.join(parent, 'existing');
    const original = crypto.generateKeyPairSync;
    crypto.generateKeyPairSync = () => { throw new Error('injected key setup failure'); };
    syncBuiltinESMExports();
    try {
      await assert.rejects(runN6SignedIngress({ binary: path.join(parent, 'unused-binary'), directory: owned }),
        /injected key setup failure/);
      assert.equal(existsSync(owned), false, 'failed startup leaves no owned directory or listening provider');
    } finally {
      crypto.generateKeyPairSync = original;
      syncBuiltinESMExports();
    }
    try {
      await mkdir(existing, { mode: 0o700 });
      await writeFile(path.join(existing, 'sentinel.txt'), 'caller-owned\n', { flag: 'wx' });
      await assert.rejects(runN6SignedIngress({ binary: path.join(parent, 'unused-binary'), directory: existing }),
        error => error.code === 'EEXIST');
      assert.deepEqual(await readdir(existing), ['sentinel.txt']);
      assert.equal(await readFile(path.join(existing, 'sentinel.txt'), 'utf8'), 'caller-owned\n');
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

test('Node sends bounded signed raw events; native ingress rejects invalid data and persists accepted identity',
  { skip: !available && `native binary not found: ${binary}` }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n6-signed-ingress-'));
    const storePath = path.join(directory, 'effect-demo.redb');
    const secretPath = path.join(directory, 'ingress.secret');
    const secret = Buffer.alloc(32, 0x63);
    await writeFile(secretPath, secret, { mode: 0o600, flag: 'wx' });
    await chmod(secretPath, 0o600);
    const provider = await startFakeProvider({ directory: path.join(directory, 'provider') });
    const keys = generateKeyPairSync('ed25519');
    const publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: 'n6-ingress-test', audience: 'n6-ingress-test',
      public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
    const nativeConfiguration = target => resolveConfig({ overrides: { native: { binary,
      environment: {}, configuration: { model: 'effect-demo', backend: { kind: 'redb', cluster_file: null },
        target, operator_methods: methods },
    }, runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5000, diagnosticBytes: 4096 } } });
    let native;
    let service;
    let proxy;
    let proxyAddress;
    try {
      native = await openNative(nativeConfiguration({ mode: 'create', path: storePath, tenant, actor }));
      const operator = openOperator(native, { scope: native.scope, methods });
      const start = async mode => {
        service = await operator.startService({ config: { listen: '127.0.0.1:0', identity,
          max_inflight: 4, request_timeout_seconds: 10,
          effects: { endpoint: provider.endpoint, mode, ingress_secret_file: secretPath } } });
        const token = (await operator.issueIdentity({ identity, privateKeyPem,
          request: { tenant, actor, epoch: 0, ttl: 120, key_id: 'local' } })).token;
        return connect({ endpoint: service.endpoint, credential: token });
      };
      let client = await start('disabled');
      const account = randomUUID();
      const dispatch = randomUUID();
      const plan = await client.prepare({ model: native.scope.model, commands: [
        { op: 'create', id: account, contract: 101, fields: { balance: '12' } },
        { op: 'create', id: dispatch, contract: 205, fields: {
          account, units: '3', execute_at: null, not_after: null,
        } },
      ], returning: [] });
      const committed = await client.execute(plan);
      const execution = committed.result.executions[0].execution_id;
      const store = native.scope.store;
      const outcome = { execution_id: execution, account: 'fake-account-1', action: 1,
        units: '3', phase: 'succeeded', receipt: randomUUID() };
      const event = randomUUID();
      const timestamp = String(Date.now());
      const body = Buffer.from(JSON.stringify({ execution_id: execution, outcome }), 'utf8');
      const signed = overrides => ({ endpoint: service.endpoint, secret, event, timestamp, body, ...overrides });

      for (const endpoint of ['http://127.0.0.1:1/rpc?unexpected=1', 'http://127.0.0.1:1/rpc#fragment',
        'http://127.0.0.1:1/other']) {
        await assert.rejects(postFakeIngress(signed({ endpoint })), /endpoint/);
      }

      assert.equal((await postFakeIngress(signed({ secret: Buffer.alloc(32, 0x64) }))).status, 401);

      const staleTimestamp = String(Date.now() - 300_001);
      assert.equal((await postFakeIngress(signed({ timestamp: staleTimestamp }))).status, 401);
      assert.equal((await postFakeIngress(signed({ account: 'other-account' }))).status, 401);

      const unknown = randomUUID();
      const unknownBody = Buffer.from(JSON.stringify({ execution_id: unknown,
        outcome: { ...outcome, execution_id: unknown } }), 'utf8');
      assert.equal((await postFakeIngress(signed({ event: randomUUID(), body: unknownBody }))).status, 404);

      const invalidOutcome = Buffer.from(JSON.stringify({ execution_id: execution,
        outcome: { ...outcome, units: '4' } }), 'utf8');
      assert.equal((await postFakeIngress(signed({ event: randomUUID(), body: invalidOutcome }))).status, 400);

      const duplicateKeyBody = Buffer.from(`{"execution_id":${JSON.stringify(execution)},"execution_id":${JSON.stringify(execution)},"outcome":${JSON.stringify(outcome)}}`, 'utf8');
      assert.equal((await postFakeIngress(signed({ event: randomUUID(), body: duplicateKeyBody }))).status, 400);

      assert.equal((await postFakeIngress(signed({ event: randomUUID(), body: Buffer.alloc(8193, 0x20) }))).status, 413);

      // This owned proxy forwards the complete request and discards only the
      // ACK. The caller observes an unknown result and performs one explicit retry.
      proxy = createAckDroppingProxy(service.endpoint);
      await listen(proxy);
      proxyAddress = `http://127.0.0.1:${proxy.address().port}`;
      await assert.rejects(postFakeIngress({ ...signed({}), endpoint: proxyAddress }));

      const accepted = await postFakeIngress(signed({}));
      // A duplicate ACK proves the proxy's first request reached durable intake
      // even though the caller received no response.
      assert.deepEqual(accepted, { status: 200, value: { status: 'accepted', duplicate: true } });
      const duplicate = await postFakeIngress(signed({}));
      assert.deepEqual(duplicate, { status: 200, value: { status: 'accepted', duplicate: true } });
      assert.equal((await postFakeIngress(signed({ body: Buffer.concat([body, Buffer.from(' ')]) }))).status, 409);

      await closeServer(proxy);
      proxy = null;
      await operator.stopService({ service: service.service });
      service = null;
      await native.close();
      native = null;

      native = await openNative(nativeConfiguration({ mode: 'open', path: storePath, expect_store: store }));
      const restartedOperator = openOperator(native, { scope: native.scope, methods });
      const restartedConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10,
        effects: { endpoint: provider.endpoint, mode: 'reconcile', ingress_secret_file: secretPath } };
      service = await restartedOperator.startService({ config: restartedConfig });
      const restartedToken = (await restartedOperator.issueIdentity({ identity, privateKeyPem,
        request: { tenant, actor, epoch: 0, ttl: 120, key_id: 'local' } })).token;
      client = connect({ endpoint: service.endpoint, credential: restartedToken });
      assert.deepEqual(await postFakeIngress(signed({ endpoint: service.endpoint })),
        { status: 200, value: { status: 'accepted', duplicate: true } });
      const finalStatus = await waitFor(async () => {
        const current = await client.call('effects.status', { model: native.scope.model, execution_id: execution });
        return current.application === 'applied' ? current : null;
      }, 'signed inbox consumption and application');
      assert.equal(finalStatus.phase, 'succeeded');
      assert.equal((await client.call('records.get', { model: native.scope.model, id: account })).input.balance, '9');
      assert.equal((await provider.counts(execution)).submissions, 0);
    } finally {
      if (proxy) await closeServer(proxy);
      if (native) {
        try { if (service) await native.stopService({ service: service.service }); } catch {}
        await native.close().catch(() => {});
      }
      await provider.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

function createAckDroppingProxy(targetEndpoint) {
  const target = new URL('/effects/fake', targetEndpoint);
  return http.createServer((incoming, outgoing) => {
    const upstream = http.request(target, { method: incoming.method, headers: incoming.headers, agent: false }, response => {
      response.resume();
      response.on('end', () => outgoing.destroy());
    });
    upstream.on('error', () => outgoing.destroy());
    incoming.pipe(upstream);
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
}

function closeServer(server) {
  return new Promise(resolve => server.close(() => resolve()));
}

async function waitFor(check, label) {
  const deadline = Date.now() + 15_000;
  let lastError;
  while (Date.now() < deadline) {
    try { const result = await check(); if (result) return result; }
    catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`Timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ''}`);
}
