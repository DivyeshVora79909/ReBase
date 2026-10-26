import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { startFakeProvider } from '../fake-provider.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(repositoryRoot, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const tenant = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const methods = ['store.check', 'store.backup', 'store.restore', 'store.archive', 'store.reset',
  'service.start', 'service.stop', 'identity.issue'];

test('effect-demo restores through quarantine, reconciles accepted work once, then archives and resets safely',
  { skip: !available && `native binary not found: ${binary}` }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n5-lifecycle-'));
    const provider = await startFakeProvider({ directory: path.join(directory, 'provider') });
    const probes = path.join(directory, 'probes');
    await mkdir(probes);
    const source = path.join(directory, 'source.redb');
    const prestartBackup = path.join(directory, 'prestart.backup.json');
    const restoredPath = path.join(directory, 'restored.redb');
    const archivePath = path.join(directory, 'archive.backup.json');
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: 'n5-lifecycle', audience: 'n5-lifecycle', public_keys: { local: publicKey }, max_token_seconds: 300 };
    let native;
    let service;
    let client;

    try {
      native = await openNative(nativeConfig({ mode: 'create', path: source, tenant, actor }));
      let operator = openOperator(native, { scope: native.scope, methods });
      ({ client, service } = await startAuthenticated({ native, operator, identity, privateKeyPem,
        effects: { endpoint: provider.endpoint, mode: 'disabled', probe_directory: probes } }));

      const account = randomUUID();
      const dispatch = randomUUID();
      const plan = await client.prepare({
        model: native.scope.model,
        commands: [
          { op: 'create', id: account, contract: 101, fields: { balance: '12' } },
          { op: 'create', id: dispatch, contract: 205, fields: {
            account, units: '3', execute_at: null, not_after: null,
          } },
        ],
        returning: [],
      });
      const committed = await client.execute(plan);
      const execution = committed.result.executions[0].execution_id;
      const prestart = await operator.snapshot({ destination: prestartBackup });
      assert.equal(prestart.store, native.scope.store);
      assert.equal(checkBackupStructure(await readFile(prestartBackup)).status, 'passed');
      const beforeStart = await client.call('effects.status', { model: native.scope.model, execution_id: execution });
      assert.equal(beforeStart.phase, 'ready');
      assert.equal((await provider.counts(execution)).submissions, 0);

      await stopOwned(native, service);
      native = null;
      service = null;

      // Reopen the committed source store under a fresh backend process and
      // hold its first dispatch at the native pre-start probe.
      await writeFile(path.join(probes, 'before_start.hold'), 'held\n', { mode: 0o600 });
      native = await openNative(nativeConfig({ mode: 'open', path: source, expect_store: prestart.store }));
      operator = openOperator(native, { scope: native.scope, methods });
      ({ client, service } = await startAuthenticated({ native, operator, identity, privateKeyPem,
        effects: { endpoint: provider.endpoint, mode: 'delivery', probe_directory: probes } }));
      await provider.setMode(execution, 'pause_response');
      const responseHold = provider.holdResponse(execution);
      await rm(path.join(probes, 'before_start.hold'));
      await responseHold.waitUntilPaused({ timeoutMs: 10_000 });
      const accepted = await provider.execution(execution);
      assert.equal(accepted.accepted, true);
      assert.equal((await provider.counts(execution)).submissions, 1);

      // The provider has durably accepted, while the application process still
      // has no response or local provider fact. Stop the owned worker with its
      // request held through the native transport deadline, then restart it.
      await operator.stopService({ service: service.service });
      service = null;
      await native.close();
      native = null;
      await responseHold.release();

      native = await openNative(nativeConfig({ mode: 'open', path: source, expect_store: prestart.store }));
      operator = openOperator(native, { scope: native.scope, methods });
      ({ client, service } = await startAuthenticated({ native, operator, identity, privateKeyPem,
        effects: { endpoint: provider.endpoint, mode: 'disabled', probe_directory: probes } }));
      const restartedStatus = await client.call('effects.status', { model: native.scope.model, execution_id: execution });
      assert.equal(restartedStatus.phase, 'uncertain');
      assert.equal((await provider.counts(execution)).submissions, 1);
      await stopOwned(native, service);
      native = null;
      service = null;

      // Restore the pre-start image. Its fresh activation is quarantined, so
      // reconciliation may read provider truth but cannot submit another call.
      native = await openNative(nativeConfig({ mode: 'open', path: source, expect_store: prestart.store }));
      operator = openOperator(native, { scope: native.scope, methods });
      await assert.rejects(operator.restore({ backup: prestartBackup, expectBackupStore: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: path.join(directory, 'wrong.redb') } } }),
      error => error.code === 'wrong_target');
      assert.equal(existsSync(path.join(directory, 'wrong.redb')), false);
      const restored = await operator.restore({ backup: prestartBackup, expectBackupStore: prestart.store,
        destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: restoredPath } } });
      assert.equal(restored.status, 'restored');
      assert.equal(restored.integrity.effects.quarantined, true);
      await stopOwned(native, null);
      native = null;

      native = await openNative(nativeConfig({ mode: 'open', path: restoredPath, expect_store: prestart.store }));
      operator = openOperator(native, { scope: native.scope, methods });
      ({ client, service } = await startAuthenticated({ native, operator, identity, privateKeyPem,
        effects: { endpoint: provider.endpoint, mode: 'reconcile', probe_directory: probes } }));
      const outcome = await waitFor(async () => {
        const status = await client.call('effects.status', { model: native.scope.model, execution_id: execution });
        return status.application === 'applied' ? status : null;
      }, 'restored provider fact application');
      assert.equal(outcome.phase, 'succeeded');
      assert.equal((await client.call('records.get', { model: native.scope.model, id: account })).input.balance, '9');
      const counts = await provider.counts(execution);
      assert.equal(counts.submissions, 1);
      assert.equal(counts.accepted, 1);
      assert.ok(counts.observations >= 1);
      assert.equal((await operator.check()).effects.quarantined, true);

      await stopOwned(native, service);
      native = null;
      service = null;
      native = await openNative(nativeConfig({ mode: 'open', path: restoredPath, expect_store: prestart.store }));
      operator = openOperator(native, { scope: native.scope, methods });
      const archived = await operator.archive({ destination: archivePath });
      assert.equal(archived.status, 'archived');
      assert.equal(checkBackupStructure(await readFile(archivePath)).status, 'passed');
      await assert.rejects(operator.reset({ expectStore: randomUUID() }), error => error.code === 'wrong_target');
      const reset = await operator.reset({ expectStore: prestart.store });
      assert.equal(reset.status, 'reset');
      assert.notEqual(reset.store, prestart.store);
    } finally {
      await stopOwned(native, service);
      await provider.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

function nativeConfig(target) {
  const operatorMethods = target?.mode === 'recover' ? [...methods, 'store.recover'] : methods;
  return resolveConfig({ overrides: {
    native: { binary, environment: {}, configuration: {
      model: 'effect-demo', backend: { kind: 'redb', cluster_file: null },
      target, operator_methods: operatorMethods,
    } },
    runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
  } });
}

async function startAuthenticated({ native, operator, identity, privateKeyPem, effects }) {
  const serviceConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10, effects };
  const started = await operator.startService({ config: serviceConfig });
  const token = (await operator.issueIdentity({ identity, request: {
    tenant, actor, epoch: 0, ttl: 120, key_id: 'local',
  }, privateKeyPem })).token;
  return { client: connect({ endpoint: started.endpoint, credential: token }), service: started };
}

async function stopOwned(native, service) {
  if (!native) return;
  try { if (service) await native.stopService({ service: service.service }); } catch {}
  await native.close().catch(() => {});
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
