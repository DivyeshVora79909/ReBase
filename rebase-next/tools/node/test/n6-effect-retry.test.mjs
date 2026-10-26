import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N6_BINARY ?? path.join(repositoryRoot, 'target/n6-retry-native-default/rebase-next');
const available = existsSync(binary);
const tenant = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const execution = '55555555-5555-4555-8555-555555555555';
const methods = ['effects.retry', 'service.start', 'service.stop', 'identity.issue'];

test('private effect retry is configured, scoped, and unavailable through public HTTP',
  { skip: !available && `native binary not found: ${binary}` }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n6-effect-retry-'));
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: 'n6-retry-test', audience: 'n6-retry-test',
      public_keys: { local: publicKey }, max_token_seconds: 300 };
    const configuration = resolveConfig({ overrides: {
      native: { binary, environment: {}, configuration: {
        model: 'calculation', backend: { kind: 'redb', cluster_file: null },
        target: { mode: 'create', path: path.join(directory, 'calculation.redb'), tenant, actor },
        operator_methods: methods,
      } },
      runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
    } });
    let native;
    let service;
    try {
      native = await openNative(configuration);
      const operator = openOperator(native, { scope: native.scope, methods });
      assert.equal(native.grants.includes('effects.retry'), true);

      const retry = { executionId: execution, ifRevision: '0' };
      await assert.rejects(operator.retryEffect(retry), error => error.code === 'unsupported_effect');
      await assert.rejects(native.retryEffect({ scope: { ...native.scope, store: '44444444-4444-4444-8444-444444444444' },
        execution_id: execution, if_revision: '1' }), error => error.code === 'wrong_target');

      service = await operator.startService({ config: { listen: '127.0.0.1:0', identity,
        max_inflight: 2, request_timeout_seconds: 5, effects: null } });
      const token = (await operator.issueIdentity({ identity, privateKeyPem,
        request: { tenant, actor, epoch: 0, ttl: 120, key_id: 'local' } })).token;
      const client = connect({ endpoint: service.endpoint, credential: token });
      await assert.rejects(operator.retryEffect(retry), error => error.code === 'service_running');
      await assert.rejects(client.call('effects.retry', { model: native.scope.model,
        execution_id: execution, if_revision: '0' }), error => error.code === 'method_not_found');

      await operator.stopService({ service: service.service });
      service = null;
      await assert.rejects(operator.retryEffect(retry), error => error.code === 'unsupported_effect');
    } finally {
      if (native) {
        try { if (service) await native.stopService({ service: service.service }); } catch {}
        await native.close().catch(() => {});
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
