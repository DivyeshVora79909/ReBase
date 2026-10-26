import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const expectedModels = ['calculation', 'effect-demo', 'equipment', 'invoicing', 'measurement', 'quantity'];
const methods = ['store.backup', 'service.start', 'service.stop', 'identity.issue'];

test('independently checks real complete snapshots for every model compiled by the frozen N2 host', { skip: !available && `missing ${binary}` }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n5-model-snapshots-'));
  const probe = await openNative(makeConfig(directory, 'equipment', 'probe'));
  let models;
  try {
    models = (await probe.describe()).engine.compiled_models;
  } finally {
    await probe.close();
  }
  assert.deepEqual([...models].sort(), [...expectedModels].sort());
  const evidence = [];
  try {
    for (const selector of models) evidence.push(await captureModel(directory, selector));
    assert.ok(evidence.some(item => item.model === 'equipment' && item.nodeCount > 0));
    assert.ok(evidence.some(item => item.model === 'invoicing' && item.nodeCount > 0));
    assert.ok(evidence.some(item => item.model === 'measurement' && item.nodeCount > 0));
    assert.ok(evidence.every(item => item.status === 'passed' && Number.isSafeInteger(item.nativeKvRows)));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

async function captureModel(directory, selector) {
  const tenant = randomUUID();
  const actor = randomUUID();
  const targetPath = path.join(directory, `${selector}.redb`);
  const backupPath = path.join(directory, `${selector}.backup.json`);
  const native = await openNative(makeConfig(directory, selector, selector, targetPath, tenant, actor));
  let service;
  try {
    const operator = openOperator(native, { scope: native.scope, methods });
    const pair = generateKeyPairSync('ed25519');
    const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: `n5-${selector}`, audience: 'n5-model-snapshots', public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
    const serviceConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10, effects: null };
    service = await operator.startService({ config: serviceConfig });
    const token = (await operator.issueIdentity({ identity,
      request: { tenant, actor, epoch: 0, ttl: 120, key_id: 'local' }, privateKeyPem })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    await native.catalog({ scope: 'developer' });
    const fixtures = await native.fixtureCatalog();
    assert.ok(fixtures.length > 0, `${selector} exposes a native fixture`);
    const fixture = await native.fixturePlan({ name: fixtures[0].name, namespace: randomUUID() });
    const receipt = await client.execute(await client.prepare({ model: fixture.model, commands: fixture.commands, returning: fixture.returning }));
    assert.equal(receipt.status, 'committed', `${selector} fixture commits`);
    await operator.snapshot({ destination: backupPath });
    const checked = checkBackupStructure(await readFile(backupPath));
    assert.equal(checked.status, 'passed', `${selector} backup passes independent structure check`);
    assert.ok(checked.nativeKvRows > checked.nodeCount);
    return { model: selector, ...checked, complete: true };
  } finally {
    if (service) await native.stopService({ service: service.service }).catch(() => {});
    await native.close();
  }
}

function makeConfig(directory, selector, label, targetPath = path.join(directory, `${label}.redb`), tenant = randomUUID(), actor = randomUUID()) {
  return resolveConfig({ overrides: {
    native: { binary: path.resolve(binary), environment: {}, configuration: {
      model: selector, backend: { kind: 'redb', cluster_file: null }, target: { mode: 'create', path: targetPath, tenant, actor }, operator_methods: methods,
    } },
    runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
  } });
}
