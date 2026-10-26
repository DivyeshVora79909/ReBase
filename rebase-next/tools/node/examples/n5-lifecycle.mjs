import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { startFakeProvider } from '../fake-provider.mjs';
import { checkBackupStructure } from '../storage-check.mjs';

const TENANT = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const METHODS = ['store.backup', 'service.start', 'service.stop', 'identity.issue'];

/**
 * Prepare an effect-demo intent and a complete pre-start image. The caller
 * chooses every path and owns the returned provider handle and directory.
 */
export async function prepareN5EffectRecovery({ binary, directory, tenant = TENANT, actor = ACTOR } = {}) {
  for (const [name, value] of Object.entries({ binary, directory })) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) throw new TypeError(`${name} must be an explicit absolute path`);
  }
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const provider = await startFakeProvider({ directory: path.join(directory, 'provider') });
  const storePath = path.join(directory, 'effect-demo.redb');
  const backupPath = path.join(directory, 'prestart.backup.json');
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const identity = { issuer: 'n5-example', audience: 'n5-example', public_keys: { local: publicKey }, max_token_seconds: 300 };
  let native;
  let service;
  try {
    const config = resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'effect-demo', backend: { kind: 'redb', cluster_file: null },
      target: { mode: 'create', path: storePath, tenant, actor }, operator_methods: METHODS,
    } } } });
    native = await openNative(config);
    const operator = openOperator(native, { scope: native.scope, methods: METHODS });
    const serviceConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4,
      request_timeout_seconds: 10,
      effects: { endpoint: provider.endpoint, mode: 'disabled' } };
    service = await operator.startService({ config: serviceConfig });
    const token = (await operator.issueIdentity({ identity, request: {
      tenant, actor, epoch: 0, ttl: 120, key_id: 'local',
    }, privateKeyPem })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
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
    const backup = await operator.snapshot({ destination: backupPath });
    const structure = checkBackupStructure(await readFile(backupPath));
    if (structure.status !== 'passed') throw new Error('Native pre-start backup failed independent structural checking');
    await operator.stopService({ service: service.service });
    service = null;
    await native.close();
    native = null;
    return Object.freeze({ store: backup.store, account, dispatch, execution, storePath, backupPath,
      structure, provider, async close() { await provider.close(); } });
  } catch (error) {
    if (native) {
      try { if (service) await native.stopService({ service: service.service }); } catch {}
      await native.close().catch(() => {});
    }
    await provider.close().catch(() => {});
    throw error;
  }
}
