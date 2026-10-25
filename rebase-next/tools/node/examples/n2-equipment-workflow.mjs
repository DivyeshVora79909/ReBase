import { generateKeyPairSync, randomUUID } from 'node:crypto';
import path from 'node:path';
import { connect, savePlan } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';

const OPERATOR_METHODS = Object.freeze([
  'store.check', 'store.inspect', 'service.start', 'service.stop',
  'identity.issue', 'store.backup',
]);

/** Run one caller-owned Equipment fixture through the N2 native service APIs. */
export async function runEquipmentWorkflow({ binary, storePath, planPath, backupPath, tenant = randomUUID(), actor = randomUUID() }) {
  for (const [name, value] of Object.entries({ binary, storePath, planPath, backupPath })) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) throw new TypeError(`${name} must be an explicit absolute path`);
  }
  const keyPair = generateKeyPairSync('ed25519');
  const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const identity = {
    issuer: 'local-equipment-example',
    audience: 'rebase-equipment-example',
    public_keys: { local: publicKeyPem },
    max_token_seconds: 300,
  };
  const config = resolveConfig({ overrides: {
    native: {
      binary,
      environment: {},
      configuration: {
        model: 'equipment',
        backend: { kind: 'redb', cluster_file: null },
        target: { mode: 'create', path: storePath, tenant, actor },
        operator_methods: [...OPERATOR_METHODS],
      },
    },
    service: {
      listen: '127.0.0.1:0',
      identity,
      max_inflight: 8,
      request_timeout_seconds: 20,
      effects: null,
    },
  } });

  const native = await openNative(config);
  const scope = native.scope;
  const operator = openOperator(native, { scope, methods: OPERATOR_METHODS });
  let service;
  try {
    service = await operator.startService({ config: config.service });
    const token = (await operator.issueIdentity({
      identity,
      request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem,
    })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector: 'equipment' });
    const poolId = randomUUID();
    const deliveryId = randomUUID();
    const draft = model.draftFixture([
      { contract: 'Pool', id: poolId, fields: { unit: 1 } },
      { contract: 'Delivery', id: deliveryId, fields: { pool: poolId, at: '0', quantity: '10' } },
    ], { returning: [poolId, deliveryId] });
    const plan = await client.prepare(draft);
    await savePlan(planPath, plan);

    let mutation;
    try {
      mutation = await client.execute(plan);
    } catch (error) {
      if (error.code !== 'outcome_unknown') throw error;
      const status = await client.status(plan);
      return { outcome: 'unknown', savedPlan: planPath, status, model: model.identity, scope };
    }

    const rendered = await model.render({ scope: 'store', target: scope });
    const backup = await operator.snapshot({ destination: backupPath });
    return { outcome: 'committed', mutation, model: model.identity, scope, html: rendered.html, backup };
  } finally {
    try {
      if (service) await operator.stopService({ service: service.service });
    } finally {
      await native.close();
    }
  }
}
