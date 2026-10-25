import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { connect, savePlan } from '../client.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N2_BINARY ?? path.join(root, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const tenant = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const grants = Object.freeze([
  'store.check', 'store.inspect', 'service.start', 'service.stop', 'identity.issue',
  'store.backup', 'store.restore', 'store.archive', 'store.reset',
]);

function config(target, operatorMethods = grants, service) {
  const overrides = {
    native: {
      binary,
      environment: {},
      configuration: {
        model: 'equipment',
        backend: { kind: 'redb', cluster_file: null },
        target,
        operator_methods: [...operatorMethods],
      },
    },
    runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
  };
  if (service !== undefined) overrides.service = service;
  return resolveConfig({ overrides });
}

function makeServiceConfig(publicKeyPem, issuer = 'local-n2') {
  return {
    listen: '127.0.0.1:0',
    identity: {
      issuer,
      audience: 'rebase-n2-workflow',
      public_keys: { local: publicKeyPem },
      max_token_seconds: 300,
    },
    max_inflight: 8,
    request_timeout_seconds: 10,
    effects: null,
  };
}

test('real N2 model, scoped operator, authenticated service and saved mutation workflow', { skip: !available && `native binary not found: ${binary}` }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n2-workflow-'));
  const storePath = path.join(directory, 'equipment.redb');
  const backupPath = path.join(directory, 'before-archive.backup.json');
  const archivePath = path.join(directory, 'archive.backup.json');
  const restorePath = path.join(directory, 'restored.redb');
  const badRestorePath = path.join(directory, 'wrong-backup.redb');
  const wrongScopeBackupPath = path.join(directory, 'wrong-scope.backup.json');
  const keyPair = generateKeyPairSync('ed25519');
  const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const identity = {
    issuer: 'local-n2',
    audience: 'rebase-n2-workflow',
    public_keys: { local: publicKeyPem },
    max_token_seconds: 300,
  };
  const nativeConfig = makeServiceConfig(publicKeyPem);
  const primaryTarget = { mode: 'create', path: storePath, tenant, actor };
  let native;
  let nativeOther;
  let restoredHost;
  let stage = 'open native';
  try {
    native = await openNative(config(primaryTarget, grants, nativeConfig));
    const scope = native.scope;
    const operator = openOperator(native, { scope, methods: grants });
    const description = await native.describe();
    assert.equal(description.selection.selector, 'equipment');
    assert.equal(description.selection.model, scope.model);
    assert.equal(description.ownership.store, scope.store);

    stage = 'model catalog and validation';
    const developerCatalog = await native.catalog({ scope: 'developer' });
    const model = prepareModel(developerCatalog, { native, selector: 'equipment' });
    assert.equal(model.identity, scope.model);
    assert.equal((await model.explain('Pool')).model, scope.model);
    assert.equal(model.validate('Pool', { unit: 1 }).valid, true);
    assert.equal((await model.validateNative('Pool', { unit: 1 })).status, 'valid');
    assert.match((await model.render({ scope: 'model' })).html, /^<!doctype html>/i);
    assert.deepEqual(await model.fixtureCatalog(), [{ name: 'equipment', description: '10 units, two clipped interval reservations' }]);
    assert.equal((await model.fixturePlan({ name: 'equipment', namespace: randomUUID() })).model, scope.model);

    stage = 'wrong operator scope';
    await assert.rejects(native.backup({
      scope: { model: scope.model, store: randomUUID() },
      destination: wrongScopeBackupPath,
    }), error => error.code === 'wrong_target');
    await assert.rejects(stat(wrongScopeBackupPath), error => error.code === 'ENOENT');

    stage = 'service start and credentials';
    const live = await operator.startService({ config: nativeConfig });
    assert.equal(live.scope.model, scope.model);
    assert.equal(live.scope.store, scope.store);
    assert.match(live.endpoint, /^http:\/\/127\.0\.0\.1:\d+\/rpc$/);
    const ownerCredential = (await operator.issueIdentity({
      identity,
      request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem,
    })).token;
    const client = connect({ endpoint: live.endpoint, credential: ownerCredential });
    const session = await client.call('session.describe');
    assert.equal(session.model, scope.model);
    assert.equal(session.store, scope.store);

    await assert.rejects(client.call('store.inspect', { scope }), error => error.code === 'method_not_found');
    await assert.rejects(client.call('model.catalog', { scope: 'developer' }), error => error.code === 'method_not_found');

    const lockBefore = createHash('sha256').update(await readFile(storePath)).digest('hex');
    await assert.rejects(openNative(config({ mode: 'open', path: storePath, expect_store: scope.store }, ['store.check'])), error => error.code === 'store_busy');
    assert.equal(createHash('sha256').update(await readFile(storePath)).digest('hex'), lockBefore);

    stage = 'saved atomic fixture mutation';
    const poolId = randomUUID();
    const deliveryId = randomUUID();
    const fixtureDraft = model.draftFixture([
      { contract: 'Pool', id: poolId, fields: { unit: 1 } },
      { contract: 'Delivery', id: deliveryId, fields: { pool: poolId, at: '0', quantity: '10' } },
    ], { returning: [poolId, deliveryId] });
    const plan = await client.prepare(fixtureDraft);
    const planPath = path.join(directory, 'equipment-intent.json');
    await savePlan(planPath, plan);
    const first = await client.execute(plan);
    const replay = await client.execute(plan);
    assert.equal(first.status, 'committed');
    assert.equal(replay.status, 'committed');
    assert.equal(replay.replayed, true);
    assert.equal((await client.status(plan)).status, 'committed');
    assert.deepEqual((await client.call('records.get', { model: scope.model, id: poolId })).input, { unit: 1 });
    assert.deepEqual((await client.call('records.get', { model: scope.model, id: deliveryId })).input, { pool: poolId, at: '0', quantity: '10' });

    stage = 'atomic rejection';
    const missingPool = randomUUID();
    const orphanPool = randomUUID();
    const orphanDelivery = randomUUID();
    const rejectedPlan = await client.prepare({
      model: scope.model,
      commands: [
        { op: 'create', id: orphanPool, contract: 101, fields: { unit: 1 } },
        { op: 'create', id: orphanDelivery, contract: 205, fields: { pool: missingPool, at: '1', quantity: '2' } },
      ],
      returning: [orphanPool],
    });
    await savePlan(path.join(directory, 'atomic-rejection.json'), rejectedPlan);
    await assert.rejects(client.execute(rejectedPlan), error => error.code === 'unavailable_reference' || error.code === 'not_found');
    assert.equal(await client.call('records.get', { model: scope.model, id: orphanPool }), null);

    stage = 'CAS winner and stale mutation';
    const currentDelivery = await client.call('records.get', { model: scope.model, id: deliveryId });
    const staleVersion = currentDelivery.version;
    const stalePlan = await client.prepare({
      model: scope.model,
      commands: [{ op: 'update', id: deliveryId, if_version: staleVersion, set: { quantity: '12' }, unset: [] }],
      returning: [deliveryId],
    });
    await savePlan(path.join(directory, 'stale-version.json'), stalePlan);
    const winnerPlan = await client.prepare({
      model: scope.model,
      commands: [{ op: 'update', id: deliveryId, if_version: staleVersion, set: { quantity: '11' }, unset: [] }],
      returning: [deliveryId],
    });
    await savePlan(path.join(directory, 'cas-winner.json'), winnerPlan);
    await client.execute(winnerPlan);
    await assert.rejects(client.execute(stalePlan), error => error.code === 'stale_version');
    assert.deepEqual((await client.call('records.get', { model: scope.model, id: deliveryId })).input, { pool: poolId, at: '0', quantity: '11' });

    stage = 'live inspect and backup';
    const renderedStore = await model.render({ scope: 'store', target: scope });
    assert.equal(renderedStore.store, scope.store);
    assert.match(renderedStore.html, new RegExp(poolId));
    const inspected = await operator.inspect();
    assert.ok(inspected.records.some(row => row.id === poolId));
    assert.ok(await operator.check());
    const backup = await operator.snapshot({ destination: backupPath });
    assert.equal(backup.store, scope.store);
    assert.equal(typeof backup.sha256, 'string');

    stage = 'access DAG';
    const access = await client.call('access.describe', { model: scope.model });
    const group = randomUUID();
    const reader = randomUUID();
    const deniedActor = randomUUID();
    access.graph.principals.push({
      id: group, kind: 'group', parents: [tenant], active: true, credential_epoch: 0,
      grants: { admin: false, contracts: { '101': ['create', 'read'] } },
    });
    access.graph.principals.push({
      id: reader, kind: 'user', parents: [group], active: true, credential_epoch: 0,
      grants: { admin: false, contracts: {} },
    });
    access.graph.principals.push({
      id: deniedActor, kind: 'user', parents: [tenant], active: true, credential_epoch: 0,
      grants: { admin: false, contracts: {} },
    });
    const replaced = await client.call('access.replace', { model: scope.model, if_revision: access.revision, graph: access.graph });
    assert.equal(replaced.changed, true);
    await assert.rejects(client.call('access.replace', { model: scope.model, if_revision: access.revision, graph: access.graph }), error => error.code === 'stale_version');

    const groupToken = (await operator.issueIdentity({
      identity,
      request: { tenant, actor: group, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem,
    })).token;
    const readerToken = (await operator.issueIdentity({
      identity,
      request: { tenant, actor: reader, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem,
    })).token;
    const deniedToken = (await operator.issueIdentity({
      identity,
      request: { tenant, actor: deniedActor, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem,
    })).token;
    const groupClient = connect({ endpoint: live.endpoint, credential: groupToken });
    const readerClient = connect({ endpoint: live.endpoint, credential: readerToken });
    const deniedClient = connect({ endpoint: live.endpoint, credential: deniedToken });
    const groupPoolId = randomUUID();
    const groupPlan = await groupClient.prepare(model.draftFixture([
      { contract: 'Pool', id: groupPoolId, fields: { unit: 4 } },
    ], { returning: [groupPoolId] }));
    await savePlan(path.join(directory, 'group-pool-intent.json'), groupPlan);
    await groupClient.execute(groupPlan);
    assert.deepEqual((await readerClient.call('records.get', { model: scope.model, id: groupPoolId })).input, { unit: 4 });
    const deniedSession = await deniedClient.call('session.describe');
    await assert.rejects(deniedClient.call('records.mutate', {
      model: scope.model,
      context: deniedSession.operation_context,
      operation_id: randomUUID(),
      commands: [{ op: 'create', id: randomUUID(), contract: 101, fields: { unit: 1 } }],
      returning: [],
    }), error => error.code === 'forbidden');

    stage = 'restore';
    await operator.stopService({ service: live.service });
    const restored = await operator.restore({
      backup: backupPath,
      expectBackupStore: scope.store,
      destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: restorePath } },
    });
    assert.equal(restored.status, 'restored');
    const restoredBytes = await readFile(restorePath);
    await assert.rejects(operator.restore({
      backup: backupPath,
      expectBackupStore: scope.store,
      destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: restorePath } },
    }), error => error.code === 'invalid_destination');
    assert.deepEqual(await readFile(restorePath), restoredBytes);
    await assert.rejects(operator.restore({
      backup: backupPath,
      expectBackupStore: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: badRestorePath } },
    }), error => error.code === 'wrong_target');
    await assert.rejects(stat(badRestorePath), error => error.code === 'ENOENT');

    restoredHost = await openNative(config({ mode: 'open', path: restorePath, expect_store: scope.store }, ['store.check', 'store.inspect']));
    assert.ok(await restoredHost.check());
    assert.ok((await restoredHost.inspect()).records.some(row => row.id === poolId));

    stage = 'archive, old context, reset';
    const archived = await operator.archive({ destination: archivePath });
    assert.equal(archived.status, 'archived');
    const afterArchiveService = await operator.startService({ config: { ...nativeConfig, listen: live.address } });
    assert.equal(afterArchiveService.endpoint, live.endpoint);
    await assert.rejects(client.status(plan), error => error.code === 'operation_expired');
    await operator.stopService({ service: afterArchiveService.service });
    const reset = await operator.reset({ expectStore: scope.store });
    assert.equal(reset.status, 'reset');
    assert.notEqual(reset.store, scope.store);
    await assert.rejects(native.check(), error => error.code === 'wrong_target');

    stage = 'wrong endpoint and close join';
    const otherPath = path.join(directory, 'other.redb');
    nativeOther = await openNative(config({ mode: 'create', path: otherPath, tenant, actor }, grants, nativeConfig));
    const otherOperator = openOperator(nativeOther, { scope: nativeOther.scope, methods: ['store.check', 'store.inspect', 'service.start', 'service.stop', 'identity.issue'] });
    const otherService = await otherOperator.startService({ config: nativeConfig });
    const otherToken = (await otherOperator.issueIdentity({
      identity,
      request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' },
      privateKeyPem,
    })).token;
    const otherClient = connect({ endpoint: otherService.endpoint, credential: otherToken });
    await assert.rejects(otherClient.execute(plan), error => error.code === 'target_mismatch');
    const mismatchedEndpointPlan = { ...plan, target: { ...plan.target, url: otherService.endpoint } };
    await assert.rejects(otherClient.execute(mismatchedEndpointPlan), error => error.code === 'target_mismatch');
    assert.equal((await otherOperator.inspect()).records.length, 0);
    const healthUrl = otherService.endpoint.replace(/\/rpc$/, '/health');
    await nativeOther.close();
    nativeOther = null;
    await assert.rejects(fetch(healthUrl));
  } catch (error) {
    error.message = `${stage}: ${error.message}`;
    throw error;
  } finally {
    if (restoredHost) await restoredHost.close().catch(() => {});
    if (nativeOther) await nativeOther.close().catch(() => {});
    if (native) await native.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
  await assert.rejects(stat(directory), error => error.code === 'ENOENT');
});
