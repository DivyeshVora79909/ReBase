import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { connect } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';

const TENANT = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const METHODS = ['service.start', 'service.stop', 'identity.issue', 'store.backup', 'store.check'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Run the native IssueShare fixture and one fresh-parent recomputation. */
export async function runIssueShareWorkflow({ binary, directory, namespace, tenant = TENANT, actor = ACTOR } = {}) {
  for (const [name, value] of Object.entries({ binary, directory })) {
    if (typeof value !== 'string' || !path.isAbsolute(value)) throw new TypeError(`${name} must be an explicit absolute path`);
  }
  if (typeof namespace !== 'string' || !UUID.test(namespace) || namespace === '00000000-0000-0000-0000-000000000000') {
    throw new TypeError('namespace must be an explicit canonical nonnil UUID');
  }
  await mkdir(directory, { mode: 0o700 });
  let native;
  let service;
  try {
    const pair = generateKeyPairSync('ed25519');
    const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: 'n6-issue-share-example', audience: 'n6-issue-share-example',
      public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
    const storePath = path.join(directory, 'invoicing.redb');
    const config = resolveConfig({ overrides: {
      native: { binary, environment: {}, configuration: {
        model: 'invoicing', backend: { kind: 'redb', cluster_file: null },
        target: { mode: 'create', path: storePath, tenant, actor }, operator_methods: METHODS,
      } },
      runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
    } });
    native = await openNative(config);
    const scope = native.scope;
    const operator = openOperator(native, { scope, methods: METHODS });
    const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector: 'invoicing' });
    const availableFixtures = await model.fixtureCatalog();
    if (!availableFixtures.some(fixture => fixture.name === 'issue-share')) throw new Error('Native catalog has no issue-share fixture');
    const fixture = await model.fixturePlan({ name: 'issue-share', namespace });
    if (fixture.model !== scope.model) throw new Error('Native fixture belongs to a different invoicing model');

    service = await operator.startService({ config: { listen: '127.0.0.1:0', identity,
      max_inflight: 8, request_timeout_seconds: 15, effects: null } });
    const credential = (await operator.issueIdentity({ identity,
      request: { tenant, actor, epoch: 0, ttl: 180, key_id: 'local' }, privateKeyPem })).token;
    const client = connect({ endpoint: service.endpoint, credential });
    const plan = await client.prepare(fixture);
    const committed = await client.execute(plan);
    const ids = fixture.fixture.ids;
    const issueId = ids.Issue;
    const shareId = ids.Share;
    const issue = await client.call('records.get', { model: scope.model, id: issueId });
    const share = await client.call('records.get', { model: scope.model, id: shareId });
    if (issue.derived.amount_minor !== '15002' || share.derived.basis_minor !== '15002' || share.derived.amount_minor !== '5001') {
      throw new Error('Native IssueShare fixture differs from its exact literal values');
    }

    const edited = await client.call('records.get', { model: scope.model, id: issueId });
    const update = await client.prepare({ model: scope.model, commands: [{ op: 'update', id: issueId,
      if_version: edited.version, set: { quantity: { numerator: '2', denominator: '1' } }, unset: [] }], returning: [shareId] });
    await client.execute(update);
    const freshIssue = await client.call('records.get', { model: scope.model, id: issueId });
    const freshShare = await client.call('records.get', { model: scope.model, id: shareId });
    if (freshIssue.derived.amount_minor !== '20002' || freshShare.derived.basis_minor !== '20002' || freshShare.derived.amount_minor !== '6667') {
      throw new Error('IssueShare did not follow the current ready Issue publication');
    }
    return Object.freeze({ model: scope.model, store: scope.store, namespace,
      fixture: 'issue-share', initial: { issueMinor: '15002', basisMinor: '15002', amountMinor: '5001' },
      afterParentEdit: { issueMinor: '20002', basisMinor: '20002', amountMinor: '6667' },
      committed: committed.status === 'committed', replayed: (await client.execute(plan)).replayed });
  } finally {
    if (native) {
      try { if (service) await native.stopService({ service: service.service }); } catch {}
      await native.close().catch(() => {});
    }
    try { await rm(directory, { recursive: true, force: true }); } catch {}
  }
}
