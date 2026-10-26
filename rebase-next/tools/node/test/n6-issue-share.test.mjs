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
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { runIssueShareWorkflow } from '../examples/n6-issue-share.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N6_BINARY ?? process.env.REBASE_NODE_N5_BINARY
  ?? path.join(repositoryRoot, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const namespace = '26b04280-0b09-4f3c-8bb7-a882f8242026';
const tenant = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const methods = ['service.start', 'service.stop', 'identity.issue', 'store.backup', 'store.check'];

test('IssueShare example refuses an existing caller directory without touching it', async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'rebase-n6-issue-share-dir-'));
  const existing = path.join(parent, 'caller-directory');
  try {
    await mkdir(existing, { mode: 0o700 });
    const sentinel = path.join(existing, 'keep.txt');
    await writeFile(sentinel, 'caller-owned\n', { flag: 'wx' });
    await assert.rejects(runIssueShareWorkflow({ binary, directory: existing, namespace }), error => error.code === 'EEXIST');
    assert.equal(await readFile(sentinel, 'utf8'), 'caller-owned\n');
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test('Node composes authoritative IssueShare math, schema validation and client mutations',
  { skip: !available && `native binary not found: ${binary}` }, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n6-issue-share-'));
    const storePath = path.join(directory, 'invoicing.redb');
    const keyPair = generateKeyPairSync('ed25519');
    const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const identity = { issuer: 'n6-issue-share-test', audience: 'n6-issue-share-test',
      public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
    const config = resolveConfig({ overrides: { native: { binary, environment: {}, configuration: {
      model: 'invoicing', backend: { kind: 'redb', cluster_file: null },
      target: { mode: 'create', path: storePath, tenant, actor }, operator_methods: methods,
    } }, runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5000, diagnosticBytes: 4096 } } });
    let native;
    let service;
    try {
      native = await openNative(config);
      const scope = native.scope;
      const operator = openOperator(native, { scope, methods });
      const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector: 'invoicing' });
      const fixtures = await model.fixtureCatalog();
      assert.ok(fixtures.some(entry => entry.name === 'issue-share'));
      const fixture = await model.fixturePlan({ name: 'issue-share', namespace });
      assert.equal(fixture.model, scope.model);
      assert.deepEqual(fixture.fixture.expected, { issue_minor: '15002', basis_minor: '15002', amount_minor: '5001' });

      service = await operator.startService({ config: { listen: '127.0.0.1:0', identity,
        max_inflight: 8, request_timeout_seconds: 15, effects: null } });
      const token = (await operator.issueIdentity({ identity,
        request: { tenant, actor, epoch: 0, ttl: 180, key_id: 'local' }, privateKeyPem })).token;
      const client = connect({ endpoint: service.endpoint, credential: token });

      const issueCode = model.contract('Issue').code;
      const shareCode = model.contract('IssueShare').code;
      const shareFields = fixture.commands.find(command => command.contract === shareCode).fields;
      assert.deepEqual(model.validate('IssueShare', shareFields), { valid: true, errors: [] });
      assert.equal((await model.validateNative('IssueShare', shareFields)).status, 'valid');
      for (const ratio of [{ numerator: '2', denominator: '6' }, { numerator: '4', denominator: '3' }]) {
        const fields = { ...shareFields, ratio };
        assert.equal(model.validate('IssueShare', fields).valid, true, 'schema accepts rational shape and bounds only');
        await assert.rejects(model.validateNative('IssueShare', fields));
      }

      const fixturePlan = await client.prepare(fixture);
      const committed = await client.execute(fixturePlan);
      assert.equal(committed.status, 'committed');
      const immediateReplay = await client.execute(fixturePlan);
      assert.equal(immediateReplay.replayed, true);
      assert.deepEqual(immediateReplay.result, committed.result);
      const invoiceId = fixture.fixture.ids.Invoice;
      const issueId = fixture.fixture.ids.Issue;
      const shareId = fixture.fixture.ids.Share;
      const read = id => client.call('records.get', { model: scope.model, id });
      const initialIssue = await read(issueId);
      const initialShare = await read(shareId);
      assert.deepEqual(initialIssue.derived, { amount_minor: '15002' });
      assert.deepEqual(initialShare.derived, { basis_minor: '15002', amount_minor: '5001' });

      const mutate = async commands => {
        const plan = await client.prepare({ model: scope.model, commands, returning: [] });
        return { plan, result: await client.execute(plan) };
      };
      const update = async (id, set) => {
        const record = await read(id);
        return { op: 'update', id, if_version: record.version, set, unset: [] };
      };
      const tables = async label => {
        const destination = path.join(directory, `${label}.backup.json`);
        await operator.snapshot({ destination });
        return JSON.parse(await readFile(destination, 'utf8')).payload.tables;
      };

      const beforeExact = await tables('before-exact-rejection');
      const exact = await client.prepare({ model: scope.model,
        commands: [await update(shareId, { rounding: 'exact' })], returning: [] });
      await assert.rejects(client.execute(exact), error => error.code === 'inexact');
      assert.equal((await client.status(exact)).status, 'not_observed');
      assert.deepEqual(await tables('after-exact-rejection'), beforeExact, 'inexact rejection preserves every backup table');
      assert.deepEqual((await read(shareId)).derived, { basis_minor: '15002', amount_minor: '5001' });

      for (const [rounding, expected] of [['floor', '5000'], ['ceiling', '5001']]) {
        await mutate([await update(shareId, { rounding })]);
        assert.equal((await read(shareId)).derived.amount_minor, expected);
      }
      await mutate([await update(shareId, { ratio: { numerator: '0', denominator: '1' } })]);
      assert.equal((await read(shareId)).derived.amount_minor, '0');
      await mutate([await update(shareId, { ratio: { numerator: '1', denominator: '3' }, rounding: 'half_even' })]);

      const staleShare = await read(shareId);
      const stale = await client.prepare({ model: scope.model, commands: [{ op: 'update', id: shareId,
        if_version: staleShare.version, set: { ratio: { numerator: '1', denominator: '2' } }, unset: [] }], returning: [] });
      await mutate([await update(shareId, { rounding: 'floor' })]);
      const beforeStale = await tables('before-stale-rejection');
      await assert.rejects(client.execute(stale), error => error.code === 'stale_version');
      assert.equal((await client.status(stale)).status, 'not_observed');
      assert.deepEqual(await tables('after-stale-rejection'), beforeStale, 'stale CAS rejection preserves every backup table');
      await mutate([await update(shareId, { rounding: 'half_even' })]);

      await mutate([await update(issueId, { quantity: { numerator: '2', denominator: '1' } })]);
      assert.deepEqual((await read(issueId)).derived, { amount_minor: '20002' });
      assert.deepEqual((await read(shareId)).derived, { basis_minor: '20002', amount_minor: '6667' });

      const otherIssueId = randomUUID();
      const otherShareId = randomUUID();
      await mutate([
        { op: 'create', id: otherIssueId, contract: issueCode, fields: { invoice: invoiceId, at: '1',
          quantity: { numerator: '1', denominator: '1' }, unit_price_minor: '300', rounding: 'half_even' } },
        { op: 'create', id: otherShareId, contract: shareCode, fields: { issue: issueId,
          ratio: { numerator: '1', denominator: '3' }, rounding: 'half_even' } },
      ]);
      await mutate([
        await update(otherIssueId, { unit_price_minor: '600' }),
        await update(shareId, { issue: otherIssueId }),
      ]);
      assert.deepEqual((await read(shareId)).derived, { basis_minor: '600', amount_minor: '200' });
      await mutate([
        await update(otherShareId, { issue: otherIssueId }),
        await update(otherIssueId, { unit_price_minor: '900' }),
      ]);
      assert.deepEqual((await read(shareId)).derived, { basis_minor: '900', amount_minor: '300' });
      assert.deepEqual((await read(otherShareId)).derived, { basis_minor: '900', amount_minor: '300' });

      const replay = await client.execute(fixturePlan);
      assert.equal(replay.replayed, true);
      assert.equal(replay.result.operation_id, committed.result.operation_id);
      assert.ok(replay.result.records.every(entry => entry.record === null), 'replay redacts records changed since the original receipt');
    } finally {
      if (native) {
        try { if (service) await native.stopService({ service: service.service }); } catch {}
        await native.close().catch(() => {});
      }
      await rm(directory, { recursive: true, force: true });
    }
  });
