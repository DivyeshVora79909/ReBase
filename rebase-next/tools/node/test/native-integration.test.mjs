import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { resolveConfig } from '../config.mjs';
import { openNative } from '../native.mjs';
import { prepareModel } from '../model.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const defaultBinary = path.join(repositoryRoot, 'target/verification-build/debug/rebase-next');
const binary = process.env.REBASE_NODE_N1_BINARY ?? defaultBinary;
const available = existsSync(binary);

function config(model, target = null, operatorMethods = []) {
  return resolveConfig({ overrides: {
    native: {
      binary,
      environment: {},
      configuration: {
        model,
        backend: { kind: 'redb', cluster_file: null },
        target,
        operator_methods: operatorMethods,
      },
    },
    runner: { startTimeoutMs: 15_000, closeTimeoutMs: 5_000, diagnosticBytes: 4096 },
  } });
}

test('real native host serves all six public/developer catalogs over private framed IPC', { skip: !available && `native binary not found: ${binary}` }, async () => {
  const selectors = ['calculation', 'equipment', 'invoicing', 'measurement', 'effect-demo', 'quantity'];
  for (const selector of selectors) {
    const host = await openNative(config(selector));
    try {
      const description = await host.describe();
      assert.equal(description.state, 'configured');
      assert.equal(description.selection.selector, selector);
      assert.match(description.selection.model, /^[0-9a-f]{64}$/);
      const publicCatalog = await host.catalog({ scope: 'public' });
      const developerCatalog = await host.catalog({ scope: 'developer' });
      assert.ok(publicCatalog && typeof publicCatalog === 'object');
      assert.ok(developerCatalog && typeof developerCatalog === 'object');
      assert.notDeepEqual(publicCatalog, developerCatalog);
    } finally {
      await host.close();
    }
  }
});

test('real redb ownership grants scoped check/inspect, rejects conflicts and wrong identities without modifying the store', { skip: !available && `native binary not found: ${binary}` }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n1-native-store-'));
  const storePath = path.join(directory, 'store.redb');
  const tenant = '11111111-1111-4111-8111-111111111111';
  const actor = '22222222-2222-4222-8222-222222222222';
  let owner;
  try {
    owner = await openNative(config('calculation', { mode: 'create', path: storePath, tenant, actor }, ['store.check', 'store.inspect']));
    const description = await owner.describe();
    const storeId = description.ownership.store;
    assert.match(storeId, /^[0-9a-f-]{36}$/);
    assert.ok(await owner.check());
    assert.ok(await owner.inspect());

    const duringBefore = createHash('sha256').update(await readFile(storePath)).digest('hex');
    await assert.rejects(openNative(config('calculation', { mode: 'open', path: storePath, expect_store: storeId }, ['store.check'])), error => error.code === 'store_busy');
    assert.equal(createHash('sha256').update(await readFile(storePath)).digest('hex'), duringBefore);
    await owner.close();
    owner = null;
    const before = createHash('sha256').update(await readFile(storePath)).digest('hex');
    await assert.rejects(openNative(config('calculation', { mode: 'open', path: storePath, expect_store: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, ['store.check'])), error => error.code === 'wrong_target');
    await assert.rejects(openNative(config('equipment', { mode: 'open', path: storePath, expect_store: storeId }, ['store.check'])), error => error.code === 'wrong_target');
    const after = createHash('sha256').update(await readFile(storePath)).digest('hex');
    assert.equal(after, before);
  } finally {
    if (owner) await owner.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }

  await assert.rejects(stat(directory), error => error.code === 'ENOENT');
});

test('all six native models prepare both catalog scopes and validate native fixtures before drafting', { skip: !available && `native binary not found: ${binary}` }, async () => {
  for (const selector of ['calculation', 'equipment', 'invoicing', 'measurement', 'effect-demo', 'quantity']) {
    const native = await openNative(config(selector));
    try {
      const models = [];
      for (const scope of ['public', 'developer']) {
        const model = prepareModel(await native.catalog({ scope }), { native, selector });
        assert.equal(model.identity, native.selection.model);
        assert.ok(model.contracts.length > 0);
        models.push(model);
      }
      const fixtures = await models[1].fixtureCatalog();
      assert.ok(fixtures.length > 0);
      for (const fixture of fixtures) {
        const plan = await models[1].fixturePlan({ name: fixture.name, namespace: '11111111-1111-4111-8111-111111111111' });
        const records = plan.commands.map(({ op, id, contract, fields }) => {
          assert.equal(op, 'create');
          return { id, contract, fields };
        });
        for (const model of models) {
          assert.deepEqual(model.draftFixture(records, { returning: plan.returning }), {
            model: plan.model, commands: plan.commands, returning: plan.returning,
          });
        }
        for (const record of records) {
          const checked = await models[1].validateNative(record.contract, record.fields);
          assert.equal(checked.status, 'valid');
        }
      }
    } finally {
      await native.close();
    }
  }
});
