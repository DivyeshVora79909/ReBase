import assert from 'node:assert/strict';
import { mkdtemp, copyFile, chmod, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openNative } from '../native.mjs';
import { resolveConfig } from '../config.mjs';

const fakeSource = new URL('./fixtures/fake-native-host.mjs', import.meta.url);
let sandbox;
const openedHandles = new Set();

test.before(async () => { sandbox = await mkdtemp(path.join(os.tmpdir(), 'rebase-n1-node-')); });
test.after(async () => {
  await Promise.allSettled([...openedHandles].map(handle => handle.close()));
  if (sandbox) await rm(sandbox, { recursive: true, force: true });
});

async function open(mode, configuration, runner) {
  const handle = await openNative(await configFor(mode, configuration, runner));
  openedHandles.add(handle);
  return handle;
}

async function configFor(mode, configuration = { model: 'calculation', backend: { kind: 'redb', cluster_file: null }, target: null, operator_methods: [] }, runner = {}) {
  const binary = path.join(sandbox, `fake-host-${mode}`);
  await copyFile(fakeSource, binary);
  await chmod(binary, 0o755);
  return resolveConfig({ overrides: {
    native: { binary, environment: { PATH: process.env.PATH, ...(process.env.LD_LIBRARY_PATH ? { LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH } : {}) }, configuration },
    runner: { startTimeoutMs: 1000, closeTimeoutMs: 500, diagnosticBytes: 256, ...runner },
  } });
}

test('N1 private host configures once, exposes N1 methods and shares one idempotent close promise', async () => {
  const handle = await open('normal');
  const description = await handle.describe();
  assert.equal(description.state, 'configured');
  assert.equal((await handle.catalog({ scope: 'developer' })).scope, 'developer');
  const firstClose = handle.close();
  const secondClose = handle.close();
  assert.equal(firstClose, secondClose);
  await assert.rejects(handle.describe(), error => error.code === 'native_transport');
  await firstClose;
  openedHandles.delete(handle);
  await assert.rejects(handle.describe(), error => error.code === 'native_transport');
});

test('store check and inspection use configured native identity and require explicit grants', async () => {
  const configuration = {
    model: 'calculation', backend: { kind: 'redb', cluster_file: null },
    target: { mode: 'open', path: path.join(sandbox, 'existing.redb'), expect_store: '33333333-3333-4333-8333-333333333333' },
    operator_methods: ['store.inspect', 'store.check'],
  };
  const handle = await open('normal', configuration);
  assert.deepEqual(await handle.check(), { valid: true });
  assert.deepEqual(await handle.inspect(), { records: [] });
  await handle.close();
  openedHandles.delete(handle);

  const noGrant = await open('normal', { ...configuration, operator_methods: [] });
  await assert.rejects(noGrant.check(), error => error.name === 'NativeHostError' && error.code === 'forbidden');
  await noGrant.close();
  openedHandles.delete(noGrant);
});

test('complete native config errors remain known errors; lost configure response retains original intent as unknown', async () => {
  await assert.rejects(openNative(await configFor('configure-error')), error => error.name === 'NativeHostError' && error.code === 'invalid_config' && !error.operation);
  await assert.rejects(openNative(await configFor('configure-duplicate')), error => error.name === 'NativeOutcomeUnknownError' && error.operation.method === 'host.configure');
  const createdPath = path.join(sandbox, 'side-effect.redb');
  const config = await configFor('configure-hang', {
    model: 'calculation', backend: { kind: 'redb', cluster_file: null },
    target: { mode: 'create', path: createdPath, tenant: '11111111-1111-4111-8111-111111111111', actor: '22222222-2222-4222-8222-222222222222' },
    operator_methods: ['store.check'],
  }, { startTimeoutMs: 100 });
  await assert.rejects(openNative(config), error => {
    assert.equal(error.name, 'NativeOutcomeUnknownError');
    assert.equal(error.code, 'outcome_unknown');
    assert.equal(error.operation.method, 'host.configure');
    assert.equal(error.operation.params.target.path, createdPath);
    assert.match(error.operation.id, /^node:[0-9]+$/);
    return true;
  });
  assert.equal((await stat(createdPath)).isFile(), true);
});

test('abort after configure dispatch is unknown and retains the exact target even if the child already touched it', async () => {
  const createdPath = path.join(sandbox, 'aborted-create.redb');
  const configuration = {
    model: 'calculation', backend: { kind: 'redb', cluster_file: null },
    target: { mode: 'create', path: createdPath, tenant: '11111111-1111-4111-8111-111111111111', actor: '22222222-2222-4222-8222-222222222222' },
    operator_methods: [],
  };
  const controller = new AbortController();
  const opening = openNative(await configFor('configure-hang', configuration), { signal: controller.signal });
  const abortTimer = setTimeout(() => controller.abort(), 50);
  await assert.rejects(opening, error => {
    assert.equal(error.name, 'NativeOutcomeUnknownError');
    assert.equal(error.operation.method, 'host.configure');
    assert.equal(error.operation.params.target.path, createdPath);
    return true;
  });
  clearTimeout(abortTimer);
  assert.equal((await stat(createdPath)).isFile(), true);
});

test('startup timeout, abort, unexpected exit, and bounded close terminate only the owned child', async () => {
  await assert.rejects(openNative(await configFor('hang-describe', undefined, { startTimeoutMs: 60 })), error => error.code === 'native_transport');
  const controller = new AbortController();
  const opening = openNative(await configFor('hang-describe'), { signal: controller.signal });
  const abortTimer = setTimeout(() => controller.abort(), 30);
  await assert.rejects(opening, error => error.code === 'ABORT_ERR');
  clearTimeout(abortTimer);
  await assert.rejects(openNative(await configFor('exit-before-response')), error => error.code === 'native_transport');
  const closeFailure = await open('close-hang', undefined, { closeTimeoutMs: 60 });
  await assert.rejects(closeFailure.close(), error => error.code === 'native_transport');
  openedHandles.delete(closeFailure);
  const closeAfterAck = await open('close-ack-stuck', undefined, { closeTimeoutMs: 60 });
  await assert.rejects(closeAfterAck.close(), error => error.code === 'native_transport');
  openedHandles.delete(closeAfterAck);
});

test('malformed, duplicate, wrong-id, wrong-version, unsafe-number, invalid-Unicode and oversized responses fail closed', async t => {
  for (const mode of ['duplicate-response', 'wrong-id', 'invalid-version', 'surrogate-response', 'invalid-utf8', 'unsafe-number', 'oversized-response', 'extra-frames']) {
    await t.test(mode, async () => {
      await assert.rejects(openNative(await configFor(mode)), error => error.code === 'native_transport');
    });
  }
});

test('remote schema references and native framing changes are rejected before host.configure', async () => {
  await assert.rejects(openNative(await configFor('remote-ref')), /external schema/);
  await assert.rejects(openNative(await configFor('wrong-framing')), /framing/);
});

test('model support comes from host.describe and an unsupported selector cannot create its target', async () => {
  const createdPath = path.join(sandbox, 'unsupported-model.redb');
  const configuration = {
    model: 'future-binding', backend: { kind: 'redb', cluster_file: null },
    target: { mode: 'create', path: createdPath, tenant: '11111111-1111-4111-8111-111111111111', actor: '22222222-2222-4222-8222-222222222222' },
    operator_methods: [],
  };
  await assert.rejects(openNative(await configFor('normal', configuration)), /does not compile the requested model/);
  await assert.rejects(stat(createdPath), error => error.code === 'ENOENT');
});

test('a future model compiles when native metadata and its native schema both advertise it', async () => {
  const configuration = { model: 'future-binding', backend: { kind: 'redb', cluster_file: null }, target: null, operator_methods: [] };
  const handle = await open('future-binding', configuration);
  assert.equal((await handle.describe()).selection.selector, 'future-binding');
  assert.ok(await handle.catalog({ scope: 'public' }));
  await handle.close();
  openedHandles.delete(handle);
});

test('a late unsolicited stdout frame poisons the owned host and cannot be mistaken for a later reply', async () => {
  let handle;
  try {
    handle = await open('late-extra-frame');
  } catch (error) {
    assert.ok(error.code === 'outcome_unknown' || error.code === 'native_transport');
    return;
  }
  await new Promise(resolve => setTimeout(resolve, 75));
  await assert.rejects(handle.describe(), error => error.code === 'native_transport');
  await assert.rejects(handle.close(), error => error.code === 'native_transport');
  openedHandles.delete(handle);
});

test('an aborted read stops caller waiting but drains its response before the next request', async () => {
  const handle = await open('delayed-catalog');
  const controller = new AbortController();
  const read = handle.catalog({ scope: 'developer', signal: controller.signal });
  const abortTimer = setTimeout(() => controller.abort(), 20);
  await assert.rejects(read, error => error.name === 'AbortError');
  clearTimeout(abortTimer);
  const description = await handle.describe();
  assert.equal(description.state, 'configured');
  await handle.close();
  openedHandles.delete(handle);
});

test('close stops new admission but waits for work already queued', async () => {
  const handle = await open('delayed-catalog');
  const admitted = handle.catalog({ scope: 'developer' });
  const closing = handle.close();
  await assert.rejects(handle.describe(), error => error.code === 'native_transport');
  assert.equal((await admitted).scope, 'developer');
  await closing;
  openedHandles.delete(handle);
});

test('owned stderr is continuously drained, bounded, and redacted before exposure', async () => {
  const handle = await open('stderr-flood');
  const diagnostic = handle.diagnostics();
  assert.ok(Buffer.byteLength(diagnostic, 'utf8') <= 256);
  assert.doesNotMatch(diagnostic, /topsecret|abcdef/);
  await handle.close();
  openedHandles.delete(handle);

  const tinyTail = await open('stderr-flood', undefined, { diagnosticBytes: 8 });
  assert.ok(Buffer.byteLength(tinyTail.diagnostics(), 'utf8') <= 8);
  assert.doesNotMatch(tinyTail.diagnostics(), /topsecret|abcdef/);
  await tinyTail.close();
  openedHandles.delete(tinyTail);

  const pemTail = await open('stderr-pem', undefined, { diagnosticBytes: 24 });
  assert.ok(Buffer.byteLength(pemTail.diagnostics(), 'utf8') <= 24);
  assert.doesNotMatch(pemTail.diagnostics(), /supersecretkeymaterial/);
  await pemTail.close();
  openedHandles.delete(pemTail);

  const unicodeTail = await open('stderr-unicode', undefined, { diagnosticBytes: 2 });
  assert.ok(Buffer.byteLength(unicodeTail.diagnostics(), 'utf8') <= 2);
  assert.doesNotMatch(unicodeTail.diagnostics(), /�/);
  await unicodeTail.close();
  openedHandles.delete(unicodeTail);
});
