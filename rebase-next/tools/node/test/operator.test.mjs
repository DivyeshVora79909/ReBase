import assert from 'node:assert/strict';
import test from 'node:test';
import { openOperator } from '../operator.mjs';

const scope = Object.freeze({
  model: 'a'.repeat(64),
  store: '33333333-3333-4333-8333-333333333333',
});

function host(grants) {
  const calls = [];
  const native = { scope, grants: Object.freeze(grants) };
  for (const method of ['check', 'inspect', 'backup', 'restore', 'archive', 'reset', 'startService', 'stopService', 'issueIdentity', 'retryEffect']) {
    native[method] = async params => { calls.push([method, params]); return { method }; };
  }
  return { native, calls };
}

test('operator requires exact existing native scope and a subset of configured grants', () => {
  const { native } = host(['store.inspect']);
  assert.throws(() => openOperator(native, { scope: { ...scope, store: '44444444-4444-4444-8444-444444444444' }, methods: ['store.inspect'] }), error => error.code === 'wrong_target');
  assert.throws(() => openOperator(native, { scope, methods: ['store.reset'] }), error => error.code === 'forbidden');
  assert.throws(() => openOperator(native, { scope, methods: ['store.inspect', 'store.inspect'] }), /Duplicate/);
  assert.throws(() => openOperator(native, { scope, methods: ['native.exec'] }), /Unsupported/);
});

test('operator returns only narrowed functions and delegates using the same store scope', async () => {
  const { native, calls } = host(['store.check', 'store.inspect', 'store.backup', 'store.restore', 'store.archive', 'store.reset']);
  const operator = openOperator(native, { scope, methods: ['store.inspect', 'store.backup', 'store.restore', 'store.archive', 'store.reset'] });
  assert.deepEqual(Object.keys(operator).sort(), ['archive', 'grants', 'inspect', 'reset', 'restore', 'scope', 'snapshot']);
  const destination = '/owned/store.backup';
  await operator.snapshot({ destination });
  await operator.inspect();
  await operator.archive({ destination: '/owned/archive.backup' });
  await operator.reset({ expectStore: scope.store });
  await operator.restore({
    backup: '/owned/store.backup',
    expectBackupStore: scope.store,
    destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: '/owned/restored.redb' } },
  });
  assert.deepEqual(calls, [
    ['backup', { scope, destination }],
    ['inspect', {}],
    ['archive', { scope, destination: '/owned/archive.backup' }],
    ['reset', { scope, expect_store: scope.store }],
    ['restore', { scope, backup: '/owned/store.backup', expect_backup_store: scope.store,
      destination: { backend: { kind: 'redb', cluster_file: null }, target: { path: '/owned/restored.redb' } } }],
  ]);
});

test('service and identity functions stay scoped; private signing material is passed only to native issuance', async () => {
  const { native, calls } = host(['service.start', 'service.stop', 'identity.issue']);
  const operator = openOperator(native, { scope, methods: ['service.start', 'service.stop', 'identity.issue'] });
  const config = { listen: '127.0.0.1:0', identity: { issuer: 'local', audience: 'n2', public_keys: { local: '<public>' }, max_token_seconds: 60 }, max_inflight: 2, request_timeout_seconds: 5, effects: null };
  const identity = { issuer: 'local', audience: 'n2', public_keys: { local: '<public>' }, max_token_seconds: 60 };
  const request = { tenant: '11111111-1111-4111-8111-111111111111', actor: '22222222-2222-4222-8222-222222222222', epoch: 0, ttl: 30, key_id: 'local' };
  const privateKeyPem = 'SECRET-PEM';
  await operator.startService({ config });
  await operator.issueIdentity({ identity, request, privateKeyPem });
  await operator.stopService({ service: '55555555-5555-4555-8555-555555555555' });
  assert.deepEqual(calls, [
    ['startService', { scope, config }],
    ['issueIdentity', { scope, identity, request, private_key_pem: privateKeyPem }],
    ['stopService', { scope, service: '55555555-5555-4555-8555-555555555555' }],
  ]);
  assert.equal(JSON.stringify(operator).includes(privateKeyPem), false);
});

test('private effect retry narrows its grant and adds the host-owned store scope', async () => {
  const { native, calls } = host(['effects.retry']);
  const operator = openOperator(native, { scope, methods: ['effects.retry'] });
  assert.deepEqual(Object.keys(operator).sort(), ['grants', 'retryEffect', 'scope']);
  const options = { signal: new AbortController().signal };
  await operator.retryEffect({ executionId: '55555555-5555-4555-8555-555555555555', ifRevision: '0' }, options);
  assert.deepEqual(calls, [['retryEffect', {
    scope,
    execution_id: '55555555-5555-4555-8555-555555555555',
    if_revision: '0',
  }]]);
  assert.throws(() => openOperator(native, { scope, methods: ['effects.retry', 'effects.retry'] }), /Duplicate/);
  assert.throws(() => openOperator(native, { scope, methods: ['effects.retry', 'store.reset'] }), error => error.code === 'forbidden');
});
