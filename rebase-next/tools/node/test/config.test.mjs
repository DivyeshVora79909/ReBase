import assert from 'node:assert/strict';
import test from 'node:test';
import * as configAPI from '../config.mjs';
const { parseEnvironment, resolveConfig } = configAPI;
import { ConfigurationError } from '../private/config-errors.mjs';
import { validateNativeConfigurationSchema, validateNativeDescription } from '../private/config-validation.mjs';

const target = Object.freeze({
  model: 'calculation',
  backend: Object.freeze({ kind: 'redb', cluster_file: null }),
  target: null,
  operator_methods: Object.freeze([]),
});

test('config exposes only the frozen config entry points', () => {
  assert.deepEqual(Object.keys(configAPI).sort(), ['parseEnvironment', 'resolveConfig']);
});

test('config applies explicit override > parsed environment > defaults and reports provenance', () => {
  const environment = parseEnvironment({
    PATH: '/usr/bin',
    REBASE_NODE_START_TIMEOUT_MS: '2000',
    REBASE_NODE_DIAGNOSTIC_BYTES: '0',
  });
  const config = resolveConfig({
    defaults: { native: { binary: '/opt/rebase-next', configuration: target }, runner: { startTimeoutMs: 1000 } },
    environment,
    overrides: { runner: { startTimeoutMs: 500 } },
  });
  assert.equal(config.runner.startTimeoutMs, 500);
  assert.equal(config.runner.diagnosticBytes, 0);
  assert.equal(config.runner.closeTimeoutMs, 5000);
  assert.equal(config.provenance['runner.startTimeoutMs'], 'override');
  assert.equal(config.provenance['runner.diagnosticBytes'], 'environment');
  assert.equal(config.provenance['runner.closeTimeoutMs'], 'default');
  assert.equal(config.provenance['native.binary'], 'default');
  assert.ok(Object.isFrozen(config) && Object.isFrozen(config.runner) && Object.isFrozen(config.native.configuration));
});

test('environment parser ignores unrelated process settings and rejects unknown or ambiguous owned settings', () => {
  assert.deepEqual(parseEnvironment({ HOME: '/home/user' }), { runner: {} });
  for (const environment of [
    { REBASE_NODE_UNKNOWN: '1' },
    { REBASE_NODE_START_TIMEOUT_MS: '+2' },
    { REBASE_NODE_START_TIMEOUT_MS: '02' },
    { REBASE_NODE_DIAGNOSTIC_BYTES: 'NaN' },
    { REBASE_NODE_CLOSE_TIMEOUT_MS: '0' },
  ]) assert.throws(() => parseEnvironment(environment), ConfigurationError);
  assert.throws(() => parseEnvironment({ REBASE_NODE_START_TIMEOUT_MS: '1' }, ['REBASE_NODE_CLOSE_TIMEOUT_MS']), /disallowed/);
});

test('resolver rejects unknown keys, null, unsafe numbers, invalid child env, and relative executable paths', () => {
  for (const fragment of [
    { other: {} },
    { runner: { surprise: true } },
    { runner: { diagnosticBytes: null } },
    { runner: { startTimeoutMs: Number.MAX_SAFE_INTEGER + 1 } },
    { native: { environment: { LD_PRELOAD: '/tmp/inject.so' } } },
    { native: { binary: 'rebase-next' } },
  ]) assert.throws(() => resolveConfig({ overrides: fragment }), ConfigurationError);
});

test('N1 native config rejects ambiguous backends, unknown fields, duplicate grants, invalid paths and UUIDs', () => {
  const invalid = [
    { ...target, backend: { kind: 'redb', cluster_file: '/tmp/cluster' } },
    { ...target, unexpected: true },
    { ...target, operator_methods: ['store.check', 'store.check'] },
    { ...target, target: { mode: 'create', path: 'relative.db', tenant: '11111111-1111-4111-8111-111111111111', actor: '22222222-2222-4222-8222-222222222222' } },
    { ...target, target: { mode: 'open', path: '/tmp/store.db', expect_store: 'ABC' } },
    { ...target, target: null, operator_methods: ['store.inspect'] },
  ];
  for (const config of invalid) assert.throws(() => resolveConfig({ overrides: { native: { configuration: config } } }), ConfigurationError);
  assert.equal(resolveConfig({ overrides: { native: { configuration: { ...target, model: 'future-binding' } } } }).native.configuration.model, 'future-binding');
});

test('N2 config accepts explicit backend target shapes and defers method availability to native schema', () => {
  const configuration = value => resolveConfig({ overrides: { native: { configuration: value } } }).native.configuration;
  const surrealkv = configuration({
    ...target,
    backend: { kind: 'surrealkv', cluster_file: null },
    target: { mode: 'open', path: '/tmp/owned.skv', expect_store: '33333333-3333-4333-8333-333333333333' },
    operator_methods: ['store.backup', 'service.start'],
  });
  assert.equal(surrealkv.backend.kind, 'surrealkv');
  assert.deepEqual(surrealkv.operator_methods, ['store.backup', 'service.start']);
  assert.equal(configuration({
    ...target,
    backend: { kind: 'foundationdb', cluster_file: '/etc/foundationdb/fdb.cluster' },
    target: { mode: 'create', namespace: 'n2-isolated', tenant: '11111111-1111-4111-8111-111111111111', actor: '22222222-2222-4222-8222-222222222222' },
    operator_methods: [],
  }).target.namespace, 'n2-isolated');
  assert.throws(() => configuration({
    ...target,
    backend: { kind: 'foundationdb', cluster_file: null },
  }), ConfigurationError);
  assert.equal(configuration({
    ...target,
    target: { mode: 'recover', path: '/tmp/crashed.redb', expect_store: '33333333-3333-4333-8333-333333333333' },
    operator_methods: ['store.recover'],
  }).target.mode, 'recover');
  assert.throws(() => configuration({
    ...target,
    backend: { kind: 'surrealkv', cluster_file: null },
    target: { mode: 'recover', path: '/tmp/crashed.skv', expect_store: '33333333-3333-4333-8333-333333333333' },
  }), ConfigurationError);
});

test('configured host ownership mode matches its advertised backend', () => {
  const store = '33333333-3333-4333-8333-333333333333';
  const description = (kind, mode) => ({
    protocol: 'rebase-native-host-1',
    state: 'configured',
    engine: {
      version: '0.16.0', api: '4', store_format: '10', native_codec: '7', effect_codec: '4',
      compiled_models: ['equipment'], compiled_backends: ['redb', 'surrealkv', 'foundationdb'],
    },
    configuration: { schema: {}, defaults: {}, sources: {} },
    capabilities: {
      framing: { request_bytes: 65536, response_bytes: 8388608, max_outstanding: 1, bytes_exclude_lf: true },
      host_methods: ['host.configure', 'host.close'],
      host_backends: ['redb', 'surrealkv', 'foundationdb'],
      model: null, mutation_work_limit: null, backup_bytes: null,
    },
    selection: {
      selector: 'equipment', model: 'a'.repeat(64),
      backend: { kind, cluster_file: kind === 'foundationdb' ? '/etc/foundationdb/fdb.cluster' : null },
      target: kind === 'foundationdb' ? { namespace: 'n2-test', store } : { path: '/tmp/n2-test.db', store },
    },
    ownership: { store, mode },
  });

  for (const [backend, mode] of [['redb', 'exclusive'], ['surrealkv', 'exclusive'], ['foundationdb', 'shared_transactional']]) {
    assert.equal(validateNativeDescription(description(backend, mode)).ownership.mode, mode);
  }
  for (const [backend, mode] of [['redb', 'shared_transactional'], ['surrealkv', 'shared_transactional'], ['foundationdb', 'exclusive']]) {
    assert.throws(() => validateNativeDescription(description(backend, mode)), ConfigurationError);
  }
  const unscoped = description('foundationdb', 'shared_transactional');
  unscoped.selection.target = null;
  assert.throws(() => validateNativeDescription(unscoped), ConfigurationError);
});

test('N2 service config has no implicit listen, identity, concurrency, deadline, or effect defaults', () => {
  const service = {
    listen: '127.0.0.1:0',
    identity: { issuer: 'local', audience: 'rebase-test', public_keys: { local: 'PUBLIC PEM' }, max_token_seconds: 60 },
    max_inflight: 8,
    request_timeout_seconds: 10,
    effects: null,
  };
  const config = resolveConfig({
    defaults: { service },
    overrides: { service: { request_timeout_seconds: 20 } },
  });
  assert.equal(config.service.request_timeout_seconds, 20);
  assert.equal(config.provenance['service.request_timeout_seconds'], 'override');
  assert.equal(config.provenance['service.listen'], 'default');
  assert.ok(Object.isFrozen(config.service.identity.public_keys));
  for (const invalid of [
    { ...service, listen: null },
    { ...service, identity: { ...service.identity, private_key_pem: 'not config' } },
    { ...service, max_inflight: 0 },
    { ...service, request_timeout_seconds: null },
  ]) assert.throws(() => resolveConfig({ overrides: { service: invalid } }), ConfigurationError);
});

test('native schemas are compiled locally with strict unknown-key checks and no remote reference resolution', () => {
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object',
    additionalProperties: false,
    required: ['id'],
    properties: { id: { type: 'string', format: 'uuid' } },
  };
  assert.equal(validateNativeConfigurationSchema(schema, { id: '33333333-3333-4333-8333-333333333333' }).id, '33333333-3333-4333-8333-333333333333');
  assert.throws(() => validateNativeConfigurationSchema(schema, { id: 'bad', extra: true }), /native schema/);
  assert.throws(() => validateNativeConfigurationSchema({ type: 'object', properties: { x: { $ref: 'https://example.invalid/x' } } }, { x: 1 }), /external schema/);
});

test('native schema extension bounds exact decimal strings without Number conversion', () => {
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object', additionalProperties: false, required: ['amount'],
    properties: { amount: { type: 'string', pattern: '^(0|-?[1-9][0-9]*)$', 'x-rebase-range': ['-100000000000000000000', '100000000000000000000'] } },
  };
  assert.equal(validateNativeConfigurationSchema(schema, { amount: '99999999999999999999' }).amount, '99999999999999999999');
  assert.throws(() => validateNativeConfigurationSchema(schema, { amount: '100000000000000000001' }), /native schema/);
});

test('native UTF-8 byte extension counts encoded bytes rather than JavaScript characters', () => {
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object', additionalProperties: false, required: ['name'],
    properties: { name: { type: 'string', 'x-maxUtf8Bytes': 2 } },
  };
  assert.equal(validateNativeConfigurationSchema(schema, { name: 'é' }).name, 'é');
  assert.throws(() => validateNativeConfigurationSchema(schema, { name: '😀' }), /native schema/);
  assert.throws(() => validateNativeConfigurationSchema(schema, { name: 12 }), /native schema/);
});
