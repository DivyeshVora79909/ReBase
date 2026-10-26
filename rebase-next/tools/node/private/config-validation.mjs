import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { ConfigurationError } from './config-errors.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const CONFIGURATION_KEYS = new Set(['model', 'backend', 'target', 'operator_methods']);

export function validateNativeConfigurationShape(configuration) {
  assertExactKeys(configuration, CONFIGURATION_KEYS, 'native.configuration');
  if (typeof configuration.model !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(configuration.model)) {
    throw new ConfigurationError('must be a bounded lowercase model selector', 'native.configuration.model');
  }
  assertExactKeys(configuration.backend, new Set(['kind', 'cluster_file']), 'native.configuration.backend');
  if (typeof configuration.backend.kind !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(configuration.backend.kind)) {
    throw new ConfigurationError('must be a bounded backend selector', 'native.configuration.backend.kind');
  }
  if (configuration.backend.kind === 'foundationdb') {
    validateAbsolutePath(configuration.backend.cluster_file, 'native.configuration.backend.cluster_file');
  } else if (configuration.backend.cluster_file !== null) {
    throw new ConfigurationError('cluster_file is only valid for FoundationDB', 'native.configuration.backend.cluster_file');
  }
  if (configuration.target !== null) {
    if (!isRecord(configuration.target)) throw new ConfigurationError('must be null or a target object', 'native.configuration.target');
    const target = configuration.target;
    const foundationdb = configuration.backend.kind === 'foundationdb';
    const targetName = foundationdb ? 'namespace' : 'path';
    const validateTarget = () => {
      if (foundationdb) {
        if (typeof target.namespace !== 'string' || !target.namespace || target.namespace.includes('\0')) {
          throw new ConfigurationError('must be a nonempty namespace without NUL', 'native.configuration.target.namespace');
        }
      } else {
        validateAbsolutePath(target.path, 'native.configuration.target.path');
      }
    };
    if (target.mode === 'create') {
      assertExactKeys(target, new Set(['mode', targetName, 'tenant', 'actor']), 'native.configuration.target');
      validateTarget();
      validateUuid(target.tenant, 'native.configuration.target.tenant');
      validateUuid(target.actor, 'native.configuration.target.actor');
    } else if (target.mode === 'open') {
      assertExactKeys(target, new Set(['mode', targetName, 'expect_store']), 'native.configuration.target');
      validateTarget();
      validateUuid(target.expect_store, 'native.configuration.target.expect_store');
    } else if (target.mode === 'recover' && configuration.backend.kind === 'redb') {
      assertExactKeys(target, new Set(['mode', 'path', 'expect_store']), 'native.configuration.target');
      validateAbsolutePath(target.path, 'native.configuration.target.path');
      validateUuid(target.expect_store, 'native.configuration.target.expect_store');
    } else {
      throw new ConfigurationError('target mode must be create, open, or supported redb recover', 'native.configuration.target.mode');
    }
  }
  if (!Array.isArray(configuration.operator_methods)) {
    throw new ConfigurationError('must be an array', 'native.configuration.operator_methods');
  }
  const seen = new Set();
  for (const method of configuration.operator_methods) {
    if (typeof method !== 'string' || !/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){0,2}$/.test(method)) {
      throw new ConfigurationError('must be a bounded native method name', 'native.configuration.operator_methods');
    }
    if (seen.has(method)) throw new ConfigurationError('duplicate method grant', 'native.configuration.operator_methods');
    seen.add(method);
  }
  if (configuration.target === null && configuration.operator_methods.length !== 0) {
    throw new ConfigurationError('model-only configuration cannot grant store methods', 'native.configuration.operator_methods');
  }
  return configuration;
}

export function validateServiceConfigurationShape(configuration, label = 'service') {
  assertExactKeys(configuration, new Set(['listen', 'identity', 'max_inflight', 'request_timeout_seconds', 'effects']), label);
  if (typeof configuration.listen !== 'string' || !configuration.listen || configuration.listen.includes('\0')) {
    throw new ConfigurationError('must be an explicit socket address', `${label}.listen`);
  }
  if (!Number.isSafeInteger(configuration.max_inflight) || configuration.max_inflight < 1) {
    throw new ConfigurationError('must be an explicit positive integer', `${label}.max_inflight`);
  }
  if (!Number.isSafeInteger(configuration.request_timeout_seconds) || configuration.request_timeout_seconds < 1) {
    throw new ConfigurationError('must be an explicit positive integer', `${label}.request_timeout_seconds`);
  }
  assertExactKeys(configuration.identity, new Set(['issuer', 'audience', 'public_keys', 'max_token_seconds']), `${label}.identity`);
  for (const name of ['issuer', 'audience']) {
    if (typeof configuration.identity[name] !== 'string' || !configuration.identity[name] || configuration.identity[name].includes('\0')) {
      throw new ConfigurationError('must be an explicit nonempty string', `${label}.identity.${name}`);
    }
  }
  if (!isRecord(configuration.identity.public_keys) || Object.keys(configuration.identity.public_keys).length === 0) {
    throw new ConfigurationError('must contain explicit public key PEM entries', `${label}.identity.public_keys`);
  }
  for (const [keyId, pem] of Object.entries(configuration.identity.public_keys)) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyId) || typeof pem !== 'string' || !pem || pem.includes('\0')) {
      throw new ConfigurationError('must contain a valid key ID and public PEM', `${label}.identity.public_keys`);
    }
  }
  if (!Number.isSafeInteger(configuration.identity.max_token_seconds) || configuration.identity.max_token_seconds < 1) {
    throw new ConfigurationError('must be an explicit positive integer', `${label}.identity.max_token_seconds`);
  }
  if (!(configuration.effects === null || isRecord(configuration.effects))) {
    throw new ConfigurationError('must be null or an explicit effects configuration object', `${label}.effects`);
  }
  return configuration;
}

/** One strict registry for native configuration and model value schemas. */
export function createNativeAjv() {
  const ajv = new Ajv2020({ strict: true, strictTypes: false, allErrors: true, validateSchema: true });
  addFormats(ajv);
  for (const name of ['i64', 'i128', 'u16']) {
    ajv.addFormat(name, { type: 'string', validate: value => {
      if (!/^(0|-?[1-9][0-9]*)$/.test(value)) return false;
      const number = BigInt(value);
      if (name === 'i64') return number >= -(1n << 63n) && number <= (1n << 63n) - 1n;
      if (name === 'i128') return number >= -(1n << 127n) && number <= (1n << 127n) - 1n;
      return number >= 1n && number <= 65535n;
    } });
  }
  ajv.addKeyword({
    keyword: 'x-rebase-range', schemaType: 'array',
    validate: (range, value) => {
      if (!Array.isArray(range) || range.length !== 2 || range.some(bound => typeof bound !== 'string' || !/^(0|-?[1-9][0-9]*)$/.test(bound))
        || typeof value !== 'string' || !/^(0|-?[1-9][0-9]*)$/.test(value)) return false;
      const number = BigInt(value);
      return number >= BigInt(range[0]) && number <= BigInt(range[1]);
    },
  });
  ajv.addKeyword({ keyword: 'x-rebase-binding', schemaType: 'string', valid: true });
  ajv.addKeyword({
    keyword: 'x-maxUtf8Bytes', type: 'string', schemaType: 'number',
    validate: (maximum, value) => typeof value === 'string' && Number.isSafeInteger(maximum) && maximum >= 0 && Buffer.byteLength(value, 'utf8') <= maximum,
  });
  return ajv;
}

export function validateNativeConfigurationSchema(schema, configuration) {
  assertJsonSchema(schema, 'native.configuration.schema');
  const ajv = createNativeAjv();
  let validate;
  try { validate = ajv.compile(schema); }
  catch (error) { throw new ConfigurationError(`native configuration schema rejected: ${safeSchemaError(error)}`, 'native.configuration.schema'); }
  if (!validate(configuration)) {
    const details = (validate.errors ?? []).slice(0, 8).map(error => `${error.instancePath || '/'} ${error.keyword}`).join('; ');
    throw new ConfigurationError(`does not satisfy native schema${details ? ` (${details})` : ''}`, 'native.configuration');
  }
  return configuration;
}

export function validateNativeDescription(description, protocol = 'rebase-native-host-1') {
  assertExactKeys(description, new Set(['protocol', 'state', 'engine', 'configuration', 'capabilities', 'selection', 'ownership']), 'host.describe.result');
  if (description.protocol !== protocol || !['unconfigured', 'configured'].includes(description.state)) {
    throw new ConfigurationError('protocol or state mismatch', 'host.describe.result');
  }
  assertExactKeys(description.engine, new Set(['version', 'api', 'store_format', 'native_codec', 'effect_codec', 'compiled_models', 'compiled_backends']), 'host.describe.result.engine');
  for (const name of ['version', 'api', 'store_format', 'native_codec', 'effect_codec']) {
    if (typeof description.engine[name] !== 'string') throw new ConfigurationError('must be a string', `host.describe.result.engine.${name}`);
  }
  for (const name of ['compiled_models', 'compiled_backends']) {
    if (!Array.isArray(description.engine[name]) || description.engine[name].some(item => typeof item !== 'string')) {
      throw new ConfigurationError('must be an array of strings', `host.describe.result.engine.${name}`);
    }
  }
  assertExactKeys(description.configuration, new Set(['schema', 'defaults', 'sources']), 'host.describe.result.configuration');
  if (!isRecord(description.configuration.defaults) || !isRecord(description.configuration.sources)) {
    throw new ConfigurationError('defaults and sources must be objects', 'host.describe.result.configuration');
  }
  assertExactKeys(description.capabilities, new Set(['framing', 'host_methods', 'host_backends', 'model', 'mutation_work_limit', 'backup_bytes']), 'host.describe.result.capabilities');
  assertExactKeys(description.capabilities.framing, new Set(['request_bytes', 'response_bytes', 'max_outstanding', 'bytes_exclude_lf']), 'host.describe.result.capabilities.framing');
  if (description.capabilities.framing.request_bytes !== 65_536
    || description.capabilities.framing.response_bytes !== 8_388_608
    || description.capabilities.framing.max_outstanding !== 1
    || description.capabilities.framing.bytes_exclude_lf !== true) {
    throw new ConfigurationError('native framing does not match frozen protocol bounds', 'host.describe.result.capabilities.framing');
  }
  for (const name of ['host_methods', 'host_backends']) {
    if (!Array.isArray(description.capabilities[name]) || description.capabilities[name].some(item => typeof item !== 'string')) {
      throw new ConfigurationError('must be an array of strings', `host.describe.result.capabilities.${name}`);
    }
  }
  if (!description.capabilities.host_methods.includes('host.configure')
    || !description.capabilities.host_methods.includes('host.close')) {
    throw new ConfigurationError('missing required N1 host method', 'host.describe.result.capabilities.host_methods');
  }
  if (description.capabilities.model !== null && !isRecord(description.capabilities.model)) {
    throw new ConfigurationError('must be null or an object', 'host.describe.result.capabilities.model');
  }
  if (!(description.capabilities.mutation_work_limit === null || Number.isSafeInteger(description.capabilities.mutation_work_limit))
    || !(description.capabilities.backup_bytes === null || Number.isSafeInteger(description.capabilities.backup_bytes))) {
    throw new ConfigurationError('native limit must be a safe integer or null', 'host.describe.result.capabilities');
  }
  if (description.state === 'unconfigured' && (description.selection !== null || description.ownership !== null || description.capabilities.model !== null)) {
    throw new ConfigurationError('unconfigured host disclosed configured state', 'host.describe.result');
  }
  if (description.state === 'configured') {
    assertExactKeys(description.selection, new Set(['selector', 'model', 'backend', 'target']), 'host.describe.result.selection');
    if (typeof description.selection.selector !== 'string' || !HASH.test(description.selection.model)
      || !description.engine.compiled_models.includes(description.selection.selector)) {
      throw new ConfigurationError('configured host selection identity was invalid', 'host.describe.result.selection');
    }
    assertExactKeys(description.selection.backend, new Set(['kind', 'cluster_file']), 'host.describe.result.selection.backend');
    const backend = description.selection.backend.kind;
    if (!['redb', 'surrealkv', 'foundationdb'].includes(backend)
      || !description.capabilities.host_backends.includes(backend)) {
      throw new ConfigurationError('configured backend was not advertised by the host', 'host.describe.result.selection.backend');
    }
    if (description.selection.target !== null && !isRecord(description.selection.target)) {
      throw new ConfigurationError('must be null or a target descriptor', 'host.describe.result.selection.target');
    }
    if (description.selection.target === null) {
      if (description.ownership !== null) {
        throw new ConfigurationError('unscoped host disclosed store ownership', 'host.describe.result.ownership');
      }
    } else {
      assertExactKeys(description.ownership, new Set(['store', 'mode']), 'host.describe.result.ownership');
      const expectedMode = backend === 'foundationdb' ? 'shared_transactional' : 'exclusive';
      if (!UUID.test(description.ownership.store) || description.ownership.mode !== expectedMode) {
        throw new ConfigurationError('ownership identity was invalid', 'host.describe.result.ownership');
      }
    }
  }
  return description;
}

export function validatePublicConfig(configuration) {
  return validateNativeConfigurationShape(configuration);
}

function validateAbsolutePath(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) throw new ConfigurationError('must be an explicit absolute path without NUL', label);
  if (Buffer.byteLength(value, 'utf8') > 4096) throw new ConfigurationError('UTF-8 path exceeds 4096 bytes', label);
}

function validateUuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new ConfigurationError('must be a canonical lowercase UUID', label);
}

function assertJsonSchema(schema, label) {
  if (!isRecord(schema)) throw new ConfigurationError('must be an object', label);
  const walk = value => {
    if (Array.isArray(value)) return value.forEach(walk);
    if (!isRecord(value)) return;
    for (const [key, item] of Object.entries(value)) {
      if (key === '$ref' && (typeof item !== 'string' || !item.startsWith('#'))) {
        throw new ConfigurationError('external schema references are not allowed', label);
      }
      if (key === '$id' && typeof item === 'string' && !item.startsWith('#')) {
        throw new ConfigurationError('external schema identifiers are not allowed', label);
      }
      walk(item);
    }
  };
  walk(schema);
}

function safeSchemaError(error) {
  return error instanceof Error ? error.message.slice(0, 300) : 'invalid schema';
}

function assertExactKeys(value, expected, label) {
  if (!isRecord(value)) throw new ConfigurationError('must be an object', label);
  for (const key of Object.keys(value)) if (!expected.has(key)) throw new ConfigurationError('unknown key', `${label}.${key}`);
  for (const key of expected) if (!Object.hasOwn(value, key)) throw new ConfigurationError('required key is missing', `${label}.${key}`);
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
