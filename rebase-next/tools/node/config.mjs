import path from 'node:path';
import { ConfigurationError } from './private/config-errors.mjs';
import { validateNativeConfigurationShape, validateServiceConfigurationShape } from './private/config-validation.mjs';

const ENVIRONMENT_SETTINGS = Object.freeze({
  REBASE_NODE_START_TIMEOUT_MS: { path: ['runner', 'startTimeoutMs'], minimum: 1, maximum: 120_000 },
  REBASE_NODE_DIAGNOSTIC_BYTES: { path: ['runner', 'diagnosticBytes'], minimum: 0, maximum: 1_048_576 },
  REBASE_NODE_CLOSE_TIMEOUT_MS: { path: ['runner', 'closeTimeoutMs'], minimum: 1, maximum: 120_000 },
});

const DEFAULTS = Object.freeze({
  runner: Object.freeze({ startTimeoutMs: 10_000, diagnosticBytes: 16_384, closeTimeoutMs: 5_000 }),
  native: Object.freeze({ environment: Object.freeze({}) }),
});

const NATIVE_ENVIRONMENT_KEYS = new Set([
  'PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'FDB_CLIENT_LIB_PATH', 'TMPDIR', 'TMP', 'TEMP',
]);
const NODE_KEYS = new Set(['runner', 'native', 'service']);
const RUNNER_KEYS = new Set(['startTimeoutMs', 'diagnosticBytes', 'closeTimeoutMs']);
const NATIVE_KEYS = new Set(['binary', 'environment', 'configuration']);

export function parseEnvironment(environment, allowlist = Object.keys(ENVIRONMENT_SETTINGS)) {
  assertRecord(environment, 'environment');
  if (!Array.isArray(allowlist) || allowlist.some(name => typeof name !== 'string')) {
    throw new ConfigurationError('allowlist must be an array of setting names', 'allowlist');
  }
  const allowed = new Set(allowlist);
  for (const name of allowed) {
    if (!Object.hasOwn(ENVIRONMENT_SETTINGS, name)) throw new ConfigurationError('unknown environment setting', name);
  }

  const parsed = { runner: {} };
  for (const [name, raw] of Object.entries(environment)) {
    if (!name.startsWith('REBASE_NODE_')) continue;
    if (!allowed.has(name)) throw new ConfigurationError('unknown or disallowed environment setting', name);
    const descriptor = ENVIRONMENT_SETTINGS[name];
    if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) {
      throw new ConfigurationError('must be a canonical nonnegative decimal integer', name);
    }
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < descriptor.minimum || value > descriptor.maximum) {
      throw new ConfigurationError(`must be an integer in ${descriptor.minimum}..${descriptor.maximum}`, name);
    }
    parsed[descriptor.path[0]][descriptor.path[1]] = value;
  }
  return deepFreeze(parsed);
}

export function resolveConfig({ defaults = DEFAULTS, environment = {}, overrides = {} } = {}) {
  validateFragment(defaults, 'defaults');
  validateFragment(environment, 'environment');
  validateFragment(overrides, 'overrides');

  const values = clone(DEFAULTS);
  const provenance = Object.create(null);
  collectLeaves(DEFAULTS, 'default', '', provenance);
  mergeFragment(values, defaults, 'default', '', provenance);
  mergeFragment(values, environment, 'environment', '', provenance);
  mergeFragment(values, overrides, 'override', '', provenance);
  validateResolved(values);

  return deepFreeze({ ...values, provenance: flattenProvenance(provenance) });
}

function validateFragment(fragment, label) {
  assertRecord(fragment, label);
  assertKnownKeys(fragment, NODE_KEYS, label);
  if (Object.hasOwn(fragment, 'runner')) {
    assertRecord(fragment.runner, `${label}.runner`);
    assertKnownKeys(fragment.runner, RUNNER_KEYS, `${label}.runner`);
    for (const [name, value] of Object.entries(fragment.runner)) {
      const range = name === 'diagnosticBytes' ? [0, 1_048_576] : [1, 120_000];
      if (!Number.isSafeInteger(value) || value < range[0] || value > range[1]) {
        throw new ConfigurationError(`must be a safe integer in ${range[0]}..${range[1]}`, `${label}.runner.${name}`);
      }
    }
  }
  if (Object.hasOwn(fragment, 'native')) {
    assertRecord(fragment.native, `${label}.native`);
    assertKnownKeys(fragment.native, NATIVE_KEYS, `${label}.native`);
    if (Object.hasOwn(fragment.native, 'binary')) validateAbsolutePath(fragment.native.binary, `${label}.native.binary`);
    if (Object.hasOwn(fragment.native, 'environment')) validateChildEnvironment(fragment.native.environment, `${label}.native.environment`);
    if (Object.hasOwn(fragment.native, 'configuration')) validateNativeConfigurationShape(fragment.native.configuration);
  }
  if (Object.hasOwn(fragment, 'service')) assertRecord(fragment.service, `${label}.service`);
}

function validateResolved(config) {
  const resolved = { runner: config.runner, native: config.native };
  if (Object.hasOwn(config, 'service')) {
    validateServiceConfigurationShape(config.service, 'config.service');
    resolved.service = config.service;
  }
  validateFragment(resolved, 'config');
}

function validateChildEnvironment(environment, label) {
  assertRecord(environment, label);
  for (const [key, value] of Object.entries(environment)) {
    if (!NATIVE_ENVIRONMENT_KEYS.has(key)) throw new ConfigurationError('environment key is not allowed for an owned native child', `${label}.${key}`);
    if (typeof value !== 'string' || value.includes('\0')) throw new ConfigurationError('must be a string without NUL', `${label}.${key}`);
  }
}

function validateAbsolutePath(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) throw new ConfigurationError('must be an explicit absolute path without NUL', label);
  if (Buffer.byteLength(value, 'utf8') > 4096) throw new ConfigurationError('UTF-8 path exceeds 4096 bytes', label);
}

function assertRecord(value, label) {
  if (!isRecord(value)) throw new ConfigurationError('must be an object', label);
}

function assertKnownKeys(value, allowed, label) {
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new ConfigurationError('unknown key', `${label}.${key}`);
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function clone(value) {
  if (Array.isArray(value)) return value.map(clone);
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, clone(child)]));
  return value;
}

function collectLeaves(value, source, prefix, provenance) {
  if (isRecord(value) && Object.keys(value).length) {
    for (const [key, child] of Object.entries(value)) collectLeaves(child, source, prefix ? `${prefix}.${key}` : key, provenance);
  } else if (prefix) provenance[prefix] = source;
}

function mergeFragment(target, fragment, source, prefix, provenance) {
  for (const [key, child] of Object.entries(fragment)) {
    const name = prefix ? `${prefix}.${key}` : key;
    if (isRecord(child) && isRecord(target[key]) && !(prefix === 'native' && key === 'configuration')) {
      mergeFragment(target[key], child, source, name, provenance);
    } else {
      target[key] = clone(child);
      if (isRecord(child) && Object.keys(child).length) collectLeaves(child, source, name, provenance);
      else provenance[name] = source;
    }
  }
}

function flattenProvenance(provenance) {
  return Object.freeze(Object.fromEntries(Object.entries(provenance).sort(([left], [right]) => left.localeCompare(right))));
}

function deepFreeze(value) {
  if (Array.isArray(value) || isRecord(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
