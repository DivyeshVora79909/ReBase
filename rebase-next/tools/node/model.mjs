import { createNativeAjv } from './private/config-validation.mjs';

const DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MODEL_SELECTOR = /^[a-z][a-z0-9-]{0,63}$/;

/**
 * Prepare reusable local validators and metadata from one native catalog.
 * Native semantic operations remain explicit methods on the supplied host.
 */
export function prepareModel(catalog, { native, selector } = {}) {
  if (typeof selector !== 'string' || !MODEL_SELECTOR.test(selector)) {
    throw new TypeError('selector must be a bounded lowercase native model selector');
  }
  const snapshot = cloneJson(catalog, 'catalog');
  const entries = validateCatalog(snapshot);
  if (native && (native.selection?.model !== snapshot.model || native.selection?.selector !== selector)) {
    throw new TypeError('Native handle selection does not match the supplied catalog and selector');
  }
  const ajv = createNativeAjv();
  const byName = new Map();
  const byCode = new Map();

  for (const entry of entries) {
    const validator = ajv.compile(entry.schema);
    const metadata = deepFreeze({
      code: entry.code,
      name: entry.name,
      visibility: entry.visibility,
      schema: entry.schema,
      references: entry.contract.references ?? [],
      contract: entry.contract,
    });
    byName.set(entry.name, { metadata, validator });
    byCode.set(entry.code, { metadata, validator });
  }
  deepFreeze(snapshot);

  const get = selector => {
    const result = typeof selector === 'number' ? byCode.get(selector) : byName.get(selector);
    if (!result) throw new TypeError(`Unknown contract ${String(selector)}`);
    return result;
  };
  const validate = (selector, value) => {
    const { validator } = get(selector);
    assertJsonValue(value, 'schema value');
    const valid = validator(value);
    return Object.freeze({
      valid,
      errors: valid ? [] : (validator.errors ?? []).map(error => Object.freeze({ ...error })),
    });
  };
  const callNative = (method, params) => {
    if (!native || typeof native[method] !== 'function') {
      throw new TypeError(`Native model handle does not provide ${method}()`);
    }
    return native[method](params);
  };

  return Object.freeze({
    identity: snapshot.model,
    selector,
    catalog: snapshot,
    contracts: Object.freeze([...byName.values()].map(({ metadata }) => metadata)),
    contract(selector) { return get(selector).metadata; },
    schema(selector) { return get(selector).metadata.schema; },
    validate,
    explain(selector) {
      const { metadata } = get(selector);
      return callNative('explain', { selector: metadata.name });
    },
    validateNative(selector, input) {
      const { metadata } = get(selector);
      const local = validate(metadata.name, input);
      if (!local.valid) throw new TypeError(`Input does not satisfy ${metadata.name} schema`);
      return callNative('validate', { code: metadata.code, input });
    },
    render(params) { return callNative('render', params); },
    fixtureCatalog() { return callNative('fixtureCatalog'); },
    fixturePlan({ name, namespace }) {
      if (typeof name !== 'string' || name.length === 0) throw new TypeError('fixture name is required');
      if (typeof namespace !== 'string' || !UUID.test(namespace)) throw new TypeError('fixture namespace must be a canonical UUID');
      return callNative('fixturePlan', { name, namespace });
    },
    draftFixture(records, { returning = [] } = {}) {
      if (!Array.isArray(records) || records.length === 0 || records.length > 64) throw new TypeError('fixture records must contain 1 to 64 rows');
      if (!Array.isArray(returning) || returning.some(id => typeof id !== 'string' || !UUID.test(id))) throw new TypeError('returning must contain canonical record IDs');
      const seenIds = new Set();
      const commands = records.map(record => {
        if (!record || typeof record !== 'object' || Array.isArray(record)) throw new TypeError('fixture record must be an object');
        if (Object.keys(record).some(key => !['contract', 'id', 'fields'].includes(key))) throw new TypeError('fixture record has an unknown field');
        const { contract: selector, id, fields } = record;
        const { metadata } = get(selector);
        if (metadata.visibility && metadata.visibility !== 'public') throw new TypeError(`Fixture records cannot author ${metadata.visibility} contract ${metadata.name}`);
        if (typeof id !== 'string' || !UUID.test(id)) throw new TypeError('fixture record id must be a canonical UUID');
        if (seenIds.has(id)) throw new TypeError('fixture record IDs must be unique');
        seenIds.add(id);
        const check = validate(metadata.name, fields);
        if (!check.valid) throw new TypeError(`Fixture record does not satisfy ${metadata.name} schema`);
        return Object.freeze({ op: 'create', id, contract: metadata.code, fields: cloneJson(fields, 'fixture fields') });
      });
      if (returning.some(id => !seenIds.has(id))) throw new TypeError('returning IDs must refer to supplied fixture records');
      if (new Set(returning).size !== returning.length) throw new TypeError('returning IDs must be unique');
      return deepFreeze({ model: snapshot.model, commands, returning: [...returning] });
    },
  });
}

function validateCatalog(catalog) {
  if (!isRecord(catalog) || !HASH.test(catalog.model ?? '') || !Array.isArray(catalog.contracts)) {
    throw new TypeError('catalog must contain a native model identity and contract array');
  }
  const dialect = catalog.schema_dialect;
  if (dialect !== undefined && dialect !== DIALECT) throw new TypeError('unsupported native schema dialect');
  const names = new Set();
  const codes = new Set();
  const result = [];
  for (const contract of catalog.contracts) {
    if (!isRecord(contract)) throw new TypeError('catalog contract must be an object');
    const { name, code } = contract;
    const schema = contract.schema ?? contract.input_schema;
    if (typeof name !== 'string' || !name || !Number.isSafeInteger(code) || code < 1 || code > 65535
      || names.has(name) || codes.has(code)) throw new TypeError('catalog contracts require unique names and u16 codes');
    if (!isRecord(schema) || schema.$schema !== DIALECT) throw new TypeError(`contract ${name} has an unsupported schema`);
    rejectRemoteReferences(schema, name);
    names.add(name);
    codes.add(code);
    result.push({
      contract,
      name,
      code,
      schema,
      visibility: contract.visibility ?? (contract.input_schema ? 'public' : undefined),
    });
  }
  if (result.length === 0) throw new TypeError('catalog has no contracts');
  return result;
}

function rejectRemoteReferences(value, name) {
  if (Array.isArray(value)) return value.forEach(item => rejectRemoteReferences(item, name));
  if (!isRecord(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (key === '$ref' || key === '$dynamicRef') {
      throw new TypeError(`contract ${name} contains a schema reference; native catalogs are self-contained`);
    }
    rejectRemoteReferences(child, name);
  }
}

function cloneJson(value, label) {
  try {
    assertJsonValue(value, label);
    const encoded = JSON.stringify(value);
    return JSON.parse(encoded);
  } catch {
    throw new TypeError(`${label} must be a finite JSON value`);
  }
}

function assertJsonValue(value, label, ancestors = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw new TypeError(`${label} contains an unsafe number`);
    return;
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError(`${label} must not be cyclic`);
    ancestors.add(value);
    for (const item of value) assertJsonValue(item, label, ancestors);
    ancestors.delete(value);
    return;
  }
  if (!isRecord(value) || ancestors.has(value)) throw new TypeError(`${label} must be a finite JSON value`);
  ancestors.add(value);
  for (const [key, item] of Object.entries(value)) {
    if (item === undefined || typeof item === 'function' || typeof item === 'symbol' || typeof item === 'bigint') {
      throw new TypeError(`${label} must be a finite JSON value`);
    }
    assertJsonValue(item, label, ancestors);
  }
  ancestors.delete(value);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
