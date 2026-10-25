import JSONbigFactory from 'json-bigint';

const strictJson = JSONbigFactory({ strict: true });
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });

export function parseFrame(bytes) {
  let text;
  try { text = fatalUtf8.decode(bytes); }
  catch { throw protocolError('Invalid UTF-8 frame'); }
  let parsed;
  try { parsed = strictJson.parse(text); }
  catch { throw protocolError('Invalid JSON frame'); }
  try { return normalizeParsed(parsed); }
  catch (error) {
    if (error?.code === 'protocol_error') throw error;
    throw protocolError('Invalid JSON response value');
  }
}

export function encodeFrame(value, maximumBytes) {
  validateJsonValue(value);
  let serialized;
  try { serialized = JSON.stringify(value); }
  catch { throw protocolError('Request is not serializable JSON'); }
  const bytes = Buffer.from(serialized, 'utf8');
  if (bytes.byteLength > maximumBytes) throw protocolError('Request byte limit');
  return Buffer.concat([bytes, Buffer.from('\n')]);
}

export function assertWellFormedString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw protocolError('Unpaired UTF-16 surrogate');
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw protocolError('Unpaired UTF-16 surrogate');
    }
  }
}

function normalizeParsed(value, depth = 0) {
  if (depth > 128) throw protocolError('Response nesting limit');
  if (isBigNumber(value)) {
    const integer = BigInt(value.toString());
    if (integer < BigInt(Number.MIN_SAFE_INTEGER) || integer > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw protocolError('Unsafe JSON integer; exact integers must be decimal strings');
    }
    return Number(integer);
  }
  if (typeof value === 'string') {
    assertWellFormedString(value);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw protocolError('Invalid or unsafe JSON number');
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(child => normalizeParsed(child, depth + 1));
  if (value && typeof value === 'object') {
    const normalized = {};
    for (const [key, child] of Object.entries(value)) {
      assertWellFormedString(key);
      Object.defineProperty(normalized, key, { value: normalizeParsed(child, depth + 1), enumerable: true, writable: false, configurable: false });
    }
    return normalized;
  }
  return value;
}

function validateJsonValue(value, depth = 0, seen = new Set()) {
  if (depth > 128) throw protocolError('Request nesting limit');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') return assertWellFormedString(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw protocolError('Invalid or unsafe JSON number');
    return;
  }
  if (typeof value !== 'object' || typeof value === 'bigint') throw protocolError('Request contains a non-JSON value');
  if (seen.has(value)) throw protocolError('Request contains a cycle');
  seen.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) throw protocolError('Sparse arrays are not JSON data');
      validateJsonValue(value[index], depth + 1, seen);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw protocolError('Request objects must be plain data');
    if (Object.getOwnPropertySymbols(value).length) throw protocolError('Symbol keys are not JSON data');
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (!descriptor.enumerable) throw protocolError('Non-enumerable properties are not JSON data');
      if (!Object.hasOwn(descriptor, 'value')) throw protocolError('Accessor properties are not JSON data');
      assertWellFormedString(key);
      validateJsonValue(descriptor.value, depth + 1, seen);
    }
  }
  seen.delete(value);
}

function isBigNumber(value) {
  return value !== null && typeof value === 'object' && value.constructor?.name === 'BigNumber' && typeof value.toString === 'function';
}

function protocolError(message) {
  const error = new TypeError(message);
  error.name = 'NativeProtocolError';
  error.code = 'protocol_error';
  return error;
}
