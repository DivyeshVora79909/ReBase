const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const METHODS = Object.freeze({
  'store.check': ['check', (native, scope, _params, options) => native.check(options)],
  'store.inspect': ['inspect', (native, scope, _params, options) => native.inspect(options)],
  'store.backup': ['snapshot', (native, scope, params, options) => native.backup({ scope, destination: params.destination }, options)],
  'store.restore': ['restore', (native, scope, params, options) => native.restore({
    scope,
    backup: params.backup,
    expect_backup_store: params.expectBackupStore,
    destination: params.destination,
  }, options)],
  'store.archive': ['archive', (native, scope, params, options) => native.archive({ scope, destination: params.destination }, options)],
  'store.reset': ['reset', (native, scope, params, options) => native.reset({ scope, expect_store: params.expectStore }, options)],
  'service.start': ['startService', (native, scope, params, options) => native.startService({ scope, config: params.config }, options)],
  'service.stop': ['stopService', (native, scope, params, options) => native.stopService({ scope, service: params.service }, options)],
  'identity.issue': ['issueIdentity', (native, scope, params, options) => native.issueIdentity({
    scope,
    identity: params.identity,
    request: params.request,
    private_key_pem: params.privateKeyPem,
  }, options)],
});

/** Narrow methods over an already-owned host. This function never opens a store or process. */
export function openOperator(native, requested) {
  if (!isRecord(native) || !isRecord(requested) || !isRecord(requested.scope) || !Array.isArray(requested.methods)) {
    throw new TypeError('openOperator requires an existing native handle, exact scope, and method list');
  }
  const { model, store } = requested.scope;
  if (!HASH.test(model ?? '') || !UUID.test(store ?? '')) throw new TypeError('operator scope requires the native model hash and store UUID');
  if (!isRecord(native.scope) || native.scope.model !== model || native.scope.store !== store) {
    throw operatorError('wrong_target', 'Operator scope does not match the host-owned store');
  }
  if (!Array.isArray(native.grants)) throw new TypeError('Native host does not expose its configured grants');
  const grants = new Set(native.grants);
  const selected = new Set();
  for (const method of requested.methods) {
    if (!Object.hasOwn(METHODS, method)) throw new TypeError(`Unsupported N2 operator method ${String(method)}`);
    if (selected.has(method)) throw new TypeError(`Duplicate operator method ${method}`);
    if (!grants.has(method)) throw operatorError('forbidden', `Native host did not grant ${method}`);
    selected.add(method);
  }

  const scope = Object.freeze({ model, store });
  const handle = { scope, grants: Object.freeze([...selected].sort()) };
  for (const method of selected) {
    const [name, invoke] = METHODS[method];
    handle[name] = (params = {}, options = {}) => {
      if (!isRecord(params) || !isRecord(options)) return Promise.reject(new TypeError(`${name} requires object arguments`));
      try { return invoke(native, scope, params, options); }
      catch (error) { return Promise.reject(error); }
    };
  }
  return Object.freeze(handle);
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function operatorError(code, message) {
  const error = new Error(message);
  error.name = 'NativeOperatorError';
  error.code = code;
  return error;
}
