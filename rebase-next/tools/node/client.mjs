import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import {
  encodeJson, isObject, MAX_PLAN_BYTES, MAX_REQUEST_BYTES, PLAN_FORMAT, parseJson,
  requestOnce, rpcError,
} from './private/client-wire.mjs';
import { validateOperationDraft as validateDraft, validateOperationPlan as validatePlan } from './private/operation-plan.mjs';
import { persistWriteOnce } from './private/plan-files.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Create a stateless authenticated HTTP client. No request occurs until a method is called. */
export function connect({ endpoint: endpointInput, credential, timeoutMs = 20_000, allowRemoteHttp = false } = {}) {
  if (typeof allowRemoteHttp !== 'boolean') throw rpcError('invalid_endpoint_policy', 'allowRemoteHttp must be a boolean');
  const endpoint = normalizeEndpoint(endpointInput, { allowRemoteHttp });
  if (typeof credential !== 'string' && typeof credential !== 'function') {
    throw rpcError('invalid_token', 'credential must be a bearer token or an explicit token provider');
  }
  if (typeof credential === 'string') validateToken(credential);
  validateTimeout(timeoutMs);
  const rpc = (method, params, options = {}) => callAt(endpoint, credential, method, params, timeoutMs, options.signal);
  return Object.freeze({
    call(method, params = {}, options = {}) { return rpc(method, params, options); },
    async prepare(draft, { operationId = randomUUID(), signal } = {}) {
      const stableDraft = parseJson(encodeJson(draft, MAX_REQUEST_BYTES));
      validateDraft(stableDraft);
      validateUuid(operationId, 'operationId');
      const session = await rpc('session.describe', {}, { signal });
      validateSession(session);
      if (session.model !== stableDraft.model) throw rpcError('model_mismatch', 'Draft and server model differ');
      const plan = {
        format: PLAN_FORMAT,
        target: {
          url: endpoint.href,
          model: session.model,
          store: session.store,
          tenant: session.tenant,
          actor: session.actor,
          credential_epoch: session.credential_epoch,
        },
        request: {
          model: stableDraft.model,
          context: session.operation_context,
          operation_id: operationId,
          commands: stableDraft.commands,
          returning: stableDraft.returning,
        },
      };
      if (Object.hasOwn(stableDraft, 'fixture')) plan.fixture = stableDraft.fixture;
      const detached = parseJson(encodeJson(plan, MAX_PLAN_BYTES));
      validatePlan(detached);
      return deepFreeze(detached);
    },
    async execute(plan, { signal } = {}) {
      const stablePlan = parseJson(encodeJson(plan, MAX_PLAN_BYTES));
      validatePlan(stablePlan);
      await verifyCurrentTarget(rpc, endpoint, stablePlan.target, signal);
      return rpc('records.mutate', stablePlan.request, { signal });
    },
    async status(plan, { signal } = {}) {
      const stablePlan = parseJson(encodeJson(plan, MAX_PLAN_BYTES));
      validatePlan(stablePlan);
      await verifyCurrentTarget(rpc, endpoint, stablePlan.target, signal);
      const { model, context, operation_id } = stablePlan.request;
      return rpc('operations.status', { model, context, operation_id }, { signal });
    },
  });
}

/**
 * Publish a complete private intent artifact atomically, refusing to replace an existing path.
 * `plan_durability_unknown` means the complete target may already exist; retain and reconcile it.
 */
export async function savePlan(destination, plan) {
  validatePlan(plan);
  const data = Buffer.concat([encodeJson(plan, MAX_PLAN_BYTES - 1), Buffer.from('\n')]);
  if (data.byteLength > MAX_PLAN_BYTES) throw rpcError('invalid_plan', 'Plan exceeds the file limit');
  await persistWriteOnce(destination, data);
}

async function callAt(endpoint, credential, method, params, timeoutMs, signal) {
  if (typeof method !== 'string' || method.length === 0 || !isObject(params)) {
    throw rpcError('invalid_request', 'A method name and object params are required');
  }
  const stableParams = parseJson(encodeJson(params, MAX_REQUEST_BYTES));
  encodeJson({ jsonrpc: '2.0', id: randomUUID(), method, params: stableParams });
  const token = typeof credential === 'function' ? await credential() : credential;
  validateToken(token);
  return requestOnce(endpoint, token, method, stableParams, { timeoutMs, signal });
}

function normalizeEndpoint(value, { allowRemoteHttp = false } = {}) {
  let parsed;
  try { parsed = new URL(value); } catch { throw rpcError('invalid_endpoint', 'An HTTP(S) endpoint is required'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw rpcError('invalid_endpoint', 'An HTTP(S) endpoint without credentials, query or fragment is required');
  }
  if (parsed.protocol === 'http:' && !allowRemoteHttp && !isLoopbackHost(parsed.hostname)) {
    throw rpcError('invalid_endpoint_policy', 'Remote plaintext HTTP requires allowRemoteHttp: true');
  }
  if (!parsed.pathname || parsed.pathname === '/') parsed.pathname = '/rpc';
  return parsed;
}

function isLoopbackHost(hostname) {
  const host = hostname.toLowerCase();
  if (host === 'localhost' || host === '[::1]') return true;
  if (isIP(host) === 4) return Number(host.split('.')[0]) === 127;
  return false;
}

function validateToken(token) {
  if (typeof token !== 'string' || !token || Buffer.byteLength(token, 'utf8') > 16_384 || /\s/u.test(token)) {
    throw rpcError('invalid_token', 'A bounded bearer token without whitespace is required');
  }
}

function validateTimeout(timeoutMs) {
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) {
    throw rpcError('invalid_timeout', 'Timeout must be in (0, 300000] milliseconds');
  }
}

async function verifyCurrentTarget(rpc, endpoint, target, signal) {
  if (endpoint.href !== target.url) throw rpcError('target_mismatch', 'Plan belongs to a different endpoint');
  const session = await rpc('session.describe', {}, { signal });
  validateSession(session);
  for (const key of ['model', 'store', 'tenant', 'actor', 'credential_epoch']) {
    if (session[key] !== target[key]) throw rpcError('target_mismatch', `Plan belongs to a different ${key.replace('_', ' ')}`);
  }
}

function validateSession(value) {
  if (!isObject(value) || typeof value.model !== 'string' || !value.model || typeof value.operation_context !== 'string' || !value.operation_context) {
    throw rpcError('invalid_session', 'Server returned an invalid session identity');
  }
  for (const key of ['store', 'tenant', 'actor']) validateUuid(value[key], `session.${key}`);
  if (!Number.isSafeInteger(value.credential_epoch) || value.credential_epoch < 0) throw rpcError('invalid_session', 'Server returned an invalid credential epoch');
}

function validateUuid(value, name) {
  if (typeof value !== 'string' || !UUID.test(value)) throw rpcError('invalid_plan', `Canonical UUID required for ${name}`);
}


function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
