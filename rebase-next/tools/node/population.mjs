import { createGeneratorSync } from 'json-schema-faker';
import { createHash } from 'node:crypto';
import { validateOperationPlan } from './private/operation-plan.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DEFINITE_NO_COMMIT = new Set([
  'invalid_input', 'forbidden', 'not_found', 'unavailable_reference', 'already_exists',
  'stale_version', 'transaction_conflict', 'transaction_aborted', 'transaction_limit',
  'model_mismatch', 'invariant', 'feedback', 'inexact', 'operation_conflict',
  'work_limit', 'state_limit', 'receipt_limit', 'request_limit', 'overflow',
]);

/** Prepare reusable population metadata from an already prepared native model. */
export function preparePopulation(model, counts, options = {}) {
  if (!model || !model.catalog || typeof model.validate !== 'function') {
    throw new TypeError('model must be a prepared native model');
  }
  const catalog = cloneJson(model.catalog, 'model catalog');
  const limits = catalog.capabilities?.limits;
  if (!isRecord(limits) || !(limits.public_records === null || (Number.isSafeInteger(limits.public_records) && limits.public_records >= 0))) {
    throw new TypeError('native catalog must publish public_records limits');
  }
  if (!isRecord(counts)) throw new TypeError('counts must be an object keyed by public contract name');
  const contracts = new Map();
  const codes = new Map();
  for (const entry of catalog.contracts ?? []) {
    if (entry.visibility !== 'public') continue;
    if (typeof entry.name !== 'string' || !Number.isSafeInteger(entry.code) || contracts.has(entry.name) || codes.has(entry.code)) {
      throw new TypeError('public catalog contracts need unique names and integer codes');
    }
    const schema = entry.schema ?? entry.input_schema;
    if (!isRecord(schema)) throw new TypeError(`public contract ${entry.name} has no input schema`);
    contracts.set(entry.name, Object.freeze({ name: entry.name, code: entry.code, schema, references: entry.references ?? [] }));
    codes.set(entry.code, entry.name);
  }
  if (contracts.size === 0) throw new TypeError('native catalog has no public contracts');
  const quotas = Object.fromEntries([...contracts.keys()].map(name => [name, counts[name] ?? 0]));
  for (const [name, value] of Object.entries(counts)) {
    if (!contracts.has(name)) throw new TypeError(`unknown or private contract in counts: ${name}`);
    nonnegativeInteger(value, `count for ${name}`);
  }
  if (limits.public_records !== null && Object.values(quotas).reduce((a, b) => a + b, 0) > limits.public_records) {
    throw new TypeError('requested quotas exceed native public_records limit');
  }
  const perContract = limits.per_contract ?? {};
  for (const [name, quota] of Object.entries(quotas)) {
    const cap = perContract[String(contracts.get(name).code)] ?? perContract[name];
    if (cap !== undefined && quota > cap) throw new TypeError(`requested quota exceeds ${name} per-contract limit`);
  }
  const batchSize = options.batchSize ?? Math.min(1, limits.commands ?? 64);
  nonnegativeInteger(batchSize, 'batchSize');
  if (batchSize < 1 || batchSize > Math.min(limits.commands ?? 64, 64)) throw new TypeError('batchSize exceeds native command limit');
  const seed = options.seed;
  if (!(typeof seed === 'string' || Number.isSafeInteger(seed))) throw new TypeError('seed must be a string or safe integer');
  for (const key of ['strategies', 'rules', 'priorities']) {
    if (options[key] !== undefined && !isRecord(options[key])) throw new TypeError(`${key} must be an object`);
    for (const name of Object.keys(options[key] ?? {})) if (!contracts.has(name)) throw new TypeError(`${key} contains unknown public contract ${name}`);
  }
  for (const [name, fn] of Object.entries(options.strategies ?? {})) if (typeof fn !== 'function') throw new TypeError(`strategy for ${name} must be callable`);
  for (const [name, fn] of Object.entries(options.rules ?? {})) if (typeof fn !== 'function') throw new TypeError(`rule for ${name} must be callable`);
  for (const [name, weight] of Object.entries(options.priorities ?? {})) nonnegativeInteger(weight, `priority for ${name}`);
  for (const key of ['selectReference', 'selectContract']) if (options[key] !== undefined && typeof options[key] !== 'function') throw new TypeError(`${key} must be callable`);
  if (options.clock !== undefined && typeof options.clock !== 'function') cloneJson(options.clock, 'clock');
  if (options.context !== undefined && typeof options.context !== 'function') cloneJson(options.context, 'context');
  const generators = new Map([...contracts.values()].map(contract => [
    contract.name,
    createGeneratorSync({ seed: seedNumber(seed, contract.code), alwaysFakeOptionals: true, useDefaultValue: true, maxDepth: 8 }),
  ]));
  const pools = Object.fromEntries([...contracts.keys()].map(name => [name, new Map()]));
  const poolIds = Object.fromEntries([...contracts.keys()].map(name => [name, []]));
  const identities = new Set();
  for (const [name, rows] of Object.entries(options.existing ?? {})) {
    if (!contracts.has(name) || !Array.isArray(rows)) throw new TypeError(`existing pool must name a public contract: ${name}`);
    for (const row of rows) {
      if (!isRecord(row) || row.contract !== name || typeof row.id !== 'string' || !UUID.test(row.id) || identities.has(row.id)) {
        throw new TypeError('existing rows need unique canonical IDs and their declared public contract');
      }
      if (row.fields !== undefined && !model.validate(name, row.fields).valid) throw new TypeError(`existing projection does not match ${name}`);
      const stored = Object.freeze({ id: row.id, contract: name, ...(row.fields === undefined ? {} : { fields: cloneJson(row.fields, 'existing fields') }) });
      pools[name].set(row.id, stored);
      poolIds[name].push(row.id);
      identities.add(row.id);
    }
  }
  if (limits.public_records !== null && identities.size + Object.values(quotas).reduce((a, b) => a + b, 0) > limits.public_records) {
    throw new TypeError('existing IDs plus requested quotas exceed native public_records lower-bound limit');
  }
  for (const [name, quota] of Object.entries(quotas)) {
    const cap = perContract[String(contracts.get(name).code)] ?? perContract[name];
    if (cap !== undefined && poolIds[name].length + quota > cap) throw new TypeError(`existing IDs plus quota exceed ${name} per-contract limit`);
  }
  const usage = validateInitialUsage(options.referenceUsage ?? {}, contracts);
  return {
    model, catalog, contracts, codes, quotas, accepted: Object.fromEntries([...contracts.keys()].map(name => [name, 0])),
    pools, poolIds, identities, seed, cursor: 0, batchSize, priorities: { ...(options.priorities ?? {}) },
    strategies: { ...(options.strategies ?? {}) }, rules: { ...(options.rules ?? {}) }, generators,
    selectReference: options.selectReference, selectContract: options.selectContract,
    clock: options.clock, context: options.context, referenceUsage: usage, pending: null,
    lastTarget: options.target === undefined ? null : cloneJson(options.target, 'target'), proposing: false,
  };
}

/** Produce a detached bounded proposal. It never submits or retries a mutation. */
export async function propose(state, context = state?.context, options = {}) {
  assertState(state);
  if (state.pending || state.proposing) throw populationError('proposal_pending', 'Accept or reject the current pending proposal first');
  if (context === undefined || (typeof context !== 'function' && !isRecord(context))) {
    throw populationError('missing_context', 'Provide a fresh context mapping or callback');
  }
  state.proposing = true;
  try { return await buildProposal(state, context, options); }
  finally { state.proposing = false; }
}

async function buildProposal(state, context, { maxCommands = state.batchSize } = {}) {
  nonnegativeInteger(maxCommands, 'maxCommands');
  if (maxCommands < 1 || maxCommands > state.batchSize) throw populationError('invalid_batch', 'maxCommands exceeds prepared batchSize');
  const rng = seededRandom(state.seed, state.cursor);
  const clockCache = new Map();
  const getClock = cursor => {
    if (state.clock === undefined) return undefined;
    if (!clockCache.has(cursor)) clockCache.set(cursor, cloneJson(typeof state.clock === 'function' ? state.clock(cursor) : state.clock, 'clock value'));
    return cloneJson(clockCache.get(cursor), 'clock value');
  };
  const selectedContracts = [];
  const remaining = Object.fromEntries([...state.contracts.keys()].map(name => [name, state.quotas[name] - state.accepted[name]]));
  for (let i = 0; i < maxCommands; i += 1) {
    const eligible = [...state.contracts.values()].filter(contract => remaining[contract.name] > 0
      && (state.priorities[contract.name] ?? 1) > 0 && prerequisitesAvailable(state, contract));
    if (!eligible.length) {
      if (!selectedContracts.length) throw populationError('stalled', 'No quota is currently eligible; add required typed anchors or change quotas');
      break;
    }
    const custom = await state.selectContract?.(Object.freeze(eligible.map(x => x.name)), Object.freeze({ ...remaining }), rng);
    const name = custom ?? weightedPick(eligible, eligible.map(x => remaining[x.name] * (state.priorities[x.name] ?? 1)), rng).name;
    if (!eligible.some(contract => contract.name === name)) throw populationError('invalid_selection', 'selectContract chose an ineligible contract');
    selectedContracts.push(name);
    remaining[name] -= 1;
  }
  const start = state.cursor;
  const ids = selectedContracts.map((_, i) => deterministicId(state.seed, start + i));
  if (new Set(ids).size !== ids.length || ids.some(id => state.identities.has(id))) throw populationError('identity_collision', 'Deterministic proposal ID collides with a known identity');
  const additions = [];
  const commands = [];
  const addedUsage = {};
  for (let index = 0; index < selectedContracts.length; index += 1) {
    const name = selectedContracts[index];
    const contract = state.contracts.get(name);
    const strategy = state.strategies[name];
    const strategyContext = {};
    const strategyClock = getClock(start + index);
    if (strategyClock !== undefined) strategyContext.clock = strategyClock;
    let fields;
    if (strategy) fields = await strategy(cloneJson(contract.schema, 'schema'), state.seed, start + index, frozenCopy(strategyContext));
    else {
      try { fields = state.generators.get(name).generate(contract.schema); }
      catch (cause) { throw populationError('generation_unsupported', `Schema generation for ${name} failed; provide an explicit strategy`, { cause }); }
    }
    if (!isRecord(fields)) throw populationError('invalid_generated_shape', `Base values for ${name} must be an object`);
    fields = cloneJson(fields, 'generated fields');
    const selected = {};
    for (const reference of contract.references) {
      const path = reference.field;
      const targets = [...state.contracts.values()].filter(target => (reference.targets ?? []).includes(target.code) && state.poolIds[target.name].length > 0);
      const current = getPathValues(fields, path);
      if (reference.optional && (!current.length || current.every(value => value === null))) continue;
      if (!targets.length) {
        if (reference.optional) continue;
        throw populationError('stalled', `Missing typed reference prerequisite for ${name}.${path}`);
      }
      const selectionContext = typeof context === 'function' ? {} : context;
      let picked;
      if (state.selectReference) {
        const view = Object.freeze(Object.fromEntries(targets.map(target => [target.name, Object.freeze([...state.pools[target.name].values()])] )));
        picked = await state.selectReference(name, path, view, Object.freeze({ ...state.referenceUsage }), rng, frozenCopy(selectionContext));
      } else {
        const target = weightedPick(targets, targets.map(item => state.poolIds[item.name].length), rng);
        picked = [target.name, state.poolIds[target.name][Math.floor(rng() * state.poolIds[target.name].length)]];
      }
      if (!Array.isArray(picked) || picked.length !== 2 || !state.pools[picked[0]]?.has(picked[1]) || !targets.some(target => target.name === picked[0])) {
        throw populationError('invalid_selection', `Reference selector chose an incompatible pool for ${name}.${path}`);
      }
      setDeclaredPath(fields, path, picked[1]);
      selected[path] = picked[1];
    }
    const fresh = typeof context === 'function' ? await context(name, frozenCopy(selected), start + index) : cloneJson(context, 'context');
    if (!isRecord(fresh)) throw populationError('invalid_context', 'Context callback must return a mapping');
    const withClock = { ...fresh };
    const clock = getClock(start + index);
    if (clock !== undefined) {
      if (Object.hasOwn(withClock, 'clock')) throw populationError('duplicate_clock', 'clock must come from the explicit clock option');
      withClock.clock = clock;
    }
    if (state.rules[name]) fields = await state.rules[name](cloneJson(fields, 'rule fields'), frozenCopy(withClock), frozenCopy(selected));
    if (!isRecord(fields)) throw populationError('invalid_generated_shape', `Final fields for ${name} must be an object`);
    fields = cloneJson(fields, 'final fields');
    const validation = state.model.validate(name, fields);
    if (!validation.valid) throw populationError('schema_invalid', `Final fields do not satisfy ${name}`, validation.errors);
    for (const reference of contract.references) {
      const allowed = [...state.contracts.values()].filter(target => (reference.targets ?? []).includes(target.code));
      const values = getPathValues(fields, reference.field);
      if (!values.length && !reference.optional && !reference.field.includes('[]') && !reference.field.includes('[*]')) {
        throw populationError('reference_invalid', `Required reference ${name}.${reference.field} is absent`);
      }
      for (const id of values) {
        if (id === null && reference.optional) continue;
        const target = allowed.find(item => typeof id === 'string' && state.pools[item.name].has(id));
        if (!target) throw populationError('reference_invalid', `Reference ${name}.${reference.field} is outside compatible typed pools`);
        const key = `${name}\0${reference.field}\0${target.name}\0${id}`;
        addedUsage[key] = (addedUsage[key] ?? 0) + 1;
      }
    }
    const id = ids[index];
    commands.push({ op: 'create', id, contract: contract.code, fields });
    additions.push({ id, contract: name, fields, references: selected });
  }
  if (Buffer.byteLength(JSON.stringify(commands)) > 65_536) throw populationError('proposal_too_large', 'Proposal exceeds 65536 command bytes');
  const proposal = { commands, returning: additions.slice(0, 32).map(row => row.id), additions, usage: addedUsage, startCursor: start, endCursor: start + additions.length };
  proposal.digest = proposalFingerprint(proposal);
  const pending = makePending(state, proposal);
  state.pending = pending;
  return proposal;
}

/** Advance committed population state after validating the native receipt. */
export function accept(state, proposal, plan, receipt) {
  const pending = bound(state, proposal, plan);
  if (!isRecord(receipt) || receipt.status !== 'committed' || !isRecord(receipt.result)
    || receipt.result.operation_id !== plan.request.operation_id
    || !UUID.test(receipt.result.revision ?? '') || !Array.isArray(receipt.result.records)) {
    throw populationError('receipt_invalid', 'accept requires the client committed receipt for the exact operation ID');
  }
  const nativeReceipt = receipt.result;
  const returned = nativeReceipt.records.map(row => row?.id);
  if (returned.length !== proposal.returning.length || returned.some((id, i) => id !== proposal.returning[i])) {
    throw populationError('receipt_invalid', 'Receipt returned IDs differ from the exact ordered request');
  }
  for (const row of nativeReceipt.records) if (!isRecord(row) || typeof row.id !== 'string' || (row.record !== undefined && row.record !== null && !isRecord(row.record))) {
    throw populationError('receipt_invalid', 'Receipt records have an invalid projection shape');
  }
  for (const addition of proposal.additions) {
    const name = addition.contract;
    state.pools[name].set(addition.id, Object.freeze({ id: addition.id, contract: name, fields: cloneJson(addition.fields, 'accepted fields') }));
    state.poolIds[name].push(addition.id);
    state.identities.add(addition.id);
    state.accepted[name] += 1;
  }
  for (const [key, amount] of Object.entries(proposal.usage)) state.referenceUsage[key] = (state.referenceUsage[key] ?? 0) + amount;
  state.cursor = proposal.endCursor;
  state.lastReceipt = nativeReceipt.operation_id;
  state.lastTarget ??= cloneJson(plan.target, 'plan target');
  state.pending = null;
  return state;
}

/** Release only an unbound proposal or an exact plan with a definite native rejection. */
export function reject(state, proposal, plan, outcome) {
  assertState(state);
  const pending = state.pending;
  if (!pending || pending.proposal !== proposal || pending.digest !== proposalFingerprint(proposal)) throw populationError('pending_mismatch', 'Only the exact current proposal may be rejected');
  if (plan === undefined && outcome === undefined) {
    if (pending.plan) throw populationError('plan_bound', 'A bound plan requires a definite no-commit server outcome');
    state.cursor = proposal.endCursor;
    state.pending = null;
    return state;
  }
  bound(state, proposal, plan);
  const kind = outcome?.code ?? outcome?.kind;
  if (outcome?.name !== 'RpcError' || outcome?.httpStatus !== 200 || !DEFINITE_NO_COMMIT.has(kind)
    || outcome?.outcomeUnknown === true || ['outcome_unknown', 'operation_expired', 'not_observed'].includes(kind)) {
    throw populationError('outcome_uncertain', 'Unknown outcomes retain the exact pending proposal and plan');
  }
  state.cursor = proposal.endCursor;
  state.pending = null;
  return state;
}

function makePending(state, proposal) {
  const proposalDigest = proposalFingerprint(proposal);
  let planSnapshot = null;
  const pending = { proposal, digest: proposalDigest };
  Object.defineProperty(pending, 'plan', {
    enumerable: true,
    get() { return planSnapshot && cloneJson(planSnapshot, 'bound plan'); },
    set(value) {
      if (proposalDigest !== proposalFingerprint(pending.proposal) || pending.proposal.digest !== proposalDigest) throw populationError('proposal_changed', 'Proposal changed before plan binding');
      validatePlanBinding(state, proposal, value);
      const encoded = cloneJson(value, 'plan');
      if (planSnapshot && digest(planSnapshot) !== digest(encoded)) throw populationError('plan_rebound', 'Pending plan binding is write-once');
      planSnapshot ??= deepFreeze(encoded);
    },
  });
  return Object.freeze(pending);
}

function validatePlanBinding(state, proposal, plan) {
  try { validateOperationPlan(plan); }
  catch (cause) { throw populationError('plan_invalid', 'Bind a complete client operation plan', { cause }); }
  if (plan.request.model !== state.catalog.model || plan.target.model !== state.catalog.model || !UUID.test(plan.request.operation_id ?? '')
    || digest(plan.request.commands) !== digest(proposal.commands) || digest(plan.request.returning) !== digest(proposal.returning)) {
    throw populationError('plan_mismatch', 'Plan model, operation ID, commands or returning IDs differ from proposal');
  }
  if (state.lastTarget && digest(plan.target) !== digest(state.lastTarget)) throw populationError('target_mismatch', 'Plan target differs from previously committed target');
}

function bound(state, proposal, plan) {
  assertState(state);
  const pending = state.pending;
  if (!pending || pending.proposal !== proposal || pending.digest !== proposalFingerprint(proposal) || proposal.digest !== pending.digest) throw populationError('pending_mismatch', 'Proposal is not the exact intact pending proposal');
  const boundPlan = pending.plan;
  if (!boundPlan || digest(boundPlan) !== digest(plan)) throw populationError('plan_unbound', 'Bind the exact plan on state.pending.plan before submission');
  validatePlanBinding(state, proposal, plan);
  return pending;
}

function validateInitialUsage(usage, contracts) {
  if (!isRecord(usage)) throw new TypeError('referenceUsage must be an object');
  const result = {};
  for (const [key, value] of Object.entries(usage)) {
    nonnegativeInteger(value, `referenceUsage ${key}`);
    const [child, path, parent, id] = key.split('\0');
    if (!contracts.has(child) || !contracts.has(parent) || typeof path !== 'string' || !UUID.test(id ?? '')) throw new TypeError('referenceUsage keys must encode child, path, parent and UUID');
    const declared = contracts.get(child).references.some(ref => ref.field === path && ref.targets.includes(contracts.get(parent).code));
    if (!declared) throw new TypeError(`referenceUsage is not declared by ${child}.${path}`);
    result[key] = value;
  }
  return result;
}

function prerequisitesAvailable(state, contract) {
  return contract.references.every(ref => ref.optional || [...state.contracts.values()].some(target => ref.targets.includes(target.code) && state.poolIds[target.name].length));
}
function weightedPick(items, weights, rng) {
  const total = weights.reduce((sum, weight) => sum + weight, 0);
  if (!(total > 0) || !Number.isFinite(total)) throw populationError('stalled', 'No positive selection weight remains');
  let choice = rng() * total;
  for (let i = 0; i < items.length; i += 1) if ((choice -= weights[i]) < 0) return items[i];
  return items.at(-1);
}
function seededRandom(seed, cursor) {
  let state = seedNumber(seed, cursor) || 1;
  return () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 0x1_0000_0000; };
}
function seedNumber(seed, cursor) { return Number.parseInt(createHash('sha256').update(`${typeof seed}:${seed}:${cursor}`).digest('hex').slice(0, 8), 16); }
function deterministicId(seed, cursor) { const hex = createHash('sha256').update(`rebase-population:${typeof seed}:${seed}:${cursor}`).digest('hex').slice(0, 32); return `${hex.slice(0,8)}-${hex.slice(8,12)}-5${hex.slice(13,16)}-a${hex.slice(17,20)}-${hex.slice(20)}`; }
function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function proposalFingerprint(proposal) { const { digest: _ignored, ...content } = proposal; return digest(content); }
function cloneJson(value, label) { assertJson(value, label); return JSON.parse(JSON.stringify(value)); }
function assertJson(value, label, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') { if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw new TypeError(`${label} contains an unsafe number`); return; }
  if (Array.isArray(value)) { if (seen.has(value)) throw new TypeError(`${label} is cyclic`); seen.add(value); for (const item of value) assertJson(item, label, seen); seen.delete(value); return; }
  if (!isRecord(value) || seen.has(value)) throw new TypeError(`${label} must be finite JSON`);
  seen.add(value); for (const [key, item] of Object.entries(value)) { if (item === undefined || typeof item === 'function' || typeof item === 'bigint' || typeof item === 'symbol') throw new TypeError(`${label} must be finite JSON`); assertJson(item, label, seen); } seen.delete(value);
}
function isRecord(value) { if (!value || typeof value !== 'object' || Array.isArray(value)) return false; const proto = Object.getPrototypeOf(value); return proto === Object.prototype || proto === null; }
function nonnegativeInteger(value, label) { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a nonnegative safe integer`); }
function frozenCopy(value) { return deepFreeze(cloneJson(value, 'callback input')); }
function deepFreeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const item of Object.values(value)) deepFreeze(item); Object.freeze(value); } return value; }
function assertState(state) { if (!state || !(state.contracts instanceof Map) || !Number.isSafeInteger(state.cursor)) throw new TypeError('state must come from preparePopulation'); }
function populationError(code, message, details) { const error = new TypeError(message); error.name = 'PopulationError'; error.code = code; if (details !== undefined) error.details = details; return error; }

function pathTokens(path) {
  if (typeof path !== 'string' || !path) throw populationError('reference_path', 'Reference declaration has an empty path');
  if (path.startsWith('/')) return path.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));
  const tokens = [];
  for (const match of path.matchAll(/(?:^|\.)([^.\[\]]+)|\[(\*|\d*)\]/g)) tokens.push(match[1] ?? (match[2] === '' || match[2] === '*' ? '*' : Number(match[2])));
  if (!tokens.length) throw populationError('reference_path', `Unsupported reference path ${path}`);
  return tokens;
}
function setDeclaredPath(root, path, replacement) {
  const tokens = pathTokens(path);
  const visit = (node, index) => {
    if (index === tokens.length) return replacement;
    const token = tokens[index];
    if (token === '*') {
      if (!Array.isArray(node)) throw populationError('reference_shape', `${path} expects an array`);
      return node.map(item => visit(item, index + 1));
    }
    if (Array.isArray(node)) {
      const at = typeof token === 'number' ? token : Number(token);
      if (!Number.isInteger(at) || at < 0 || at > node.length) throw populationError('reference_shape', `${path} has an invalid array position`);
      if (at === node.length) node.push(visit({}, index + 1)); else node[at] = visit(node[at], index + 1);
      return node;
    }
    if (isRecord(node)) {
      if (!Object.hasOwn(node, token)) node[token] = tokens[index + 1] === '*' || typeof tokens[index + 1] === 'number' ? [] : {};
      node[token] = visit(node[token], index + 1);
      return node;
    }
    throw populationError('reference_shape', `${path} has incompatible generated shape`);
  };
  return visit(root, 0);
}
function getPathValues(root, path) {
  const tokens = pathTokens(path);
  const visit = (node, index) => {
    if (index === tokens.length) return [node];
    const token = tokens[index];
    if (token === '*') return Array.isArray(node) ? node.flatMap(item => visit(item, index + 1)) : [];
    if (Array.isArray(node)) return visit(node[typeof token === 'number' ? token : Number(token)], index + 1);
    if (isRecord(node) && Object.hasOwn(node, token)) return visit(node[token], index + 1);
    return [];
  };
  return visit(root, 0);
}
