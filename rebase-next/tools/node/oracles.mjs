/**
 * Source-only expectations for the bounded public Equipment, Quantity and
 * Measurement models. Inputs are authored facts: { id: { contract, fields } }.
 * These functions intentionally do not call a model, native host or cache.
 */
import { checkBackupStructure } from './storage-check.mjs';

export class OracleError extends Error {
  constructor(kind, message) { super(message); this.name = 'OracleError'; this.kind = kind; }
}

/**
 * The private native `inspect` snapshot exposes records, root addresses and
 * summaries, query descriptors, role bindings, and root revisions. It does not
 * expose B-tree nodes, child links, heights, leaf order, or cached node
 * aggregates. Native `store.check` can report engine integrity, but is not an
 * independent structural oracle; independent physical structure remains owed
 * to N5 through a typed backup or physical snapshot.
 */
export const SNAPSHOT_STRUCTURE_SCOPE = Object.freeze({
  visible: Object.freeze(['record inventory', 'root inventory/revision/summary', 'query descriptor inventory', 'role binding inventory']),
  unavailable: Object.freeze(['tree node inventory', 'child links', 'tree heights', 'leaf ordering', 'per-node aggregates']),
  authority: 'native store.check validates engine integrity but is not an independent source oracle; independent structural-tree obligations remain owed to N5/N6',
});

const REFERENCES = new Set(['pool', 'instrument', 'parent', 'left', 'right', 'account']);
const fail = (condition, kind, message) => { if (!condition) throw new OracleError(kind, message); };

/** Apply commands to a detached source map, preserving authored command order. */
export function stageSources(facts, commands) {
  assertFacts(facts);
  if (!Array.isArray(commands)) throw new TypeError('commands must be an array');
  const proposed = clone(facts);
  for (const command of commands) {
    if (!command || typeof command !== 'object') throw new TypeError('command must be an object');
    const { id, op } = command;
    if (typeof id !== 'string') throw new TypeError('command id must be a string');
    if (op === 'create') {
      fail(!Object.hasOwn(proposed, id), 'already_exists', 'Source already exists');
      const fields = clone(command.fields);
      fail(fields && typeof fields === 'object' && !Array.isArray(fields), 'invalid_request', 'Create fields must be an object');
      for (const field of REFERENCES) if (Object.hasOwn(fields, field)) {
        fail(Object.hasOwn(proposed, fields[field]), 'unavailable_reference', 'New parents precede children');
      }
      proposed[id] = { contract: command.contract, fields };
    } else if (op === 'update') {
      fail(Object.hasOwn(proposed, id), 'not_found', 'Source to update is absent');
      const fields = command.set ?? {};
      for (const field of REFERENCES) if (Object.hasOwn(fields, field)) {
        fail(Object.hasOwn(proposed, fields[field]), 'unavailable_reference', 'Retarget parent is absent');
      }
      Object.assign(proposed[id].fields, clone(fields));
      for (const field of command.unset ?? []) delete proposed[id].fields[field];
    } else if (op === 'delete') {
      fail(Object.hasOwn(proposed, id), 'not_found', 'Source to delete is absent');
      delete proposed[id];
    } else throw new OracleError('invalid_request', 'Unknown command');
  }
  return proposed;
}

/** Return independently derived source values, roots and declared dependencies. */
export function evaluateSources(model, facts) {
  assertFacts(facts);
  if (model === 'equipment') return equipment(facts);
  if (model === 'quantity') return quantity(facts);
  if (model === 'measurement') return measurement(facts);
  throw new TypeError(`No source oracle for ${model}`);
}

/** Build a plain checker callback suitable for workload checkRun. */
export function sourceOracle({ model, facts, select, snapshot: snapshotSelector } = {}) {
  if (select !== undefined && typeof select !== 'function') throw new TypeError('select must be a function');
  const expected = evaluateSources(model, facts);
  return ({ observations, ...context }) => {
    const obligations = [];
    const actual = observations.filter(row => row.action === true && row.status === 'completed');
    if (select && !actual.length) obligations.push({ name: 'source-observations', status: 'incomplete', reason: 'no completed action observations' });
    for (const row of select ? actual : []) {
      try {
        const projected = select(row.value, row);
        const wanted = projected?.sourceId ? expected.derived[projected.sourceId] : expected;
        const observed = projected?.sourceId ? projected.derived : projected;
        const equal = stable(observed) === stable(wanted);
        obligations.push({ name: `source:${row.id}`, status: equal ? 'passed' : 'failed',
          ...(equal ? {} : { reason: 'raw observation differs from the source-derived expectation' }) });
      } catch (error) {
        obligations.push({ name: `source:${row.id}`, status: 'failed', reason: error.message });
      }
    }
    let captured;
    try {
      if (typeof snapshotSelector === 'function') captured = snapshotSelector({ observations, ...context });
      else if (snapshotSelector !== undefined) captured = snapshotSelector;
      else captured = observations.find(row => isNativeSnapshot(row.value?.snapshot))?.value.snapshot
        ?? observations.find(row => isNativeSnapshot(row.value))?.value;
      if (!isNativeSnapshot(captured)) obligations.push({ name: 'source-snapshot', status: 'incomplete',
        reason: 'retained observations contain no complete native inspect snapshot' });
      else obligations.push(...checkSourceSnapshot({ model, facts, snapshot: captured }).obligations);
    } catch (error) {
      obligations.push({ name: 'source-snapshot', status: 'failed', reason: error.message });
    }
    return obligations;
  };
}

/** Check a retained native inspect snapshot using only authored source facts. */
export function checkSourceSnapshot({ model, facts, snapshot, roleHistory } = {}) {
  const obligations = [];
  const add = (name, passed, reason) => obligations.push({ name, status: passed ? 'passed' : 'failed', ...(passed ? {} : { reason }) });
  let expected;
  try { expected = evaluateSources(model, facts); }
  catch (error) { return Object.freeze({ status: 'failed', structuralScope: SNAPSHOT_STRUCTURE_SCOPE,
    obligations: Object.freeze([{ name: 'source-facts', status: 'failed', reason: error.message }]) }); }
  if (!isNativeSnapshot(snapshot)) return Object.freeze({ status: 'failed', structuralScope: SNAPSHOT_STRUCTURE_SCOPE,
    obligations: Object.freeze([{ name: 'snapshot-shape', status: 'failed', reason: 'snapshot must retain records, roots, queries and roles arrays' }]) });

  const wantedIds = Object.keys(facts).sort();
  const recordRows = uniqueRows(snapshot.records, row => row?.id, 'record');
  const privateOutputs = expected.privateRecords ?? [];
  const publicRows = [...recordRows].filter(([, row]) => row?.record?.contract !== 900);
  const actualIds = publicRows.map(([id]) => id).sort();
  const privateRows = [...recordRows.values()].filter(row => row?.record?.contract === 900);
  const allowedContracts = model === 'equipment' ? [101, 205, 410, 900]
    : model === 'quantity' ? [101, 205, 309] : [101, 211, 307, 419];
  const unknownRows = [...recordRows.values()].filter(row => !allowedContracts.includes(row?.record?.contract));
  add('source-inventory', !recordRows.duplicate && same(actualIds, wantedIds) && privateRows.length === privateOutputs.length && unknownRows.length === 0,
    'native authored or derived record inventory is missing, extra, duplicated, or malformed');
  let inputsMatch = actualIds.length === wantedIds.length;
  let derivedMatch = actualIds.length === wantedIds.length;
  for (const id of wantedIds) {
    const row = recordRows.get(id)?.record;
    if (!row || row.contract !== facts[id].contract || !same(row.input, facts[id].fields)) inputsMatch = false;
    if (!row || !same(row.derived ?? null, expected.derived[id] ?? null)) derivedMatch = false;
  }
  add('source-contract-and-inputs', inputsMatch, 'a retained record contract or exact authored input fields differ');
  add('source-derived-values', derivedMatch, 'a retained derived record value differs from the source-only expectation');
  const privateKey = row => [row?.record?.input?.producer, row?.record?.input?.role].join('\0');
  const expectedPrivate = new Map(privateOutputs.map(row => [privateKey({ record: { input: row } }), row]));
  const actualPrivate = new Map(privateRows.map(row => [privateKey(row), row]));
  const privateMatch = privateRows.length === privateOutputs.length && expectedPrivate.size === privateOutputs.length
    && actualPrivate.size === privateRows.length && [...expectedPrivate].every(([key, wanted]) => {
      const actual = actualPrivate.get(key)?.record;
      return actual && same(actual.input, wanted) && actual.derived === null;
    });
  if (privateOutputs.length || privateRows.length) add('private-output-records', privateMatch,
    'engine output records do not match source-derived active Equipment roles');

  const wantedRoots = expected.roots.map(row => ({ id: row.owner, slot: row.slot })).sort(addressSort);
  const rootRows = uniqueRows(snapshot.roots, row => addressKey(row?.root), 'root');
  const actualRoots = [...rootRows.keys()].map(parseAddressKey).sort(addressSort);
  add('root-inventory', !rootRows.duplicate && same(actualRoots, wantedRoots), 'native root addresses are missing, extra, duplicated, or malformed');
  let summariesMatch = !rootRows.duplicate && actualRoots.length === wantedRoots.length;
  for (const item of expected.roots) {
    const row = rootRows.get(addressKey({ id: item.owner, slot: item.slot }));
    const summary = rootSummaryExpectation(model, item);
    const actualSummary = row?.summary;
    if (item.prefixOrderKnown === false && model === 'equipment') {
      const actualValue = actualSummary?.value;
      const expectedValue = summary.value;
      const actualWithoutPrefixes = actualValue && Object.fromEntries(Object.entries(actualValue).filter(([key]) => !['min_prefix', 'max_prefix'].includes(key)));
      const expectedWithoutPrefixes = Object.fromEntries(Object.entries(expectedValue).filter(([key]) => !['min_prefix', 'max_prefix'].includes(key)));
      if (!actualSummary || actualSummary.kind !== summary.kind || !same(actualWithoutPrefixes, expectedWithoutPrefixes)) summariesMatch = false;
    } else if (!row || !same(row.summary, summary)) summariesMatch = false;
    if (row && (typeof row.revision !== 'string' || row.revision.length === 0)) summariesMatch = false;
  }
  add('root-summaries', summariesMatch, 'a root summary differs from independently recomputed source totals or lacks a retained revision');
  if (model === 'equipment' && expected.roots.some(root => root.prefixOrderKnown === false)) obligations.push({
    name: 'root-prefix-extrema-order', status: 'incomplete',
    reason: 'equal-time mixed-sign leaf ordering is absent from inspect, so min/max prefix extrema cannot be independently ordered',
  });

  const wantedQueries = expected.dependencies.filter(dep => model !== 'quantity' && (model !== 'equipment' || dep.active !== false))
    .map(dep => ({ id: dep.source, slot: dep.query_slot })).sort(addressSort);
  const queryRows = uniqueRows(snapshot.queries, row => addressKey(row?.query), 'query');
  const actualQueries = [...queryRows.keys()].map(parseAddressKey).sort(addressSort);
  add('query-inventory', !queryRows.duplicate && same(actualQueries, wantedQueries), 'native query descriptor addresses are missing, extra, duplicated, or malformed');
  const currentRoles = Object.entries(facts).flatMap(([id, row]) => model === 'equipment' && row.contract === 410 && row.fields.active
    ? [11, 29].map(slot => ({ id, slot })) : []).sort(addressSort);
  const currentRoleKeys = new Set(currentRoles.map(addressKey));
  const roleRows = uniqueRows(snapshot.roles, row => addressKey(row?.source_role), 'role');
  const actualRoles = [...roleRows.keys()].map(parseAddressKey).sort(addressSort);
  let history;
  try { history = validateRoleHistory(roleHistory); }
  catch (error) { add('role-history', false, error.message); }
  const historicalRoles = actualRoles.filter(address => !currentRoleKeys.has(addressKey(address)));
  const wantedRoles = history ? [...history.values()].map(row => ({ id: row.producer, slot: row.role })).sort(addressSort)
    : [...currentRoles, ...historicalRoles].sort(addressSort);
  const wantedRoleKeys = new Set(wantedRoles.map(addressKey));
  add('role-inventory', !roleRows.duplicate && same(actualRoles, wantedRoles)
    && currentRoles.every(address => wantedRoleKeys.has(addressKey(address)))
    && (model === 'equipment' || actualRoles.length === 0),
  'native role bindings are missing, extra, duplicated, or malformed');
  if (model === 'equipment' && historicalRoles.length && roleHistory === undefined) obligations.push({
    name: 'role-history-inventory', status: 'incomplete',
    reason: 'current facts cannot establish historical inactive or deleted producer reservations; supply retained roleHistory identities',
  });
  const queryContentsMatch = expected.dependencies.filter(dep => model !== 'quantity' && (model !== 'equipment' || dep.active !== false))
    .every(dep => {
      const row = queryRows.get(addressKey({ id: dep.source, slot: dep.query_slot }));
      const descriptor = row?.descriptor;
      const source = { id: model === 'equipment' ? dep.pool : dep.instrument, slot: 7 };
      const contract = facts[dep.source]?.contract;
      const operation = model === 'equipment' ? 'sum' : contract === 307 ? 'summary' : 'latest';
      const channel = model === 'equipment' ? 'amount' : contract === 307 ? 'statistics' : 'observation';
      const expectedResult = model === 'equipment' ? expected.derived[dep.source]?.available_before : expected.queryResults?.[dep.source];
      return descriptor && same(Object.keys(descriptor).sort(), ['source', 'operation', 'phase', 'channel', 'range', 'selected', 'result'].sort())
        && same(descriptor.source, source) && descriptor.operation === operation
        && descriptor.phase === 'calculate' && descriptor.channel === channel
        && same(descriptor.range, dep.range)
        && same(descriptor.result, expectedResult) && descriptor.selected === null;
    });
  if (wantedQueries.length) add('query-descriptor-contents', queryContentsMatch,
    'query descriptor source, operation, phase, channel, range, result, or selected identity differs from source facts');
  const outputIdentities = new Set();
  const producers = new Set(actualRoles.map(row => row.id));
  const roleContentsMatch = wantedRoles.every(address => {
    const binding = roleRows.get(addressKey(address))?.binding;
    if (!binding || typeof binding.output !== 'string' || typeof binding.retired !== 'boolean'
      || !same(Object.keys(binding).sort(), ['output', 'retired'])
      || ![11, 29].includes(address.slot) || outputIdentities.has(binding.output)
      || Object.hasOwn(facts, binding.output) || producers.has(binding.output)) return false;
    outputIdentities.add(binding.output);
    const witness = history?.get(addressKey(address));
    if (history && witness?.output !== binding.output) return false;
    const producer = facts[address.id];
    if (binding.retired !== !producer || (producer && producer.contract !== 410)) return false;
    const output = recordRows.get(binding.output)?.record;
    if (!producer?.fields.active) return output === undefined;
    const expected = expectedPrivate.get(addressKey(address));
    return Boolean(expected && output?.contract === 900 && same(output.input, expected) && output.derived === null);
  });
  if (wantedRoles.length) add('role-binding-contents', roleContentsMatch,
    'role binding is retired, points at the wrong output, or has inconsistent private output facts');
  for (const [name, fact] of [
    ['tree-node-inventory', 'node identities and node count'],
    ['tree-child-links', 'left/right/parent links'],
    ['tree-heights', 'stored and derived heights'],
    ['tree-leaf-order', 'complete leaf ordering'],
    ['tree-node-aggregates', 'per-node cached aggregates'],
  ]) obligations.push({ name, status: 'incomplete', reason: `inspect does not expose ${fact}; independent source verification remains owed to N5/N6` });
  return Object.freeze({ status: obligations.some(row => row.status === 'failed') ? 'failed'
      : obligations.some(row => row.status === 'incomplete') ? 'incomplete' : 'passed',
    structuralScope: SNAPSHOT_STRUCTURE_SCOPE, obligations: Object.freeze(obligations.map(Object.freeze)) });
}

/** Check source semantics and physical trees from one retained complete backup.
 * roleHistory is an optional bounded identity witness: [{producer, role, output}].
 * It lists every reservation ever allocated, including currently active ones.
 * Identities come from retained committed observations, never guessed UUIDs.
 */
export function checkSourceBackup({ model, facts, backup, roleHistory } = {}) {
  const obligations = [];
  const add = (name, status, reason) => obligations.push({ name, status, ...(reason ? { reason } : {}) });
  let bytes, physical, snapshot, expected;
  try {
    fail(typeof backup === 'string' || backup instanceof Uint8Array, 'backup_input', 'backup must be a UTF-8 string or Uint8Array');
    const byteLength = typeof backup === 'string' ? Buffer.byteLength(backup, 'utf8') : backup.byteLength;
    fail(byteLength > 0 && byteLength <= 64 * 1024 * 1024, 'backup_input', 'backup byte limit');
    bytes = typeof backup === 'string' ? Buffer.from(backup, 'utf8') : Buffer.from(backup);
    physical = checkBackupStructure(bytes, { includeObservation: true });
    snapshot = physical.observation;
    expected = evaluateSources(model, facts);
  } catch (error) {
    return Object.freeze({ status: 'failed', obligations: Object.freeze([
      Object.freeze({ name: 'complete-backup', status: 'failed', reason: error.message }),
    ]) });
  }
  const logical = checkSourceSnapshot({ model, facts, snapshot, roleHistory });
  const physicalNames = new Set(['tree-node-inventory', 'tree-child-links', 'tree-heights', 'tree-leaf-order', 'tree-node-aggregates', 'root-prefix-extrema-order']);
  obligations.push(...logical.obligations.filter(row => !physicalNames.has(row.name)));
  if (model === 'equipment' && roleHistory === undefined && !obligations.some(row => row.name === 'role-history-inventory')) {
    add('role-history-inventory', 'incomplete',
      'supply retained roleHistory identities to establish the complete historical reservation inventory, including absence');
  }
  try {
    const expectedRoots = new Map(expected.roots.map(row => [`${row.owner}/${row.slot}`, { kind: model === 'equipment' ? 1 : 7 }]));
    const expectedMembers = new Map();
    const roleRows = new Map(snapshot.roles.map(row => [addressKey(row.source_role), row.binding]));
    const put = (id, slot, root, time, leaf) => {
      const token = `${id}/${slot}`;
      fail(!expectedMembers.has(token), 'source_membership', 'independent membership identity is duplicated');
      expectedMembers.set(token, { root: { id: root, slot: 7 }, time: String(time), leaf });
    };
    for (const [id, row] of Object.entries(facts)) {
      if (model === 'equipment' && row.contract === 205) put(id, 17, row.fields.pool, row.fields.at,
        { kind: 'financial', value: String(row.fields.quantity) });
      if (model === 'measurement' && row.contract === 211) put(id, 17, row.fields.instrument, row.fields.at,
        { unit: row.fields.unit, value: String(row.fields.value) });
    }
    for (const output of expected.privateRecords ?? []) {
      const binding = roleRows.get(addressKey({ id: output.producer, slot: output.role }));
      fail(binding && binding.retired === false, 'source_membership', 'active source output role is missing');
      put(binding.output, 23, output.pool, output.at, { kind: 'financial', value: output.quantity });
    }
    physical = checkBackupStructure(bytes, { expectedMembers, expectedRoots });
    add('source-physical-membership', 'passed');
    for (const name of physicalNames) if (name !== 'root-prefix-extrema-order' || model === 'equipment') add(name, 'passed');
  } catch (error) { add('source-physical-membership', 'failed', error.message); }
  const reserved = uniqueRows(snapshot.reserved, row => row?.id, 'reservation');
  const roles = uniqueRows(snapshot.roles, row => addressKey(row?.source_role), 'role');
  const inverse = !reserved.duplicate && !roles.duplicate && reserved.size === roles.size
    && [...roles].every(([key, row]) => {
      const address = reserved.get(row.binding?.output)?.source_role;
      return address && same(Object.keys(address).sort(), ['id', 'slot']) && addressKey(address) === key;
    });
  add('role-reservation-inverse', inverse ? 'passed' : 'failed', inverse ? undefined : 'reserved identities and producer-role bindings are not bijective');
  const result = { status: obligations.some(row => row.status === 'failed') ? 'failed'
    : obligations.some(row => row.status === 'incomplete') ? 'incomplete' : 'passed',
  scope: 'bounded source records, queries, roles, roots and complete physical trees; other native inventories are outside this checker',
  physical: Object.freeze(Object.fromEntries(Object.entries(physical).filter(([name]) => name !== 'observation'))),
  obligations: Object.freeze(obligations.map(Object.freeze)) };
  return Object.freeze(result);
}

function validateRoleHistory(history) {
  if (history === undefined) return undefined;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  fail(Array.isArray(history) && history.length <= 16_384, 'role_history', 'roleHistory must be an array of at most 16384 reservations');
  const roles = new Map(), outputs = new Set();
  for (const row of history) {
    fail(row && typeof row === 'object' && !Array.isArray(row)
      && same(Object.keys(row).sort(), ['producer', 'role', 'output'].sort())
      && typeof row.producer === 'string' && typeof row.output === 'string'
      && uuid.test(row.producer) && uuid.test(row.output) && [11, 29].includes(row.role), 'role_history', 'invalid roleHistory identity');
    const key = addressKey({ id: row.producer, slot: row.role });
    fail(!roles.has(key) && !outputs.has(row.output), 'role_history', 'roleHistory identities are not bijective');
    roles.set(key, row); outputs.add(row.output);
  }
  return roles;
}

function equipment(facts) {
  fail(Object.keys(facts).length <= 4096, 'state_limit', 'Equipment source bound');
  const events = new Map();
  const derived = {};
  const dependencies = [];
  const poolRows = Object.entries(facts).filter(([, row]) => row.contract === 101);
  for (const [id] of poolRows) events.set(id, []);
  for (const [id, row] of Object.entries(facts)) {
    const f = row.fields;
    fail([101, 205, 410].includes(row.contract), 'contract', 'Public equipment contract required');
    if (row.contract === 101) {
      fail(Number.isInteger(f.unit) && f.unit >= 1 && f.unit <= 65535, 'invariant', 'Unit code');
    } else if (row.contract === 205) {
      fail(events.has(f.pool), 'unavailable_reference', 'Delivery pool type/existence');
      const at = integer(f.at, 'delivery time');
      const quantity = integer(f.quantity, 'delivery quantity');
      fail(quantity >= 0n, 'invariant', 'Nonnegative delivery');
      events.get(f.pool).push([at, quantity]);
    } else {
      fail(events.has(f.pool), 'unavailable_reference', 'Reservation pool type/existence');
      const starts = integer(f.starts, 'reservation start'), ends = integer(f.ends, 'reservation end');
      const requested = integer(f.requested, 'reservation request');
      fail(starts < ends && requested >= 0n && typeof f.active === 'boolean', 'invariant', 'Reservation interval/request');
      dependencies.push({ source: id, pool: f.pool, query_slot: 31,
        range: { lower: null, upper: { excluded: String(f.starts) } }, active: f.active,
        roles: f.active ? [11, 29] : [] });
    }
  }
  const reservations = Object.entries(facts).filter(([, row]) => row.contract === 410)
    .sort(([a, left], [b, right]) => cmp(integer(left.fields.starts), integer(right.fields.starts)) || a.localeCompare(b));
  for (const [id, row] of reservations) {
    const f = row.fields, start = integer(f.starts), end = integer(f.ends);
    const before = f.active ? events.get(f.pool).reduce((sum, [at, amount]) => at < start ? sum + amount : sum, 0n) : 0n;
    const allocated = f.active ? min(integer(f.requested), max(0n, before)) : 0n;
    derived[id] = { available_before: String(before), allocated: String(allocated) };
    if (f.active) events.get(f.pool).push([start, -allocated], [end, allocated]);
  }
  const roots = [];
  for (const [owner, rows] of [...events].sort(([a], [b]) => a.localeCompare(b))) {
    const grouped = new Map();
    for (const [at, q] of rows) {
      const current = grouped.get(at) ?? { sum: 0n, count: 0, positive: false, negative: false };
      current.sum += q; current.count += 1; current.positive ||= q > 0n; current.negative ||= q < 0n;
      grouped.set(at, current);
    }
    let balance = 0n;
    let summary = { count: 0, first: null, last: null, sum: 0n, min_prefix: 0n, max_prefix: 0n, boundary_min: null, boundary_max: null };
    for (const at of [...grouped.keys()].sort(cmp)) {
      const { sum: amount, count } = grouped.get(at);
      if (summary.count === 0) summary = { count, first: at, last: at, sum: amount,
        min_prefix: amount < 0n ? amount : 0n, max_prefix: amount > 0n ? amount : 0n, boundary_min: null, boundary_max: null };
      else {
        const split = summary.last < at ? summary.sum : null;
        const next = summary.sum + amount;
        summary = { count: summary.count + count, first: summary.first, last: at, sum: next,
          min_prefix: summary.min_prefix < summary.sum + (amount < 0n ? amount : 0n) ? summary.min_prefix : summary.sum + (amount < 0n ? amount : 0n),
          max_prefix: summary.max_prefix > summary.sum + (amount > 0n ? amount : 0n) ? summary.max_prefix : summary.sum + (amount > 0n ? amount : 0n),
          boundary_min: split === null ? summary.boundary_min : summary.boundary_min === null || split < summary.boundary_min ? split : summary.boundary_min,
          boundary_max: split === null ? summary.boundary_max : summary.boundary_max === null || split > summary.boundary_max ? split : summary.boundary_max };
      }
      balance += grouped.get(at).sum;
      fail(balance >= 0n, 'invariant', 'Complete-time equipment history becomes negative');
    }
    roots.push({ owner, slot: 7, prefixOrderKnown: ![...grouped.values()].some(group => group.count > 1 && group.positive && group.negative), summary: { kind: 'financial', value: {
      count: summary.count, first: summary.first === null ? null : String(summary.first), last: summary.last === null ? null : String(summary.last),
      sum: String(summary.sum), min_prefix: String(summary.min_prefix), max_prefix: String(summary.max_prefix),
      boundary_min: summary.boundary_min === null ? null : String(summary.boundary_min),
      boundary_max: summary.boundary_max === null ? null : String(summary.boundary_max),
    } } });
  }
  const privateRecords = reservations.flatMap(([producer, row]) => {
    if (!row.fields.active) return [];
    const allocated = derived[producer].allocated;
    return [{ producer, role: 11, pool: row.fields.pool, at: String(row.fields.starts), quantity: String(-BigInt(allocated)) },
      { producer, role: 29, pool: row.fields.pool, at: String(row.fields.ends), quantity: allocated }];
  });
  return { derived, roots, dependencies, privateRecords };
}

function quantity(facts) {
  fail(Object.keys(facts).length <= 16, 'state_limit', 'Quantity source limit');
  const dependencies = [];
  const parents = new Map();
  for (const [id, row] of Object.entries(facts)) {
    const { contract: code, fields: f } = row;
    fail([101, 205, 309].includes(code), 'contract', 'Unknown quantity contract');
    const list = code === 101 ? [] : code === 205 ? [f.parent] : [f.left, f.right];
    for (const parent of list) fail(Object.hasOwn(facts, parent), 'unavailable_reference', 'Quantity parent missing');
    parents.set(id, list);
    dependencies.push({ source: id, parents: list, slots: code === 101 ? [] : code === 205 ? [9] : [8, 3] });
  }
  const remaining = new Set(Object.keys(facts)), order = [];
  while (remaining.size) {
    const ready = [...remaining].filter(id => parents.get(id).every(parent => !remaining.has(parent))).sort();
    fail(ready.length > 0, 'feedback', 'Final publication graph is cyclic');
    for (const id of ready) { remaining.delete(id); order.push(id); }
  }
  const derived = {};
  for (const id of order) {
    const { contract: code, fields: f } = facts[id];
    let value;
    if (code === 101) {
      value = integer(f.value, 'source quantity');
      fail(abs(value) <= 10n ** 18n, 'invalid_input', 'Source quantity bound');
    } else if (code === 205) {
      const numerator = integer(f.factor?.numerator, 'factor numerator');
      const denominator = integer(f.factor?.denominator, 'factor denominator');
      fail(denominator > 0n && gcd(abs(numerator), denominator) === 1n, 'invalid_request', 'Canonical rational required');
      fail(numerator >= -(1n << 127n) && numerator < (1n << 127n) && denominator < (1n << 127n), 'invalid_request', 'Rational components exceed i128');
      value = roundRational(integer(derived[f.parent].quantity) * numerator, denominator, f.rounding);
    } else value = integer(derived[f.left].quantity) + integer(derived[f.right].quantity);
    fail(abs(value) <= 10n ** 18n, 'overflow', 'Published quantity bound');
    derived[id] = { quantity: String(value) };
  }
  return { derived, roots: [], dependencies };
}

function measurement(facts) {
  fail(Object.keys(facts).length <= 64, 'state_limit', 'Measurement source bound');
  const roots = new Map(Object.entries(facts).filter(([, row]) => row.contract === 101).map(([id]) => [id, []]));
  const derived = {};
  const queryResults = {};
  for (const [id, row] of Object.entries(facts)) {
    const f = row.fields;
    fail([101, 211, 307, 419].includes(row.contract), 'contract', 'Unknown measurement contract');
    fail(Number.isInteger(f.unit) && f.unit >= 1 && f.unit <= 65535, 'invariant', 'Unit code bound');
    if (row.contract === 101) continue;
    fail(roots.has(f.instrument) && facts[f.instrument].fields.unit === f.unit, 'unavailable_reference', 'Authored parent dimension');
    if (row.contract === 211) {
      const at = integer(f.at, 'observation time'), value = integer(f.value, 'observation value');
      fail(at >= -(1n << 63n) && at < (1n << 63n) && abs(value) <= 10n ** 12n, 'invalid_input', 'Observation bounds');
      roots.get(f.instrument).push({ id, at, value, unit: f.unit });
    } else if (row.contract === 307) fail(abs(integer(f.threshold, 'threshold')) <= 10n ** 12n, 'invalid_input', 'Threshold bound');
    else fail(integer(f.at, 'selection time') >= -(1n << 63n) && integer(f.at, 'selection time') < (1n << 63n), 'invalid_input', 'Selection time bound');
  }
  for (const [id, row] of Object.entries(facts)) {
    const f = row.fields;
    if (row.contract === 307) {
      const values = roots.get(f.instrument).filter(event => contains(event.at, f.range)).map(event => event.value);
      const threshold = integer(f.threshold);
      derived[id] = { count: values.length, min: values.length ? String(min(...values)) : null,
        max: values.length ? String(max(...values)) : null, unit: f.unit,
        at_least_threshold: values.length > 0 && values.every(value => value >= threshold) };
      queryResults[id] = { count: values.length, sum: String(values.reduce((sum, value) => sum + value, 0n)),
        min: derived[id].min, max: derived[id].max,
        dimension: values.length ? { kind: 'unit', code: f.unit } : { kind: 'empty' } };
    } else if (row.contract === 419) {
      const at = integer(f.at);
      const candidates = roots.get(f.instrument).filter(event => event.at <= at)
        .sort((a, b) => cmp(a.at, b.at) || a.id.localeCompare(b.id));
      const event = candidates.at(-1);
      derived[id] = { selection: event ? { identity: event.id, member_slot: 17, time: String(event.at), unit: event.unit, value: String(event.value) } : null };
      queryResults[id] = derived[id].selection;
    } else if (row.contract !== 101) derived[id] = null;
  }
  const summaries = [...roots].sort(([a], [b]) => a.localeCompare(b)).map(([owner, rows]) => ({ owner, slot: 7,
    summary: { count: rows.length, sum: String(rows.reduce((sum, row) => sum + row.value, 0n)),
      min: rows.length ? String(min(...rows.map(row => row.value))) : null,
      max: rows.length ? String(max(...rows.map(row => row.value))) : null,
      unit: rows.length ? facts[owner].fields.unit : null } }));
  const dependencies = Object.entries(facts).flatMap(([id, row]) => row.contract === 307 || row.contract === 419
    ? [{ source: id, instrument: row.fields.instrument, query_slot: row.contract === 307 ? 31 : 43,
      range: row.contract === 307 ? clone(row.fields.range) : { lower: null, upper: { included: row.fields.at } } }]
    : []);
  return { derived, roots: summaries, dependencies, queryResults };
}

function contains(at, range) {
  if (!range || typeof range !== 'object') throw new OracleError('invalid_request', 'Range must be an object');
  for (const side of ['lower', 'upper']) {
    const bound = range[side];
    if (bound == null) continue;
    const keys = Object.keys(bound);
    fail(keys.length === 1 && ['included', 'excluded'].includes(keys[0]), 'invalid_request', 'Invalid range bound');
    const value = integer(bound[keys[0]], 'range bound');
    if (side === 'lower' && (at < value || (at === value && keys[0] === 'excluded'))) return false;
    if (side === 'upper' && (at > value || (at === value && keys[0] === 'excluded'))) return false;
  }
  return true;
}

function roundRational(numerator, denominator, mode) {
  const q = numerator / denominator, r = numerator % denominator;
  if (mode === 'exact') { fail(r === 0n, 'inexact', 'Exact quantity is fractional'); return q; }
  if (mode === 'toward_zero') return q;
  if (mode === 'floor') return numerator < 0n && r ? q - 1n : q;
  if (mode === 'ceiling') return numerator > 0n && r ? q + 1n : q;
  if (mode === 'half_away_from_zero' || mode === 'half_even') {
    const twice = abs(r) * 2n;
    if (twice < denominator) return q;
    const direction = numerator < 0n ? -1n : 1n;
    if (twice > denominator || mode === 'half_away_from_zero' || abs(q) % 2n === 1n) return q + direction;
    return q;
  }
  throw new OracleError('invalid_request', 'Unknown rounding mode');
}

function integer(value, label = 'integer') {
  try { if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error(); return BigInt(value); }
  catch { throw new OracleError('invalid_input', `${label} must be an exact integer`); }
}
function assertFacts(facts) { if (!facts || typeof facts !== 'object' || Array.isArray(facts)) throw new TypeError('facts must be an object'); }
function clone(value) { return structuredClone(value); }
function gcd(a, b) { while (b) [a, b] = [b, a % b]; return a; }
function abs(n) { return n < 0n ? -n : n; }
function min(...values) { return values.reduce((a, b) => a < b ? a : b); }
function max(...values) { return values.reduce((a, b) => a > b ? a : b); }
function cmp(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
function stable(value) {
  const sort = item => Array.isArray(item) ? item.map(sort) : item && typeof item === 'object'
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sort(item[key])])) : item;
  return JSON.stringify(sort(value));
}
function isNativeSnapshot(value) {
  return Boolean(value && typeof value === 'object' && Array.isArray(value.records)
    && Array.isArray(value.roots) && Array.isArray(value.queries) && Array.isArray(value.roles));
}
function uniqueRows(rows, keyOf, label) {
  const result = new Map();
  for (const row of rows) {
    const key = keyOf(row);
    if (typeof key !== 'string' || key.length === 0) { result.duplicate = true; continue; }
    if (result.has(key)) result.duplicate = true;
    else result.set(key, row);
  }
  result.label = label;
  return result;
}
function addressKey(address) {
  return address && typeof address.id === 'string' && Number.isSafeInteger(address.slot) ? `${address.id}\0${address.slot}` : null;
}
function parseAddressKey(key) { const split = key.lastIndexOf('\0'); return { id: key.slice(0, split), slot: Number(key.slice(split + 1)) }; }
function addressSort(a, b) { return a.id.localeCompare(b.id) || a.slot - b.slot; }
function same(left, right) { return stable(left) === stable(right); }
function rootSummaryExpectation(model, root) {
  if (model === 'equipment') return root.summary;
  if (model === 'measurement') return { count: root.summary.count, sum: root.summary.sum,
    min: root.summary.min, max: root.summary.max,
    dimension: root.summary.count ? { kind: 'unit', code: root.summary.unit } : { kind: 'empty' } };
  return root.summary;
}
