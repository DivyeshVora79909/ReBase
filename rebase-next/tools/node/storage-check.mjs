import { createHash } from 'node:crypto';
import { parseFrame } from './private/json-codec.mjs';

const MAX_BACKUP_BYTES = 64 * 1024 * 1024;
const MAX_SNAPSHOT_ROWS = 81_920;
const MAX_TREE_DEPTH = 64;
const MAX_TREE_NODES = 81_920;
const REQUIRED_TABLES = new Set(['effect_due', 'effect_executions', 'effect_facts', 'effect_inbox',
  'effect_runtime', 'local_runtime', 'native_kv', 'operations', 'public_records', 'query_epochs', 'receipt_slots']);
const HEX = /^[0-9a-f]*$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DECIMAL = /^(0|-?[1-9][0-9]*)$/;

/**
 * Independently checks the physical AVL portion of a complete native backup.
 * Pass raw UTF-8 bytes/string to retain duplicate-key JSON rejection. The
 * optional expectedMembers Map is keyed by `uuid/slot` and contains
 * `{ root: {id,slot}, time, leaf }` rows from a separate source oracle.
 */
export function checkBackupStructure(input, { expectedMembers, maxBytes = MAX_BACKUP_BYTES,
  maxRows = MAX_SNAPSHOT_ROWS, maxDepth = MAX_TREE_DEPTH } = {}) {
  positiveBound(maxBytes, MAX_BACKUP_BYTES, 'maxBytes');
  positiveBound(maxRows, MAX_SNAPSHOT_ROWS, 'maxRows');
  positiveBound(maxDepth, MAX_TREE_DEPTH, 'maxDepth');
  const backupBytes = asBytes(input, maxBytes);
  const backup = parseFrame(backupBytes);
  object(backup, 'backup');
  exactKeys(backup, ['format', 'sha256', 'payload'], 'backup envelope');
  requireThat(backup.format === 'rebase-backup-1', 'unsupported backup format');
  requireThat(typeof backup.sha256 === 'string' && /^[0-9a-f]{64}$/.test(backup.sha256), 'invalid backup checksum');
  object(backup.payload, 'backup payload');
  requireThat(backup.payload.format === 'rebase-authorized-observation-1' && backup.payload.complete === true,
    'backup is not a complete authorized observation');
  const payloadBytes = Buffer.from(canonicalJson(backup.payload), 'utf8');
  requireThat(sha256(payloadBytes) === backup.sha256, 'backup checksum differs');

  object(backup.payload.tables, 'backup tables');
  const tableNames = Object.keys(backup.payload.tables).sort();
  requireThat([...REQUIRED_TABLES].every(name => tableNames.includes(name))
    && (tableNames.length === 11 || (tableNames.length === 13
      && tableNames.includes('authority') && tableNames.includes('reader_records'))), 'backup application table inventory differs');
  for (const [name, tableRows] of Object.entries(backup.payload.tables)) {
    requireThat(Array.isArray(tableRows) && tableRows.length <= maxRows, `table ${name} exceeds the bounded inventory`);
    const tableKeys = new Set();
    for (const row of tableRows) {
      object(row, `table ${name} row`);
      requireThat(typeof row.key === 'string' && !tableKeys.has(row.key), `table ${name} has a missing or duplicate key`);
      tableKeys.add(row.key);
    }
  }
  const rows = backup.payload.tables.native_kv;
  const roots = new Map();
  const nodes = new Map();
  const nativeKeys = new Set();
  for (const row of rows) {
    object(row, 'native KV row');
    exactKeys(row, ['key', 'value'], 'native KV row');
    const keyBytes = decodeHex(row.key, 'native key');
    const valueBytes = decodeHex(row.value, 'native value');
    const decodedKey = decodeKey(keyBytes);
    const keyToken = keyBytes.toString('hex');
    requireThat(!nativeKeys.has(keyToken), 'repeated native KV key');
    nativeKeys.add(keyToken);
    const value = parseFrame(valueBytes);
    const valueText = new TextDecoder('utf-8', { fatal: true }).decode(valueBytes);
    object(value, 'stored native value');
    exactKeys(value, ['type', 'data'], 'stored native value');
    requireThat(value.type === decodedKey.type, 'native key/value tag differs');
    object(value.data, 'stored tree value');
    if (decodedKey.type === 'root' || decodedKey.type === 'node') {
      requireThat(canonicalTypedValue(value) === valueText, 'root/node bytes are not canonical serde JSON');
    } else {
      requireThat(JSON.stringify(value) === valueText, 'non-tree native value bytes are not compact JSON');
    }
    if (decodedKey.type !== 'root' && decodedKey.type !== 'node') continue;
    const token = addressToken(decodedKey.address);
    requireThat(!(decodedKey.type === 'root' ? roots : nodes).has(token), `duplicate ${decodedKey.type} address`);
    if (decodedKey.type === 'root') roots.set(token, { address: decodedKey.address, value: value.data });
    else nodes.set(token, { address: decodedKey.address, value: value.data });
  }
  requireThat(nodes.size <= MAX_TREE_NODES, 'tree node inventory exceeds its bound');
  requireThat(expectedMembers === undefined || expectedMembers instanceof Map, 'expectedMembers must be a Map');

  const reached = new Set();
  let visited = 0;
  for (const [rootToken, rootRow] of roots) {
    const root = rootRow.value;
    validateRoot(root, rootRow.address);
    const ordered = [];
    const stats = visit(root.head, null, rootRow.address, root, 0, ordered);
    requireThat(root.height === stats.height, 'root height differs');
    requireThat(sameAddress(root.first, stats.firstAddress), 'root first link differs');
    requireThat(sameAddress(root.last, stats.lastAddress), 'root last link differs');
    requireThat(root.span === null ? ordered.length === 0 : ordered.length > 0, 'root span presence differs');
    if (ordered.length) {
      requireThat(compareTime(root.span.first, stats.firstTime) === 0
        && compareTime(root.span.last, stats.lastTime) === 0, 'root span differs');
    }
    requireThat(equalJson(root.summary, stats.summary), 'root summary differs');
    for (let index = 0; index < ordered.length; index += 1) {
      const row = ordered[index];
      const node = row.value;
      requireThat(sameAddress(node.prev, ordered[index - 1]?.address ?? null), 'previous link differs');
      requireThat(sameAddress(node.next, ordered[index + 1]?.address ?? null), 'next link differs');
      if (index) requireThat(compareFullKey(ordered[index - 1], row) < 0, 'tree keys are not strictly ordered');
      if (expectedMembers) {
        const expected = expectedMembers.get(addressToken(row.address));
        requireThat(expected !== undefined, 'tree node is absent from independent source membership');
        requireThat(addressToken(expected.root) === rootToken, 'source membership root differs');
        requireThat(compareTime(expected.time, row.time) === 0, 'source membership time differs');
        requireThat(equalJson(expected.leaf, node.leaf), 'source membership leaf differs');
      }
    }
    visited += ordered.length;
    requireThat(visited <= MAX_TREE_NODES, 'tree traversal exceeds its bound');

    function visit(address, parent, owner, ownerRoot, depth, inOrder) {
      if (address === null) return emptyStats(ownerRoot.kind);
      requireThat(depth < maxDepth, 'tree path depth limit');
      const token = addressToken(address);
      requireThat(!reached.has(token), 'tree cycle or duplicate reachability');
      reached.add(token);
      const row = nodes.get(token);
      requireThat(row !== undefined, 'linked tree node is missing');
      const node = row.value;
      exactKeys(node, ['kind', 'root', 'key', 'leaf', 'parent', 'left', 'right', 'prev', 'next', 'height', 'span', 'summary'], 'tree node');
      exactKeys(node.key, ['value', 'id', 'slot'], 'tree node key');
      exactKeys(node.span, ['first', 'last'], 'tree node span');
      requireThat(addressToken(node.root) === addressToken(owner), 'node root owner differs');
      requireThat(addressToken(node.parent) === (parent ? addressToken(parent) : null), 'node parent differs');
      requireThat(node.kind === ownerRoot.kind, 'node index kind differs');
      requireThat(node.key?.id === address.id && node.key?.slot === address.slot, 'node address differs from key');
      requireThat(node.key && node.leaf && node.span, 'node key, leaf, or span is missing');
      const time = canonicalTime(node.key.value);
      const left = visit(node.left, address, owner, ownerRoot, depth + 1, inOrder);
      const current = { ...row, address, time, leaf: node.leaf };
      inOrder.push(current);
      const right = visit(node.right, address, owner, ownerRoot, depth + 1, inOrder);
      requireThat(Math.abs(left.height - right.height) <= 1, 'AVL balance differs');
      const height = Math.max(left.height, right.height) + 1;
      requireThat(node.height === height && height < maxDepth, 'node height differs');
      const firstTime = left.count ? left.firstTime : time;
      const lastTime = right.count ? right.lastTime : time;
      requireThat(compareTime(node.span.first, firstTime) === 0
        && compareTime(node.span.last, lastTime) === 0, 'node span differs');
      requireThat(compareTime(node.span.first, time) <= 0 && compareTime(time, node.span.last) <= 0,
        'node key lies outside span');
      const singleton = singletonSummary(node.kind, time, node.leaf);
      const summary = combineSummaries(node.kind, combineSummaries(node.kind, left.summary, singleton), right.summary);
      requireThat(equalJson(node.summary, summary), 'tree node summary differs');
      return { height, count: left.count + 1 + right.count, firstTime, lastTime,
        firstAddress: left.count ? left.firstAddress : address,
        lastAddress: right.count ? right.lastAddress : address, summary };
    }
  }
  requireThat(reached.size === nodes.size, 'tree node inventory has disconnected entries');
  if (expectedMembers) requireThat(expectedMembers.size === nodes.size, 'source membership inventory size differs');
  return Object.freeze({ status: 'passed', sourceMembership: expectedMembers ? 'checked' : 'not_evaluated',
    rootCount: roots.size, nodeCount: nodes.size, nativeKvRows: rows.length, snapshotBytes: backupBytes.length });
}

function emptyStats(kind) {
  return { height: 0, count: 0, firstTime: null, lastTime: null, firstAddress: null, lastAddress: null,
    summary: kind === 1 ? { kind: 'financial', value: { count: 0, first: null, last: null, sum: '0',
      min_prefix: '0', max_prefix: '0', boundary_min: null, boundary_max: null } }
      : kind === 2 ? { kind: 'quote', value: { count: 0, first: null, last: null } }
        : kind === 7 ? { count: 0, sum: '0', min: null, max: null, dimension: { kind: 'empty' } }
          : unsupportedKind(kind) };
}

function singletonSummary(kind, time, leaf) {
  if (kind === 1) {
    exactKeys(leaf, ['kind', 'value'], 'financial leaf');
    requireThat(leaf.kind === 'financial', 'financial leaf kind differs');
    const amount = canonicalI128(leaf.value, 'financial leaf value');
    const min = amount < 0n ? amount : 0n, max = amount > 0n ? amount : 0n;
    return { kind: 'financial', value: { count: 1, first: time.toString(), last: time.toString(), sum: amount.toString(),
      min_prefix: min.toString(), max_prefix: max.toString(), boundary_min: null, boundary_max: null } };
  } else if (kind === 2) {
    exactKeys(leaf, ['kind', 'value'], 'quote leaf');
    requireThat(leaf.kind === 'quote', 'quote leaf is invalid');
    canonicalU16(leaf.value, 'quote leaf value');
    return { kind: 'quote', value: { count: 1, first: time.toString(), last: time.toString() } };
  } else if (kind === 7) {
    exactKeys(leaf, ['unit', 'value'], 'Measurement leaf');
    requireThat(Number.isInteger(leaf.unit) && leaf.unit > 0 && leaf.unit <= 65535, 'Measurement unit is invalid');
    const value = canonicalI128(leaf.value, 'Measurement leaf value');
    requireThat(value >= -1_000_000_000_000n && value <= 1_000_000_000_000n, 'Measurement leaf exceeds its bound');
    return { count: 1, sum: value.toString(), min: value.toString(), max: value.toString(),
      dimension: { kind: 'unit', code: leaf.unit } };
  } else throw new TypeError(`unsupported native index kind ${String(kind)}`);
}

function combineSummaries(kind, left, right) {
  if (kind === 1) {
    const a = left.value, b = right.value;
    if (a.count === 0) return right;
    if (b.count === 0) return left;
    const aSum = BigInt(a.sum), bSum = BigInt(b.sum), total = aSum + bSum;
    checkI128(total, 'financial combined sum');
    const shiftedMin = aSum + BigInt(b.min_prefix), shiftedMax = aSum + BigInt(b.max_prefix);
    checkI128(shiftedMin, 'financial combined minimum'); checkI128(shiftedMax, 'financial combined maximum');
    const gap = BigInt(a.last) < BigInt(b.first);
    const boundaryCandidatesMin = [nullableBigInt(a.boundary_min), shiftNullable(aSum, b.boundary_min), gap ? aSum : null].filter(v => v !== null);
    const boundaryCandidatesMax = [nullableBigInt(a.boundary_max), shiftNullable(aSum, b.boundary_max), gap ? aSum : null].filter(v => v !== null);
    const boundaryMin = boundaryCandidatesMin.length ? minBigInt(boundaryCandidatesMin) : null;
    const boundaryMax = boundaryCandidatesMax.length ? maxBigInt(boundaryCandidatesMax) : null;
    for (const value of [boundaryMin, boundaryMax]) if (value !== null) checkI128(value, 'financial combined boundary');
    return { kind: 'financial', value: { count: a.count + b.count, first: a.first, last: b.last,
      sum: total.toString(), min_prefix: minBigInt([BigInt(a.min_prefix), shiftedMin]).toString(),
      max_prefix: maxBigInt([BigInt(a.max_prefix), shiftedMax]).toString(),
      boundary_min: boundaryMin?.toString() ?? null, boundary_max: boundaryMax?.toString() ?? null } };
  }
  if (kind === 2) {
    const a = left.value, b = right.value;
    if (a.count === 0) return right;
    if (b.count === 0) return left;
    requireThat(BigInt(a.last) <= BigInt(b.first), 'quote summaries are out of time order');
    return { kind: 'quote', value: { count: a.count + b.count, first: a.first, last: b.last } };
  }
  if (kind === 7) {
    if (left.count === 0) return right;
    if (right.count === 0) return left;
    const sum = BigInt(left.sum) + BigInt(right.sum);
    checkI128(sum, 'Measurement combined sum');
    const dimension = equalJson(left.dimension, right.dimension) ? left.dimension : { kind: 'mixed' };
    return { count: left.count + right.count, sum: sum.toString(),
      min: minBigInt([BigInt(left.min), BigInt(right.min)]).toString(),
      max: maxBigInt([BigInt(left.max), BigInt(right.max)]).toString(), dimension };
  }
  return unsupportedKind(kind);
}

function nullableBigInt(value) { return value === null ? null : BigInt(value); }
function shiftNullable(amount, value) { return value === null ? null : amount + BigInt(value); }
function minBigInt(values) { return values.reduce((a, b) => a < b ? a : b); }
function maxBigInt(values) { return values.reduce((a, b) => a > b ? a : b); }
function unsupportedKind(kind) { throw new TypeError(`unsupported native index kind ${String(kind)}`); }

function decodeKey(bytes) {
  if (bytes.length === 1 && bytes[0] === 0) return { type: 'meta' };
  if (bytes.length === 1 && bytes[0] === 13) return { type: 'population' };
  const tag = bytes[0];
  const expectedLength = new Set([1, 5, 6, 9]).has(tag) ? 17
    : new Set([2, 3, 4, 7, 8, 10, 11, 12]).has(tag) ? 19 : 0;
  requireThat(expectedLength > 0 && bytes.length === expectedLength, 'invalid native point key');
  const id = formatUuid(bytes.subarray(1, 17));
  const slot = expectedLength === 19 ? bytes.readUInt16BE(17) : null;
  if (expectedLength === 19) requireThat(slot > 0, 'native address slot is zero');
  const type = ({ 1: 'record', 2: 'root', 3: 'node', 4: 'query', 5: 'incoming', 6: 'direct',
    7: 'subscribers', 8: 'role', 9: 'reserved', 10: 'route_node', 11: 'route_node', 12: 'route_node' })[tag];
  requireThat(type !== undefined, 'invalid native point key tag');
  return { type, ...(expectedLength === 19 ? { address: { id, slot } } : {}) };
}

function decodeHex(value, label) {
  requireThat(typeof value === 'string' && value.length % 2 === 0 && HEX.test(value), `${label} is not canonical hex`);
  return Buffer.from(value, 'hex');
}
function asBytes(input, maxBytes) {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  requireThat(bytes.length > 0 && bytes.length <= maxBytes, 'backup byte limit');
  return bytes;
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function canonicalTime(value) {
  requireThat(typeof value === 'string' && DECIMAL.test(value), 'native time key is not canonical decimal');
  const time = BigInt(value);
  requireThat(time >= -(1n << 63n) && time < (1n << 63n), 'native time key exceeds i64');
  return time;
}
function canonicalI128(value, label) {
  requireThat(typeof value === 'string' && DECIMAL.test(value), `${label} is not canonical decimal`);
  const parsed = BigInt(value);
  checkI128(parsed, label);
  return parsed;
}
function canonicalU16(value, label) {
  requireThat(typeof value === 'string' && /^[1-9][0-9]*$/.test(value), `${label} is not canonical positive decimal`);
  const parsed = BigInt(value);
  requireThat(parsed <= 65_535n, `${label} exceeds u16`);
  return parsed;
}
function checkI128(value, label) { requireThat(value >= -(1n << 127n) && value < (1n << 127n), `${label} exceeds i128`); }
function compareTime(left, right) { return (typeof left === 'bigint' ? left : canonicalTime(left)) < (typeof right === 'bigint' ? right : canonicalTime(right)) ? -1
  : (typeof left === 'bigint' ? left : canonicalTime(left)) > (typeof right === 'bigint' ? right : canonicalTime(right)) ? 1 : 0; }
function compareFullKey(left, right) {
  const at = compareTime(left.time, right.time); if (at) return at;
  const a = Buffer.from(left.address.id.replaceAll('-', ''), 'hex'), b = Buffer.from(right.address.id.replaceAll('-', ''), 'hex');
  const id = Buffer.compare(a, b); return id || left.address.slot - right.address.slot;
}
function addressToken(address) {
  if (address === null) return null;
  object(address, 'tree address');
  exactKeys(address, ['id', 'slot'], 'tree address');
  requireThat(typeof address.id === 'string' && UUID.test(address.id) && Number.isInteger(address.slot) && address.slot > 0 && address.slot <= 65535,
    'invalid tree address');
  return `${address.id}/${address.slot}`;
}
function sameAddress(left, right) { return (left === null && right === null) || (left !== null && right !== null && addressToken(left) === addressToken(right)); }
function validateRoot(root, address) {
  exactKeys(root, ['kind', 'head', 'first', 'last', 'height', 'span', 'summary', 'revision'], 'tree root');
  if (root.span !== null) { object(root.span, 'tree root span'); exactKeys(root.span, ['first', 'last'], 'tree root span'); }
  requireThat(address.slot > 0 && (root.head === null) === (root.height === 0)
    && (root.head === null) === (root.first === null) && (root.head === null) === (root.last === null)
    && (root.head === null) === (root.span === null), 'invalid root empty-state shape');
  for (const link of [root.head, root.first, root.last]) if (link !== null) addressToken(link);
  requireThat(root.revision && UUID.test(root.revision) && root.revision !== '00000000-0000-0000-0000-000000000000', 'invalid root revision');
}
function formatUuid(bytes) { const hex = bytes.toString('hex'); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function object(value, label) { requireThat(value !== null && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`); }
function exactKeys(value, expected, label) { requireThat(Object.keys(value).sort().join('\0') === [...expected].sort().join('\0'), `${label} fields differ`); }
function equalJson(a, b) { return canonicalJson(a) === canonicalJson(b); }
function canonicalTypedValue(value) {
  if (value.type === 'root') {
    const data = value.data;
    const kind = data.kind;
    exactKeys(data, ['kind', 'head', 'first', 'last', 'height', 'span', 'summary', 'revision'], 'tree root');
    return JSON.stringify({ type: 'root', data: {
      kind, head: orderedAddress(data.head), first: orderedAddress(data.first), last: orderedAddress(data.last),
      height: data.height, span: orderedSpan(data.span), summary: orderedSummary(kind, data.summary), revision: data.revision,
    } });
  }
  const data = value.data;
  exactKeys(data, ['kind', 'root', 'key', 'leaf', 'parent', 'left', 'right', 'prev', 'next', 'height', 'span', 'summary'], 'tree node');
  exactKeys(data.key, ['value', 'id', 'slot'], 'tree node key');
  return JSON.stringify({ type: 'node', data: {
    kind: data.kind, root: orderedAddress(data.root),
    key: { value: data.key.value, id: data.key.id, slot: data.key.slot },
    leaf: orderedLeaf(data.kind, data.leaf), parent: orderedAddress(data.parent), left: orderedAddress(data.left),
    right: orderedAddress(data.right), prev: orderedAddress(data.prev), next: orderedAddress(data.next),
    height: data.height, span: orderedSpan(data.span), summary: orderedSummary(data.kind, data.summary),
  } });
}
function orderedAddress(address) {
  if (address === null) return null;
  object(address, 'tree address');
  exactKeys(address, ['id', 'slot'], 'tree address');
  return { id: address.id, slot: address.slot };
}
function orderedSpan(span) {
  if (span === null) return null;
  object(span, 'tree span');
  exactKeys(span, ['first', 'last'], 'tree span');
  return { first: span.first, last: span.last };
}
function orderedLeaf(kind, leaf) {
  object(leaf, 'tree leaf');
  if (kind === 1 || kind === 2) {
    exactKeys(leaf, ['kind', 'value'], 'standard leaf');
    return { kind: leaf.kind, value: leaf.value };
  }
  if (kind === 7) {
    exactKeys(leaf, ['unit', 'value'], 'Measurement leaf');
    return { unit: leaf.unit, value: leaf.value };
  }
  throw new TypeError(`unsupported native index kind ${String(kind)}`);
}
function orderedSummary(kind, summary) {
  object(summary, 'tree summary');
  if (kind === 1) {
    exactKeys(summary, ['kind', 'value'], 'Financial summary');
    const value = summary.value;
    exactKeys(value, ['count', 'first', 'last', 'sum', 'min_prefix', 'max_prefix', 'boundary_min', 'boundary_max'], 'Financial summary value');
    return { kind: summary.kind, value: { count: value.count, first: value.first, last: value.last, sum: value.sum,
      min_prefix: value.min_prefix, max_prefix: value.max_prefix, boundary_min: value.boundary_min, boundary_max: value.boundary_max } };
  }
  if (kind === 2) {
    exactKeys(summary, ['kind', 'value'], 'Quote summary');
    const value = summary.value;
    exactKeys(value, ['count', 'first', 'last'], 'Quote summary value');
    return { kind: summary.kind, value: { count: value.count, first: value.first, last: value.last } };
  }
  if (kind === 7) {
    exactKeys(summary, ['count', 'sum', 'min', 'max', 'dimension'], 'Measurement summary');
    const dimension = summary.dimension;
    object(dimension, 'Measurement dimension');
    if (dimension.kind === 'unit') {
      exactKeys(dimension, ['kind', 'code'], 'unit dimension');
      return { count: summary.count, sum: summary.sum, min: summary.min, max: summary.max,
        dimension: { kind: dimension.kind, code: dimension.code } };
    }
    exactKeys(dimension, ['kind'], 'empty/mixed dimension');
    return { count: summary.count, sum: summary.sum, min: summary.min, max: summary.max,
      dimension: { kind: dimension.kind } };
  }
  throw new TypeError(`unsupported native index kind ${String(kind)}`);
}
function requireThat(condition, message) { if (!condition) throw new TypeError(message); }
function positiveBound(value, ceiling, label) {
  requireThat(Number.isSafeInteger(value) && value > 0 && value <= ceiling, `${label} must be within its hard bound`);
}
