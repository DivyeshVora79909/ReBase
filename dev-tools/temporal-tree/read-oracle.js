'use strict';

const assert = require('node:assert/strict');
const { scan, equal } = require('./oracle');
const { instant } = require('./harness');

const scalarCompare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const idOf = link => link == null ? null : `${link.rid}/${link.slot}`;
const recordTable = id => typeof id === 'string' ? id.slice(0, id.indexOf(':')) : '';
const project = (value, path) => path ? path.split('.').reduce((row, part) => row?.[part], value) : value;

function comparePosition(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let index = 0; index < Math.min(a.length, b.length); index++) {
      const compared = comparePosition(a[index], b[index]);
      if (compared) return compared;
    }
    return a.length - b.length;
  }
  const date = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value);
  if (date(a) && date(b)) {
    const left = instant(a), right = instant(b);
    return left < right ? -1 : left > right ? 1 : 0;
  }
  return scalarCompare(a, b);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().filter(key => value[key] !== undefined)
    .map(key => [key, stable(value[key])]));
}

function readDescription(read) {
  return {
    reader: read.reader,
    phase: read.phase,
    source_root: read.source_root,
    source_slot: read.source_slot,
    kind: read.kind,
    arguments: read.arguments,
    path: read.path,
    fallback: read.fallback?.value,
  };
}

function expectedPosition(read) {
  if (read.kind === 'latest' || read.kind === 'next' || read.kind === 'range') return read.arguments[0];
  if (read.kind === 'before' || read.kind === 'exact') return read.arguments;
  return [];
}

function expectedChannel(read) {
  if (read.kind === 'record') return read.path === '' ? '*' : read.path.split('.')[0];
  if (read.path === '') return '*';
  const parts = read.path.split('.');
  return ['measures', 'tags', 'spans'].includes(parts[0]) && parts.length >= 2
    ? `${parts[0]}:${parts[1]}` : 'order';
}

function assertReadShape(read) {
  assert(['refresh', 'validate'].includes(read.phase), `${read.id}: legal phase`);
  assert.equal(read.reader_identity, read.reader, `${read.id}: stable reader identity matches its typed reference`);
  assert(Number.isInteger(read.version) && read.version > 0, `${read.id}: positive generation`);
  assert(['record', 'latest', 'next', 'exact', 'before', 'range', 'summary'].includes(read.kind), `${read.id}: known operation`);
  assert(Array.isArray(read.arguments), `${read.id}: arguments are an array`);
  assert.equal(typeof read.source_slot, 'string', `${read.id}: source slot is a string`);
  assert.equal(typeof read.path, 'string', `${read.id}: projection is a string`);
  assert(read.fallback && typeof read.fallback === 'object' && !Array.isArray(read.fallback), `${read.id}: fallback wrapper`);
  assert(read.observed && typeof read.observed === 'object' && !Array.isArray(read.observed), `${read.id}: observed wrapper`);

  if (read.kind === 'record') {
    assert.equal(read.source_slot, '', `${read.id}: record read has no tree slot`);
    assert.deepEqual(read.arguments, [], `${read.id}: record read takes no arguments`);
  } else {
    assert.notEqual(read.source_slot, '', `${read.id}: tree read names a source slot`);
    if (['latest', 'next'].includes(read.kind)) {
      assert(read.arguments.length === 1 || read.arguments.length === 2, `${read.id}: seek arguments`);
      assert(Array.isArray(read.arguments[0]), `${read.id}: seek key`);
      if (read.arguments.length === 2) assert.equal(typeof read.arguments[1], 'boolean', `${read.id}: inclusive flag`);
    } else if (read.kind === 'range') {
      assert.equal(read.arguments.length, 2, `${read.id}: range bounds`);
      assert(Array.isArray(read.arguments[0]) && Array.isArray(read.arguments[1]), `${read.id}: range keys`);
    } else if (read.kind === 'before') {
      assert(Array.isArray(read.arguments), `${read.id}: prefix key`);
    } else if (read.kind === 'exact') {
      assert(Array.isArray(read.arguments), `${read.id}: exact key`);
    } else {
      assert.equal(read.kind, 'summary');
      assert.deepEqual(read.arguments, [], `${read.id}: summary takes no arguments`);
    }
  }
  assert.deepEqual(read.position, expectedPosition(read), `${read.id}: logical position matches operation arguments`);
  assert.equal(read.channel, expectedChannel(read), `${read.id}: dependency channel matches projection`);
}

function expectedQuery(read, rows, entries, compare, summarize = scan) {
  const source = rows.get(read.source_root);
  assert(source, `${read.id}: live source record`);
  if (read.kind === 'record') return project(source, read.path);
  const sequence = entries.filter(entry => entry.owner.rid === read.source_root && entry.owner.slot === read.source_slot)
    .slice().sort((a, b) => compare(a.key, b.key));
  let selected;
  if (read.kind === 'latest') {
    selected = sequence.filter(entry => compare(entry.key, read.arguments[0]) < 0
      || (read.arguments[1] === true && compare(entry.key, read.arguments[0]) === 0)).at(-1);
  } else if (read.kind === 'next') {
    selected = sequence.find(entry => compare(entry.key, read.arguments[0]) > 0
      || (read.arguments[1] === true && compare(entry.key, read.arguments[0]) === 0));
  } else if (read.kind === 'exact') {
    selected = sequence.find(entry => compare(entry.key.slice(0, -2), read.arguments) === 0);
  }
  let value;
  if (['latest', 'next', 'exact'].includes(read.kind)) {
    value = selected ? { ...summarize([selected]), record: selected.link.rid, key: selected.key } : undefined;
  } else if (read.kind === 'before') value = summarize(sequence.filter(entry => compare(entry.key, read.arguments) < 0));
  else if (read.kind === 'range') value = summarize(sequence.filter(entry => compare(entry.key, read.arguments[0]) >= 0
    && compare(entry.key, read.arguments[1]) < 0));
  else {
    assert.equal(read.kind, 'summary');
    value = summarize(sequence);
  }
  return project(value, read.path);
}

function combineIndex(entries, compare, isInterval) {
  const expected = scan(entries);
  if (isInterval && entries.length) {
    expected.end_key = entries.map(entry => entry.end_key).sort(compare).at(-1);
  }
  return expected;
}

function verifyIndex(group, members, rows, compare, interval) {
  const nodeSlot = interval ? 'z_interval' : 'z_position';
  const headSlot = interval ? 'z_intervals' : 'z_positions';
  const head = group[headSlot];
  const owner = { rid: group.id, slot: headSlot };
  const active = members.filter(read => interval
    ? group.kind === 'range' && compare(read.arguments[0], read.arguments[1]) < 0
    : group.kind !== 'range');
  const expectedEntries = active.map(read => ({
    link: { rid: read.id, slot: nodeSlot },
    key: [read.position, read.id, nodeSlot],
    end_key: interval ? read.arguments[1] : undefined,
    dependent: false,
    measures: {}, tags: {}, spans: {},
  })).sort((a, b) => comparePosition(a.key[0], b.key[0]) || scalarCompare(a.key[1], b.key[1]) || scalarCompare(a.key[2], b.key[2]));
  const byRead = new Map(active.map(read => [read.id, read]));
  const byKey = (a, b) => comparePosition(a[0], b[0]) || scalarCompare(a[1], b[1]) || scalarCompare(a[2], b[2]);
  const seen = new Set();

  assert(head && typeof head === 'object', `${group.id}: ${headSlot} head exists`);
  assert.equal(head.refreshing, false, `${group.id}: finished index`);
  assert(head.dirty == null, `${group.id}: no dirty key after a committed transaction`);
  assert(head.cursor == null, `${group.id}: no repair cursor after a committed transaction`);
  if (!active.length) {
    assert(head.root == null, `${group.id}: empty index has no root`);
    assert.equal(head.height, 0, `${group.id}: empty index height`);
    assert.deepEqual(stable(head.summary), stable(scan([])), `${group.id}: complete empty root summary`);
    return;
  }

  function visit(link, parent, lower, upper) {
    assert(link && typeof link === 'object', `${group.id}: nonempty tree node link`);
    assert.equal(typeof link.rid, 'string');
    assert.equal(link.slot, nodeSlot, `${group.id}: correct linked slot`);
    const identity = idOf(link);
    assert(!seen.has(identity), `${identity}: no cycle or duplicate reachability`);
    seen.add(identity);
    const read = byRead.get(link.rid);
    assert(read, `${identity}: reachable read belongs to this logical group`);
    const row = rows.get(read.id);
    assert(row, `${identity}: node record exists`);
    const node = row[nodeSlot];
    assert(node && typeof node === 'object', `${identity}: active node slot exists`);
    assert.deepEqual(node.owner, owner, `${identity}: exact owning root`);
    assert.deepEqual(node.parent, parent, `${identity}: parent link`);
    const expectedKey = [read.position, read.id, nodeSlot];
    assert.deepEqual(node.key, expectedKey, `${identity}: key is derived from its logical query`);
    if (lower) assert(byKey(lower, node.key) < 0, `${identity}: exceeds lower bound`);
    if (upper) assert(byKey(node.key, upper) < 0, `${identity}: below upper bound`);
    if (interval) {
      assert.deepEqual(node.value.end_key, read.arguments[1], `${identity}: stored interval upper bound`);
    } else {
      assert(node.value.end_key == null, `${identity}: point node has no interval bound`);
    }

    const childLeft = visitOptional(node.left, link, lower, node.key);
    const childRight = visitOptional(node.right, link, node.key, upper);
    const own = { ...scan([expectedEntries.find(entry => entry.link.rid === read.id)]) };
    if (interval) own.end_key = read.arguments[1];
    assert.deepEqual(stable(node.value), stable(own), `${identity}: complete leaf value`);
    const ordered = [...childLeft.entries, expectedEntries.find(entry => entry.link.rid === read.id), ...childRight.entries];
    const expectedSummary = combineIndex(ordered, compare, interval);
    assert.deepEqual(stable(node.summary), stable(expectedSummary), `${identity}: complete subtree summary`);
    assert.equal(node.height, 1 + Math.max(childLeft.height, childRight.height), `${identity}: height`);
    assert(Math.abs(childLeft.height - childRight.height) <= 1, `${identity}: AVL balance`);
    return { height: node.height, entries: ordered };
  }

  function visitOptional(link, parent, lower, upper) {
    if (link == null) return { height: 0, entries: [] };
    const result = visit(link, parent, lower, upper);
    const row = rows.get(link.rid), node = row?.[nodeSlot];
    const order = expectedEntries;
    const at = order.findIndex(entry => entry.link.rid === link.rid);
    const expectedPrev = at > 0 ? order[at - 1].link : null;
    const expectedNext = at + 1 < order.length ? order[at + 1].link : null;
    assert.deepEqual(node.prev ?? null, expectedPrev, `${idOf(link)}: predecessor thread`);
    assert.deepEqual(node.next ?? null, expectedNext, `${idOf(link)}: successor thread`);
    return result;
  }

  const tree = visitOptional(head.root, owner, null, null);
  assert.equal(seen.size, active.length, `${group.id}: every active node is reachable exactly once`);
  assert.equal(head.height, tree.height, `${group.id}: root height`);
  assert.deepEqual(stable(head.summary), stable(combineIndex(tree.entries, compare, interval)), `${group.id}: complete root summary`);
}

// Reconstruct consumed values from independently authored source entries and
// check every maintained private subscription tree. `expectedReads` is a set of
// logical calls supplied by the fixture/model, not inferred from the metadata
// under test. It detects the case where an entire registration was deleted.
function verifyReads(data, sourceRows, entries, compare, options = {}) {
  const reads = data.rebase_read || [];
  const groups = data.rebase_read_group || [];
  const frames = data.rebase_read_frame || [];
  const byId = new Map(sourceRows.map(row => [row.id, row]));
  assert.equal(byId.size, sourceRows.length, 'source rows have unique record identities');
  const readById = new Map(reads.map(read => [read.id, read]));
  assert.equal(readById.size, reads.length, 'logical reads have unique record identities');
  const groupById = new Map(groups.map(group => [group.id, group]));
  assert.equal(groupById.size, groups.length, 'read groups have unique record identities');
  const frameById = new Map(frames.map(frame => [frame.id, frame]));
  assert.equal(frameById.size, frames.length, 'read frames have unique record identities');
  const rootSpecs = options.rootSpecs ? new Set(options.rootSpecs.map(root => `${root.table}.${root.slot}`)) : null;

  const membersByGroup = new Map();
  const versionByFrame = new Map();
  for (const read of reads) {
    assertReadShape(read);
    const reader = byId.get(read.reader), source = byId.get(read.source_root);
    assert(reader && source, `${read.id}: live subscriber and source`);
    assert.equal(read.tenant, reader.tenant, `${read.id}: reader tenant`);
    assert.equal(source.tenant, reader.tenant, `${read.id}: source and reader share a tenant`);
    const group = groupById.get(read.group);
    assert(group, `${read.id}: owning read group exists`);
    assert.equal(group.tenant, read.tenant, `${read.id}: group tenant`);
    assert.equal(group.source_root, read.source_root, `${read.id}: group source`);
    assert.equal(group.source_slot, read.source_slot, `${read.id}: group source slot`);
    assert.equal(group.kind, read.kind, `${read.id}: group operation`);
    assert.equal(group.channel, read.channel, `${read.id}: group channel`);
    if (read.kind === 'record') assert.equal(read.source_slot, '');
    else if (rootSpecs) assert(rootSpecs.has(`${recordTable(read.source_root)}.${read.source_slot}`),
      `${read.id}: source slot is a declared business root`);

    const frameId = `rebase_read_frame:[${read.reader}, '${read.phase}']`;
    const frame = frameById.get(frameId);
    assert(frame, `${read.id}: evaluation frame exists`);
    assert(Number.isInteger(frame.version) && frame.version > 0, `${frameId}: positive generation`);
    assert.equal(read.version, frame.version, `${read.id}: no obsolete subscription`);
    if (versionByFrame.has(frameId)) assert.equal(versionByFrame.get(frameId), read.version, `${frameId}: one generation per frame`);
    versionByFrame.set(frameId, read.version);
    if (!membersByGroup.has(read.group)) membersByGroup.set(read.group, []);
    membersByGroup.get(read.group).push(read);

    const calculated = expectedQuery(read, byId, entries, compare, options.exactSummary || scan);
    const observed = read.observed?.value, wanted = calculated ?? read.fallback?.value;
    if (options.decimal && wanted instanceof options.decimal) {
      assert(observed !== undefined && observed !== null, `${read.reader}: cached ${read.kind}/${read.path} exists`);
      assert.equal(new options.decimal(observed).cmp(wanted), 0,
        `${read.reader}: cached ${read.kind}/${read.path} ${observed} != ${wanted.number()}`);
    } else equal(observed, wanted, `${read.reader}: cached ${read.kind}/${read.path}`);
    if (read.z_position != null && read.kind === 'range') assert.fail(`${read.id}: range read indexed in point tree`);
    if (read.z_interval != null && read.kind !== 'range') assert.fail(`${read.id}: non-range read indexed in interval tree`);
  }

  for (const group of groups) {
    const members = membersByGroup.get(group.id) || [];
    assert(members.length > 0, `${group.id}: no orphan empty read group`);
    verifyIndex(group, members, readById, compare, group.kind === 'range');
    verifyIndex(group, members, readById, compare, group.kind !== 'range');
  }
  // Source identities may themselves contain arrays or escaped delimiters.
  // Match known identities instead of parsing their serialized contents.
  const fenceSources = new Map(sourceRows.map(row => [`rebase_read_lock:[${row.id}]`, row]));
  for (const lock of data.rebase_read_lock || []) {
    const source = fenceSources.get(lock.id);
    assert(source, `${lock.id}: fence belongs to a live source row`);
    assert(Number.isInteger(lock.revision) && lock.revision > 0, `${lock.id}: positive fence revision`);
    const allowedTenants = [source.tenant, source.id, ...(source.parents || [])].filter(value => value != null);
    assert(allowedTenants.includes(lock.tenant), `${lock.id}: fence tenant matches its source`);
  }
  for (const read of reads) assert(groupById.has(read.group), `${read.id}: no orphan read`);
  const expectedFrames = new Set(reads.map(read => `rebase_read_frame:[${read.reader}, '${read.phase}']`));
  for (const frame of frames) assert(expectedFrames.has(frame.id), `${frame.id}: no orphan evaluation frame`);

  if (options.expectedReads) {
    const normalize = item => stable({
      reader: item.reader,
      phase: item.phase,
      source_root: item.source_root,
      source_slot: item.source_slot ?? '',
      kind: item.kind,
      arguments: item.arguments ?? [],
      path: item.path ?? '',
      fallback: item.fallback,
    });
    const expected = new Map(options.expectedReads.map(item => [JSON.stringify(normalize(item)), normalize(item)]));
    const actual = new Map(reads.map(item => [JSON.stringify(normalize(readDescription(item))), normalize(readDescription(item))]));
    assert.equal(actual.size, reads.length, 'no duplicate logical read descriptions');
    assert.deepEqual([...actual.keys()].sort(), [...expected.keys()].sort(), 'exact logical read coverage, including absent registrations');
  }
  return { reads: reads.length, groups: groups.length, frames: frames.length };
}

module.exports = { verifyReads, readDescription, expectedPosition, expectedChannel };
