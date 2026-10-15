'use strict';

const { scan } = require('./oracle');

const compareValue = (a, b) => {
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const compared = compareValue(a[i], b[i]);
      if (compared) return compared;
    }
    return a.length - b.length;
  }
  return a < b ? -1 : a > b ? 1 : 0;
};
const compareKey = (a, b) => compareValue(a, b);
const idOf = link => link ? `${link.rid}/${link.slot}` : null;
const linkFor = (row, slot) => ({ rid: row.id, slot });

function fixture({ sourceId = 'read_curve:probe', includeReaders, conditionalFallback = false } = {}) {
  const tenant = 'tenant:probe';
  const source = { id: sourceId, tenant, initial: 3, seed: { initial: 3 } };
  const readers = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map(name => ({ id: `read_reader:${name}`, tenant }));
  const sourceRows = [source, ...readers];
  const sourceEntries = [
    { link: { rid: 'read_point:four', slot: 'z_point' }, owner: { rid: source.id, slot: 'z_points' }, key: [4, 'read_point:four', 'z_point'], measures: { value: 3 }, tags: {}, spans: {}, dependent: false },
    { link: { rid: 'read_point:eight', slot: 'z_point' }, owner: { rid: source.id, slot: 'z_points' }, key: [8, 'read_point:eight', 'z_point'], measures: { value: 5 }, tags: {}, spans: {}, dependent: false },
  ];
  const descriptions = [
    { reader: 'read_reader:a', phase: 'refresh', source_root: source.id, source_slot: '', kind: 'record', arguments: [], path: 'initial', fallback: 0, observed: 3 },
    { reader: 'read_reader:b', phase: 'refresh', source_root: source.id, source_slot: '', kind: 'record', arguments: [], path: 'initial', fallback: 0, observed: 3 },
    { reader: 'read_reader:c', phase: 'refresh', source_root: source.id, source_slot: 'z_points', kind: 'latest', arguments: [[7]], path: 'measures.value.sum', fallback: 0, observed: 3 },
    { reader: 'read_reader:d', phase: 'validate', source_root: source.id, source_slot: 'z_points', kind: 'latest', arguments: [[7]], path: 'measures.value.sum', fallback: 0, observed: 3 },
    { reader: 'read_reader:e', phase: 'refresh', source_root: source.id, source_slot: 'z_points', kind: 'range', arguments: [[0], [7]], path: 'measures.value.sum', fallback: 0, observed: 3 },
    { reader: 'read_reader:f', phase: 'refresh', source_root: source.id, source_slot: 'z_points', kind: 'range', arguments: [[7], [10]], path: 'measures.value.sum', fallback: 0, observed: 5 },
  ];
  if (conditionalFallback) descriptions.push(
    { reader: 'read_reader:g', phase: 'refresh', source_root: source.id, source_slot: 'z_points', kind: 'latest', arguments: [[0]], path: 'measures.value.sum', fallback: 0, observed: 0 },
    { reader: 'read_reader:g', phase: 'refresh', source_root: source.id, source_slot: '', kind: 'record', arguments: [], path: 'seed.initial', fallback: '0', observed: 3 },
  );
  const selectedDescriptions = includeReaders
    ? descriptions.filter(read => includeReaders.includes(read.reader.slice(read.reader.indexOf(':') + 1)))
    : descriptions;
  const data = { rebase_read: [], rebase_read_group: [], rebase_read_frame: [], rebase_read_lock: [
    { id: `rebase_read_lock:[${source.id}]`, tenant, revision: 1 },
  ] };
  const rootSpecs = [{ table: 'read_curve', slot: 'z_points' }];

  const groupId = read => `rebase_read_group:[${read.source_root}, '${read.source_slot}', '${read.kind}', '${read.kind === 'record' ? read.path.split('.')[0] : 'measures:value'}']`;
  const fingerprint = read => `fingerprint:${read.reader.slice(read.reader.indexOf(':') + 1)}:${read.phase}`;
  for (const description of selectedDescriptions) {
    const channel = description.kind === 'record' ? description.path.split('.')[0] : 'measures:value';
    const group = groupId(description);
    const position = ['latest', 'next', 'range'].includes(description.kind) ? description.arguments[0]
      : ['before', 'exact'].includes(description.kind) ? description.arguments : [];
    const id = `rebase_read:[${group}, ${JSON.stringify(position)}, '${description.reader}', '${description.phase}', '${fingerprint(description)}']`;
    const read = {
      id, canonical_id: id, tenant, reader: description.reader, reader_identity: description.reader, phase: description.phase, version: 1,
      source_root: description.source_root, source_slot: description.source_slot,
      kind: description.kind, channel, arguments: description.arguments, path: description.path,
      fallback: { value: description.fallback }, observed: { value: description.observed },
      group, position,
    };
    if (description.kind !== 'range') {
      const entry = description.kind === 'record'
        ? { link: { rid: id, slot: 'z_position' }, key: [position, id, 'z_position'], dependent: false, measures: {}, tags: {}, spans: {} }
        : null;
      if (entry) read.z_position = { owner: { rid: group, slot: 'z_positions' }, parent: null, left: null, right: null,
        prev: null, next: null, key: entry.key, value: scan([entry]), summary: scan([entry]), height: 1 };
    }
    data.rebase_read.push(read);
    const frameId = `rebase_read_frame:[${description.reader}, '${description.phase}']`;
    if (!data.rebase_read_frame.some(frame => frame.id === frameId)) data.rebase_read_frame.push({ id: frameId, version: 1 });
    if (!data.rebase_read_group.some(row => row.id === group)) {
      data.rebase_read_group.push({ id: group, canonical_id: group, tenant, source_root: description.source_root, source_slot: description.source_slot,
        kind: description.kind, channel, z_positions: emptyHead(), z_intervals: emptyHead() });
    }
  }

  for (const group of data.rebase_read_group) {
    const members = data.rebase_read.filter(read => read.group === group.id);
    const interval = group.kind === 'range';
    const slot = interval ? 'z_interval' : 'z_position';
    const headSlot = interval ? 'z_intervals' : 'z_positions';
    const active = members.filter(read => !interval || compareKey(read.arguments[0], read.arguments[1]) < 0);
    const entries = active.map(read => ({
      link: { rid: read.id, slot }, key: [read.position, read.id, slot], end_key: interval ? read.arguments[1] : undefined,
      dependent: false, measures: {}, tags: {}, spans: {},
    })).sort((a, b) => compareKey(a.key, b.key));
    const build = (start, end, parent) => {
      if (start >= end) return { link: null, height: 0, entries: [] };
      const middle = Math.floor((start + end) / 2), entry = entries[middle], read = data.rebase_read.find(row => row.id === entry.link.rid);
      const left = build(start, middle, entry.link), right = build(middle + 1, end, entry.link);
      const own = { count: 1, dependents: 0, first: entry.key, last: entry.key, measures: {}, tags: {}, spans: {} };
      if (interval) own.end_key = read.arguments[1];
      const ordered = [...left.entries, entry, ...right.entries];
      const summary = scan(ordered);
      if (interval) summary.end_key = ordered.map(item => item.end_key).sort(compareKey).at(-1);
      const node = { owner: { rid: group.id, slot: headSlot }, parent, left: left.link, right: right.link,
        prev: null, next: null, key: entry.key, value: own, summary, height: 1 + Math.max(left.height, right.height) };
      read[slot] = node;
      return { link: entry.link, height: node.height, entries: ordered };
    };
    const tree = build(0, entries.length, { rid: group.id, slot: headSlot });
    for (let i = 0; i < entries.length; i++) {
      const read = data.rebase_read.find(row => row.id === entries[i].link.rid);
      read[slot].prev = i ? entries[i - 1].link : null;
      read[slot].next = i + 1 < entries.length ? entries[i + 1].link : null;
    }
    const summary = scan(entries);
    if (interval && entries.length) summary.end_key = entries.map(item => item.end_key).sort(compareKey).at(-1);
    group[headSlot] = { root: tree.link, height: tree.height, revision: entries.length ? 1 : 0,
      refreshing: false, summary };
  }

  const entries = [...sourceEntries];
  const expectedReads = selectedDescriptions;
  const checkOptions = { rootSpecs, expectedReads };
  return { data, sourceRows, entries, compare: compareKey, expectedReads, checkOptions, descriptions:selectedDescriptions };
}

function emptyHead() {
  return { height: 0, revision: 0, refreshing: false, summary: { count: 0, dependents: 0, measures: {}, tags: {}, spans: {} } };
}

module.exports = { fixture, compareKey, idOf };
