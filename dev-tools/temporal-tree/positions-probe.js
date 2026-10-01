#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const { execFileSync } = require('node:child_process');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema, compareKey, compareIntKey } = require('./harness');
const oracle = require('./oracle');

const suffixes = ['z', 'a', 'm', 'b']; // Declaration order, deliberately not lexical.
const slots = ['time', 'order'].flatMap(kind => suffixes.map(suffix => `rb_${kind}_${suffix}`));
const at = n => `2026-09-25T00:00:00.${String(n).padStart(9, '0')}Z`;
const literal = value => JSON.stringify(value); // SQL data, never shell text.
const keySql = key => `[${key.map((value, i) => i === 0 && typeof value === 'string' ? `d'${value}'` : literal(value)).join(',')}]`;
const compare = (a, b) => typeof a[0] === 'number' ? compareIntKey(a, b) : compareKey(a, b);
const identity = link => `${link.rid}/${link.slot}`;
const snapshot = q => q(`RETURN {
    owners: (SELECT * FROM position_owner ORDER BY id), facts: (SELECT * FROM position_fact ORDER BY id)
};`);
const keyFields = (keys, kind) => suffixes.map((suffix, i) => `a_${kind}_${suffix}=${keys[i] == null ? 'NONE'
  : kind === 'time' ? `d'${at(keys[i])}'` : keys[i]}`).join(', ');
const bothKeys = (time, order = time) => `${keyFields(time, 'time')}, ${keyFields(order, 'order')}`;
const createFact = (name, keys, extra = '', order = keys) => `CREATE position_fact:${name} SET owned_by=rebase_group:root,
    a_time_owner=position_owner:left, a_order_owner=position_owner:left, ${bothKeys(keys, order)}${extra ? `, ${extra}` : ''};`;

async function setup() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-positions-'));
  let server;
  try {
    fs.copyFileSync(path.join(__dirname, 'positions-fixture.surql'), path.join(directory, 'schema.surql'));
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    const { bundle } = generateBundle(materials);
    assert.equal(generateBundle(materials).bundle, bundle, 'deterministic compilation');
    server = await start({ engine: 'surrealkv' });
    const query = client(server.url);
    await query('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(query, bundle);
    return { query, server, bundle, async close() {
      await server.close(); fs.rmSync(directory, { recursive: true, force: true });
    } };
  } catch (error) {
    if (server) await server.close();
    fs.rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

function verify(data) {
  const entries = [];
  for (const row of [...data.owners, ...data.facts]) {
    // Reconstruct ONLY from authoritative inputs; no cached keys, values,
    // provider array, links or summaries participate in this netting oracle.
    for (const kind of ['time', 'order']) {
      const owner = row[`a_${kind}_owner`] ?? (row.id.startsWith('position_owner:') ? row.id : undefined);
      if (!owner) continue;
      const grouped = new Map();
      for (const suffix of suffixes) {
        const value = row[`a_${kind}_${suffix}`];
        if (value == null) continue;
        let entry = grouped.get(value);
        if (!entry) {
          const slot = `rb_${kind}_${suffix}`;
          entry = { link: { rid: row.id, slot }, owner: { rid: owner, slot: `rb_${kind}` },
            key: [value, row.id, slot], measures: { weight: 0 }, tags: {}, spans: {}, dependent: false };
          grouped.set(value, entry);
        }
        entry.measures.weight += Number(row[`a_weight_${suffix}`]);
        const tag = row[`a_tag_${suffix}`];
        if (entry.tags.unit !== undefined) assert.equal(entry.tags.unit, tag);
        entry.tags.unit = tag;
        const span = kind === 'time' ? row[`a_span_${suffix}`] : undefined;
        if (span !== undefined) {
          if (entry.spans.basis !== undefined) assert.equal(entry.spans.basis, span);
          entry.spans.basis = span;
        }
      }
      entries.push(...grouped.values());
    }
  }
  return oracle.verify(data.owners, [...data.owners, ...data.facts], entries, compare);
}

function fences(before, after) {
  for (const [name, group] of after) {
    const old = before.get(name);
    const changed = !isDeepStrictEqual(old?.entries ?? [], group.entries);
    assert.equal(group.head.revision, (old?.head.revision ?? 0) + Number(changed), `one revision per affected owner: ${name}`);
  }
}

async function queries(q, groups) {
  const requests = [], expected = [];
  const add = (request, value) => { requests.push(request); expected.push(value); };
  for (const { owner, entries } of groups.values()) {
    const read = (operation, argument) => `fn::tree::read(${owner.rid}, '${owner.slot}', '${operation}', ${argument})`;
    add(read('summary', '[]'), oracle.scan(entries));
    for (const k of new Set([0, 1, Math.ceil(entries.length / 2), entries.length, entries.length + 1])) {
      add(read('select', `[${k}]`), entries[k - 1]?.link ?? null);
    }
    for (const p of [0, 0.5, 1]) add(read('percentile', `[${p}dec]`), entries[Math.max(1, Math.ceil(p * entries.length)) - 1]?.link ?? null);
    const time = owner.slot === 'rb_time';
    const bounds = time ? [[at(0)], [at(20)], [at(80)]] : [[-9007199254740991], [20], [9007199254740991]];
    const keys = [...bounds, ...entries.flatMap(entry => [entry.key.slice(0, 2), entry.key])];
    for (const key of keys) {
      const before = entries.filter(entry => compare(entry.key, key) < 0);
      add(read('before', keySql(key)), oracle.scan(before));
      add(read('rank', keySql(key)), before.length + 1);
    }
    const pairs = [[bounds[0], bounds[2]], [bounds[1], bounds[2]], [bounds[2], bounds[0]], [bounds[1], bounds[1]]];
    if (entries.length) pairs.push([entries[0].key, entries.at(-1).key]);
    for (const [low, high] of pairs) add(read('range', `[${keySql(low)},${keySql(high)}]`),
      oracle.scan(entries.filter(entry => compare(entry.key, low) >= 0 && compare(entry.key, high) < 0)));
  }
  for (let i = 0; i < requests.length; i += 100) {
    const actual = await q(`RETURN [${requests.slice(i, i + 100).join(',\n')}];`);
    assert.equal(actual.length, Math.min(100, requests.length - i));
    actual.forEach((value, index) => oracle.equal(value, expected[i + index], requests[i + index]));
  }
  return requests.length;
}

// Inspect actual pre-delete topology, without assuming that an insertion order
// produced a particular shape. Two-child categories use the first removed slot
// in each owner, so a previous removal cannot have eliminated that path.
function deletionShapes(data, rid, coverage) {
  const records = new Map([...data.owners, ...data.facts].map(row => [row.id, row]));
  const row = records.get(rid), owners = new Set();
  if (!row) return;
  for (const slot of slots) {
    const node = row[slot];
    if (!node || node.owner.rid === rid) continue;
    for (const field of ['parent', 'left', 'right', 'prev', 'next']) if (node[field]?.rid === rid) coverage.add(`${field}-on-deleted`);
    const head = records.get(node.owner.rid)[node.owner.slot];
    if (head.root?.rid === rid) coverage.add('root-on-deleted');
    const owner = identity(node.owner);
    if (!owners.has(owner) && node.left && node.right) {
      let successor = node.right;
      while (records.get(successor.rid)[successor.slot].left) successor = records.get(successor.rid)[successor.slot].left;
      const next = records.get(successor.rid)[successor.slot];
      coverage.add(`successor-${identity(next.parent) === `${rid}/${slot}` ? 'direct' : 'indirect'}-${successor.rid === rid ? 'deleted' : 'live'}`);
    }
    owners.add(owner);
  }
}

async function main() {
  const env = await setup(), q = env.query;
  let mutations = 0, reads = 0, rejections = 0;
  const coverage = new Set();
  const mutate = async (sql, user = q) => {
    const before = await snapshot(q), old = verify(before);
    const deletion = sql.match(/^DELETE (\w+:\w+);$/);
    if (deletion) deletionShapes(before, deletion[1], coverage);
    await user(sql);
    const after = await snapshot(q), groups = verify(after);
    fences(old, groups); mutations++;
    return after;
  };
  const reject = async (sql, pattern, user = q) => {
    const before = await snapshot(q);
    await assert.rejects(user(sql), pattern);
    assert.deepEqual(await snapshot(q), before, 'rollback includes sources, slots, roots, revisions and metadata');
    verify(before); rejections++;
  };
  try {
    const version = execFileSync(process.env.REBASE_TREE_SURREAL_BIN || 'surreal', ['version'], { encoding: 'utf8' }).trim();
    console.log(`Compiled multi-position trees: SurrealDB ${version}, Node ${process.version}, ${env.server.engine}`);
    for (const name of ['left', 'right', 'limited']) await mutate(`CREATE position_owner:${name} SET owned_by=rebase_group:root;`);
    assert.deepEqual(await q('RETURN fn::rebase::slots(position_fact:example);'), slots);
    await mutate(createFact('edge', [30, 10, 20, 40]));
    const original = await snapshot(q);
    await mutate('UPDATE position_fact:edge SET a_reverse=true;');
    const reversed = await snapshot(q);
    assert.deepEqual(reversed.owners, original.owners, 'provider order does not fence or rewrite roots');
    for (const slot of slots) assert.deepEqual(reversed.facts[0][slot], original.facts[0][slot]);
    await mutate(`UPDATE position_fact:edge SET ${bothKeys([20, 20, 20, 20])},
      a_weight_z=9dec, a_weight_a=-9dec, a_weight_m=4dec, a_weight_b=-4dec;`);
    const merged = (await snapshot(q)).facts[0];
    for (const kind of ['time', 'order']) {
      assert.equal(merged[`rb_${kind}_z`].value.count, 1);
      oracle.equal(merged[`rb_${kind}_z`].value.measures.weight,
        { sum: 0, min: 0, max: 0, min_prefix: 0, max_prefix: 0, instant_min: 0, instant_max: 0 });
      for (const suffix of ['a', 'm', 'b']) assert.equal(merged[`rb_${kind}_${suffix}`], undefined);
    }
    await mutate(createFact('tie', [20, 20]));
    assert.equal((await snapshot(q)).owners[0].rb_time.summary.count, 2, 'different sources never coalesce together');
    for (const keys of [[null, 20, 20, 20], [null, null, 20, 20], [20, 20, 20, 20], [10, 10, 30, 30], [10, 20, 30, 40]]) {
      await mutate(`UPDATE position_fact:edge SET ${bothKeys(keys)};`);
    }
    await mutate(`UPDATE position_fact:edge SET ${bothKeys([0, 1, null, null], [-9007199254740991, 9007199254740991])};`);
    await mutate('UPDATE position_fact:edge SET a_time_owner=position_owner:right;');
    await mutate('UPDATE position_fact:edge SET a_order_owner=position_owner:right, a_weight_z=3dec;');
    await mutate(`UPDATE position_fact:edge SET ${bothKeys([])};`);
    await mutate(`UPDATE position_fact:edge SET a_time_owner=position_owner:left, a_order_owner=position_owner:left,
      ${bothKeys([40, 20, 60, 50])}, a_weight_z=1dec, a_weight_a=1dec, a_weight_m=1dec, a_weight_b=1dec;`);
    reads += await queries(q, verify(await snapshot(q)));
    console.log('PASS distinct datetime/int positions, schema-order identities, merge/split, absence, net zero, nanosecond ties, rekeys and owner moves');

    await reject('UPDATE position_fact:edge SET a_fail=true, a_order_z=21, a_time_owner=position_owner:right;', /POSITIONS_SOURCE_GUARD/);
    await reject(createFact('failed', [40, 20, 60, 50], 'a_fail=true'), /POSITIONS_SOURCE_GUARD/);
    await reject(`UPDATE position_fact:edge SET ${bothKeys([20, 20])}, a_tag_a='EUR';`, /TREE_COALESCE_DIMENSION/);
    await reject(`UPDATE position_fact:edge SET ${bothKeys([20, 20])}, a_span_z=d'${at(1)}', a_span_a=d'${at(2)}';`, /TREE_COALESCE_SPAN/);
    await reject('UPDATE position_fact:edge SET a_time_owner=position_owner:missing;', /record::exists/);
    await reject('BEGIN TRANSACTION; DELETE position_fact:edge; THROW "POSITIONS_LATE_FAILURE"; COMMIT TRANSACTION;', /POSITIONS_LATE_FAILURE/);
    await mutate('UPDATE position_owner:left SET a_floor=3dec;');
    await reject('DELETE position_fact:edge;', /POSITIONS_OWNER_FLOOR/);
    await mutate('UPDATE position_owner:left SET a_floor=NONE;');
    await reject('DELETE position_owner:left;', /ON DELETE REJECT/);
    await reject('UPDATE position_owner:left SET a_time_limit=1;', /POSITIONS_OWNER_LIMIT/);
    await mutate('DELETE position_fact:edge;');
    await mutate('DELETE position_fact:tie;');
    console.log('PASS post-maintenance source/owner guards, incompatible coincident legs, delete rollback and nonempty-owner protection');

    // All insertion permutations exercise rotations with four linked slots on
    // one deleted row. Larger shapes mix detached and still-live successors.
    const permutations = values => values.length ? values.flatMap((value, i) =>
      permutations(values.filter((_, j) => i !== j)).map(tail => [value, ...tail])) : [[]];
    for (const keys of [[20, 10, 30], [40, 20, 60, 50], ...permutations([10, 20, 30, 40])]) {
      await mutate(createFact('shape', keys));
      await mutate('DELETE position_fact:shape;');
    }
    await mutate(createFact('shape', [40, 20, 60, 50]));
    for (const key of [10, 30, 45, 55, 70]) await mutate(createFact(`live_${key}`, [key]));
    await mutate('DELETE position_fact:shape;');
    for (const key of [10, 30, 45, 55, 70]) await mutate(`DELETE position_fact:live_${key};`);
    for (const expected of ['parent-on-deleted', 'left-on-deleted', 'right-on-deleted', 'prev-on-deleted', 'next-on-deleted',
      'root-on-deleted', 'successor-direct-deleted', 'successor-indirect-deleted', 'successor-indirect-live']) {
      assert(coverage.has(expected), `missing observed deletion topology: ${expected}`);
    }
    console.log(`PASS 24 insertion permutations and linked-slot deletion paths: ${[...coverage].sort().join(', ')}`);

    const composedOrder = `CREATE position_owner:composed SET owned_by=rebase_group:root,
      a_order_owner=position_owner:right, ${keyFields([40, 20, 60, 50], 'order')};`;
    await mutate(composedOrder);
    await mutate('DELETE position_owner:composed;');
    await mutate(composedOrder);
    await mutate(createFact('outside', [25], 'a_time_owner=position_owner:composed'));
    await reject('DELETE position_owner:composed;', /ON DELETE REJECT/);
    await mutate('DELETE position_fact:outside;');
    await mutate('DELETE position_owner:composed;');
    console.log('PASS root/source composition and native owner-reference fencing');

    let seed = 260925, serial = 0;
    const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
    const randomKeys = () => suffixes.map(() => random() < 0.2 ? null : Math.floor(random() * 32));
    const live = [];
    const addRandom = async () => {
      const name = `fuzz_${serial++}`;
      await mutate(createFact(name, randomKeys(), `a_reverse=${random() < 0.5}`, randomKeys()));
      live.push(name);
    };
    for (let i = 0; i < 16; i++) await addRandom();
    for (let i = 0; i < 80; i++) {
      const index = Math.floor(random() * live.length), name = live[index], operation = random();
      if (!live.length || operation < 0.15) await addRandom();
      else if (operation < 0.3) { await mutate(`DELETE position_fact:${name};`); live.splice(index, 1); }
      else if (operation < 0.5) await mutate(`UPDATE position_fact:${name} SET a_time_owner=position_owner:${random() < 0.5 ? 'left' : 'right'},
        a_order_owner=position_owner:${random() < 0.5 ? 'left' : 'right'};`);
      else if (operation < 0.65) await mutate(`UPDATE position_fact:${name} SET a_weight_z=${Math.floor(random() * 9) - 4}dec, a_reverse=${random() < 0.5};`);
      else await mutate(`UPDATE position_fact:${name} SET ${bothKeys(randomKeys(), randomKeys())};`);
    }
    reads += await queries(q, verify(await snapshot(q)));
    const populated = await snapshot(q);
    await applySchema(q, env.bundle);
    assert.deepEqual(await snapshot(q), populated, 'populated schema reapplication is a no-op');
    // Delete entire sources chosen from actual roots until every tree is empty.
    while (true) {
      const data = await snapshot(q);
      const rid = data.owners.flatMap(row => [row.rb_time.root?.rid, row.rb_order.root?.rid]).find(Boolean) ?? data.facts[0]?.id;
      if (!rid) break;
      await mutate(`DELETE ${rid};`);
    }
    console.log('PASS 96 deterministic multi-position mutations, repeated root-source deletion and populated reapplication (seed 260925)');

    await mutate('UPDATE position_owner:limited SET a_time_limit=4, a_order_limit=4;');
    const beforeRace = verify(await snapshot(q));
    let conflicts = 0;
    const contenders = await Promise.all(Array.from({ length: 6 }, (_, i) => (async () => {
      const name = `contender_${i}`;
      for (let retry = 0; ; retry++) {
        try {
          await q(createFact(name, [10, 20, 30, 40], 'a_time_owner=position_owner:limited, a_order_owner=position_owner:limited'));
          return { name, success: true };
        } catch (error) {
          if (/POSITIONS_OWNER_LIMIT/.test(error.message)) return { name, success: false };
          if (!/conflict|retry/i.test(error.message) || retry >= 20) throw error;
          conflicts++;
          await new Promise(resolve => setTimeout(resolve, Math.min(50, 3 * retry + 2)));
        }
      }
    })()));
    assert.equal(contenders.filter(result => result.success).length, 1);
    const afterRace = await snapshot(q);
    const raced = verify(afterRace); fences(beforeRace, raced); mutations++;
    for (const result of contenders) assert.equal(afterRace.facts.some(row => row.id === `position_fact:${result.name}`), result.success);
    for (const kind of ['time', 'order']) assert.equal(afterRace.owners.find(row => row.id === 'position_owner:limited')[`rb_${kind}`].summary.count, 4);
    console.log(`PASS six competing eight-slot writes: one commit, five complete rollbacks (${conflicts} conflict retries)`);

    await q(`CREATE rebase_user:reader SET name='Reader', parents=[rebase_group:root];
      DEFINE ACCESS positions_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;`);
    const response = await fetch(`${env.server.url}/signin`, { method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'positions_reader' }) });
    const { token } = await response.json(); assert(token);
    const user = client(env.server.url, 'fixture', token);
    await reject("RETURN fn::tree::load({rid:position_owner:left,slot:'rb_time'}, {rid:position_owner:left,slots:{rb_time:{}}});", /permission|not allowed/i, user);
    await reject("RETURN fn::tree::put({rid:position_owner:left,slot:'rb_time'}, {}, {rid:position_owner:left,slots:{}});", /permission|not allowed/i, user);
    await mutate(`CREATE position_owner:reader SET owned_by=rebase_user:reader;`, user);
    await mutate(createFact('reader', [40, 20, 60, 50], 'owned_by=rebase_user:reader, a_time_owner=position_owner:reader, a_order_owner=position_owner:reader'), user);
    await mutate('DELETE position_fact:reader;', user);
    await mutate('DELETE position_owner:reader;', user);
    reads += await queries(q, verify(await snapshot(q)));
    for (const row of (await snapshot(q)).facts) await mutate(`DELETE ${row.id};`);
    reads += await queries(q, verify(await snapshot(q)));
    for (const row of (await snapshot(q)).owners) await mutate(`DELETE ${row.id};`);
    assert.deepEqual(await snapshot(q), { owners: [], facts: [] });
    console.log(`PASS ${mutations} mutation checkpoints, ${reads} ordered reads, ${rejections} rejection snapshots; private frames, record-user deletion and complete cleanup`);
    return { mutations, reads, rejections, coverage: [...coverage].sort(), conflicts };
  } finally { await env.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, setup, snapshot, verify, queries };
