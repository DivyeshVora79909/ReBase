#!/usr/bin/env node
'use strict';
// Handwritten primitive regression. The compiled contract is in typed-probe.js.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { start, client, applySchema, compareIntKey: compareOrdinal } = require('./harness');
const oracle = require('./oracle');

const literal = value => JSON.stringify(value); // SQL data, never a shell argument.
const ownerLink = id => `{ rid: ${id}, slot: 'rb_order' }`;
const snapshot = q => q('RETURN { owners: (SELECT * FROM ordinal_owner ORDER BY id), facts: (SELECT * FROM ordinal_fact ORDER BY id) };');

function verify(data) {
  // Authoritative fields only: do not use rb_order to derive expected entries.
  const entries = data.facts.filter(row => row.order_value !== undefined).map(row => ({
    link: { rid: row.id, slot: 'rb_order' },
    owner: { rid: row.owner, slot: 'rb_order' },
    key: [row.order_value, row.id, 'rb_order'],
    measures: { weight: Number(row.weight) }, tags: {}, spans: {}, dependent: false
  }));
  return oracle.verify(data.owners, data.facts, entries, compareOrdinal);
}

async function queries(q, groups) {
  const requests = [], expected = [];
  for (const { owner, entries } of groups.values()) {
    const link = ownerLink(owner.rid);
    for (const k of new Set([0, 1, Math.ceil(entries.length / 2), entries.length, entries.length + 1])) {
      requests.push(`fn::tree::select(${link}, ${k}, false)`);
      expected.push(entries[k - 1]?.link || null);
    }
    // A short key excludes all ties; a full key can divide a tied group.
    for (const key of [[-10], [0], [2], [10], ...entries.map(entry => entry.key)]) {
      const preceding = entries.filter(entry => compareOrdinal(entry.key, key) < 0);
      requests.push(`fn::tree::before(${link}, ${literal(key)})`);
      expected.push(oracle.scan(preceding));
      requests.push(`fn::tree::before(${link}, ${literal(key)}).count + 1`);
      expected.push(preceding.length + 1);
    }
    for (const [lower, upper] of [[[-100], [100]], [[-10], [2]], [[2], [10]], [[10], [2]], [[2], [2]]]) {
      requests.push(`fn::tree::range(${link}, ${literal(lower)}, ${literal(upper)})`);
      expected.push(oracle.scan(entries.filter(entry => compareOrdinal(entry.key, lower) >= 0 && compareOrdinal(entry.key, upper) < 0)));
    }
  }
  const actual = await q(`RETURN [${requests.join(',\n')}];`);
  assert.equal(actual.length, expected.length);
  actual.forEach((result, i) => oracle.equal(result, expected[i], `ordinal query ${i}`));
  return requests.length;
}

async function rejected(q, sql, pattern) {
  const before = await snapshot(q);
  await assert.rejects(q(sql), pattern);
  assert.deepEqual(await snapshot(q), before, 'rejection must restore sources, links, summaries and revisions');
  verify(before);
}

async function main() {
  const server = await start();
  const q = client(server.url);
  let mutations = 0, reads = 0, rejections = 0;
  const mutate = async sql => {
    await q(sql);
    mutations++;
    const data = await snapshot(q);
    verify(data);
    return data;
  };
  const reject = async (sql, pattern) => { await rejected(q, sql, pattern); rejections++; };
  const create = (id, owner, order, weight = 1) => mutate(
    `CREATE ordinal_fact:${id} SET owner=ordinal_owner:${owner}, order_value=${order === null ? 'NONE' : order}, weight=${weight}dec;`
  );
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    const runtime = fs.readFileSync(path.join(__dirname, '../../src/temporal.surql'), 'utf8');
    const fixture = fs.readFileSync(path.join(__dirname, 'ordinal-fixture.surql'), 'utf8');
    await applySchema(q, `${runtime}\n${fixture}`);
    const version = execFileSync(process.env.REBASE_TREE_SURREAL_BIN || 'surreal', ['version'], { encoding: 'utf8' }).trim();
    console.log(`Ordinal primitive probe: SurrealDB ${version}, Node ${process.version}, ${server.engine}`);

    // Each three-node sequence forces one of LL, RR, LR or RL balancing paths.
    for (const [name, values] of Object.entries({ ll: [30, 20, 10], rr: [10, 20, 30], lr: [30, 10, 20], rl: [10, 30, 20] })) {
      await mutate(`CREATE ordinal_owner:${name};`);
      for (const value of values) await create(`${name}_${value}`, name, value, value === 20 ? -2 : 3);
      const root = await q(`RETURN ordinal_owner:${name}.rb_order.root;`);
      const node = await q(`RETURN ${root.rid}.rb_order;`);
      assert.equal(node.key[0], 20, `${name} rotation should promote the middle key`);
      assert(node.left && node.right, `${name} should exercise two-child root deletion`);
      reads += await queries(q, verify(await snapshot(q)));
      await mutate(`DELETE ${root.rid};`);
      for (const value of [10, 30]) await mutate(`DELETE ordinal_fact:${name}_${value};`);
      reads += await queries(q, verify(await snapshot(q)));
      await mutate(`DELETE ordinal_owner:${name};`);
    }
    console.log('PASS integer keys through LL/RR/LR/RL rotations, two-child deletion and empty trees');

    for (const id of ['alpha', 'beta', 'limited']) await mutate(`CREATE ordinal_owner:${id} SET max_count=${id === 'limited' ? 1 : 100};`);
    for (const [id, value, weight] of [['ten', 10, 5], ['z_tie', 2, -4], ['zero', 0, 3], ['negative', -10, -2], ['a_tie', 2, 6], ['middle', -2, 1]]) {
      await create(id, 'alpha', value, weight);
    }
    await create('other', 'beta', 2);
    await create('full', 'limited', 0);
    await create('unranked', 'alpha', null);
    let data = await snapshot(q);
    assert.equal(data.facts.find(row => row.id === 'ordinal_fact:unranked').rb_order, undefined);
    const group = verify(data).get('ordinal_owner:alpha/rb_order');
    assert.deepEqual(group.entries.map(entry => entry.key[0]), [-10, -2, 0, 2, 2, 10]);
    assert.deepEqual(group.entries.filter(entry => entry.key[0] === 2).map(entry => entry.link.rid), ['ordinal_fact:a_tie', 'ordinal_fact:z_tie']);
    reads += await queries(q, verify(data));

    const untouched = data.owners.filter(row => row.id !== 'ordinal_owner:alpha');
    await mutate('UPDATE ordinal_fact:ten SET order_value=-20, weight=7dec;');
    assert.deepEqual((await snapshot(q)).owners.filter(row => row.id !== 'ordinal_owner:alpha'), untouched, 'a rekey must not touch other owners');
    await mutate('UPDATE ordinal_fact:z_tie SET weight=9dec;');
    await mutate('UPDATE ordinal_fact:a_tie SET owner=ordinal_owner:beta, order_value=10;');
    await mutate('UPDATE ordinal_fact:unranked SET order_value=2;');
    data = await mutate('UPDATE ordinal_fact:unranked SET order_value=NONE;');
    assert.equal(data.facts.find(row => row.id === 'ordinal_fact:unranked').rb_order, undefined);
    reads += await queries(q, verify(data));
    console.log('PASS numeric order, stable ties, absent ranks, value edits, rekeys and owner isolation');

    await reject('CREATE ordinal_fact:overflow SET owner=ordinal_owner:limited, order_value=1;', /ORDINAL_OWNER_LIMIT/);
    await reject('UPDATE ordinal_fact:zero SET owner=ordinal_owner:limited;', /ORDINAL_OWNER_LIMIT/);
    await reject('UPDATE ordinal_owner:alpha SET max_count=0;', /ORDINAL_OWNER_LIMIT/);
    for (const invalid of ["'high'", "d'2026-09-25T00:00:00Z'", '1.5dec', '1dec', 'true', 'NULL']) {
      await reject(`UPDATE ordinal_fact:zero SET order_value=${invalid};`, /order_value|int/i);
    }
    await reject("UPDATE ordinal_fact:zero SET rb_order.key=[d'2026-09-25T00:00:00Z', 'ordinal_fact:zero', 'rb_order'];", /rb_order|int/i);
    await reject('DELETE ordinal_owner:alpha;', /TREE_OWNER_NOT_EMPTY|reference/i);
    console.log('PASS post-maintenance create/move/owner-guard rollback and invalid key types');

    let seed = 250925;
    const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
    const live = [];
    for (let i = 0; i < 12; i++) {
      live.push(`ordinal_fact:fuzz_${i}`);
      await create(`fuzz_${i}`, i % 2 ? 'alpha' : 'beta', Math.floor(random() * 21) - 10, Math.floor(random() * 11) - 5);
    }
    for (let i = 0; i < 32 && live.length; i++) {
      const index = Math.floor(random() * live.length), id = live[index];
      if (random() < 0.2) {
        await mutate(`DELETE ${id};`);
        live.splice(index, 1);
      } else {
        const owner = random() < 0.5 ? 'alpha' : 'beta';
        const order = random() < 0.2 ? 'NONE' : Math.floor(random() * 21) - 10;
        await mutate(`UPDATE ${id} SET owner=ordinal_owner:${owner}, order_value=${order}, weight=${Math.floor(random() * 11) - 5}dec;`);
      }
    }
    reads += await queries(q, verify(await snapshot(q)));
    console.log('PASS deterministic mutation oracle (seed 250925)');

    for (const owner of ['alpha', 'beta', 'limited']) {
      for (;;) {
        const root = await q(`RETURN ordinal_owner:${owner}.rb_order.root;`);
        if (!root) break;
        await mutate(`DELETE ${root.rid};`);
      }
    }
    data = await snapshot(q);
    for (const row of data.facts) await mutate(`DELETE ${row.id};`);
    reads += await queries(q, verify(await snapshot(q)));
    for (const owner of ['alpha', 'beta', 'limited']) await mutate(`DELETE ordinal_owner:${owner};`);
    assert.deepEqual(await snapshot(q), { owners: [], facts: [] });
    console.log(`PASS ${mutations} mutation checkpoints, ${reads} numeric read assertions, ${rejections} rejection snapshots; complete cleanup`);
    console.log('Scope: handwritten integer-key regression on the shared runtime; compiled contracts and ACL are covered by probe:typed-tree. Integer prefix dependencies remain unsupported.');
  } finally {
    await server.close();
  }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
