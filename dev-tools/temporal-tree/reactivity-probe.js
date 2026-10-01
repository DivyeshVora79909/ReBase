#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { start, client, compareKey } = require('./harness');
const { compileFromArgs } = require('../compiler/cli');
const oracle = require('./oracle');

async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-v2-compile-'));
  fs.copyFileSync(path.join(__dirname, 'compiler-fixture.surql'), path.join(dir, 'schema.surql'));
  const result = compileFromArgs({ projectDir: dir, frameworkDir: 'framework', outputDir: path.join(dir, 'build') });
  const server = await start();
  const query = client(server.url);
  try {
    await query('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await query(result.bundle);
  } catch (error) { await server.close(); fs.rmSync(dir, { recursive: true, force: true }); throw error; }
  return { query, server, bundle: result.bundle, async close() { await server.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}

const date = (day) => new Date(Date.UTC(2026, 0, 1 + day)).toISOString();
const literal = (value) => JSON.stringify(value);

async function snapshot(q) {
  return q('RETURN { owners: (SELECT * FROM tree_owner), facts: (SELECT * FROM fact), charges: (SELECT * FROM charge), inherited: (SELECT * FROM inherited_fact), chained: (SELECT * FROM chained_fact), unlinked: (SELECT * FROM unlinked_fact), rules: (SELECT * FROM rule), reports: (SELECT * FROM report) };');
}

function verify(data) {
  const facts = new Map(data.facts.map((r) => [r.id, r]));
  const rules = new Map(data.rules.map((r) => [r.id, r]));
  const entries = [], totals = new Map();
  const inherited = new Map(data.inherited.map((r) => [r.id, r]));
  const rows = [...data.facts, ...data.charges, ...data.inherited, ...data.chained, ...data.unlinked].sort((a, b) => compareKey([a.a_effective_at, a.id], [b.a_effective_at, b.id]));
  const add = (row, slot, owner, measures, tags = {}, spans = {}, dependent = false) => {
    if (!owner) return;
    entries.push({ link: { rid: row.id, slot }, owner: { rid: owner, slot: 'z_book' }, key: [row.a_effective_at, row.id, slot], measures, tags, spans, dependent });
    totals.set(owner, (totals.get(owner) || 0) + (measures.amount || 0));
  };
  for (const row of rows) {
    if (row.id.startsWith('fact:')) {
      add(row, 'z_leg', row.a_owner, { amount: row.a_owner === row.a_mirror ? 0 : Number(row.a_amount), quantity: Number(row.a_quantity) }, { currency: 'USD' }, { fact: row.a_effective_at });
      if (row.a_mirror !== row.a_owner) add(row, 'z_mirror', row.a_mirror, { amount: -Number(row.a_amount) });
    } else if (row.id.startsWith('inherited_fact:')) {
      const parent = facts.get(row.a_parent);
      const amount = Number(parent.a_amount) * Number(row.a_factor);
      assert.equal(row.z10_owner, parent.a_owner);
      oracle.equal(row.z20_amount, amount);
      add(row, 'z_leg', parent.a_owner, { amount }, {}, { inherited: row.a_effective_at });
    } else if (row.id.startsWith('chained_fact:')) {
      const parent = inherited.get(row.a_parent), original = facts.get(parent.a_parent);
      const amount = Number(original.a_amount) * Number(parent.a_factor) * 2;
      assert.equal(row.z10_owner, original.a_owner);
      oracle.equal(row.z20_amount, amount);
      add(row, 'z_leg', original.a_owner, { amount }, {}, { inherited: row.a_effective_at });
    } else if (row.id.startsWith('unlinked_fact:')) {
      add(row, 'z_leg', 'tree_owner:singleton', { amount: Number(row.a_amount) });
    } else {
      const rule = rules.get(row.a_rule);
      const basis = totals.get(row.a_owner) || 0;
      const amount = Math.min(Number(rule.a_cap), basis * Number(rule.a_rate));
      oracle.equal(row.z20_basis, basis, `basis ${row.id}`);
      oracle.equal(row.z30_amount, amount, `amount ${row.id}`);
      add(row, 'z_leg', row.a_owner, { amount }, { currency: 'USD' }, { charge: row.a_effective_at }, true);
      add(row, 'z_mirror', row.a_mirror, { amount: -amount });
    }
  }
  for (const row of data.reports) oracle.equal(row.z_total, totals.get(row.a_owner) || 0, 'published consumer');
  return oracle.verify(data.owners, rows, entries);
}

async function rejected(q, sql, pattern) {
  const old = await snapshot(q);
  await assert.rejects(q(sql), pattern);
  assert.deepEqual(await snapshot(q), old, 'a rejected write must roll back source, shadows, and every tree');
}

async function queries(q, groups) {
  for (const { owner, entries } of groups.values()) {
    for (const k of [0, 1, Math.floor(entries.length / 2), entries.length, entries.length + 1]) {
      assert.deepEqual(await q(`RETURN fn::tree::read(${owner.rid}, '${owner.slot}', 'select', [${k}]);`), entries[k - 1]?.link || null);
    }
    for (const p of [0, 0.5, 1]) {
      const k = Math.max(1, Math.ceil(p * entries.length));
      assert.deepEqual(await q(`RETURN fn::tree::read(${owner.rid}, '${owner.slot}', 'percentile', [${p}dec]);`), entries[k - 1]?.link || null);
    }
    for (const [lo, hi] of [[-100,1000],[0,8],[2,7],[7,8],[20,10]]) {
      const from = [date(lo)], to = [date(hi)];
      oracle.equal(await q(`RETURN fn::tree::read(${owner.rid}, '${owner.slot}', 'range', [[d'${date(lo)}'], [d'${date(hi)}']]);`),
        oracle.scan(entries.filter((e) => compareKey(e.key, from) >= 0 && compareKey(e.key, to) < 0)), 'range');
    }
    for (const entry of entries.slice(0, 6)) {
      const [at, id, slot] = entry.key;
      oracle.equal(await q(`RETURN fn::tree::read(${owner.rid}, '${owner.slot}', 'before', [d'${at}', ${literal(id)}, '${slot}']);`),
        oracle.scan(entries.filter((e) => compareKey(e.key, entry.key) < 0)), 'prefix');
    }
  }
}

async function boundaries(env) {
  const q = env.query;
  await q('CREATE tree_owner:ordered SET owned_by=rebase_group:root;');
  const at = (i) => `2026-02-01T00:00:00.${String(i).padStart(9, '0')}Z`;
  for (let i = 1; i <= 32; i++) {
    await q(`CREATE fact:ordered_${String(i).padStart(2, '0')} SET owned_by=rebase_group:root, a_owner=tree_owner:ordered, a_amount=1dec, a_effective_at=d'${at(i)}';`);
  }
  verify(await snapshot(q));
  assert((await q('RETURN tree_owner:ordered.z_book.height;')) <= Math.ceil(1.45 * Math.log2(34)), 'ascending insertion must remain AVL bounded');
  assert.equal(await q(`RETURN fn::tree::read(tree_owner:ordered,'z_book','before',[d'${at(17)}']).count;`), 16);
  assert.equal(await q(`RETURN fn::tree::read(tree_owner:ordered,'z_book','range',[[d'${at(9)}'],[d'${at(17)}']]).count;`), 8);
  await q(`UPDATE fact:ordered_32 SET a_effective_at=d'${at(1)}';`);
  const entries = verify(await snapshot(q)).get('tree_owner:ordered/z_book').entries;
  assert.equal(entries[0].link.rid, 'fact:ordered_01');
  assert.equal(entries[1].link.rid, 'fact:ordered_32');
  assert.deepEqual(await q("RETURN fn::tree::read(tree_owner:ordered,'z_book','select',[2]);"), entries[1].link);
  assert.equal(await q(`RETURN fn::tree::read(tree_owner:ordered,'z_book','rank',[d'${at(1)}','fact:ordered_32','z_leg']);`), 2);
  const before = await snapshot(q);
  await q(env.bundle);
  assert.deepEqual(await snapshot(q), before, 'reapplying the current schema must preserve populated trees and shadows');
  console.log('PASS ascending AVL bound, nanosecond ordering, stable ties/date edits and populated schema reapplication');
}

async function permissions(env) {
  const q = env.query;
  await q("CREATE rebase_user:reader SET name='Reader', parents=[rebase_group:root]; CREATE rebase_user:stranger SET name='Stranger', parents=[rebase_group:root]; DEFINE ACCESS fixture_user ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;");
  await q('CREATE tree_owner:hidden SET owned_by=rebase_user:stranger;');
  const response = await fetch(`${env.server.url}/signin`, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'fixture_user' }) });
  const { token } = await response.json(); assert(token);
  const user = client(env.server.url, 'fixture', token);
  await q('CREATE principal_report:a SET owned_by=rebase_group:root, a_user=rebase_user:reader;');
  const principalStamp = await q('RETURN rebase_user:reader.updated_at;');
  await q('UPDATE rebase_user:reader;');
  assert.equal(await q('RETURN rebase_user:reader.updated_at;'), principalStamp);
  await q("UPDATE rebase_user:reader SET name='Renamed';");
  assert.equal(await q('RETURN principal_report:a.z_name;'), 'Renamed');
  assert.notEqual(await q('RETURN rebase_user:reader.updated_at;'), principalStamp);
  const head = await user("RETURN fn::tree::read(tree_owner:a,'z_book','summary',[]);");
  assert(head.count > 0);
  assert.equal((await user('SELECT * FROM ONLY report:a;')).z_private, undefined);
  await assert.rejects(user("RETURN fn::tree::get({rid:report:a,slot:'z_private'});"), /MISSING_SLOT/);
  await assert.rejects(user("RETURN fn::tree::read(tree_owner:hidden,'z_book','summary',[]);"), /permission|not allowed/i);
  await assert.rejects(user("RETURN fn::tree::before({rid:tree_owner:hidden,slot:'z_book'}, []);"), /MISSING_SLOT/);
  await assert.rejects(user("RETURN fn::tree::patch({rid:tree_owner:a,slot:'z_book'},{root:NONE});"), /permission|not allowed/i);
  const before = await snapshot(q);
  await user("UPDATE tree_owner:a SET z_book.root=NONE, z_book.summary.count=999; UPDATE fact:a SET z_leg.parent={rid:tree_owner:a,slot:'z_book'}, z_leg.summary.count=999;");
  assert.deepEqual(await snapshot(q), before);
  await user(`CREATE charge:authenticated SET owned_by=rebase_user:reader, a_owner=tree_owner:a, a_rule=rule:a, a_effective_at=d'${date(50)}', z20_basis=99999dec, z30_amount=99999dec;`);
  verify(await snapshot(q));
  console.log('PASS record-auth queries, private mutators, forged metadata/shadows, authenticated live-rule creation');
}

async function concurrency(q) {
  await q('CREATE tree_owner:hot SET owned_by=rebase_group:root;');
  let conflicts = 0;
  await Promise.all(Array.from({ length: 10 }, (_, i) => (async () => {
    for (let retry = 0; ; retry++) {
      try {
        await q(`CREATE fact:parallel_${i} SET owned_by=rebase_group:root, a_owner=tree_owner:hot, a_amount=1dec, a_effective_at=d'${date(i)}';`);
        break;
      } catch (error) {
        if (!/conflict|retry/i.test(error.message) || retry > 50) throw error;
        conflicts++;
        await new Promise((resolve) => setTimeout(resolve, Math.min(50, retry * 3 + 2)));
      }
    }
  })()));
  verify(await snapshot(q));
  assert.equal(Number(await q('RETURN tree_owner:hot.z_book.summary.measures.amount.sum;')), 10);
  assert(conflicts > 0);
  console.log(`PASS concurrent owner fencing (${conflicts} conflict retries)`);
}

async function main() {
  const env = await setup(); const q = env.query;
  try {
    const member = (slot, amount, currency = 'USD', day = 0, dependent = false) =>
      `fn::tree::member(fact:coalesce,'${slot}',tree_owner:a,'z_book',d'${date(day)}',{amount:${amount}dec},{currency:'${currency}'},{},${dependent})`;
    const net = await q(`RETURN fn::tree::coalesce([${member('z_leg',-100,'USD',0,true)},${member('z_mirror',100)}])[0].value;`);
    assert.equal(net.count, 1); assert.equal(net.dependents, 1);
    oracle.equal(net.measures.amount,
      { sum: 0, min_prefix: 0, max_prefix: 0, min: 0, max: 0, instant_min: 0, instant_max: 0 });
    await assert.rejects(q(`RETURN fn::tree::coalesce([${member('z_leg',1)},${member('z_mirror',1,'EUR')}]);`), /TREE_COALESCE_DIMENSION/);
    const positions = await q(`RETURN fn::tree::coalesce([${member('z_mirror',1,'USD',1)},${member('z_leg',1)}]);`);
    assert.deepEqual(positions.map(position => position.link.slot), ['z_leg', 'z_mirror']);
    assert.equal(positions.length, 2, 'distinct instants remain separate positions in the same owner');
    await assert.rejects(q(`RETURN fn::tree::coalesce([${member('z_leg',1)},${member('z_mirror',1,'USD',0,true)}]);`), /TREE_COALESCE_CAUSAL_SLOT/);
    await assert.rejects(q(`RETURN fn::tree::coalesce([${member('z_leg',1)},${member('z_leg',1)}]);`), /TREE_DUPLICATE_MEMBERSHIP/);
    console.log('PASS simultaneous contribution netting, exact dimensions, temporal boundaries and stable causal slots');
    await q('CREATE tree_owner:a SET owned_by=rebase_group:root, a_nonnegative=true; CREATE tree_owner:b SET owned_by=rebase_group:root; CREATE tree_owner:c SET owned_by=rebase_group:root; CREATE rule:a SET owned_by=rebase_group:root; CREATE rule:cap SET owned_by=rebase_group:root, a_rate=0.5dec, a_cap=5dec;');
    await q(`CREATE fact:a SET owned_by=rebase_group:root, a_owner=tree_owner:a, a_mirror=tree_owner:b, a_amount=100dec, a_effective_at=d'${date(0)}';`);
    await q('CREATE report:a SET owned_by=rebase_group:root, a_owner=tree_owner:a;');
    await q(`CREATE fact:same SET owned_by=rebase_group:root, a_owner=tree_owner:a, a_mirror=tree_owner:a, a_amount=-10000dec, a_effective_at=d'${date(1)}';`);
    verify(await snapshot(q));
    await q('UPDATE fact:same SET a_mirror=tree_owner:b, a_amount=10dec;'); verify(await snapshot(q));
    await q('UPDATE fact:same SET a_mirror=tree_owner:a;'); verify(await snapshot(q));
    await q('DELETE fact:same;'); verify(await snapshot(q));
    for (const [name, day, rule] of [['a', 2, 'a'], ['cap', 4, 'cap'], ['b', 6, 'a'], ['c', 8, 'a']]) {
      await q(`CREATE charge:${name} SET owned_by=rebase_group:root, a_owner=tree_owner:a, a_mirror=tree_owner:b, a_rule=rule:${rule}, a_effective_at=d'${date(day)}';`);
    }
    await q(`CREATE fact:middle SET owned_by=rebase_group:root, a_owner=tree_owner:a, a_mirror=tree_owner:b, a_amount=20dec, a_effective_at=d'${date(3)}';`);
    verify(await snapshot(q));
    const capped = Number(await q('RETURN charge:cap.z30_amount;'));
    await q('UPDATE fact:middle SET a_amount=40dec;');
    verify(await snapshot(q));
    assert.equal(Number(await q('RETURN charge:cap.z30_amount;')), capped);
    await q(`UPDATE fact:middle SET a_effective_at=d'${date(5)}';`); verify(await snapshot(q));
    await q('DELETE charge:a;'); verify(await snapshot(q));
    await q('DELETE fact:middle;'); verify(await snapshot(q));
    await q('UPDATE rule:a SET a_rate=0.2dec;'); verify(await snapshot(q));
    await q(`UPDATE charge:b SET a_effective_at=d'${date(7)}';`); verify(await snapshot(q));
    await q('UPDATE charge:b SET a_owner=tree_owner:c;'); verify(await snapshot(q));
    await q('UPDATE charge:b SET a_owner=tree_owner:a;'); verify(await snapshot(q));
    await q(`CREATE inherited_fact:a SET owned_by=rebase_group:root, a_parent=fact:a, a_effective_at=d'${date(1)}';`); verify(await snapshot(q));
    await q(`CREATE chained_fact:a SET owned_by=rebase_group:root, a_parent=inherited_fact:a, a_effective_at=d'${date(2)}';`); verify(await snapshot(q));
    await q('UPDATE fact:a SET a_owner=tree_owner:c, a_amount=120dec;'); verify(await snapshot(q));
    await q('UPDATE fact:a SET a_owner=tree_owner:a;'); verify(await snapshot(q));
    await rejected(q, `UPDATE fact:a SET a_effective_at=d'${date(2)}';`, /FIXTURE_CHILD_BEFORE_PARENT/);
    await rejected(q, `CREATE fact:bad SET owned_by=rebase_group:root, a_owner=tree_owner:a, a_amount=-1dec, a_effective_at=d'${date(-1)}';`, /FIXTURE_NEGATIVE_HISTORY/);
    await rejected(q, 'DELETE tree_owner:a;', /reference|referenced/i);
    const before = await snapshot(q);
    await q('UPDATE fact:a SET system_ping=time::now();');
    const after = await snapshot(q);
    assert.equal(after.facts.find((r) => r.id === 'fact:a').updated_at, before.facts.find((r) => r.id === 'fact:a').updated_at);
    assert.deepEqual(after.owners, before.owners);
    const stamp = after.facts.find((r) => r.id === 'fact:a').updated_at;
    await q("UPDATE fact:a SET a_note='edited';");
    assert.notEqual((await snapshot(q)).facts.find((r) => r.id === 'fact:a').updated_at, stamp);
    await queries(q, verify(await snapshot(q)));
    console.log('PASS compiled multi-tree chronology, range/rank/percentile oracle, inherited references, capped-prefix invalidation, final guards and timestamps');
    let seed = 92817;
    const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
    const live = [];
    const count = process.argv.includes('--quick') ? 12 : 80;
    for (let i=0; i<count; i++) {
      live.push(`fact:fuzz_${i}`);
      await q(`CREATE fact:fuzz_${i} SET owned_by=rebase_group:root, a_owner=tree_owner:c, a_amount=${Math.floor(random()*100)}dec, a_effective_at=d'${date(Math.floor(random()*40))}';`);
    }
    verify(await snapshot(q));
    for (let i=0; i<count*2; i++) {
      const index = Math.floor(random()*live.length), id = live[index];
      if (random() < 0.3) { await q(`DELETE ${id};`); live.splice(index, 1); }
      else await q(`UPDATE ${id} SET a_amount=${Math.floor(random()*100)}dec, a_effective_at=d'${date(Math.floor(random()*40))}';`);
      verify(await snapshot(q));
    }
    console.log(`PASS ${count*3} randomized compiled mutations against independent source oracle`);
    for (;;) {
      const root = await q('RETURN tree_owner:c.z_book.root;');
      if (!root) break;
      await q(`DELETE ${root.rid};`);
      verify(await snapshot(q));
    }
    await q('CREATE tree_owner:singleton SET owned_by=rebase_group:root;');
    await q(`CREATE unlinked_fact:a SET owned_by=rebase_group:root, a_amount=1dec, a_effective_at=d'${date(0)}';`);
    await rejected(q, 'DELETE tree_owner:singleton;', /TREE_OWNER_NOT_EMPTY/);
    await q('DELETE unlinked_fact:a; DELETE tree_owner:singleton;');
    verify(await snapshot(q));
    console.log('PASS repeated root deletion, empty trees and singleton-owner lifecycle without reverse references');
    await permissions(env);
    await concurrency(q);
    await boundaries(env);
  } finally { await env.close(); }
}
if (require.main === module) main().catch(e => { console.error(e); process.exitCode = 1; });
module.exports = { setup, main, snapshot, verify, boundaries };
