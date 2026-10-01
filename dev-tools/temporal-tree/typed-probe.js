#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema, compareKey, compareIntKey } = require('./harness');
const oracle = require('./oracle');

const literal = value => JSON.stringify(value); // SQL data only, never shell text.
const at = n => `2026-09-25T00:00:00.${String(n).padStart(9, '0')}Z`;
const keySql = key => `[${key.map((value, i) => i === 0 && typeof value === 'string' ? `d'${value}'` : literal(value)).join(',')} ]`;
const compare = (a, b) => typeof a[0] === 'number' ? compareIntKey(a, b) : compareKey(a, b);
const snapshot = q => q(`RETURN {
    scales: (SELECT * FROM stage_scale ORDER BY id), stages: (SELECT * FROM stage_code ORDER BY id),
    boards: (SELECT * FROM stage_board ORDER BY id), archives: (SELECT * FROM stage_archive ORDER BY id),
    facts: (SELECT * FROM stage_fact ORDER BY id), archiveFacts: (SELECT * FROM archive_fact ORDER BY id),
    privateBoards: (SELECT * FROM private_board ORDER BY id), privateFacts: (SELECT * FROM private_fact ORDER BY id)
};`);

async function setup() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-typed-tree-'));
  let server;
  try {
    fs.copyFileSync(path.join(__dirname, 'typed-fixture.surql'), path.join(directory, 'schema.surql'));
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    const compiled = generateBundle(materials);
    assert.equal(compiled.bundle, generateBundle(materials).bundle, 'deterministic compilation');
    server = await start({ engine: 'surrealkv' });
    const query = client(server.url);
    await query('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(query, compiled.bundle);
    return { server, query, materials, bundle: compiled.bundle, async close() {
      await server.close(); fs.rmSync(directory, { recursive: true, force: true });
    } };
  } catch (error) {
    if (server) await server.close();
    fs.rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

function verify(data) {
  const stages = new Map(data.stages.map(stage => [stage.id, stage]));
  const owners = [...data.boards, ...data.archives, ...data.privateBoards];
  const entries = [];
  const add = (row, slot, owner, root, value, measures, tags = {}, spans = {}) => entries.push({
    link: { rid: row.id, slot }, owner: { rid: owner, slot: root },
    key: [value, row.id, slot], measures, tags, spans, dependent: false,
  });
  for (const row of data.facts) {
    // Expected keys come from input references and immutable scale rows, never
    // from the maintained slot or its stored derived code.
    const stage = stages.get(row.a_stage);
    assert.equal(row.z20_code, stage?.a_code, `derived code ${row.id}`);
    assert.equal(row.z10_scale, stage?.a_scale, `derived scale ${row.id}`);
    const scope = { scope: row.owned_by, visible: row.visibility };
    if (row.a_history && row.a_effective_at) add(row, 'rb_history', row.a_history, 'rb_history', row.a_effective_at,
      { weight: Number(row.a_weight) }, scope, { occurred: row.a_effective_at });
    if (row.a_ranking && stage) add(row, 'rb_rank', row.a_ranking,
      row.a_ranking.startsWith('stage_archive:') ? 'rb_priority' : 'rb_rank', stage.a_code,
      { weight: Number(row.a_weight) }, { ...scope, scale: stage.a_scale });
  }
  for (const row of data.archiveFacts) {
    if (row.a_code !== undefined) add(row, 'rb_archive', row.a_owner, 'rb_priority', row.a_code,
      { weight: 1 }, { scale: data.archives.find(owner => owner.id === row.a_owner).a_scale, scope: row.owned_by, visible: row.visibility });
  }
  for (const row of data.privateFacts) {
    for (const [slot, root] of [['rb_hidden', 'rb_hidden'], ['rb_owner', 'rb_owner'], ['rb_private', 'rb_public']]) {
      add(row, slot, row.a_owner, root, 1, {});
    }
  }
  return oracle.verify(owners, [...data.facts, ...data.archiveFacts, ...data.privateFacts], entries, compare);
}

async function queries(q, groups) {
  const requests = [], expected = [];
  for (const { owner, entries } of groups.values()) {
    const read = (operation, argument) => `fn::tree::read(${owner.rid}, '${owner.slot}', '${operation}', ${argument})`;
    requests.push(read('summary', '[]')); expected.push(oracle.scan(entries));
    for (const k of new Set([0, 1, Math.ceil(entries.length / 2), entries.length, entries.length + 1])) {
      requests.push(read('select', `[${k}]`)); expected.push(entries[k - 1]?.link || null);
    }
    for (const p of [0, 0.5, 1]) {
      requests.push(read('percentile', `[${p}dec]`));
      expected.push(entries[Math.max(1, Math.ceil(p * entries.length)) - 1]?.link || null);
    }
    const time = owner.slot === 'rb_history';
    const keys = time ? [[at(0)], [at(5)], [at(50)]] : [[-9007199254740991], [-10], [0], [10], [9007199254740991]];
    keys.push(...entries.flatMap(entry => [entry.key.slice(0, 2), entry.key]));
    for (const key of keys) {
      const before = entries.filter(entry => compare(entry.key, key) < 0);
      requests.push(read('before', keySql(key))); expected.push(oracle.scan(before));
      requests.push(read('rank', keySql(key))); expected.push(before.length + 1);
    }
    const bounds = time ? [[at(0)], [at(5)], [at(50)]] : [[-9007199254740991], [0], [9007199254740991]];
    for (const [low, high] of [[bounds[0], bounds[2]], [bounds[1], bounds[2]], [bounds[2], bounds[0]], [bounds[1], bounds[1]]]) {
      requests.push(read('range', `[${keySql(low)}, ${keySql(high)}]`));
      expected.push(oracle.scan(entries.filter(entry => compare(entry.key, low) >= 0 && compare(entry.key, high) < 0)));
    }
  }
  // Keep request bodies bounded, including the deterministic fuzz populations.
  for (let i = 0; i < requests.length; i += 100) {
    const actual = await q(`RETURN [${requests.slice(i, i + 100).join(',\n')}];`);
    actual.forEach((value, index) => oracle.equal(value, expected[i + index], requests[i + index]));
    assert.equal(actual.length, Math.min(100, requests.length - i));
  }
  return requests.length;
}

async function permissions(env, reject) {
  const q = env.query;
  await q(`CREATE rebase_user:reader SET name='Reader', parents=[rebase_group:root];
    CREATE rebase_user:stranger SET name='Stranger', parents=[rebase_group:root];
    DEFINE ACCESS typed_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;
    DEFINE ACCESS typed_stranger ON DATABASE TYPE RECORD SIGNIN rebase_user:stranger;
    CREATE stage_board:hidden SET owned_by=rebase_user:stranger, a_scale=stage_scale:v1;
    CREATE private_board:example SET owned_by=rebase_user:reader;
    CREATE private_fact:example SET owned_by=rebase_user:reader, a_owner=private_board:example;`);
  const signin = async access => {
    const response = await fetch(`${env.server.url}/signin`, { method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: access }) });
    const { token } = await response.json(); assert(token);
    return client(env.server.url, 'fixture', token);
  };
  const reader = await signin('typed_reader'), stranger = await signin('typed_stranger');
  await reject('UPDATE stage_board:alpha SET visibility=true;', /TYPED_READ_SCOPE/);
  await reject('UPDATE stage_board:alpha SET owned_by=rebase_user:stranger;', /TYPED_READ_SCOPE/);
  await reject('UPDATE archive_fact:one SET owned_by=rebase_user:stranger;', /TYPED_READ_SCOPE/);
  for (const selectPolicy of ['readers', 'owner']) {
    const before = await snapshot(q);
    await applySchema(q, generateBundle(env.materials, { selectPolicy }).bundle);
    assert.deepEqual(await snapshot(q), before, `reapply populated ${selectPolicy} policy`);
    assert((await reader("RETURN fn::tree::read(stage_board:alpha,'rb_rank','summary',[]);")).count > 0);
    assert.equal(await reader("RETURN fn::tree::read(private_board:example,'rb_owner','summary',[]).count;"), 1);
    assert.equal(await stranger("RETURN fn::tree::read(private_board:example,'rb_public','summary',[]).count;"), 1);
    const fields = await reader('SELECT * FROM ONLY private_board:example;');
    assert.equal(fields.rb_hidden, undefined);
    assert.equal((await stranger('SELECT * FROM ONLY private_board:example;')).rb_owner, undefined);
    assert.equal((await reader('SELECT * FROM ONLY private_fact:example;')).rb_private, undefined);
    assert.equal(await reader('RETURN private_board:example.rb_hidden.summary.count;'), null);
    assert.equal(await stranger('SELECT VALUE rb_owner.summary.count FROM ONLY private_board:example;'), null);
    assert.equal(await reader('SELECT VALUE rb_private.key FROM ONLY private_fact:example;'), null);
    for (const [user, sql, pattern] of [
      [reader, "RETURN fn::tree::read(stage_board:hidden,'rb_rank','summary',[]);", /permission|not allowed/i],
      [reader, "RETURN fn::tree::read(private_board:example,'rb_hidden','summary',[]);", /MISSING_SLOT/],
      [stranger, "RETURN fn::tree::read(private_board:example,'rb_owner','summary',[]);", /MISSING_SLOT/],
      [reader, "RETURN fn::tree::get({rid:private_fact:example,slot:'rb_private'});", /MISSING_SLOT/],
      [reader, "RETURN fn::tree::get({rid:private_fact:example,slot:'rb_private.summary'});", /MISSING_SLOT/],
      [reader, "RETURN fn::tree::get({rid:private_board:example,slot:'rb_hidden.summary'});", /MISSING_SLOT/],
      [reader, "RETURN fn::tree::read(private_board:example,'rb_public','select',[1]);", /MISSING_SLOT/],
      [reader, "RETURN fn::tree::read(private_board:example,'rb_public','before',[2]);", /MISSING_SLOT/],
      [reader, "RETURN fn::tree::patch({rid:stage_board:alpha,slot:'rb_rank'},{root:NONE});", /permission|not allowed/i],
    ]) await reject(sql, pattern, user);
    const stored = await snapshot(q);
    await reader(`UPDATE stage_board:alpha SET rb_rank.root=NONE, rb_rank.summary.count=999;
      UPDATE stage_fact:anchor SET rb_rank.owner={rid:stage_archive:alpha,slot:'rb_priority'}, rb_rank.summary.count=999;`);
    assert.deepEqual(await snapshot(q), stored, 'native ACL protects nested structural updates');
  }
  await reader(`CREATE stage_board:forged SET owned_by=rebase_group:root, a_scale=stage_scale:v1, rb_rank=stage_board:alpha.rb_rank;
    CREATE stage_fact:authenticated SET owned_by=rebase_group:root, a_history=stage_board:alpha,
      a_ranking=stage_board:alpha, a_stage=stage_code:low, a_effective_at=d'${at(8)}',
      z20_code=999, rb_rank=stage_fact:anchor.rb_rank;`);
  const data = await snapshot(q); verify(data);
  assert.equal(data.boards.find(row => row.id === 'stage_board:forged').rb_rank.summary.count, 0);
  console.log('PASS root/slot ACL, conditional fields, deliberate aggregate publication, forged writes and both select policies');
}

async function main() {
  require('./contract-probe').main();
  const env = await setup(), q = env.query;
  let mutations = 0, reads = 0, rejections = 0;
  const mutate = async sql => { await q(sql); mutations++; const data = await snapshot(q); verify(data); return data; };
  const reject = async (sql, pattern, actor = q) => {
    const before = await snapshot(q);
    await assert.rejects(actor(sql), pattern, sql);
    assert.deepEqual(await snapshot(q), before, 'rejection restores sources, derived fields, slots, roots and revisions');
    verify(before); rejections++;
  };
  const create = (id, stage, tick, extra = '') => mutate(`CREATE stage_fact:${id} SET owned_by=rebase_group:root,
    a_history=stage_board:alpha, a_ranking=stage_board:alpha, a_stage=stage_code:${stage},
    a_effective_at=d'${at(tick)}'${extra};`);
  try {
    const version = execFileSync(process.env.REBASE_TREE_SURREAL_BIN || 'surreal', ['version'], { encoding: 'utf8' }).trim();
    console.log(`Compiled typed trees: SurrealDB ${version}, Node ${process.version}, ${env.server.engine}`);
    await q("CREATE stage_scale:v1 SET owned_by=rebase_group:root, a_name='pipeline', a_version=1; CREATE stage_scale:v2 SET owned_by=rebase_group:root, a_name='pipeline', a_version=2;");
    for (const [id, code, scale] of [['low', -10, 'v1'], ['zero', 0, 'v1'], ['ten', 10, 'v1'], ['high', 30, 'v1'],
      ['min', -9007199254740991, 'v1'], ['max', 9007199254740991, 'v1'], ['v2', 100, 'v2']]) {
      await q(`CREATE stage_code:${id} SET owned_by=rebase_group:root, a_scale=stage_scale:${scale}, a_code=${code}, a_label='${id}';`);
    }
    for (const name of ['alpha', 'beta', 'limited', 'v2']) await mutate(`CREATE stage_board:${name} SET owned_by=rebase_group:root,
      a_scale=stage_scale:${name === 'v2' ? 'v2' : 'v1'}, a_limit=${name === 'limited' ? 0 : 100};`);
    await mutate('CREATE stage_archive:alpha SET owned_by=rebase_group:root, a_scale=stage_scale:v1;');
    await mutate('CREATE archive_fact:one SET owned_by=rebase_group:root, a_owner=stage_archive:alpha, a_code=2;');
    for (const [id, stage, tick] of [['anchor', 'low', 3], ['moving', 'ten', 1], ['a_tie', 'ten', 5], ['z_tie', 'ten', 5],
      ['zero', 'zero', 9], ['minimum', 'min', 2], ['maximum', 'max', 2]]) await create(id, stage, tick);
    let data = await snapshot(q);
    const groups = verify(data);
    assert.deepEqual(groups.get('stage_board:alpha/rb_rank').entries.filter(entry => entry.key[0] === 10).map(entry => entry.link.rid),
      ['stage_fact:a_tie', 'stage_fact:moving', 'stage_fact:z_tie']);
    reads += await queries(q, groups);

    const history = data.boards.find(row => row.id === 'stage_board:alpha').rb_history;
    data = await mutate('UPDATE stage_fact:moving SET a_stage=stage_code:high;');
    assert.deepEqual(data.boards.find(row => row.id === 'stage_board:alpha').rb_history, history, 'rank rekey leaves time tree unchanged');
    const rank = data.boards.find(row => row.id === 'stage_board:alpha').rb_rank;
    data = await mutate(`UPDATE stage_fact:moving SET a_effective_at=d'${at(15)}';`);
    assert.deepEqual(data.boards.find(row => row.id === 'stage_board:alpha').rb_rank, rank, 'time rekey leaves rank tree unchanged');
    await mutate('UPDATE stage_fact:moving SET a_weight=-3dec;');
    await mutate('UPDATE stage_fact:moving SET a_ranking=stage_archive:alpha;');
    await mutate('UPDATE stage_fact:moving SET a_history=stage_board:beta;');
    data = await mutate('UPDATE stage_fact:moving SET a_stage=NONE;');
    assert.equal(data.facts.find(row => row.id === 'stage_fact:moving').rb_rank, undefined);
    assert(data.facts.find(row => row.id === 'stage_fact:moving').rb_history);
    await mutate('UPDATE stage_fact:moving SET a_stage=stage_code:zero, a_effective_at=NONE;');
    data = await mutate(`UPDATE stage_fact:moving SET a_effective_at=d'${at(4)}';`);
    await mutate('UPDATE stage_fact:moving SET a_history=NONE, a_ranking=NONE;');
    await mutate('UPDATE stage_fact:moving SET a_history=stage_board:alpha, a_ranking=stage_board:alpha;');
    await reject('UPDATE stage_fact:moving SET a_stage=stage_code:v2;', /TYPED_SCALE_MISMATCH/);
    await mutate('UPDATE stage_fact:moving SET a_stage=stage_code:v2, a_history=stage_board:v2, a_ranking=stage_board:v2;');
    await reject('UPDATE stage_fact:anchor SET a_ranking=stage_board:v2;', /TYPED_SCALE_MISMATCH/);
    for (const sql of ["UPDATE stage_code:low SET a_label='changed';", 'UPDATE stage_code:low SET a_code=11;',
      'UPDATE stage_scale:v1 SET a_version=3;', 'UPDATE stage_board:alpha SET a_scale=stage_scale:v2;']) {
      await reject(sql, /read.?only/i);
    }
    await reject('UPDATE stage_fact:anchor SET visibility=true;', /TYPED_READ_SCOPE/);
    await reject('UPDATE stage_fact:anchor SET a_ranking=stage_board:limited;', /TYPED_OWNER_LIMIT/);
    await reject(`CREATE stage_fact:rejected SET owned_by=rebase_group:root, a_history=stage_board:alpha,
      a_ranking=stage_board:limited, a_stage=stage_code:low, a_effective_at=d'${at(1)}';`, /TYPED_OWNER_LIMIT/);
    await reject('UPDATE stage_board:alpha SET a_limit=0;', /TYPED_OWNER_LIMIT/);
    await reject('DELETE stage_board:alpha;', /reference|TREE_OWNER_NOT_EMPTY/i);
    await reject('DELETE stage_code:low;', /reference/i);
    await mutate('DELETE stage_fact:moving;');
    console.log('PASS compiled dual ordering, nanosecond ties, safe int extremes, absence, rekeys, independent owners, scale versions and rollback');

    for (const invalid of ["'high'", "d'2026-09-25T00:00:00Z'", '1.5dec', '1dec', 'true', 'NULL', '9007199254740992', '-9007199254740992']) {
      await reject(`UPDATE archive_fact:one SET a_code=${invalid};`, /a_code|int/i);
      await reject(`CREATE stage_code:invalid SET owned_by=rebase_group:root, a_scale=stage_scale:v1, a_code=${invalid}, a_label='invalid';`, /a_code|int/i);
    }
    for (const [slot, argumentsList] of [
      ['rb_rank', ['[]', '[1.5dec]', '[1dec]', "['10']", `[d'${at(0)}']`, '[true]', '[NONE]', '[NULL]', '[9007199254740992]',
        '[-9007199254740992]', "[10, 'stage_fact:anchor', 1]", '[10, 1]', "[10, 'x', 'rb_rank', 'extra']"]],
      ['rb_history', ['[]', '[1]', `['${at(0)}']`, '[NONE]', `[d'${at(0)}','x',1]`]],
    ]) for (const args of argumentsList) await reject(`RETURN fn::tree::read(stage_board:alpha,'${slot}','before',${args});`, /TREE_READ_KEY/);
    for (const [operation, argument, error] of [
      ['summary', '[1]', /TREE_READ_ARGUMENT/], ['select', '[1.5dec]', /TREE_READ_ARGUMENT/], ['select', '[1dec]', /TREE_READ_ARGUMENT/],
      ['select', "['1']", /TREE_READ_ARGUMENT/], ['select', '[]', /TREE_READ_ARGUMENT/], ['select', '[1,2]', /TREE_READ_ARGUMENT/],
      ['percentile', '[-0.1dec]', /TREE_PERCENTILE_RANGE/], ['percentile', '[1.1dec]', /TREE_PERCENTILE_RANGE/],
      ['percentile', "['0.5']", /TREE_READ_ARGUMENT/], ['percentile', '[]', /TREE_READ_ARGUMENT/],
      ['range', '[[0]]', /TREE_READ_KEY/], ['range', '[[0], [1dec]]', /TREE_READ_KEY/], ['range', '[0, 1]', /TREE_READ_KEY/],
      ['unknown', '[]', /TREE_UNKNOWN_OPERATION/],
    ]) await reject(`RETURN fn::tree::read(stage_board:alpha,'rb_rank','${operation}',${argument});`, error);
    await reject("RETURN fn::tree::read(stage_board:alpha,'rb_priority','summary',[]);", /TREE_UNKNOWN_ROOT/);
    await reject("RETURN fn::tree::select({rid:stage_board:alpha,slot:'rb_rank'},1.5dec,false);", /TREE_READ_ARGUMENT/);
    await reject("RETURN fn::tree::before({rid:stage_board:alpha,slot:'rb_rank'},[1.5dec]);", /TREE_READ_KEY/);
    await reject("RETURN fn::tree::range({rid:stage_board:alpha,slot:'rb_rank'},[0],[1dec]);", /TREE_READ_KEY/);

    // Each table and slot below is individually known, but these pairings are
    // invalid. Native generated link assertions must reject the Cartesian mix.
    for (const field of ['owner', 'parent', 'left', 'right', 'prev', 'next']) {
      const link = field === 'owner' ? "{rid:stage_board:alpha,slot:'rb_priority'}" : "{rid:archive_fact:one,slot:'rb_rank'}";
      await reject(`UPDATE stage_fact:anchor SET rb_rank.${field}=${link};`, /rb_rank|assert/i);
    }
    await reject("UPDATE stage_archive:alpha SET rb_priority.root={rid:stage_fact:anchor,slot:'rb_archive'};", /rb_priority|assert/i);
    await reject("UPDATE stage_archive:alpha SET rb_priority.root={rid:archive_fact:one,slot:'rb_rank'};", /rb_priority|assert/i);

    const member = ({ slot = 'rb_rank', root = 'rb_rank', owner = 'stage_board:alpha', key = "[10,'stage_fact:anchor','rb_rank']", dependent = false } = {}) =>
      `{link:{rid:stage_fact:anchor,slot:'${slot}'},owner:{rid:${owner},slot:'${root}'},key:${key},value:fn::tree::value(${key},{weight:1dec},{},{},${dependent})}`;
    for (const [members, pattern] of [
      [`[${member({ key: "[1.5dec,'stage_fact:anchor','rb_rank']" })}]`, /TREE_MEMBERSHIP_KEY/],
      [`[${member({ key: `[d'${at(0)}','stage_fact:anchor','rb_rank']` })}]`, /TREE_MEMBERSHIP_KEY/],
      [`[${member({ key: "[10,'stage_fact:wrong','rb_rank']" })}]`, /TREE_MEMBERSHIP_KEY/],
      [`[${member({ owner: 'stage_archive:alpha' })}]`, /TREE_INVALID_MEMBERSHIP/],
      [`[${member({ slot: 'unknown' })}]`, /TREE_INVALID_MEMBERSHIP/],
      [`[${member({ dependent: true })}]`, /TREE_INT_DEPENDENCY/],
      [`[${member()},${member()}]`, /TREE_DUPLICATE_MEMBERSHIP/],
      [`[${member()},${member({ slot: 'rb_history', key: "[10,'stage_fact:anchor','rb_history']" })}]`, /TREE_INVALID_MEMBERSHIP/],
    ]) await reject(`BEGIN TRANSACTION;
      UPDATE stage_fact:anchor SET a_weight += 1dec;
      fn::tree::sync(stage_fact:anchor, (SELECT * FROM ONLY stage_fact:anchor), ${members}, ['rb_rank','rb_history']);
      COMMIT TRANSACTION;`, pattern);
    console.log('PASS malformed inputs before int coercion, public read bounds, exact structural pairs and pre-coalescing validation');

    let seed = 250925;
    const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
    const stages = ['low', 'zero', 'ten', 'high'], live = [];
    for (let i = 0; i < 16; i++) {
      live.push(`stage_fact:fuzz_${i}`);
      await create(`fuzz_${i}`, stages[Math.floor(random() * stages.length)], Math.floor(random() * 30));
    }
    for (let i = 0; i < 40 && live.length; i++) {
      const index = Math.floor(random() * live.length), rid = live[index];
      if (random() < 0.2) { await mutate(`DELETE ${rid};`); live.splice(index, 1); }
      else {
        const stage = random() < 0.2 ? 'NONE' : `stage_code:${stages[Math.floor(random() * stages.length)]}`;
        const owner = ['stage_board:alpha', 'stage_board:beta', 'stage_archive:alpha'][Math.floor(random() * 3)];
        await mutate(`UPDATE ${rid} SET a_stage=${stage}, a_ranking=${owner},
          a_effective_at=d'${at(Math.floor(random() * 30))}', a_weight=${Math.floor(random() * 11) - 5}dec;`);
      }
    }
    reads += await queries(q, verify(await snapshot(q)));
    console.log('PASS 56 deterministic mixed-order mutations reconstructed from authoritative source fields (seed 250925)');

    await mutate('UPDATE stage_board:limited SET a_limit=1;');
    let conflicts = 0;
    const contenders = await Promise.all(Array.from({ length: 6 }, (_, i) => (async () => {
      const rid = `stage_fact:contender_${i}`;
      for (let retry = 0; ; retry++) {
        try {
          await q(`CREATE ${rid} SET owned_by=rebase_group:root, a_history=stage_board:beta,
            a_ranking=stage_board:limited, a_stage=stage_code:ten, a_effective_at=d'${at(i)}';`);
          return { rid, success: true };
        } catch (error) {
          if (/TYPED_OWNER_LIMIT/.test(error.message)) return { rid, success: false };
          if (!/conflict|retry/i.test(error.message) || retry >= 20) throw error;
          conflicts++;
          await new Promise(resolve => setTimeout(resolve, Math.min(50, 3 * retry + 2)));
        }
      }
    })()));
    assert.equal(contenders.filter(result => result.success).length, 1, 'only one writer can claim the last rank slot');
    const afterRace = await snapshot(q); verify(afterRace); mutations++;
    for (const result of contenders) assert.equal(afterRace.facts.some(row => row.id === result.rid), result.success);
    assert.equal(afterRace.boards.find(row => row.id === 'stage_board:limited').rb_rank.summary.count, 1);
    assert.equal(afterRace.boards.find(row => row.id === 'stage_board:beta').rb_history.summary.count, 1);
    console.log(`PASS competing dual-tree writes: one commit, five complete rollbacks (${conflicts} conflict retries)`);
    await permissions(env, reject);
    const before = await snapshot(q);
    await applySchema(q, env.bundle);
    assert.deepEqual(await snapshot(q), before, 'reapplying the original schema preserves all typed roots and slots');
    reads += await queries(q, verify(before));
    // Delete roots' source records repeatedly, including both slots on a source.
    for (const row of before.facts) await mutate(`DELETE ${row.id};`);
    for (const row of before.archiveFacts) await mutate(`DELETE ${row.id};`);
    for (const row of before.privateFacts) await mutate(`DELETE ${row.id};`);
    reads += await queries(q, verify(await snapshot(q)));
    for (const row of [...before.boards, ...before.archives, ...before.privateBoards]) await mutate(`DELETE ${row.id};`);
    console.log(`PASS ${mutations} mutation checkpoints, ${reads} ordered reads, ${rejections} rejection snapshots; populated reapplication and empty-tree cleanup`);
    return { mutations, reads, rejections };
  } finally { await env.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, setup, snapshot, verify, queries };
