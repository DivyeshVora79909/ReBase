#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema, instant } = require('../temporal-tree/harness');
const oracle = require('../temporal-tree/oracle');

const wide = Array(16).fill('string').join(',');
const fixture = `
DEFINE TABLE OVERWRITE reader_anchor SCHEMAFULL;
DEFINE FIELD OVERWRITE title ON reader_anchor TYPE string;
DEFINE TABLE OVERWRITE reader_report SCHEMAFULL;
DEFINE FIELD OVERWRITE anchors ON reader_report TYPE array<record<reader_anchor>> DEFAULT []
  REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE TABLE OVERWRITE identity_alias SCHEMAFULL COMMENT '@rebase-members fn::probe::alias_members';
DEFINE FIELD OVERWRITE kind ON identity_alias TYPE string;
DEFINE FIELD OVERWRITE value ON identity_alias TYPE string;
DEFINE FIELD OVERWRITE z_auth_identifier ON identity_alias TYPE option<object> PERMISSIONS NONE
  COMMENT '@rebase-tree-node @rebase-tree-key string,string @rebase-tree-owner rebase_tenant.z_auth_identifiers @rebase-tree-no-reader';
DEFINE FUNCTION OVERWRITE fn::probe::alias_members($row: object) {
  RETURN [fn::tree::ordered_member($row.id, 'z_auth_identifier', $row.tenant,
    'z_auth_identifiers', [$row.kind, $row.value], {}, {})];
} PERMISSIONS NONE;
DEFINE FIELD OVERWRITE z_wide ON rebase_tenant TYPE object PERMISSIONS NONE
  COMMENT '@rebase-tree-root @rebase-tree-key ${wide}';
DEFINE TABLE OVERWRITE wide_key SCHEMAFULL COMMENT '@rebase-members fn::probe::wide';
DEFINE FIELD OVERWRITE value ON wide_key TYPE string;
DEFINE FIELD OVERWRITE z_key ON wide_key TYPE option<object> PERMISSIONS NONE
  COMMENT '@rebase-tree-node @rebase-tree-key ${wide} @rebase-tree-owner rebase_tenant.z_wide @rebase-tree-no-reader';
DEFINE FUNCTION OVERWRITE fn::probe::wide($row: object) {
  RETURN [fn::tree::ordered_member($row.id, 'z_key', $row.tenant, 'z_wide',
    array::range(0,16).map(|$i| $row.value), {}, {})];
} PERMISSIONS NONE;
`;

function compare(left, right) {
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const datetime = typeof left[i] === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(left[i]);
    const a = datetime ? instant(left[i]) : left[i], b = datetime ? instant(right[i]) : right[i];
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return left.length - right.length;
}

// Derive every expected membership from source fields, including auth and
// sixteen-part keys. The existing oracle reconstructs links, AVL and summaries.
function verify(data) {
  const rows = Object.values(data).flat(), entries = [];
  const add = (row, slot, owner, root, key, measures = {}) => entries.push({
    link: { rid: row.id, slot }, owner: { rid: owner, slot: root },
    key: [...key, row.id, slot], measures, tags: {}, dependent: false,
  });
  for (const [table, kind, field] of [['rebase_user', 'username', 'username'],
    ['authentication_email', 'email', 'address'], ['authentication_phone', 'phone', 'number'],
    ['authentication_passkey', 'passkey', 'credential_id'], ['identity_alias', null, 'value']]) {
    for (const row of data[table] || []) if (row[field] != null) {
      add(row, 'z_auth_identifier', row.tenant, 'z_auth_identifiers', [kind || row.kind, row[field]]);
    }
  }
  for (const row of [...data.activity, ...data.annotation]) {
    assert.equal(row.read_by, row.owned_by, 'analytics membership never expands visibility');
    assert(!Object.hasOwn(row, 'readers_index'));
    if (!row.include_analytics) continue;
    const measure = { points: Number(row.points) };
    add(row, 'z_tenant_created', row.tenant, 'z_created', [row.created_at], measure);
    add(row, 'z_owner_created', row.tenant, 'z_owner_created', [row.owned_by, row.created_at], measure);
    add(row, 'z_owned_created', row.owned_by, 'z_owned_created', [row.created_at], measure);
    if (row.effective_at != null) {
      add(row, 'z_tenant_effective', row.tenant, 'z_effective', [row.effective_at], measure);
      add(row, 'z_owned_effective', row.owned_by, 'z_owned_effective', [row.effective_at], measure);
    }
  }
  for (const row of data.wide_key) add(row, 'z_key', row.tenant, 'z_wide', Array(16).fill(row.value));
  return oracle.verify(rows, rows, entries, compare);
}

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-reader-index-'));
  let server, checkpoints = 0, rollbacks = 0;
  try {
    fs.writeFileSync(path.join(directory, 'fixture.surql'), fixture);
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [path.resolve(__dirname, '../../designs/index-analytics'), directory] },
    ] });
    const compiled = generateBundle(materials);
    server = await start();
    const q = client(server.url);
    const snapshot = () => q(`RETURN {${[...compiled.schema.tables.keys()].map(table =>
      `${table}: (SELECT * FROM ${table} WITH NOINDEX ORDER BY id)`).join(',')}};`);
    const mutate = async sql => { await q(sql); checkpoints++; const data = await snapshot(); verify(data); return data; };
    const reject = async (sql, pattern = /TREE_|TENANT|assert|permission|readonly/i) => {
      const before = await snapshot();
      await assert.rejects(q(sql), pattern);
      assert.deepEqual(await snapshot(), before, 'complete source, audit and tree rollback');
      verify(before); rollbacks++;
    };
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;');
    await applySchema(q, compiled.bundle);
    await mutate(`CREATE rebase_tenant:a SET name='A'; CREATE rebase_tenant:b SET name='B';
      CREATE rebase_user:admin SET name='Admin',username='admin_user',parents=[rebase_tenant:a];
      CREATE rebase_user:a SET name='A',username='branch_user',parents=[rebase_user:admin,rebase_tenant:a];
      CREATE rebase_user:b SET name='B',parents=[rebase_user:admin,rebase_tenant:a];
      CREATE rebase_user:other SET name='Other',username='admin_user',parents=[rebase_tenant:b];
      CREATE reader_anchor:a SET owned_by=rebase_user:a,title='A';
      CREATE reader_anchor:b SET owned_by=rebase_user:b,title='B';
      CREATE reader_report:one SET owned_by=rebase_user:admin,anchors=[reader_anchor:a,reader_anchor:b];
      DEFINE ACCESS probe ON DATABASE TYPE RECORD SIGNIN type::record('rebase_user',$name);`);
    const actor = async name => {
      const response = await fetch(`${server.url}/signin`, { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'probe', name }) });
      const { token } = await response.json(); assert(token); return client(server.url, 'fixture', token);
    };
    const a = await actor('a'), b = await actor('b'), other = await actor('other'), admin = await actor('admin');
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_user:a');
    assert.equal((await a('SELECT * FROM reader_report:one;')).length, 1);
    assert.deepEqual(await b('SELECT * FROM reader_report:one;'), []);
    assert.deepEqual(await a('UPDATE reader_report:one SET anchors=[];'), [], 'reading grants no writes');
    await mutate('UPDATE rebase_user:b SET parents=[rebase_user:a,rebase_tenant:a];');
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_user:b', 'DAG edit chooses the descendant');
    assert.equal((await b('SELECT * FROM reader_report:one;')).length, 1);
    await admin('CREATE reader_report:native SET owned_by=$auth,anchors=[reader_anchor:a,reader_anchor:b],read_by=rebase_user:other;');
    assert.equal(await q('RETURN reader_report:native.read_by;'), 'rebase_user:b', 'record-client create settles the same dominant reader');
    verify(await snapshot()); checkpoints++;
    await mutate('UPDATE rebase_user:b SET parents=[rebase_user:admin,rebase_tenant:a];');
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_user:a');
    assert.deepEqual(await b('SELECT * FROM reader_report:one;'), [], 'existing token loses the old chosen-reader grant');
    await mutate('UPDATE reader_report:one SET anchors=[reader_anchor:b,reader_anchor:a];');
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_user:b', 'authored candidate order breaks incomparable ties');
    await mutate('UPDATE reader_anchor:b SET owned_by=rebase_user:a;');
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_user:a', 'owner edit refreshes direct dependents');
    await mutate(`CREATE rebase_group:shared SET name='Shared',parents=[rebase_user:admin],role=[];
      UPDATE rebase_user:a SET parents=[rebase_user:admin,rebase_tenant:a,rebase_group:shared];
      UPDATE rebase_user:b SET parents=[rebase_user:admin,rebase_tenant:a,rebase_group:shared];
      UPDATE reader_anchor:a SET owned_by=rebase_group:shared;
      UPDATE reader_report:one SET anchors=[reader_anchor:a];`);
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_group:shared');
    for (const reader of [a, b]) assert.equal((await reader('SELECT * FROM reader_report:one;')).length, 1);
    await mutate('UPDATE reader_report:one SET anchors=[];');
    assert.equal(await q('RETURN reader_report:one.read_by;'), 'rebase_user:admin');
    console.log('PASS scalar readers, branch order, dominance moves, ownership refresh, groups and fallback');

    await mutate(`CREATE authentication_email:a SET owned_by=rebase_user:a,address='  Same@Example.test  ';
      CREATE authentication_phone:a SET owned_by=rebase_user:a,number='+12345678901';
      CREATE authentication_email:other SET owned_by=rebase_user:other,address='same@example.test';`);
    assert.equal((await q("RETURN fn::rebase::identity(rebase_tenant:a,'email','same@example.test');")).id, 'authentication_email:a');
    await reject("CREATE authentication_email:duplicate SET owned_by=rebase_user:b,address='SAME@example.test';", /TREE_DUPLICATE_VALUE/);
    await reject("CREATE identity_alias:duplicate SET owned_by=rebase_user:b,kind='email',value='same@example.test';", /TREE_DUPLICATE_VALUE/);
    await reject("UPDATE rebase_user:a SET username='admin_user';", /TREE_DUPLICATE_VALUE/);
    await mutate("UPDATE authentication_email:a SET address='changed@example.test';");
    assert.equal(await q("RETURN fn::rebase::identity(rebase_tenant:a,'email','same@example.test');"), null);
    await mutate("CREATE identity_alias:reuse SET owned_by=rebase_user:b,kind='email',value='same@example.test';");
    const outcomes = await Promise.allSettled([
      q("CREATE authentication_email:race_a SET owned_by=rebase_user:a,address='race@example.test';"),
      client(server.url)("CREATE identity_alias:race_b SET owned_by=rebase_user:b,kind='email',value='race@example.test';"),
    ]);
    assert.equal(outcomes.filter(r => r.status === 'fulfilled').length, 1);
    assert.match(outcomes.find(r => r.status === 'rejected').reason.message, /TREE_DUPLICATE|conflict|retry/i);
    verify(await snapshot()); checkpoints++;
    await a("CREATE authentication_email:client SET owned_by=$auth,address='client@example.test';");
    verify(await snapshot()); checkpoints++;
    for (const query of ["RETURN fn::rebase::identity(rebase_tenant:a,'email','client@example.test');",
      "RETURN fn::tree::read(rebase_tenant:a,'z_auth_identifiers','summary',[]);",
      "RETURN fn::tree::read(rebase_tenant:a,'z_auth_identifiers','find',['email','client@example.test']);"]) {
      await assert.rejects(a(query), /permission|not allowed/i);
    }
    assert.equal(await a('RETURN rebase_tenant:a.z_auth_identifiers;'), null);
    assert.deepEqual(await other('SELECT * FROM authentication_email:client;'), []);
    await mutate(`CREATE rebase_user:cascade SET name='Cascade',username='cascade_user',parents=[rebase_user:admin,rebase_tenant:a];
      CREATE authentication_email:cascade SET owned_by=rebase_user:cascade,address='cascade@example.test';
      CREATE authentication_phone:cascade SET owned_by=rebase_user:cascade,number='+12345678902';`);
    await mutate('DELETE rebase_user:cascade;');
    assert.equal(await q("RETURN fn::rebase::identity(rebase_tenant:a,'email','cascade@example.test');"), null);
    assert.equal(await q("RETURN fn::rebase::identity(rebase_tenant:a,'username','cascade_user');"), null);
    assert.deepEqual(await q('SELECT * FROM [authentication_email:cascade,authentication_phone:cascade];'), []);
    console.log('PASS custom identifier lookup, normalization, cross-table uniqueness, concurrency, record writes and privacy');

    for (const [i, points] of [3, 5, 7, 11, 13, 17].entries()) {
      const table = i % 2 ? 'annotation' : 'activity';
      await mutate(`CREATE ${table}:n${i} SET owned_by=rebase_user:a,title='Event ${i}',points=${points}dec,
        effective_at=d'2027-01-0${1 + i}';`);
    }
    const created = await q('RETURN activity:n0.created_at;');
    await mutate("UPDATE activity:n0 SET effective_at=d'2026-01-01',points=19dec;");
    assert.equal(await q('RETURN activity:n0.created_at;'), created);
    await mutate('UPDATE annotation:n1 SET owned_by=rebase_user:b;');
    await mutate('UPDATE activity:n2 SET effective_at=NONE;');
    await mutate('UPDATE annotation:n3 SET include_analytics=false;');
    await mutate("CREATE annotation:excluded SET owned_by=rebase_user:a,title='No trees',include_analytics=false;");
    await a("CREATE activity:client SET owned_by=$auth,title='Client',points=23dec,effective_at=d'2027-02-01',read_by=rebase_user:b;");
    verify(await snapshot()); checkpoints++;
    assert.equal(await q('RETURN activity:client.read_by;'), 'rebase_user:a', 'VALUE overrides forged reader');
    assert.deepEqual(await b('SELECT * FROM activity:client;'), []);
    assert.deepEqual(await other('SELECT * FROM activity;'), []);
    const groups = verify(await snapshot());
    const owner = groups.get('rebase_user:a/z_owned_created');
    const page = await a("RETURN fn::tree::read(rebase_user:a,'z_owned_created','page',[200]);");
    assert.deepEqual(page.items.map(item => item.link), owner.entries.map(entry => entry.link));
    assert.equal((await a("RETURN fn::tree::read(rebase_user:a,'z_owned_created','summary',[]);")).count, owner.entries.length);
    await assert.rejects(b("RETURN fn::tree::read(rebase_user:a,'z_owned_created','summary',[]);"), /permission|not allowed/i);
    await assert.rejects(a("RETURN fn::tree::read(rebase_tenant:a,'z_created','summary',[]);"), /permission|not allowed/i);
    const prefix = await q("RETURN fn::tree::read(rebase_tenant:a,'z_effective','before',[d'2027-01-01']);");
    assert.equal(prefix.count, 1); assert.equal(Number(prefix.measures.points.sum), 19);
    const composite = await q("RETURN fn::tree::read(rebase_tenant:a,'z_owner_created','range',[[rebase_user:a],[rebase_user:b]]);");
    assert.equal(composite.count, owner.entries.length);
    await reject('UPDATE activity:n0 SET owned_by=rebase_user:other;', /TENANT|readonly/i);
    await reject('DELETE rebase_user:a;', /TREE_OWNER|reference/i);
    await mutate("CREATE wide_key:one SET owned_by=rebase_user:a,value='wide';");
    assert.equal((await q("RETURN fn::tree::read(rebase_tenant:a,'z_wide','find',array::range(0,16).map(|$i| 'wide'));" )).rid, 'wide_key:one');
    await reject("CREATE wide_key:duplicate SET owned_by=rebase_user:a,value='wide';", /TREE_DUPLICATE_VALUE/);
    console.log('PASS opted-in cross-table analytics, creation/effective times, owner moves, ranges, pages, privacy and 16-part keys');

    const before = await snapshot();
    await applySchema(q, compiled.bundle);
    assert.deepEqual(await snapshot(), before, 'identical populated reapplication');
    verify(before);
    for (const table of ['activity','annotation','wide_key','reader_report','reader_anchor','identity_alias',
      'authentication_email','authentication_phone']) {
      for (const row of (await snapshot())[table]) await mutate(`DELETE ${row.id};`);
    }
    await mutate('UPDATE rebase_user:a SET parents=[rebase_user:admin,rebase_tenant:a]; UPDATE rebase_user:b SET parents=[rebase_user:admin,rebase_tenant:a];');
    for (const id of ['rebase_group:shared','rebase_user:a','rebase_user:b','rebase_user:admin','rebase_user:other']) await mutate(`DELETE ${id};`);
    for (const row of (await snapshot()).rebase_tenant) {
      for (const value of Object.values(row)) if (value?.summary) assert.equal(value.summary.count, 0);
    }
    console.log(`PASS reader/index acceptance: ${checkpoints} source checkpoints, ${rollbacks} complete rollback snapshots; reapplication and cleanup`);
  } finally {
    await server?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };
