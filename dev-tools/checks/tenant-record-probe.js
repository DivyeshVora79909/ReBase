#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('../temporal-tree/harness');

const fixture = `
DEFINE TABLE entity SCHEMAFULL;
DEFINE FIELD title ON entity TYPE string;
DEFINE FIELD share_anchor ON entity TYPE option<record<entity>> REFERENCE ON DELETE IGNORE COMMENT '@rebase-readers';
DEFINE FIELD history ON entity TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE TABLE entry SCHEMAFULL COMMENT '@rebase-members fn::tenant_fixture::entry';
DEFINE FIELD entity ON entry TYPE record<entity> REFERENCE ON DELETE REJECT;
DEFINE FIELD share_anchor ON entry TYPE option<record<entity>> REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD amount ON entry TYPE decimal;
DEFINE FIELD effective_at ON entry TYPE datetime;
DEFINE FIELD position ON entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner entity.history';
DEFINE FUNCTION fn::tenant_fixture::entry($row: object) {
  RETURN [fn::tree::member($row.id, 'position', $row.entity, 'history', $row.effective_at,
    { amount: $row.amount }, {}, {})];
} PERMISSIONS NONE;
DEFINE TABLE secret_entry SCHEMAFULL PERMISSIONS NONE COMMENT '@rebase-members fn::tenant_fixture::secret_entry';
DEFINE FIELD entity ON secret_entry TYPE record<entity> REFERENCE ON DELETE REJECT;
DEFINE FIELD amount ON secret_entry TYPE decimal;
DEFINE FIELD effective_at ON secret_entry TYPE datetime;
DEFINE FIELD position ON secret_entry TYPE option<object> PERMISSIONS FOR select NONE COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner entity.history';
DEFINE FUNCTION fn::tenant_fixture::secret_entry($row: object) {
  RETURN [fn::tree::member($row.id, 'position', $row.entity, 'history', $row.effective_at,
    { amount: $row.amount }, {}, {})];
} PERMISSIONS NONE;
DEFINE TABLE hidden_entry SCHEMAFULL COMMENT '@rebase-members fn::tenant_fixture::hidden_entry';
DEFINE FIELD entity ON hidden_entry TYPE record<entity> REFERENCE ON DELETE REJECT;
DEFINE FIELD amount ON hidden_entry TYPE decimal;
DEFINE FIELD effective_at ON hidden_entry TYPE datetime;
DEFINE FIELD position ON hidden_entry TYPE option<object> PERMISSIONS FOR select NONE COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner entity.history';
DEFINE FUNCTION fn::tenant_fixture::hidden_entry($row: object) {
  RETURN [fn::tree::member($row.id, 'position', $row.entity, 'history', $row.effective_at,
    { amount: $row.amount }, {}, {})];
} PERMISSIONS NONE;
DEFINE TABLE public_entity SCHEMAFULL;
DEFINE FIELD title ON public_entity TYPE string;
DEFINE FIELD share_anchor ON public_entity TYPE option<record<entity>> REFERENCE ON DELETE IGNORE COMMENT '@rebase-readers';
DEFINE FIELD history ON public_entity TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE TABLE public_entry SCHEMAFULL COMMENT '@rebase-members fn::tenant_fixture::public_entry';
DEFINE FIELD entity ON public_entry TYPE record<public_entity> REFERENCE ON DELETE REJECT;
DEFINE FIELD amount ON public_entry TYPE decimal;
DEFINE FIELD effective_at ON public_entry TYPE datetime;
DEFINE FIELD position ON public_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner public_entity.history';
DEFINE FUNCTION fn::tenant_fixture::public_entry($row: object) {
  RETURN [fn::tree::member($row.id, 'position', $row.entity, 'history', $row.effective_at,
    { amount: $row.amount }, {}, {})];
} PERMISSIONS NONE;
DEFINE TABLE note SCHEMAFULL;
DEFINE FIELD other ON note TYPE option<record<note>> REFERENCE ON DELETE IGNORE COMMENT '@rebase-readers';
DEFINE FIELD title ON note TYPE string;
DEFINE TABLE code SCHEMAFULL;
DEFINE FIELD value ON code TYPE string;
DEFINE INDEX code_value ON code FIELDS tenant, value UNIQUE;
DEFINE TABLE bundle SCHEMAFULL;
DEFINE FIELD lines ON bundle TYPE array<object> COMMENT '@rebase-audit value';
DEFINE FIELD lines.*.references ON bundle TYPE array<object>;
DEFINE FIELD lines.*.references.*.entity ON bundle TYPE option<record<entity>>;
DEFINE FIELD target ON bundle TYPE option<record<entity | code>> REFERENCE ON DELETE REJECT;
DEFINE FIELD related ON bundle TYPE array<record<entity | code>> DEFAULT [] REFERENCE ON DELETE REJECT;
DEFINE FIELD selector ON bundle TYPE option<string> COMMENT '@rebase-audit value';
DEFINE FIELD derived_target ON bundle TYPE option<record<entity>> REFERENCE ON DELETE REJECT
  VALUE IF $this.selector = NONE THEN NONE ELSE type::record('entity', $this.selector) END
  COMMENT '@rebase-derived';
DEFINE TABLE metric SCHEMAFULL;
DEFINE FIELD target ON metric TYPE record<entity> REFERENCE ON DELETE REJECT;
DEFINE FIELD shared_with ON metric TYPE option<record<entity>> REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD amount ON metric TYPE decimal;
`;
const views = `
-- @rebase-view-record-scoped
DEFINE TABLE OVERWRITE v_metric_totals AS
  SELECT tenant, target, owned_by, read_by, count() AS total_rows, math::sum(amount) AS total_amount
  FROM metric GROUP BY tenant, target, owned_by, read_by;
-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_tenant_user_count AS
  SELECT tenant, count() AS total_users FROM rebase_user GROUP BY tenant;
`;

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-tenant-record-'));
  let server;
  try {
    fs.writeFileSync(path.join(directory, 'schema.surql'), fixture.replace(/DEFINE (TABLE|FIELD|FUNCTION|INDEX) /g, 'DEFINE $1 OVERWRITE '));
    fs.writeFileSync(path.join(directory, 'views.surql'), views);
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    const compiled = generateBundle(materials);
    assert.equal(compiled.bundle, generateBundle(materials).bundle);
    assert(!compiled.bundle.includes('REBASE_READER_CYCLE'));
    server = await start();
    const q = client(server.url);
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;');
    await applySchema(q, compiled.bundle);
    await q(`
      CREATE rebase_tenant:a SET name='Tenant A';
      CREATE rebase_tenant:b SET name='Tenant B';
      CREATE rebase_user:alice SET name='Alice',parents=[rebase_tenant:a];
      CREATE rebase_user:bob SET name='Bob',parents=[rebase_tenant:a];
      CREATE rebase_user:charlie SET name='Charlie',parents=[rebase_tenant:a];
      CREATE rebase_user:other SET name='Other',parents=[rebase_tenant:b];
      CREATE rebase_group:limited SET name='Limited',parents=[rebase_tenant:a],role=['code_create','code_select','public_entity_select'];
      CREATE rebase_user:limited SET name='Limited user',parents=[rebase_group:limited];
      DEFINE ACCESS fixture ON DATABASE TYPE RECORD SIGNIN type::record('rebase_user',$name)
        DURATION FOR SESSION 1h, FOR TOKEN 1h;
      CREATE entity:a SET owned_by=rebase_user:alice,title='A';
      CREATE entity:b SET owned_by=rebase_user:other,title='B';
      CREATE entity:private_root SET owned_by=rebase_user:charlie,title='Private root';
      CREATE entity:grant_root SET owned_by=rebase_group:limited,title='Grant root';
      CREATE public_entity:native SET owned_by=rebase_user:alice,title='Native';
      CREATE public_entity:grant_root SET owned_by=rebase_group:limited,title='Grant root';
      CREATE entry:a SET owned_by=rebase_user:bob,entity=entity:a,amount=7dec,effective_at=d'2026-10-04T00:00:00Z';
      CREATE secret_entry:a SET owned_by=rebase_user:alice,entity=entity:a,amount=99dec,effective_at=d'2026-10-04T01:00:00Z';
      CREATE hidden_entry:a SET owned_by=rebase_user:alice,entity=entity:a,amount=101dec,effective_at=d'2026-10-04T02:00:00Z';
      CREATE entry:under_private_root SET owned_by=rebase_user:alice,entity=entity:private_root,share_anchor=entity:a,amount=5dec,effective_at=d'2026-10-04T00:00:00Z';
      CREATE public_entry:native SET owned_by=rebase_user:bob,entity=public_entity:native,amount=3dec,effective_at=d'2026-10-04T00:00:00Z';
      CREATE public_entry:grant_member SET owned_by=rebase_group:limited,entity=public_entity:grant_root,amount=5dec,effective_at=d'2026-10-04T00:00:00Z';
      CREATE entity:shared SET owned_by=rebase_tenant:a,title='Shared target';
      CREATE entity:reader_anchor SET owned_by=rebase_user:bob,title='Reader anchor';


      CREATE metric:alice SET owned_by=rebase_user:alice,target=entity:shared,amount=7dec;
      CREATE metric:bob_private SET owned_by=rebase_user:bob,target=entity:shared,amount=11dec;
      CREATE metric:bob_shared SET owned_by=rebase_user:bob,target=entity:shared,shared_with=entity:a,amount=3dec;
      CREATE metric:charlie SET owned_by=rebase_user:charlie,target=entity:shared,amount=13dec;
      CREATE code:a SET owned_by=rebase_user:alice,value='same';
      CREATE code:b SET owned_by=rebase_user:other,value='same';
    `);
    async function actor(name) {
      const response = await fetch(`${server.url}/signin`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'fixture', name }),
      });
      const { token } = await response.json();
      assert(token, `No token for ${name}`);
      return client(server.url, 'fixture', token);
    }
    const alice = await actor('alice'), bob = await actor('bob');
    const charlie = await actor('charlie'), other = await actor('other');
    const limited = await actor('limited');
    const anonymous = async sql => {
      const response = await fetch(`${server.url}/sql`, {
        method: 'POST', headers: { 'surreal-ns': 'temporal_probe', 'surreal-db': 'fixture', accept: 'application/json' }, body: sql,
      });
      return { status: response.status, body: await response.text() };
    };
    assert.deepEqual(await limited('SELECT * FROM rebase_group:limited;'), [], 'ownership need not grant node_select');
    await limited("CREATE code:limited SET owned_by=rebase_group:limited,value='limited';");
    assert.equal(await q('RETURN code:limited.tenant;'), 'rebase_tenant:a', 'a hidden authorized owner still derives the tenant');
    assert.equal((await limited('SELECT * FROM code:limited;')).length, 1);
    assert.equal((await alice('SELECT * FROM v_tenant_user_count;')).length, 1, 'published system aggregate uses its exact source-table permission');
    assert.equal((await alice('SELECT * FROM rebase_user:bob;')).length, 0, 'system-view permission does not bypass principal node-select and dominance checks');
    await limited("CREATE code:forged SET owned_by=rebase_group:limited,tenant=rebase_tenant:b,value='forged';");
    assert.equal(await q('RETURN code:forged.tenant;'), 'rebase_tenant:a', 'VALUE derives tenant despite forged client input');
    assert.deepEqual(await q('RETURN public_entry:native.read_by;'), 'rebase_user:alice');
    const treePage = await alice("RETURN fn::tree::read(public_entity:native, 'history', 'page', [10]);");
    assert.equal(treePage.items.length, 1, 'authenticated root owner can read an ordered-tree page');
    assert.equal(treePage.items[0].link.rid, 'public_entry:native');
    const treeSeek = await alice("RETURN fn::tree::read(public_entity:native, 'history', 'seek', [[d'2026-10-04T00:00:00Z']]);");
    assert.equal(treeSeek.rid, 'public_entry:native', 'authenticated root owner can seek an ordered tree');
    await assert.rejects(bob("RETURN fn::tree::read(public_entity:native, 'history', 'page', [10]);"), /permission|not allowed/i, 'root readability alone does not grant its members');
    assert.equal((await alice('SELECT * FROM entity:a;')).length, 1, 'the tree root is readable');
    assert.equal((await bob('SELECT * FROM entity:a;')).length, 0, 'an unrelated principal cannot read the root');
    const privateSummary = await alice("RETURN fn::tree::read(entity:a, 'history', 'summary', []);");
    assert.equal(privateSummary.count, 3, 'root policy authorizes its stored summary across private descendants');
    await assert.rejects(bob("RETURN fn::tree::read(entity:a, 'history', 'summary', []);"), /permission|not allowed/i);
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'before', [d'2026-10-04T01:30:00Z']);"), /permission|not allowed|TREE_READ/i,
      'before fails when traversal encounters a private member');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'rank', [d'2026-10-04T01:30:00Z']);"), /permission|not allowed|TREE_READ/i,
      'rank fails when traversal encounters a private member');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'range', [[d'2026-10-04T01:30:00Z'], [d'2026-10-04T02:30:00Z']]);"), /permission|not allowed|TREE_READ/i,
      'range fails when traversal encounters a private member');
    const visibleBefore = await alice("RETURN fn::tree::read(public_entity:native, 'history', 'before', [d'2026-10-04T01:00:00Z']);");
    assert.equal(visibleBefore.count, 1, 'before works when its visible-only tree path is readable');
    assert.equal(await alice("RETURN fn::tree::read(public_entity:native, 'history', 'rank', [d'2026-10-04T01:00:00Z']);"), 2,
      'rank works when its visible-only tree path is readable');
    const visibleRange = await alice("RETURN fn::tree::read(public_entity:native, 'history', 'range', [[d'2026-10-04T00:00:00Z'], [d'2026-10-04T01:00:00Z']]);");
    assert.equal(visibleRange.count, 1, 'range works when its visible-only tree path is readable');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'select', [2]);"), /permission|not allowed|TREE_READ/i,
      'select fails when its selected member is private');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'percentile', [0.5]);"), /permission|not allowed|TREE_READ/i,
      'percentile fails when its selected member is private');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'page', [10]);"), /permission|not allowed|TREE_READ/i,
      'page fails instead of returning a private member link');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'seek', [[d'2026-10-04T01:00:00Z', secret_entry:a, 'position'], false, true]);"), /permission|not allowed|TREE_READ/i,
      'seek fails instead of returning a private member link');
    await assert.rejects(alice("RETURN fn::tree::read(entity:a, 'history', 'find', [d'2026-10-04T01:00:00Z']);"), /permission|not allowed|TREE_READ/i,
      'find fails instead of returning a private member link');
    assert.equal((await limited('SELECT * FROM public_entity:grant_root;')).length, 1,
      'limited principal has the root table select permission');
    assert.deepEqual(await limited('SELECT * FROM public_entry:grant_member;'), [],
      'limited principal lacks direct member table select permission');
    assert.equal(await limited("RETURN fn::tree::read(public_entity:grant_root, 'history', 'summary', []);").then(value => value.count), 1,
      'root table permission grants aggregate access without member table permission');
    await assert.rejects(limited("RETURN fn::tree::read(public_entity:grant_root, 'history', 'page', [10]);"), /permission|not allowed|TREE_READ/i,
      'member page requires the exact source table select grant');
    await assert.rejects(bob("RETURN fn::tree::read(entity:a, 'history', 'page', [10]);"), /permission|not allowed|TREE_READ/i,
      'root readers still need permission for each returned member');
    await assert.rejects(alice("RETURN fn::tree::get({rid: public_entity:native, slot: 'history'});"), /permission|not allowed/i,
      'ordinary record token cannot call the internal tree slot reader directly');
    await assert.rejects(alice("RETURN fn::tree::page({rid: public_entity:native, slot: 'history'}, 10, NONE, false);"), /permission|not allowed/i,
      'ordinary record token cannot call an internal page helper directly');
    assert.equal(await alice("RETURN fn::rebase::tree_link_select_allowed({rid: public_entry:native, slot: 'position'}, {rid: public_entity:native, slot: 'history'});"), true,
      'member permission helper accepts a readable member under its exact root');
    assert.equal(await alice("RETURN fn::rebase::tree_link_select_allowed({rid: entity:b, slot: 'history'}, {rid: entity:b, slot: 'history'});"), false,
      'member permission helper cannot cross the tenant root boundary');
    assert.equal(await alice("RETURN fn::rebase::tree_link_select_allowed({rid: public_entity:native, slot: 'title'}, {rid: public_entity:native, slot: 'history'});"), false,
      'member permission helper rejects undeclared tree slots');
    assert.equal(await alice("RETURN fn::rebase::tree_link_select_allowed({rid: secret_entry:a, slot: 'position'}, {rid: entity:a, slot: 'history'});"), false,
      'member permission helper denies a private source table');
    assert.equal(await alice("RETURN fn::rebase::tree_link_select_allowed({rid: hidden_entry:a, slot: 'position'}, {rid: entity:a, slot: 'history'});"), false,
      'member permission helper denies a private native member field');
    assert.equal((await alice('SELECT * FROM entry:under_private_root;')).length, 1, 'member row is readable independently of its root');
    assert.deepEqual(await alice('SELECT * FROM entity:private_root;'), [], 'linked root is not readable');
    await assert.rejects(alice("RETURN fn::tree::read(entity:private_root, 'history', 'summary', []);"), /permission|not allowed|TREE_READ/i,
      'public ordered-tree reads reject an unreadable root');
    assert.equal(await alice("RETURN fn::rebase::tree_link_select_allowed({rid: entry:under_private_root, slot: 'position'}, {rid: entity:private_root, slot: 'history'});"), false,
      'readable member cannot bypass its unreadable declared root');
    await assert.rejects(other("RETURN fn::tree::read(public_entity:native, 'history', 'page', [10]);"), /Tree read not allowed/i,
      'a different tenant cannot read the ordered tree');
    await assert.rejects(alice("RETURN fn::tree::read(public_entity:native, 'title', 'summary', []);"), /Tree read not allowed|TREE_UNKNOWN_ROOT/i,
      'undeclared tree slot is rejected');
    const anonymousTree = await anonymous("RETURN fn::tree::read(public_entity:native, 'history', 'page', [10]);");
    assert(!anonymousTree.body.includes('public_entry:native'), 'anonymous function invocation cannot return tree links');
    await q("CREATE bundle:valid SET owned_by=rebase_user:alice,lines=[{references:[]},{references:[{entity:entity:a}]}];");
    const nestedBefore = await q('RETURN bundle:valid;');
    await assert.rejects(q("UPDATE bundle:valid SET lines=[{references:[]},{references:[{entity:entity:b}]}];"), /TENANT_REFERENCE/);
    assert.deepEqual(await q('RETURN bundle:valid;'), nestedBefore, 'nested references enforce tenant and roll back');
    await alice("UPDATE bundle:valid SET target=code:a,related=[entity:a,code:a],selector='a';");
    assert.equal(await q('RETURN bundle:valid.derived_target;'), 'entity:a', 'local formula materializes a permitted reference');
    const referenceSnapshot = () => q(`RETURN {
      bundles: (SELECT * FROM bundle ORDER BY id),
      roots: (SELECT * FROM entity ORDER BY id),
      entries: (SELECT * FROM entry ORDER BY id),
      audit: (SELECT * FROM audit_mutation ORDER BY id)
    };`);
    const rejectReference = async (actor, sql) => {
      const before = await referenceSnapshot();
      await assert.rejects(actor(sql), /TENANT_REFERENCE|exist|assert/i, sql);
      assert.deepEqual(await referenceSnapshot(), before, 'reference rejection restores sources, roots, and audit');
    };
    await rejectReference(q, "CREATE bundle:cross SET owned_by=rebase_user:alice,target=code:b,lines=[];");
    await rejectReference(alice, 'UPDATE bundle:valid SET target=code:b;');
    await rejectReference(q, "CREATE bundle:derived_cross SET owned_by=rebase_user:alice,selector='b',lines=[];");
    await rejectReference(alice, "UPDATE bundle:valid SET selector='b';");
    await rejectReference(q, 'UPDATE bundle:valid SET related=[entity:a,code:b];');
    await rejectReference(q, 'UPDATE bundle:valid SET lines=[{references:[]},{references:[{entity:entity:missing}]}];');
    await rejectReference(alice, 'CREATE bundle:nested_cross SET owned_by=rebase_user:alice,lines=[{references:[]},{references:[{entity:entity:b}]}];');
    await alice('UPDATE bundle:valid SET target=entity:a,related=[],selector=NONE,lines=[{references:[{}]},{references:[]}];');
    assert.equal(await q('RETURN bundle:valid.derived_target;'), null, 'an absent optional formula removes its old reference');
    await q('UPDATE bundle:valid SET owned_by=rebase_user:bob;');
    assert.equal(await q('RETURN bundle:valid.tenant;'), 'rebase_tenant:a', 'same-tenant owner changes preserve nested reference validity');
    assert((await q('SELECT * FROM audit_mutation;')).length > 0, 'reference rollback oracle includes committed audit records');
    assert.equal(await q('RETURN entry:a.tenant;'), 'rebase_tenant:a');
    assert.deepEqual(await q('RETURN entry:a.read_by;'), 'rebase_user:alice');
    assert.deepEqual(await q('RETURN entry:a.rebase_reader_sources;'), ['entity:a']);
    assert.equal((await alice('SELECT * FROM entry:a;')).length, 1);
    assert.deepEqual(await bob('SELECT * FROM entry:a;'), [], 'an incomparable writer is not an additional reader');
    assert.deepEqual(await charlie('SELECT * FROM entry:a;'), []);
    assert.deepEqual(await other('SELECT * FROM entry;'), []);
    const aliceView = await alice('SELECT id, owned_by, total_rows, total_amount FROM v_metric_totals WHERE target=entity:shared;');
    const bobView = await bob('SELECT id, owned_by, read_by, total_rows, total_amount FROM v_metric_totals WHERE target=entity:shared;');
    const charlieView = await charlie('SELECT id, owned_by, total_rows, total_amount FROM v_metric_totals WHERE target=entity:shared;');
    assert.deepEqual(new Set(aliceView.map(row => row.owned_by)), new Set(['rebase_user:alice', 'rebase_user:bob']), 'owner and declared reader can read grouped records');
    assert.deepEqual(new Set(bobView.map(row => row.owned_by)), new Set(['rebase_user:bob']), 'sibling owner cannot infer another owner aggregate');
    assert.deepEqual(new Set(charlieView.map(row => row.owned_by)), new Set(['rebase_user:charlie']), 'sibling owner cannot infer another owner aggregate');
    assert.equal(String(aliceView.find(row => row.owned_by === 'rebase_user:bob').total_amount), '3', 'reader sees only the explicitly shared source group');
    const stableViewId = bobView.find(row => row.owned_by === 'rebase_user:bob' && row.read_by === 'rebase_user:bob')?.id;
    await q('UPDATE metric:bob_private SET amount=12dec;');
    const replacedViews = await bob('SELECT id, total_amount, read_by FROM v_metric_totals WHERE target=entity:shared AND owned_by=rebase_user:bob;');
    const replacedView = replacedViews.find(row => row.read_by === 'rebase_user:bob');
    assert(replacedView, 'the private Bob group remains visible to its owner');
    assert.equal(replacedView.id, stableViewId, 'group row identity remains stable when its aggregate is replaced');
    assert.equal(String(replacedView.total_amount), '12');
    const aliceComputed = await alice('SELECT c_v_metric_totals_target FROM entity:shared;');
    const bobComputed = await bob('SELECT c_v_metric_totals_target FROM entity:shared;');
    assert.deepEqual(new Set(aliceComputed[0].c_v_metric_totals_target.map(row => row.owned_by)), new Set(['rebase_user:alice', 'rebase_user:bob']));
    assert.deepEqual(new Set(bobComputed[0].c_v_metric_totals_target.map(row => row.owned_by)), new Set(['rebase_user:bob']));
    await applySchema(q, generateBundle(materials, { selectPolicy: 'owner' }).bundle);
    assert.deepEqual(await alice('SELECT * FROM metric:bob_shared;'), [], 'owner policy disables source reader grants');
    const ownerView = await alice('SELECT * FROM v_metric_totals WHERE target=entity:shared;');
    assert.deepEqual(new Set(ownerView.map(row => row.owned_by)), new Set(['rebase_user:alice']),
      'record-scoped views retain the source owner policy');
    const ownerComputed = await alice('SELECT c_v_metric_totals_target FROM entity:shared;');
    assert.deepEqual(new Set(ownerComputed[0].c_v_metric_totals_target.map(row => row.owned_by)), new Set(['rebase_user:alice']),
      'computed view fields retain the source owner policy');
    await applySchema(q, compiled.bundle);
    assert.equal((await other('SELECT * FROM v_metric_totals;')).length, 0, 'another tenant cannot read view rows');
    const anonymousView = await anonymous('SELECT * FROM v_metric_totals;');
    assert.notEqual(anonymousView.status, 200, 'anonymous view reads are rejected');
    assert(!anonymousView.body.includes('total_amount'), 'anonymous response contains no aggregate data');
    assert.deepEqual(await alice('SELECT * FROM entity:b;'), []);
    assert.deepEqual(await alice("UPDATE entity:b SET title='wrong';"), []);
    assert.deepEqual(await other('DELETE entry:a;'), []);
    assert.deepEqual(await alice('UPDATE entry:a SET amount=100dec;'), [], 'readers grant reads only');
    const snapshot = await q('RETURN {owner: entity:a, source: entry:a};');
    await assert.rejects(q(`CREATE entry:cross SET owned_by=rebase_user:other,
      entity=entity:a,amount=5dec,effective_at=d'2026-10-04T00:00:00Z';`), /TENANT/);
    await assert.rejects(q('UPDATE entry:a SET owned_by=rebase_user:other;'), /TENANT|readonly/i);
    await assert.rejects(q('UPDATE entity:a SET owned_by=rebase_user:other;'), /TENANT|readonly/i);
    await assert.rejects(q('UPDATE entry:a SET entity=entity:b;'), /TENANT/);
    assert.deepEqual(await q('RETURN {owner: entity:a, source: entry:a};'), snapshot);
    assert.equal((await alice('SELECT * FROM code;')).length, 1);
    await assert.rejects(q("CREATE code:duplicate SET owned_by=rebase_user:bob,value='same';"), /unique|already/i);

    // The source field has no @rebase-readers marker: the cached membership
    // alone must transfer the read grant when the root owner changes.
    await q('UPDATE entity:a SET owned_by=rebase_user:charlie;');
    assert.deepEqual(await q('RETURN entry:a.read_by;'), 'rebase_user:charlie');
    assert.deepEqual(await alice('SELECT * FROM entry:a;'), []);
    assert.equal((await charlie('SELECT * FROM entry:a;')).length, 1);
    assert.deepEqual(await bob('SELECT * FROM entry:a;'), [], 'an incomparable writer is not an additional reader');

    // Immediate owner inheritance can form a cycle safely: readers never
    // inherit another record's readers, and only owner changes propagate.
    await q(`CREATE note:a SET owned_by=rebase_user:alice,title='A';
      CREATE note:b SET owned_by=rebase_user:bob,title='B',other=note:a;
      UPDATE note:a SET other=note:b;`);
    assert.deepEqual(await q('RETURN note:a.read_by;'), 'rebase_user:bob');
    assert.deepEqual(await q('RETURN note:b.read_by;'), 'rebase_user:alice');
    await q('UPDATE note:a SET owned_by=rebase_user:charlie;');
    assert.deepEqual(await q('RETURN note:b.read_by;'), 'rebase_user:charlie');
    await assert.rejects(q('UPDATE note:a SET other=entity:b;'), /record|type|assert/i);
    await applySchema(q, compiled.bundle);
    assert.deepEqual(await q('RETURN entry:a.read_by;'), 'rebase_user:charlie');
    console.log('Tenant records passed: native isolation, reference rollback, root-derived readers, ownership refresh, local uniqueness, direct-reader cycles, populated schema reapplication.');
  } finally {
    await server?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
