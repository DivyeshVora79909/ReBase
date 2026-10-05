#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema, compareKey } = require('./harness');
const oracle = require('./oracle');

const fixture = path.join(__dirname, 'required-outputs-fixture.surql');
const at = n => `2026-09-25T00:00:00.${String(n).padStart(9, '0')}Z`;

function verifyRootlessRecipeCompilation() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-rootless-recipe-'));
  try {
    fs.writeFileSync(path.join(directory, 'schema.surql'), `
      DEFINE TABLE rebase_user SCHEMAFULL;
      DEFINE TABLE rebase_group SCHEMAFULL;
      DEFINE TABLE recipe_source SCHEMAFULL COMMENT '@rebase-required-outputs fn::recipe::outputs';
      DEFINE FIELD a_value ON recipe_source TYPE int;
      DEFINE TABLE required_output SCHEMAFULL PERMISSIONS NONE COMMENT '@rebase-managed-output';
      DEFINE FIELD rebase_managed_source ON required_output TYPE string COMMENT '@rebase-system';
      DEFINE FIELD rebase_managed_role ON required_output TYPE string COMMENT '@rebase-system';
      DEFINE FUNCTION OVERWRITE fn::recipe::outputs($row: object) { RETURN []; } PERMISSIONS NONE;
    `);
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    const { bundle } = generateBundle(materials);
    assert.match(bundle, /DEFINE EVENT OVERWRITE rebase_refresh ON recipe_source/);
    assert.match(bundle, /DEFINE EVENT OVERWRITE rebase_refresh ON required_output/);
    assert.match(bundle, /DEFINE FUNCTION OVERWRITE fn::rebase::sync_required_outputs/);
    console.log('PASS required-output recipes compile without temporal tree roots');

    fs.writeFileSync(path.join(directory, 'schema.surql'), `
      DEFINE TABLE rebase_user SCHEMAFULL;
      DEFINE TABLE rebase_group SCHEMAFULL;
      DEFINE TABLE cycle_source SCHEMAFULL COMMENT '@rebase-required-outputs fn::cycle::outputs';
      DEFINE FIELD a_value ON cycle_source TYPE int;
      DEFINE TABLE a_cycle SCHEMAFULL PERMISSIONS NONE COMMENT '@rebase-managed-output';
      DEFINE FIELD rebase_managed_source ON a_cycle TYPE string COMMENT '@rebase-system';
      DEFINE FIELD rebase_managed_role ON a_cycle TYPE string COMMENT '@rebase-system';
      DEFINE FIELD a_dependency ON a_cycle TYPE record<z_cycle> REFERENCE ON DELETE REJECT;
      DEFINE TABLE z_cycle SCHEMAFULL PERMISSIONS NONE COMMENT '@rebase-managed-output';
      DEFINE FIELD rebase_managed_source ON z_cycle TYPE string COMMENT '@rebase-system';
      DEFINE FIELD rebase_managed_role ON z_cycle TYPE string COMMENT '@rebase-system';
      DEFINE FIELD a_dependency ON z_cycle TYPE record<a_cycle> REFERENCE ON DELETE REJECT;
      DEFINE FUNCTION OVERWRITE fn::cycle::outputs($row: object) { RETURN []; } PERMISSIONS NONE;
    `);
    const cycleMaterials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    assert.throws(() => generateBundle(cycleMaterials), /managed-output reference dependency cycle.*a_cycle.*z_cycle/i);
    console.log('PASS unsupported managed-output reference cycles fail clearly at compile time');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

async function setup() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-required-outputs-'));
  let server;
  try {
    verifyRootlessRecipeCompilation();
    fs.copyFileSync(fixture, path.join(directory, 'schema.surql'));
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    const { bundle } = generateBundle(materials);
    assert.equal(generateBundle(materials).bundle, bundle, 'deterministic required-output compilation');
    const orderStart = bundle.indexOf('DEFINE FUNCTION OVERWRITE fn::rebase::order_required_outputs(');
    const orderEnd = bundle.indexOf('} PERMISSIONS NONE;', orderStart);
    const orderHelper = bundle.slice(orderStart, orderEnd);
    assert(orderHelper.indexOf("= 'z_recipe_base'") < orderHelper.indexOf("= 'a_recipe_compound'"),
      'the declared prerequisite precedes its consumer despite table declaration and name order');
    server = await start({ engine: 'surrealkv' });
    const q = client(server.url);
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, bundle);
    return { q, server, bundle, async close() {
      await server.close(); fs.rmSync(directory, { recursive: true, force: true });
    } };
  } catch (error) {
    if (server) await server.close();
    fs.rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const auditIds = q => q('SELECT VALUE id FROM audit_mutation WITH NOINDEX ORDER BY id;');

async function waitForAuditQuiet(q) {
  const started = Date.now();
  let ids = JSON.stringify(await auditIds(q)), unchanged = Date.now();
  while (Date.now() - started < 5000) {
    await delay(25);
    const next = JSON.stringify(await auditIds(q));
    if (next !== ids) { ids = next; unchanged = Date.now(); }
    if (Date.now() - unchanged >= 250) return JSON.parse(ids);
  }
  throw new Error('audit events did not settle within 5 seconds');
}

const snapshot = async q => {
  await waitForAuditQuiet(q);
  // SurrealDB 3.3.0 can satisfy ORDER BY id from the readers fan-out index,
  // returning a row more than once. The source oracle must scan each row once.
  return q(`RETURN {
  owners: (SELECT * FROM recipe_owner WITH NOINDEX ORDER BY id),
  seeds: (SELECT * FROM recipe_seed WITH NOINDEX ORDER BY id),
  sources: (SELECT * FROM recipe_source WITH NOINDEX ORDER BY id),
  bases: (SELECT * FROM z_recipe_base WITH NOINDEX ORDER BY id),
  compounds: (SELECT * FROM a_recipe_compound WITH NOINDEX ORDER BY id),
  uses: (SELECT * FROM required_use WITH NOINDEX ORDER BY id),
  audit: (SELECT * FROM audit_mutation WITH NOINDEX ORDER BY id)
};`);
};

function verify(data) {
  const outputs = [...data.bases, ...data.compounds];
  const rows = [...data.seeds, ...outputs];
  const sources = new Map(data.sources.map(source => [source.id, source]));
  for (const source of data.sources) {
    const sourceBases = data.bases.filter(row => row.rebase_managed_source === source.id);
    const sourceCompounds = data.compounds.filter(row => row.rebase_managed_source === source.id);
    assert.equal(sourceBases.length, source.a_base ? 1 : 0, `base role count ${source.id}`);
    assert.equal(sourceCompounds.length, source.a_pair ? 1 : 0, `compound role count ${source.id}`);
    if (sourceCompounds.length) assert.equal(sourceCompounds[0].a_prerequisite, sourceBases[0].id,
      `compound prerequisite identity ${source.id}`);
  }
  for (const row of outputs) assert(sources.has(row.rebase_managed_source), `managed source exists for ${row.id}`);
  const entries = rows.map(row => ({
    link: { rid: row.id, slot: 'rb_position' },
    owner: { rid: row.a_owner, slot: 'rb_position' },
    key: [row.a_at, row.id, 'rb_position'],
    measures: { amount: Number(row.a_amount) }, tags: {}, spans: {}, dependent: false,
  }));
  entries.push(...data.compounds.map(row => ({
    link: { rid: row.id, slot: 'rb_prerequisite' },
    owner: { rid: row.a_prerequisite, slot: 'rb_children' },
    key: [row.a_at, row.id, 'rb_prerequisite'],
    measures: { amount: Number(row.a_amount) }, tags: {}, spans: {}, dependent: false,
  })));
  return oracle.verify([...data.owners, ...data.bases], rows, entries, compareKey);
}

async function main() {
  const env = await setup(), q = env.q;
  const reject = async (query, pattern, user = q) => {
    await waitForAuditQuiet(q);
    const before = await snapshot(q);
    await assert.rejects(user(query), pattern);
    await waitForAuditQuiet(q);
    assert.deepEqual(await snapshot(q), before, 'rejected output/source write restores all roots and rows');
    verify(before);
  };
  const denyManagedWrite = async (user, query) => {
    const before = await snapshot(q);
    assert.deepEqual(await user(query), [], 'PERMISSIONS NONE filters the record-user write');
    assert.deepEqual(await snapshot(q), before, 'filtered managed-output write leaves all rows and roots unchanged');
    verify(before);
  };
  try {
    await q(`CREATE recipe_owner:main SET owned_by=rebase_tenant:default, a_floor=0dec;
      CREATE recipe_owner:spare SET owned_by=rebase_tenant:default, a_floor=0dec;
      CREATE recipe_seed:main SET owned_by=rebase_tenant:default, a_owner=recipe_owner:main,
        a_at=d'${at(0)}', a_amount=1dec;
      CREATE recipe_seed:spare SET owned_by=rebase_tenant:default, a_owner=recipe_owner:spare,
        a_at=d'${at(0)}', a_amount=5dec;
      CREATE rebase_user:writer SET name='Writer', parents=[rebase_tenant:default];
      DEFINE ACCESS recipe_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;`);
    const response = await fetch(`${env.server.url}/signin`, { method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'recipe_writer' }) });
    const { token } = await response.json(); assert(token);
    const writer = client(env.server.url, 'fixture', token);

    await writer(`CREATE recipe_source:main SET owned_by=rebase_tenant:default, a_owner=recipe_owner:main,
      a_at=d'${at(1)}', a_amount=2dec, a_pair=true;`);
    let data = await snapshot(q), groups = verify(data);
    let mainMetric = groups.get('recipe_owner:main/rb_position').head.summary.measures.amount;
    assert.equal(data.bases.length + data.compounds.length, 2, 'both required outputs materialize in the source transaction');
    assert.equal(data.compounds[0].a_prerequisite, data.bases[0].id, 'consumer points at the materialized prerequisite');
    assert.equal(Number(mainMetric.instant_min), 0, 'same-time outputs settle before the owner floor is checked');
    assert.equal(Number(mainMetric.sum), 1, 'same-time paired outputs preserve the complete owner balance');
    console.log('PASS paired required outputs settle together at the complete timestamp');

    await applySchema(q, env.bundle);
    assert.deepEqual(await snapshot(q), data, 'populated required-output schema reapplication is a no-op');

    const mainOutputs = [...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:main');
    const mainIds = mainOutputs.map(row => row.id).sort();
    await reject(`UPDATE recipe_source:main SET a_pair=false;`, /C2C_COMPLETE_BALANCE_FLOOR/, writer);
    data = await snapshot(q); verify(data);
    assert.deepEqual([...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:main').map(row => row.id).sort(), mainIds,
      'failed recipe restores its required output identities');
    console.log('PASS final guard failure restores the source and complete required-output set');

    await writer(`CREATE recipe_source:spare SET owned_by=rebase_user:writer, a_owner=recipe_owner:spare,
      a_at=d'${at(1)}', a_amount=2dec, a_pair=true;`);
    data = await snapshot(q); verify(data);
    const spareIds = [...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.id).sort();
    assert.deepEqual(await writer('SELECT * FROM z_recipe_base;'), [], 'managed rows are private to record users');
    await denyManagedWrite(writer, `CREATE z_recipe_base:forged SET owned_by=rebase_tenant:default,
      rebase_managed_source=recipe_source:spare, rebase_managed_role='z_credit',
      a_owner=recipe_owner:spare, a_at=d'${at(1)}', a_amount=-99dec RETURN AFTER;`);
    await denyManagedWrite(writer, `UPDATE type::record('z_recipe_base', [recipe_source:spare, 'z_credit'])
      SET a_amount=-99dec RETURN AFTER;`);
    await denyManagedWrite(writer, `DELETE type::record('z_recipe_base', [recipe_source:spare, 'z_credit']) RETURN BEFORE;`);
    console.log('PASS record-user create, update and delete cannot alter managed outputs');

    await writer('UPDATE recipe_source:spare SET a_amount=3dec;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual([...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.id).sort(), spareIds,
      'source edits update stable (source, role) IDs instead of duplicating outputs');
    assert.equal([...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:spare').length, 2);
    const prerequisite = data.bases.find(row => row.rebase_managed_source === 'recipe_source:spare');
    const compound = data.compounds.find(row => row.rebase_managed_source === 'recipe_source:spare');
    await q(`CREATE required_use:spare SET owned_by=rebase_tenant:default, target=${compound.id};`);
    await reject('UPDATE recipe_source:spare SET a_pair=false;', /referenc|delete|reject/i, writer);
    await reject('DELETE recipe_source:spare;', /referenc|delete|reject/i, writer);
    await q('DELETE required_use:spare;');
    await writer('UPDATE recipe_source:spare SET a_pair=false;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.compounds.filter(row => row.rebase_managed_source === 'recipe_source:spare'), [],
      'obsolete optional role is removed');
    assert.equal(Number(groups.get('recipe_owner:spare/rb_position').head.summary.measures.amount.sum), 2);
    assert.deepEqual(data.bases.find(row => row.id === prerequisite.id).id, prerequisite.id,
      'base remains under the same stable role ID while the compound is removed');
    await writer('UPDATE recipe_source:spare SET a_base=false;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.bases.filter(row => row.rebase_managed_source === 'recipe_source:spare'), [],
      'prerequisite role is removed after its dependent role');
    assert.equal(Number(groups.get('recipe_owner:spare/rb_position').head.summary.measures.amount.sum), 5);
    await writer('UPDATE recipe_source:spare SET a_base=true, a_pair=true;');
    data = await snapshot(q); verify(data);
    assert.deepEqual([...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.id).sort(), spareIds,
      'replacement recreates both roles at stable source/role IDs');
    await writer(`UPDATE recipe_source:spare SET a_at=d'${at(2)}', a_amount=4dec;`);
    data = await snapshot(q); verify(data);
    assert.deepEqual([...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.id).sort(), spareIds,
      'rekey and replacement updates preserve role identities');
    console.log('PASS source edits update stable managed values and remove obsolete roles without duplicates');

    await writer('DELETE recipe_source:spare;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual([...data.bases, ...data.compounds].filter(row => row.rebase_managed_source === 'recipe_source:spare'), [],
      'record owner deletion removes every required child');
    assert.deepEqual(data.sources.map(row => row.id), ['recipe_source:main']);
    await q('DELETE recipe_source:main;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.bases, [], 'source deletion removes every prerequisite output');
    assert.deepEqual(data.compounds, [], 'source deletion removes every dependent output');
    assert.equal(Number(groups.get('recipe_owner:main/rb_position').head.summary.measures.amount.sum), 1);
    assert.equal(Number(groups.get('recipe_owner:spare/rb_position').head.summary.measures.amount.sum), 5);
    await q('DELETE recipe_seed:main; DELETE recipe_seed:spare; DELETE recipe_owner:main; DELETE recipe_owner:spare;');
    const empty = await snapshot(q);
    assert.deepEqual({ owners: empty.owners, seeds: empty.seeds, sources: empty.sources,
      bases: empty.bases, compounds: empty.compounds, uses: empty.uses },
    { owners: [], seeds: [], sources: [], bases: [], compounds: [], uses: [] });
    assert(empty.audit.length > 0, 'committed source mutations remain audited after cleanup');
    console.log('PASS source deletion removes outputs, restores owner histories and leaves no managed rows');
  } finally { await env.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, setup, snapshot, verify };
