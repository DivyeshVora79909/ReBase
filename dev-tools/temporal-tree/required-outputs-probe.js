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

const snapshot = q => q(`RETURN {
  owners: (SELECT * FROM recipe_owner ORDER BY id),
  seeds: (SELECT * FROM recipe_seed ORDER BY id),
  sources: (SELECT * FROM recipe_source ORDER BY id),
  legs: (SELECT * FROM required_leg ORDER BY id)
};`);

function verify(data) {
  const rows = [...data.seeds, ...data.legs];
  const entries = rows.map(row => ({
    link: { rid: row.id, slot: 'rb_position' },
    owner: { rid: row.a_owner, slot: 'rb_position' },
    key: [row.a_at, row.id, 'rb_position'],
    measures: { amount: Number(row.a_amount) }, tags: {}, spans: {}, dependent: false,
  }));
  return oracle.verify(data.owners, rows, entries, compareKey);
}

async function main() {
  const env = await setup(), q = env.q;
  const reject = async (query, pattern, user = q) => {
    const before = await snapshot(q);
    await assert.rejects(user(query), pattern);
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
    await q(`CREATE recipe_owner:main SET owned_by=rebase_group:root, a_floor=0dec;
      CREATE recipe_owner:spare SET owned_by=rebase_group:root, a_floor=0dec;
      CREATE recipe_seed:main SET owned_by=rebase_group:root, a_owner=recipe_owner:main,
        a_at=d'${at(0)}', a_amount=1dec;
      CREATE recipe_seed:spare SET owned_by=rebase_group:root, a_owner=recipe_owner:spare,
        a_at=d'${at(0)}', a_amount=5dec;
      CREATE rebase_user:writer SET name='Writer', parents=[rebase_group:root];
      DEFINE ACCESS recipe_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;`);
    const response = await fetch(`${env.server.url}/signin`, { method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'recipe_writer' }) });
    const { token } = await response.json(); assert(token);
    const writer = client(env.server.url, 'fixture', token);

    await writer(`CREATE recipe_source:main SET owned_by=rebase_group:root, a_owner=recipe_owner:main,
      a_at=d'${at(1)}', a_amount=2dec, a_pair=true;`);
    let data = await snapshot(q), groups = verify(data);
    let mainMetric = groups.get('recipe_owner:main/rb_position').head.summary.measures.amount;
    assert.equal(data.legs.length, 2, 'both required outputs materialize in the source transaction');
    assert(mainMetric.min_prefix < 0, 'record-ID order places the debit before its same-time credit');
    assert.equal(Number(mainMetric.instant_min), 0, 'complete-timestamp floor remains satisfied');
    console.log('PASS paired required outputs settle together despite a transient strict-prefix breach');

    await applySchema(q, env.bundle);
    assert.deepEqual(await snapshot(q), data, 'populated required-output schema reapplication is a no-op');

    const mainLegs = data.legs.filter(row => row.rebase_managed_source === 'recipe_source:main');
    const mainIds = mainLegs.map(row => row.id).sort();
    await reject(`UPDATE recipe_source:main SET a_pair=false;`, /C2C_COMPLETE_BALANCE_FLOOR/, writer);
    data = await snapshot(q); verify(data);
    assert.deepEqual(data.legs.filter(row => row.rebase_managed_source === 'recipe_source:main').map(row => row.id).sort(), mainIds,
      'failed recipe restores its required output identities');
    console.log('PASS final guard failure restores the source and complete required-output set');

    await writer(`CREATE recipe_source:spare SET owned_by=rebase_user:writer, a_owner=recipe_owner:spare,
      a_at=d'${at(1)}', a_amount=2dec, a_pair=true;`);
    data = await snapshot(q); verify(data);
    const spareIds = data.legs.filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.id).sort();
    assert.deepEqual(await writer('SELECT * FROM required_leg;'), [], 'managed rows are private to record users');
    await denyManagedWrite(writer, `CREATE required_leg:forged SET owned_by=rebase_group:root,
      rebase_managed_source=recipe_source:spare, rebase_managed_role='a_debit',
      a_owner=recipe_owner:spare, a_at=d'${at(1)}', a_amount=-99dec RETURN AFTER;`);
    await denyManagedWrite(writer, `UPDATE type::record('required_leg', [recipe_source:spare, 'a_debit'])
      SET a_amount=-99dec RETURN AFTER;`);
    await denyManagedWrite(writer, `DELETE type::record('required_leg', [recipe_source:spare, 'a_debit']) RETURN BEFORE;`);
    console.log('PASS record-user create, update and delete cannot alter managed outputs');

    await writer('UPDATE recipe_source:spare SET a_amount=3dec;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.legs.filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.id).sort(), spareIds,
      'source edits update stable (source, role) IDs instead of duplicating outputs');
    assert.equal(data.legs.filter(row => row.rebase_managed_source === 'recipe_source:spare').length, 2);
    await writer('UPDATE recipe_source:spare SET a_pair=false;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.legs.filter(row => row.rebase_managed_source === 'recipe_source:spare').map(row => row.rebase_managed_role), ['a_debit'],
      'obsolete optional role is removed');
    assert.equal(Number(groups.get('recipe_owner:spare/rb_position').head.summary.measures.amount.sum), 2);
    console.log('PASS source edits update stable managed values and remove obsolete roles without duplicates');

    await writer('DELETE recipe_source:spare;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.legs.filter(row => row.rebase_managed_source === 'recipe_source:spare'), [],
      'record owner deletion removes every required child');
    assert.deepEqual(data.sources.map(row => row.id), ['recipe_source:main']);
    await q('DELETE recipe_source:main;');
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.legs, [], 'source deletion removes every required child');
    assert.equal(Number(groups.get('recipe_owner:main/rb_position').head.summary.measures.amount.sum), 1);
    assert.equal(Number(groups.get('recipe_owner:spare/rb_position').head.summary.measures.amount.sum), 5);
    await q('DELETE recipe_seed:main; DELETE recipe_seed:spare; DELETE recipe_owner:main; DELETE recipe_owner:spare;');
    assert.deepEqual(await snapshot(q), { owners: [], seeds: [], sources: [], legs: [] });
    console.log('PASS source deletion removes outputs, restores owner histories and leaves no managed rows');
  } finally { await env.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, setup, snapshot, verify };
