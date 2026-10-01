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

const fixture = path.join(__dirname, 'causal-outputs-fixture.surql');
const at = n => `2026-10-01T00:00:00.${String(n).padStart(9, '0')}Z`;

async function setup() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-causal-outputs-'));
  let server;
  try {
    fs.copyFileSync(fixture, path.join(directory, 'schema.surql'));
    const materials = loadMaterials({ groups: [
      { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
      { name: 'project', roots: [directory] },
    ] });
    const { bundle } = generateBundle(materials);
    assert.equal(generateBundle(materials).bundle, bundle, 'deterministic causal-output compilation');
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
  owners: (SELECT * FROM calc_owner ORDER BY id),
  seeds: (SELECT * FROM input_seed ORDER BY id),
  batches: (SELECT * FROM batch_source ORDER BY id),
  inputs: (SELECT * FROM input_leg ORDER BY id),
  bases: (SELECT * FROM calc_basis ORDER BY id),
  left: (SELECT * FROM branch_left_leg ORDER BY id),
  right: (SELECT * FROM branch_right_leg ORDER BY id),
  diamonds: (SELECT * FROM diamond_basis ORDER BY id),
  finals: (SELECT * FROM final_leg ORDER BY id),
  feedback: (SELECT * FROM feedback_leg ORDER BY id),
  audit: (SELECT * FROM audit_mutation ORDER BY id)
};`);

function verify(data) {
  const rows = [
    ...data.seeds.map(row => [row, 'rb_seed']),
    ...data.inputs.map(row => [row, 'rb_input']),
    ...data.left.map(row => [row, 'rb_left']),
    ...data.right.map(row => [row, 'rb_right']),
    ...data.finals.map(row => [row, 'rb_final']),
    ...data.feedback.map(row => [row, 'rb_feedback']),
  ];
  const records = rows.map(([row]) => row);
  const entries = rows.map(([row, slot]) => ({
    link: { rid: row.id, slot },
    owner: { rid: row.a_owner, slot: 'z_history' },
    key: [row.a_at, row.id, slot],
    measures: { amount: Number(row.a_amount) }, tags: {}, spans: {}, dependent: false,
  }));
  return oracle.verify(data.owners, records, entries, compareKey);
}

const amount = (groups, owner) => Number(groups.get(`${owner}/z_history`).head.summary.measures.amount?.sum ?? 0);
const latestAt = (groups, owner) => groups.get(`${owner}/z_history`).head.summary.last?.[0];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const auditIds = q => q('SELECT VALUE id FROM audit_mutation ORDER BY id;');

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

async function waitForAuditGrowth(q, previousCount) {
  const started = Date.now();
  while (Date.now() - started < 5000) {
    const ids = await auditIds(q);
    if (ids.length > previousCount) return waitForAuditQuiet(q);
    await delay(25);
  }
  throw new Error('committed source recipe did not append an audit record');
}

async function main() {
  const env = await setup(), q = env.q;
  const reject = async (user, query, pattern) => {
    await waitForAuditQuiet(q);
    const before = await snapshot(q);
    await assert.rejects(user(query), pattern);
    await waitForAuditQuiet(q);
    assert.deepEqual(await snapshot(q), before, 'failed DAG operation restores every source, child, slot and root');
    verify(before);
  };
  try {
    await q(`CREATE calc_owner:input_a SET owned_by=rebase_group:root, a_floor=0dec;
      CREATE calc_owner:input_b SET owned_by=rebase_group:root, a_floor=0dec;
      CREATE calc_owner:left SET owned_by=rebase_group:root, a_floor=0dec;
      CREATE calc_owner:right SET owned_by=rebase_group:root, a_floor=0dec;
      CREATE calc_owner:final SET owned_by=rebase_group:root, a_floor=120dec;
      CREATE input_seed:a SET owned_by=rebase_group:root, a_owner=calc_owner:input_a,
        a_at=d'${at(0)}', a_amount=20dec;
      CREATE input_seed:b SET owned_by=rebase_group:root, a_owner=calc_owner:input_b,
        a_at=d'${at(0)}', a_amount=20dec;
      CREATE calc_basis:main SET owned_by=rebase_group:root, a_input_a=calc_owner:input_a,
        a_input_b=calc_owner:input_b, a_left_owner=calc_owner:left,
        a_right_owner=calc_owner:right, a_feedback=false;
      CREATE diamond_basis:main SET owned_by=rebase_group:root, a_left_owner=calc_owner:left,
        a_right_owner=calc_owner:right, a_final_owner=calc_owner:final;
      CREATE rebase_user:writer SET name='Writer', parents=[rebase_group:root];
      DEFINE ACCESS causal_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;`);
    const response = await fetch(`${env.server.url}/signin`, { method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'causal_writer' }) });
    const { token } = await response.json(); assert(token);
    const writer = client(env.server.url, 'fixture', token);

    let data = await snapshot(q), groups = verify(data);
    await waitForAuditQuiet(q);
    data = await snapshot(q); groups = verify(data);
    assert.equal(amount(groups, 'calc_owner:input_a'), 20);
    assert.equal(amount(groups, 'calc_owner:input_b'), 20);
    assert.equal(amount(groups, 'calc_owner:left'), 40);
    assert.equal(amount(groups, 'calc_owner:right'), 80);
    assert.equal(amount(groups, 'calc_owner:final'), 120);
    assert.equal(Number(data.bases[0].z_amount), 40);
    assert.equal(Number(data.diamonds[0].z_amount), 120);

    const beforeBatchAudit = (await auditIds(q)).length;
    await writer(`CREATE batch_source:main SET owned_by=rebase_group:root,
      a_input_a=calc_owner:input_a, a_input_b=calc_owner:input_b,
      a_at=d'${at(1)}', a_delta_a=2dec, a_delta_b=3dec;`);
    await waitForAuditGrowth(q, beforeBatchAudit);
    data = await snapshot(q); groups = verify(data);
    assert(data.audit.some(row => row.table_name === 'batch_source'
      && row.target === 'batch_source:main' && row.event === 'CREATE'));
    assert(data.audit.filter(row => row.table_name === 'input_leg' && row.event === 'CREATE').length >= 2,
      'both committed required inputs produce audit records');
    assert.equal(data.inputs.length, 2, 'one source operation creates both input legs');
    assert.equal(Number(data.bases[0].z_amount), 45, 'the shared basis reads both published input roots');
    assert.equal(Number(data.diamonds[0].z_amount), 135, 'the diamond joins both refreshed branch roots');
    assert.equal(amount(groups, 'calc_owner:input_a'), 22);
    assert.equal(amount(groups, 'calc_owner:input_b'), 23);
    assert.equal(amount(groups, 'calc_owner:left'), 45);
    assert.equal(amount(groups, 'calc_owner:right'), 90);
    assert.equal(amount(groups, 'calc_owner:final'), 135);
    assert.equal(latestAt(groups, 'calc_owner:final'), at(1));
    console.log('PASS two input roots publish before one basis refresh and the diamond joins both branches');

    await reject(writer, `UPDATE batch_source:main SET a_at=d'${at(2)}',
      a_delta_a=-20dec, a_delta_b=-20dec;`, /C2D_OWNER_FLOOR/);
    console.log('PASS final downstream floor failure restores the complete input and output graph');

    assert(3 * ((20 - 8) + (20 + 3)) < 120,
      'publishing the changed first input alone would fail the final floor');
    const beforeValidEditAudit = (await auditIds(q)).length;
    await writer(`UPDATE batch_source:main SET a_at=d'${at(3)}',
      a_delta_a=-8dec, a_delta_b=15dec;`);
    await waitForAuditGrowth(q, beforeValidEditAudit);
    data = await snapshot(q); groups = verify(data);
    assert.equal(data.inputs.length, 2, 'input identities remain stable across source edits');
    assert.equal(data.left.length, 1); assert.equal(data.right.length, 1); assert.equal(data.finals.length, 1);
    assert.equal(Number(data.bases[0].z_amount), 47);
    assert.equal(data.bases[0].z_at, at(3));
    assert.equal(Number(data.diamonds[0].z_amount), 141);
    assert.equal(data.diamonds[0].z_at, at(3));
    for (const table of ['batch_source', 'input_leg', 'branch_left_leg', 'branch_right_leg', 'final_leg']) {
      assert(data.audit.some(row => row.table_name === table && row.event === 'UPDATE'),
        `${table} update is audited after the committed DAG edit`);
    }
    assert.equal(amount(groups, 'calc_owner:input_a'), 12);
    assert.equal(amount(groups, 'calc_owner:input_b'), 35);
    assert.equal(amount(groups, 'calc_owner:left'), 47);
    assert.equal(amount(groups, 'calc_owner:right'), 94);
    assert.equal(amount(groups, 'calc_owner:final'), 141);
    assert.equal(latestAt(groups, 'calc_owner:input_a'), at(3));
    assert.equal(latestAt(groups, 'calc_owner:input_b'), at(3));
    assert.equal(latestAt(groups, 'calc_owner:left'), at(3));
    assert.equal(latestAt(groups, 'calc_owner:right'), at(3));
    assert.equal(latestAt(groups, 'calc_owner:final'), at(3));
    console.log('PASS future date and amount edits rekey every downstream branch and final output');

    await reject(writer, 'UPDATE calc_basis:main SET a_feedback=true;', /REBASE_REQUIRED_OUTPUT_FEEDBACK/);
    console.log('PASS a required output cannot feed a root consumed by its own derived basis');

    await q('DELETE batch_source:main; DELETE diamond_basis:main; DELETE calc_basis:main;');
    await waitForAuditQuiet(q);
    data = await snapshot(q); groups = verify(data);
    assert.deepEqual(data.inputs, []); assert.deepEqual(data.left, []); assert.deepEqual(data.right, []);
    assert.deepEqual(data.finals, []); assert.deepEqual(data.feedback, []);
    assert.equal(amount(groups, 'calc_owner:input_a'), 20);
    assert.equal(amount(groups, 'calc_owner:input_b'), 20);
    for (const owner of ['calc_owner:left', 'calc_owner:right', 'calc_owner:final']) assert.equal(amount(groups, owner), 0);
    await q(`DELETE input_seed:a; DELETE input_seed:b;
      DELETE calc_owner:input_a; DELETE calc_owner:input_b; DELETE calc_owner:left;
      DELETE calc_owner:right; DELETE calc_owner:final;`);
    await waitForAuditQuiet(q);
    const final = await snapshot(q);
    const { audit, ...state } = final;
    assert(audit.length > 0, 'committed source and output changes are auditable');
    assert.deepEqual(state, {
      owners: [], seeds: [], batches: [], inputs: [], bases: [], left: [], right: [], diamonds: [], finals: [], feedback: [],
    });
    console.log('PASS deleting basis and source rows clears the causal graph and every owned membership');
  } finally { await env.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, setup, snapshot, verify };
