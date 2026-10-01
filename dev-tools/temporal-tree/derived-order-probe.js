#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('./harness');

const ROOT = path.resolve(__dirname, '../..');
const FIXTURE = path.join(__dirname, 'derived-order-fixture.surql');
const FRAMEWORK = path.join(ROOT, 'framework');

function compileFixture(directory, fixture) {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'fixture.surql'), fixture);
  const materials = loadMaterials({ groups: [
    { name: 'framework', roots: [FRAMEWORK] },
    { name: 'project', roots: [directory] },
  ] });
  return generateBundle(materials);
}

function statement(source, field) {
  const start = source.indexOf(`DEFINE FIELD OVERWRITE ${field} ON natural_fact`);
  assert(start >= 0, `missing field statement ${field}`);
  const end = source.indexOf(';', start);
  assert(end >= 0, `unterminated field statement ${field}`);
  return source.slice(start, end + 1);
}

function reorderDerivedFields(source) {
  const definitions = ['a_total', 'm_double', 'z_factor'].map(field => statement(source, field));
  let reordered = source;
  for (const definition of definitions) reordered = reordered.replace(definition, '');
  const insertion = reordered.indexOf('DEFINE FIELD OVERWRITE rb_fact');
  assert(insertion >= 0);
  return `${reordered.slice(0, insertion)}${definitions.reverse().join('\n')}${reordered.slice(insertion)}`;
}

const snapshot = q => q(`RETURN {
  owner: (SELECT * FROM ONLY tree_owner:one),
  rules: (SELECT * FROM natural_rule ORDER BY id),
  facts: (SELECT * FROM natural_fact ORDER BY id)
};`);

async function runFixture(server, q, bundle, database) {
  await applySchema(q, bundle);
  await q(`CREATE natural_rule:base SET owned_by=rebase_group:root, a_add=3dec;
    CREATE tree_owner:one SET owned_by=rebase_group:root;
    CREATE natural_fact:sample SET owned_by=rebase_group:root, a_owner=tree_owner:one, a_rule=natural_rule:base,
      a_at=d'2026-10-01T00:00:00Z', a_quantity=2dec;`);
  await q(`CREATE c3_profile:sample SET owned_by=rebase_group:root,
    profile={ email: 'public@example.test', secret: 'private nested value' }, private_note='private top-level value';`);
  let audit = [];
  for (let attempt = 0; attempt < 100; attempt += 1) {
    audit = await q("SELECT * FROM audit_mutation WHERE table_name='c3_profile' AND target=c3_profile:sample ORDER BY at;");
    if (audit.length) break;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal(audit.length, 1, 'nested audit event settles');
  assert.deepEqual(audit[0].after, { profile: { email: 'public@example.test' } });
  await q(`CREATE c3_profile:missing SET owned_by=rebase_group:root,
    profile={ secret: 'must stay private' }, private_note='another private value';`);
  let missingAudit = [];
  for (let attempt = 0; attempt < 100; attempt += 1) {
    missingAudit = await q("SELECT * FROM audit_mutation WHERE table_name='c3_profile' AND target=c3_profile:missing ORDER BY at;");
    if (missingAudit.length) break;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal(missingAudit.length, 1, 'missing nested values still produce a CREATE audit event');
  const missingEmail = missingAudit[0].after.profile?.email;
  assert(missingEmail === undefined || missingEmail === null, 'an absent selected leaf remains absent');
  assert.doesNotMatch(JSON.stringify(missingAudit[0].after), /must stay private|another private value/);

  let data = await snapshot(q);
  let fact = data.facts[0];
  assert.equal(Number(fact.z_factor), 5);
  assert.equal(Number(fact.m_double), 4);
  assert.equal(Number(fact.a_total), 9);
  assert.equal(Number(data.owner.z_history.summary.measures.amount.sum), 9);

  await q('UPDATE natural_rule:base SET a_add=4dec;');
  data = await snapshot(q);
  fact = data.facts[0];
  assert.equal(Number(fact.z_factor), 6, 'opaque function dependency refreshed');
  assert.equal(Number(fact.a_total), 10);
  assert.equal(Number(data.owner.z_history.summary.measures.amount.sum), 10);

  await q('UPDATE natural_fact:sample SET a_quantity=3dec;');
  data = await snapshot(q);
  fact = data.facts[0];
  assert.equal(Number(fact.z_factor), 7);
  assert.equal(Number(fact.m_double), 6);
  assert.equal(Number(fact.a_total), 13);
  assert.equal(Number(data.owner.z_history.summary.measures.amount.sum), 13);

  const before = data;
  await assert.rejects(q("UPDATE natural_fact:sample SET a_quantity='not-a-decimal';"), /a_quantity|decimal|coerc/i);
  assert.deepEqual(await snapshot(q), before, 'native field type restores derived fields and tree state');
  await assert.rejects(q('UPDATE natural_fact:sample SET a_quantity=NONE;'), /a_quantity|decimal|coerc|must conform/i);
  assert.deepEqual(await snapshot(q), before, 'missing required input restores derived fields and tree state');
  await assert.rejects(q('UPDATE natural_fact:sample SET a_rule=natural_rule:missing;'), /a_rule|exists|reference/i);
  assert.deepEqual(await snapshot(q), before, 'native reference existence restores source and shadows');
  await assert.rejects(q('UPDATE natural_fact:sample SET a_quantity=-10dec;'), /must conform|a_total|a_quantity/i);
  assert.deepEqual(await snapshot(q), before, 'native ASSERT restores derived fields and tree state');

  const current = await snapshot(q);
  await applySchema(q, bundle);
  assert.deepEqual(await snapshot(q), current, 'populated reapplication preserves source and shadow values');
  let derivedAudit = [];
  for (let attempt = 0; attempt < 100; attempt += 1) {
    derivedAudit = await q("SELECT * FROM audit_mutation WHERE table_name='natural_fact' AND target=natural_fact:sample ORDER BY at;");
    if (derivedAudit.length) break;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert(derivedAudit.length > 0, 'source mutation audit settles');
  assert(derivedAudit.every(entry => !entry.after?.__rebase_derived_0000 && !entry.after?.a_total),
    'private staging and derived output fields stay out of table audit snapshots');

  await q(`CREATE rebase_user:reader SET name='Reader', parents=[rebase_group:root];
    DEFINE ACCESS c3_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;
    CREATE tree_owner:reader SET owned_by=rebase_user:reader;`);
  const response = await fetch(`${server.url}/signin`, {
    method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ ns: 'temporal_probe', db: database, ac: 'c3_reader' }),
  });
  const { token } = await response.json();
  assert(token);
  const reader = client(server.url, database, token);
  await reader(`CREATE natural_fact:reader_row SET owned_by=rebase_user:reader, a_owner=tree_owner:reader,
    a_rule=natural_rule:base, a_at=d'2026-10-01T00:00:01Z', a_quantity=2dec;`);
  const readerFact = await reader('SELECT * FROM ONLY natural_fact:reader_row;');
  assert.equal(Number(readerFact.z_factor), 6);
  assert.equal(Number(readerFact.m_double), 4);
  assert.equal(Number(readerFact.a_total), 10, 'record user CREATE uses the static topological path');
  assert.equal(readerFact.__rebase_derived_0000, undefined, 'private staging values stay hidden');
  await assert.rejects(reader('RETURN fn::rebase::derive((SELECT * FROM ONLY natural_fact:reader_row));'), /permission|not allowed/i);
}

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-derived-order-'));
  let server;
  try {
    const source = fs.readFileSync(FIXTURE, 'utf8');
    const compiled = compileFixture(path.join(directory, 'normal'), source);
    const reordered = compileFixture(path.join(directory, 'reordered'), reorderDerivedFields(source));
    assert.equal(compiled.bundle, generateBundle(loadMaterials({ groups: [
      { name: 'framework', roots: [FRAMEWORK] },
      { name: 'project', roots: [path.join(directory, 'normal')] },
    ] } )).bundle, 'deterministic compilation');
    assert.match(compiled.bundle, /LET \$r1 = object::extend\(\$r0, \{ m_double:/);
    assert.match(compiled.bundle, /LET \$r2 = object::extend\(\$r1, \{ z_factor:/);
    assert.match(compiled.bundle, /LET \$r3 = object::extend\(\$r2, \{ a_total:/);
    const audit = compiled.bundle.match(/-- REBASE: audit log\n([\s\S]*?)(?=\n-- REBASE:)/)?.[1] || '';
    assert.match(audit, /profile: \{ email: \$before\.profile\.email \}/);
    assert.doesNotMatch(audit, /profile\.secret|private_note/);
    assert.doesNotMatch(audit, /__rebase_derived_\d+/, 'field-only audit never selects generated helper fields');
    const extractDerive = bundle => bundle.match(/DEFINE FUNCTION OVERWRITE fn::rebase::derive\(\$row: object\) \{([\s\S]*?)\} PERMISSIONS NONE;/)?.[1];
    assert.equal(extractDerive(compiled.bundle), extractDerive(reordered.bundle), 'field declaration order preserves derived evaluator semantics');
    assert.deepEqual(compiled.temporalModel.derivedOrder.get('natural_fact').map(field => field.name),
      ['m_double', 'z_factor', 'a_total'], 'the resolved model stores one topological field order');

    const cyclic = source.replace('VALUE $this.a_quantity * 2dec', 'VALUE $this.a_total * 2dec');
    const cyclicDir = path.join(directory, 'cyclic');
    assert.throws(() => compileFixture(cyclicDir, cyclic), /derived field cycle.*a_total.*m_double/i);

    server = await start({ engine: 'surrealkv' });
    const first = client(server.url, 'natural');
    const second = client(server.url, 'reordered');
    for (const [index, name, q, bundle] of [[0, 'natural', first, compiled.bundle], [1, 'reordered', second, reordered.bundle]]) {
      await q(`${index === 0 ? 'DEFINE NAMESPACE temporal_probe; ' : ''}USE NS temporal_probe; DEFINE DATABASE ${name}; USE DB ${name};`);
      await runFixture(server, q, bundle, name);
    }
    console.log('PASS topological CREATE shadows, opaque dependency refresh, local updates, native ASSERT rollback, reordered declarations and populated reapplication');
  } finally {
    if (server) await server.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (require.main === module) main().catch(error => {
  console.error(`derived-order: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
