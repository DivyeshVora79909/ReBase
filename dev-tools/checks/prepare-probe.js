#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const { Surreal, escapeIdent } = require('surrealdb');
const { start } = require('../temporal-tree/harness');
const { prepare } = require('../prepare');

const schema = `
DEFINE TABLE a SCHEMAFULL;
DEFINE FIELD link ON a TYPE option<record<b>> REFERENCE ON DELETE REJECT;
DEFINE TABLE b SCHEMAFULL;
DEFINE FIELD link ON b TYPE option<record<a>> REFERENCE ON DELETE REJECT;
DEFINE FIELD custom ON b TYPE option<record<a>> REFERENCE ON DELETE THEN { THROW 'custom policy restored'; };
DEFINE TABLE selfnode SCHEMAFULL;
DEFINE FIELD parent ON selfnode TYPE option<record<selfnode>> REFERENCE ON DELETE REJECT;
DEFINE TABLE nested SCHEMAFULL;
DEFINE FIELD links ON nested TYPE array<record<a>> REFERENCE ON DELETE REJECT;
DEFINE TABLE \`odd table\` SCHEMAFULL;
DEFINE FIELD \`odd field\` ON \`odd table\` TYPE option<record<a>> REFERENCE ON DELETE REJECT;
DEFINE TABLE audit SCHEMALESS;
DEFINE EVENT created ON a WHEN $event = 'CREATE' THEN (CREATE audit SET source = $after.id);
DEFINE EVENT deleted ON a WHEN $event = 'DELETE' THEN { THROW 'delete event restored'; };
DEFINE TABLE account SCHEMAFULL;
DEFINE FIELD code ON account TYPE string;
DEFINE INDEX unique_code ON account FIELDS code UNIQUE;
DEFINE TABLE z_source SCHEMAFULL;
DEFINE FIELD amount ON z_source TYPE number;
DEFINE TABLE a_summary AS SELECT math::sum(amount) AS total FROM z_source GROUP ALL;
DEFINE FUNCTION fn::prepare_retained() { RETURN 'retained'; };
DEFINE PARAM $prepare_retained VALUE 'retained';
DEFINE USER prepare_viewer ON DATABASE PASSWORD 'disposable-probe-password' ROLES VIEWER;
`;

const records = `
CREATE a:one;
CREATE b:one SET link = a:one, custom = a:one;
UPDATE a:one SET link = b:one;
CREATE selfnode:self;
UPDATE selfnode:self SET parent = selfnode:self;
CREATE nested:one SET links=[a:one];
CREATE \`odd table\`:one SET \`odd field\`=a:one;
CREATE account:old SET code = 'shared';
CREATE z_source:one SET amount = 3;
`;

async function result(db, sql) {
  return (await db.query(sql)).at(-1);
}

async function state(db) {
  const info = await result(db, 'INFO FOR DB;');
  const tables = {};
  for (const name of Object.keys(info.tables).sort()) {
    tables[name] = {
      definition: await result(db, `INFO FOR TABLE ${escapeIdent(name)};`),
      records: await result(db, `SELECT * FROM ${escapeIdent(name)} ORDER BY id;`),
    };
  }
  return { info, tables };
}

function failBeforeCommit(db, marker) {
  let injected = false;
  return {
    client: new Proxy(db, {
      get(target, property) {
        const value = Reflect.get(target, property);
        if (property === 'query') {
          return (sql, ...rest) => {
            if (typeof sql === 'string' && /\bBEGIN\b/i.test(sql) && /\bCOMMIT\b/i.test(sql)) {
              injected = true;
              sql = sql.replace(/\bCOMMIT(?:\s+TRANSACTION)?\s*;/i, `THROW '${marker}'; COMMIT TRANSACTION;`);
            }
            return value.call(target, sql, ...rest);
          };
        }
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }),
    assertInjected() { assert(injected, 'clear must execute its explicit transaction through checked query'); },
  };
}

function beforeClear(db, action) {
  let intercepted = false;
  return new Proxy(db, {
    get(target, property) {
      const value = Reflect.get(target, property);
      if (property === 'query') {
        return (sql, ...rest) => {
          if (!intercepted && typeof sql === 'string' && /\bBEGIN\b/i.test(sql) && /\bCOMMIT\b/i.test(sql)) {
            intercepted = true;
            return { responses: async () => {
              await action();
              return value.call(target, sql, ...rest).responses();
            } };
          }
          return value.call(target, sql, ...rest);
        };
      }
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

async function main() {
  const server = await start({ engine: 'surrealkv' });
  const db = new Surreal();
  try {
    await db.connect(`${server.url.replace('http:', 'ws:')}/rpc`);
    await db.signin({ username: 'root', password: 'root' });
    await db.query('DEFINE NAMESPACE prepare_probe; USE NS prepare_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await db.use({ namespace: 'prepare_probe', database: 'fixture' });

    const progress = [];
    const installed = await prepare(db, { schema, batchBytes: 512, onProgress: item => progress.push(item) });
    assert.equal(installed.operation, 'schema');
    assert(installed.statements > 1);
    assert(installed.requests > 1, 'small batchBytes must exercise schema batching');
    assert(installed.durationMs >= 0);
    assert(progress.length > 0);
    await db.query(records);
    const original = await state(db);
    assert.equal(original.tables.a_summary.records[0].total, 3);

    await assert.rejects(prepare(db, {
      schema: "DEFINE TABLE install_rolled_back SCHEMALESS; CREATE install_rolled_back:one; THROW 'deliberate install failure';",
      batchBytes: 64,
    }));
    assert.deepEqual(await state(db), original, 'failed chunked install must restore schema and data');
    await assert.rejects(prepare(db, {
      clear: true,
      schema: "DEFINE TABLE combined_rolled_back SCHEMALESS; THROW 'deliberate combined failure';",
    }));
    assert.deepEqual(await state(db), original, 'failed combined clear/install must restore schema and all data');
    console.log('prepare: PASS chunked schema installation and failed-install/combined rollback');

    let drifted;
    const metadataDrift = beforeClear(db, async () => {
      await db.query('DEFINE FIELD drift ON account TYPE option<string>;');
      drifted = await state(db);
    });
    await assert.rejects(prepare(metadataDrift, { clear: true }), /PREPARE_SCHEMA_CHANGED/);
    assert.deepEqual(await state(db), drifted, 'metadata drift must retain both external DDL and all data');
    await db.query('REMOVE FIELD drift ON account;');
    assert.deepEqual(await state(db), original);

    await db.query('DEFINE DATABASE other;');
    await db.use({ namespace: 'prepare_probe', database: 'other' });
    await db.query('DEFINE TABLE untouched SCHEMALESS; CREATE untouched:one;');
    const other = await state(db);
    await db.use({ namespace: 'prepare_probe', database: 'fixture' });
    const contextDrift = beforeClear(db, () => db.use({ namespace: 'prepare_probe', database: 'other' }));
    try {
      await assert.rejects(prepare(contextDrift, { clear: true }), /PREPARE_CONTEXT_CHANGED/);
      assert.deepEqual(await state(db), other, 'context drift must not clear the newly selected database');
    } finally {
      await db.use({ namespace: 'prepare_probe', database: 'fixture' });
    }
    assert.deepEqual(await state(db), original, 'context drift must not clear the original database');
    let switchedInstall = false;
    try {
      await assert.rejects(prepare(db, {
        schema: 'DEFINE TABLE wrong_context_install SCHEMALESS;',
        onProgress: async item => {
          if (item.phase === 'install' && item.completed === 0 && !switchedInstall) {
            switchedInstall = true;
            await db.use({ namespace: 'prepare_probe', database: 'other' });
          }
        },
      }), /PREPARE_CONTEXT_CHANGED/);
      assert(switchedInstall, 'installation observer must exercise the context change');
      assert.deepEqual(await state(db), other, 'installation must not mutate the newly selected database');
    } finally {
      await db.use({ namespace: 'prepare_probe', database: 'fixture' });
    }
    assert.deepEqual(await state(db), original, 'installation context drift must preserve the original database');
    console.log('prepare: PASS metadata and selected-context drift guards');

    const failure = failBeforeCommit(db, 'deliberate clear failure');
    await assert.rejects(prepare(failure.client, { clear: true }));
    failure.assertInjected();
    assert.deepEqual(await state(db), original, 'failed clear must restore records and reference policies');
    await db.query('CREATE a:after_failure;');
    assert.equal((await result(db, 'SELECT * FROM audit;')).length, 2, 'events must remain active after failed clear');
    console.log('prepare: PASS failed-clear rollback and following-query event activity');

    const cleared = await prepare(db, { clear: true });
    assert.equal(cleared.operation, 'clear');
    assert.deepEqual([...cleared.tables].sort(), Object.keys(original.tables).sort());
    assert(cleared.statements >= cleared.tables.length);
    assert(cleared.requests > 0);
    assert(cleared.durationMs >= 0);
    const empty = await state(db);
    assert.deepEqual(empty.info, original.info, 'clear must retain database definitions');
    for (const name of Object.keys(original.tables)) {
      assert.deepEqual(empty.tables[name].definition, original.tables[name].definition, `${name} definitions retained`);
      assert.deepEqual(empty.tables[name].records, [], `${name} records cleared`);
    }
    assert.equal(await result(db, 'RETURN fn::prepare_retained();'), 'retained');
    assert.equal(await result(db, 'RETURN $prepare_retained;'), 'retained');

    await db.query("CREATE account:old SET code='shared';");
    await assert.rejects(async () => db.query("CREATE account:duplicate SET code='shared';"), /unique|already contains|already exists/i);
    await db.query('DELETE account:old; CREATE b:one; DELETE b:one; CREATE selfnode:self; DELETE selfnode:self;');
    await db.query('CREATE a:one; CREATE b:one SET link=a:one;');
    await assert.rejects(async () => db.query('DELETE a:one;'), /ON DELETE REJECT/);
    await db.query('DELETE b:one;');
    await assert.rejects(async () => db.query('DELETE a:one;'), /delete event restored/);
    await db.query('CREATE b:custom SET custom=a:one;');
    await assert.rejects(async () => db.query('DELETE a:one;'), /custom policy restored/);
    assert.equal((await result(db, 'SELECT * FROM audit;')).length, 1, 'CREATE event restored');
    await db.query('CREATE z_source:one SET amount=4;');
    assert.deepEqual(await result(db, 'SELECT VALUE total FROM a_summary;'), [4], 'view aggregation must start fresh');
    console.log('prepare: PASS cyclic/self/custom references, events, indexes, old IDs, views and retained metadata');

    await db.query('DEFINE EVENT pending_native_work ON a ASYNC WHEN false THEN { RETURN NONE; };');
    const guarded = await state(db);
    await assert.rejects(prepare(db, { clear: true }), /async/i);
    assert.deepEqual(await state(db), guarded, 'unsupported native async events must be rejected before mutation');
    await db.query('REMOVE EVENT pending_native_work ON a;');
    console.log('prepare: PASS native async-event rejection before mutation');

    const combined = await prepare(db, { clear: true, schema: 'DEFINE TABLE combined_created SCHEMALESS' });
    assert.equal(combined.operation, 'clear+schema');
    const combinedState = await state(db);
    assert(Object.hasOwn(combinedState.info.tables, 'combined_created'));
    for (const table of Object.values(combinedState.tables)) assert.deepEqual(table.records, []);
    console.log('prepare: PASS atomic combined clear and schema installation');

    await db.query('DEFINE TABLE lightweight TYPE RELATION IN a OUT b LIGHTWEIGHT; CREATE a:lightweight; CREATE b:lightweight; RELATE a:lightweight->lightweight->b:lightweight;');
    assert.equal((await result(db, 'SELECT * FROM lightweight;')).length, 1);
    await prepare(db, { clear: true });
    assert.deepEqual(await result(db, 'SELECT * FROM lightweight;'), []);
    await db.query('CREATE a:lightweight; CREATE b:lightweight; RELATE a:lightweight->lightweight->b:lightweight;');
    assert.equal((await result(db, 'SELECT * FROM lightweight;')).length, 1, 'lightweight endpoints and edges can be reused');
    console.log('prepare: PASS lightweight relation cleanup and endpoint/edge reuse');
    return { installed, cleared };
  } finally {
    await db.close();
    await server.close();
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error(`prepare: FAIL: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { main };
