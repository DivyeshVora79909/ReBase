#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { Surreal, RecordId } = require("surrealdb");
const { createModel, populate } = require("../fixtures");
const { start } = require("../temporal-tree/harness");

const schema = `
DEFINE TABLE parent SCHEMAFULL;
DEFINE FIELD used ON parent TYPE int DEFAULT 0;
DEFINE TABLE child SCHEMAFULL;
DEFINE FIELD parent ON child TYPE record<parent>
  VALUE IF $value = parent:a THEN parent:b
    ELSE IF $value = parent:b THEN parent:outside ELSE $value END;
DEFINE FIELD derived ON child TYPE record<parent> VALUE parent:outside;
DEFINE EVENT count_child ON child WHEN $event = 'CREATE'
  THEN { UPDATE $after.parent SET used += 1; };
`;

async function main() {
  const model = createModel({ schema, schemas: { child: {
    type: "object", properties: { parent: { type: "string" } }, required: ["parent"], additionalProperties: false,
  } } });
  const server = await start({ engine: "surrealkv" });
  const db = new Surreal();
  try {
    await db.connect(`${server.url.replace(/^http/, "ws")}/rpc`);
    await db.signin({ username: "root", password: "root" });
    await db.query("DEFINE NAMESPACE fixture_references_probe; USE NS fixture_references_probe; DEFINE DATABASE fixture;");
    await db.use({ namespace: "fixture_references_probe", database: "fixture" });
    await db.query(schema);
    await db.query("CREATE parent:a; CREATE parent:b; CREATE parent:outside;");
    const space = async tx => (await tx.query("SELECT * FROM [parent:a, parent:b];"))[0];

    const result = await populate(db, { model, space, counts: { child: 1 }, seed: "saved-references",
      rules: { child: { values: { parent: "parent:a" } } },
    });
    assert(result.created[0].parent instanceof RecordId);
    assert.equal(String(result.rows[0].content.parent), "parent:a");
    assert.equal(String(result.created[0].parent), "parent:b");
    assert.equal(String(result.created[0].derived), "parent:outside", "protected outputs are outside the public pool contract");
    assert.deepEqual(result.usage["child.parent"], { "parent:b": 1 });
    assert.equal((await db.query("RETURN parent:b.used;"))[0], 1);

    const snapshot = () => db.query("SELECT * FROM parent ORDER BY id; SELECT * FROM child ORDER BY id;");
    const before = await snapshot();
    let attempts = 0;
    await assert.rejects(populate(db, { model, space, counts: { child: 2 }, seed: "saved-reference-rollback",
      rules: { child: { refs: { parent: false }, values: async ({ index, space, transaction }) => {
        attempts++;
        if (index === 1) {
          assert.equal(space.child.length, 1, "the first pending child was accepted");
          assert.equal((await transaction.query("RETURN parent:b.used;"))[0], 2, "its event already changed the parent");
        }
        return { parent: index === 0 ? "parent:a" : "parent:b" };
      } } },
    }), /Saved reference parent=parent:outside is outside the supplied space or accepted rows/);
    assert.equal(attempts, 2);
    assert.deepEqual(await snapshot(), before, "rejection rolls back both child writes and all parent event updates");
    console.log("PASS fixtures: saved-reference normalization, usage, and complete transaction rollback");
  } finally {
    try { await db.close(); } finally { await server.close(); }
  }
}

if (require.main === module) main().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
module.exports = { main };
