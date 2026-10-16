"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { Decimal, RecordId } = require("surrealdb");
const { parseSchema } = require("../compiler/schema");
const { createModel, plan, populate } = require("../fixtures");

const objectSchema = (properties, required = Object.keys(properties)) => ({
  type: "object", additionalProperties: false, properties, required,
});

function model() {
  const schema = parseSchema(`
    DEFINE TABLE parent SCHEMAFULL;
    DEFINE FIELD name ON parent TYPE string;
    DEFINE FIELD score ON parent TYPE int;
    DEFINE TABLE tag SCHEMAFULL;
    DEFINE FIELD name ON tag TYPE string;
    DEFINE TABLE child SCHEMAFULL;
    DEFINE FIELD parent ON child TYPE record<parent>;
    DEFINE FIELD name ON child TYPE string;
    DEFINE TABLE links SCHEMAFULL;
    DEFINE FIELD peers ON links TYPE array<record<parent | tag>>;
    DEFINE TABLE payment SCHEMAFULL;
    DEFINE FIELD kind ON payment TYPE string;
    DEFINE FIELD amount ON payment TYPE decimal;
    DEFINE FIELD reference ON payment TYPE option<string>;
  `, "");
  return createModel({ schema, schemas: {
    parent: objectSchema({ name: { type: "string", minLength: 5 }, score: { type: "integer", minimum: 0, maximum: 1000000 } }),
    tag: objectSchema({ name: { type: "string", minLength: 1 } }),
    child: objectSchema({ parent: { type: "string", pattern: "^parent:.+$" }, name: { type: "string", minLength: 3 } }),
    links: objectSchema({ peers: { type: "array", minItems: 2, maxItems: 3, uniqueItems: true,
      items: { type: "string", pattern: "^(parent|tag):.+$" } } }),
    payment: {
      ...objectSchema({ kind: { enum: ["cash", "invoice"] }, amount: { type: "string", pattern: "^-?[0-9]+(?:\\.[0-9]+)?$" },
        reference: { type: "string" } }, ["kind", "amount"]),
      if: { properties: { kind: { const: "invoice" } }, required: ["kind"] },
      then: { properties: { reference: { type: "string", pattern: "^INV-[0-9]{4}$" } }, required: ["reference"] },
    },
  } });
}

function snapshot(planned) {
  return planned.rows.map(row => ({ id: String(row.id), table: row.table,
    content: Object.fromEntries(Object.entries(row.content).map(([key, value]) => [key,
      value instanceof RecordId || value instanceof Decimal ? String(value) : value])) }));
}

test("seed replay stays isolated when independent asynchronous plans interleave", async () => {
  const fixtureModel = model();
  const recipe = [{ name: "parents", table: "parent", count: 4,
    values: async ({ faker }) => {
      const name = faker.person.fullName();
      await new Promise(resolve => setImmediate(resolve));
      return { name };
    } }];
  const expected = await plan({ model: fixtureModel, seed: "replay", recipe });
  const [replayed, other] = await Promise.all([
    plan({ model: fixtureModel, seed: "replay", recipe }),
    plan({ model: fixtureModel, seed: "independent", recipe }),
  ]);
  assert.deepEqual(snapshot(replayed), snapshot(expected));
  assert.notDeepEqual(snapshot(other), snapshot(expected));
});

test("an asynchronous global predicate can reject a structurally valid plan", async () => {
  const options = { model: model(), recipe: [{ name: "parents", table: "parent", count: 2 }] };
  await assert.rejects(plan({ ...options, assert: async planned => planned.rows.length === 3 }),
    /Fixture global assertion returned false/);
  const planned = await plan({ ...options, assert: async result => result.rows.length === 2 });
  assert.equal(planned.rows.length, 2);
});

test("named pools preserve their meaning while prerequisites order generated records", async () => {
  const planned = await plan({ model: model(), seed: 7,
    space: { selectedParents: [{ id: new RecordId("parent", "chosen"), name: "Chosen" }],
      otherParents: [{ id: "parent:excluded", name: "Excluded" }] },
    recipe: [
      { name: "children", table: "child", count: 3, refs: { parent: "generatedParents" } },
      { name: "selectedChildren", table: "child", refs: { parent: "selectedParents" }, after: ["children"] },
      { name: "generatedParents", table: "parent", count: 2 },
    ],
  });
  assert.deepEqual(planned.rows.map(row => row.table), ["parent", "parent", "child", "child", "child", "child"]);
  const generated = new Set(planned.space.generatedParents.map(row => row.id));
  for (const row of planned.space.children) assert(generated.has(row.parent));
  assert.equal(planned.space.selectedChildren[0].parent, "parent:chosen");
  for (const row of planned.rows.filter(row => row.table === "child")) assert(row.content.parent instanceof RecordId);
});

test("typed array refs filter tables and sample distinct identities without changing supplied pools", async () => {
  const supplied = [{ id: "parent:one" }, { id: "parent:one" }, { id: "tag:two" }, { id: "payment:ignored" }];
  const original = structuredClone(supplied);
  Object.freeze(supplied);
  supplied.forEach(Object.freeze);
  const planned = await plan({ model: model(), seed: "arrays", space: { mixed: supplied },
    recipe: [{ name: "relations", table: "links", count: 5, refs: { peers: "mixed" } }] });
  for (const row of planned.rows) {
    assert.equal(row.content.peers.length, 2);
    assert.deepEqual(new Set(row.content.peers.map(String)), new Set(["parent:one", "tag:two"]));
    assert(row.content.peers.every(id => id instanceof RecordId));
  }
  assert.deepEqual(supplied, original);
  assert.notStrictEqual(planned.space.mixed, supplied);
});

test("array minimum cannot be satisfied by duplicate or wrong-table candidates", async () => {
  for (const mixed of [[{ id: "parent:one" }, { id: "parent:one" }], [{ id: "parent:one" }, { id: "payment:other" }]]) {
    await assert.rejects(plan({ model: model(), space: { mixed },
      recipe: [{ name: "relations", table: "links", refs: { peers: "mixed" } }] }),
    /Fixture relations\[0\].*peers needs 2 distinct candidates/);
  }
  await assert.rejects(plan({ model: model(), space: { selected: [{ id: "parent:one" }] },
    recipe: [{ name: "duplicates", table: "links", values: { peers: ["parent:one", "parent:one"] } }] }),
  /Fixture duplicates\[0\].*(unique|duplicate)/i);
});

test("pinned values guide conditional generation before exact native decimal binding", async () => {
  const amount = "9007199254740993.123456789123456789";
  const planned = await plan({ model: model(), seed: "condition", recipe: [
    { name: "invoices", table: "payment", count: 3, values: { kind: "invoice", amount } },
  ] });
  for (const row of planned.rows) {
    assert.match(row.content.reference, /^INV-[0-9]{4}$/);
    assert(row.content.amount instanceof Decimal);
    assert.equal(String(row.content.amount), amount);
  }
  await assert.rejects(plan({ model: model(), recipe: [
    { name: "badInvoice", table: "payment", values: { kind: "invoice", amount, reference: "invalid" } },
  ] }), /Fixture badInvoice\[0\].*(pattern|Invalid payment)/);
});

test("empty, missing, and outside reference spaces fail with row context", async () => {
  const fixtureModel = model();
  await assert.rejects(plan({ model: fixtureModel, space: { empty: [] }, recipe: [
    { name: "children", table: "child", refs: { parent: "empty" } },
  ] }), /Fixture children\[0\].*empty reference space/);
  await assert.rejects(plan({ model: fixtureModel, recipe: [
    { name: "children", table: "child", refs: { parent: "missing" } },
  ] }), /Unknown reference pool missing/);
  await assert.rejects(plan({ model: fixtureModel, space: { allowed: [{ id: "parent:allowed" }] }, recipe: [
    { name: "children", table: "child", values: { parent: "parent:outside" } },
  ] }), /Fixture children\[0\].*outside the supplied space/);
  await assert.rejects(plan({ model: fixtureModel, recipe: [{ name: "children", table: "child" }] }),
    /Fixture children\[0\].*Required reference parent/);
});

test("empty steps remain valid while cycles and unknown prerequisites fail before row generation", async () => {
  const fixtureModel = model();
  const planned = await plan({ model: fixtureModel, recipe: [{ name: "none", table: "parent", count: 0 }] });
  assert.deepEqual(planned.rows, []);
  assert.deepEqual(planned.space.none, []);
  await assert.rejects(plan({ model: fixtureModel, recipe: [
    { name: "a", table: "parent", count: 0, after: ["b"] },
    { name: "b", table: "parent", count: 0, after: ["a"] },
  ] }), /Cyclic fixture prerequisites/);
  await assert.rejects(plan({ model: fixtureModel, recipe: [
    { name: "a", table: "parent", count: 0, after: ["absent"] },
  ] }), /Unknown fixture prerequisite: absent/);
});

test("failed rows do not mutate caller inputs or contaminate later replay", async () => {
  const fixtureModel = model(), supplied = { selected: [{ id: "parent:existing", name: "Original" }] };
  const original = structuredClone(supplied);
  const recipe = [{ name: "children", table: "child", count: 2, refs: { parent: "selected" } }];
  const baseline = await plan({ model: fixtureModel, seed: 22, space: supplied, recipe });
  await assert.rejects(plan({ model: fixtureModel, seed: 22, space: supplied, recipe: [
    { ...recipe[0], values: ({ index, space }) => {
      space.selected[0].name = "Modified internal copy";
      if (index === 1) throw new Error("deliberate failure");
      return {};
    } },
  ] }), /Fixture children\[1\] \(child\): deliberate failure/);
  assert.deepEqual(supplied, original);
  assert.deepEqual(snapshot(await plan({ model: fixtureModel, seed: 22, space: supplied, recipe })), snapshot(baseline));
  await assert.rejects(plan({ model: fixtureModel, recipe: [
    { name: "parents", table: "parent", values: ({ index }) => ({ name: index ? "okay" : 42 }) },
  ] }), /Fixture parents\[0\].*(Invalid parent|type)/);
});

function fakeDatabase({ failBatch, failCancel = false } = {}) {
  const events = [], pending = [], committed = [];
  let batches = 0;
  const transaction = {
    async query(sql, bindings) {
      if (sql === "SELECT selected parents") {
        events.push("read-space");
        return [{ id: new RecordId("parent", "existing") }];
      }
      events.push("create");
      if (++batches === failBatch) throw new Error("database guard rejected batch");
      const ids = Object.keys(bindings).filter(key => /^id\d+$/.test(key));
      return ids.map(key => {
        const row = { id: bindings[key], ...bindings[key.replace("id", "content")] };
        pending.push(row);
        return [row];
      });
    },
    async commit() { events.push("commit"); committed.push(...pending.splice(0)); },
    async cancel() { events.push("cancel"); pending.length = 0; if (failCancel) throw new Error("cancel failed"); },
  };
  const db = { async beginTransaction() { events.push("begin"); return transaction; } };
  return { db, transaction, events, pending, committed };
}

function transactionOptions(transaction) {
  return { model: model(), seed: "transaction", batchSize: 1,
    space: async selectedTransaction => {
      assert.strictEqual(selectedTransaction, transaction);
      return { selected: await selectedTransaction.query("SELECT selected parents") };
    },
    recipe: [
      { name: "children", table: "child", refs: { parent: "selected" }, after: ["parents"] },
      { name: "parents", table: "parent" },
    ],
  };
}

test("populate reads and writes through one transaction in dependency order before committing", async () => {
  const fake = fakeDatabase();
  const result = await populate(fake.db, transactionOptions(fake.transaction));
  assert.deepEqual(fake.events, ["begin", "read-space", "create", "create", "commit"]);
  assert.deepEqual(result.created.map(row => row.id.table.name), ["parent", "child"]);
  assert.equal(String(result.created[1].parent), "parent:existing");
  assert.equal(fake.committed.length, 2);
  assert.equal(fake.pending.length, 0);
});

test("a later rejected batch cancels all preceding writes", async () => {
  const fake = fakeDatabase({ failBatch: 2 });
  await assert.rejects(populate(fake.db, transactionOptions(fake.transaction)), /database guard rejected batch/);
  assert.deepEqual(fake.events, ["begin", "read-space", "create", "create", "cancel"]);
  assert.deepEqual(fake.committed, []);
  assert.deepEqual(fake.pending, []);
});

test("planning failure cancels before writes and cancellation errors retain both failures", async () => {
  const fake = fakeDatabase();
  await assert.rejects(populate(fake.db, { ...transactionOptions(fake.transaction),
    recipe: [{ name: "bad", table: "child", values: { parent: "parent:outside" } }] }), /outside the supplied space/);
  assert.deepEqual(fake.events, ["begin", "read-space", "cancel"]);
  const broken = fakeDatabase({ failBatch: 2, failCancel: true });
  await assert.rejects(populate(broken.db, transactionOptions(broken.transaction)), error => {
    assert(error instanceof AggregateError);
    assert.match(error.errors[0].message, /database guard rejected batch/);
    assert.match(error.errors[1].message, /cancel failed/);
    return true;
  });
});
