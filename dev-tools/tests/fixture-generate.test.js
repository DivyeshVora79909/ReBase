"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { RecordId } = require("surrealdb");
const { createModel, generate, populate, FixtureStalledError } = require("../fixtures");

const object = (properties, required = Object.keys(properties)) => ({ type: "object", properties, required, additionalProperties: false });
const string = { type: "string" };
const model = createModel({ schema: `
  DEFINE TABLE parent SCHEMAFULL;
  DEFINE FIELD name ON parent TYPE string;
  DEFINE TABLE tag SCHEMAFULL;
  DEFINE FIELD name ON tag TYPE string;
  DEFINE TABLE child SCHEMAFULL;
  DEFINE FIELD parent ON child TYPE record<parent>;
  DEFINE FIELD name ON child TYPE string;
  DEFINE TABLE link SCHEMAFULL;
  DEFINE FIELD subject ON link TYPE record<parent | tag>;
  DEFINE TABLE peers SCHEMAFULL;
  DEFINE FIELD members ON peers TYPE array<record<parent | tag | parent>, 2>;
  DEFINE TABLE node SCHEMAFULL;
  DEFINE FIELD parent ON node TYPE record<node>;
  DEFINE TABLE optional_node SCHEMAFULL;
  DEFINE FIELD parent ON optional_node TYPE option<record<optional_node>>;
  DEFINE TABLE left SCHEMAFULL;
  DEFINE FIELD right ON left TYPE record<right>;
  DEFINE TABLE right SCHEMAFULL;
  DEFINE FIELD left ON right TYPE record<left>;
  DEFINE TABLE group SCHEMAFULL;
  DEFINE TABLE account SCHEMAFULL;
  DEFINE FIELD group ON account TYPE record<group>;
  DEFINE TABLE pair SCHEMAFULL;
  DEFINE FIELD a_account ON pair TYPE record<account>;
  DEFINE FIELD z_group ON pair TYPE record<group>;
  DEFINE TABLE ledger SCHEMAFULL;
  DEFINE FIELD used ON ledger TYPE int DEFAULT 0;
  DEFINE TABLE entry SCHEMAFULL;
  DEFINE FIELD ledger ON entry TYPE record<ledger>;
  DEFINE FIELD ordinal ON entry TYPE int;
`, schemas: {
  parent: object({ name: string }), tag: object({ name: string }),
  child: object({ parent: string, name: string }), link: object({ subject: string }),
  peers: object({ members: { type: "array", items: string, uniqueItems: true } }),
  node: object({ parent: string }), optional_node: object({ parent: string }, []),
  left: object({ right: string }), right: object({ left: string }), group: object({}),
  account: object({ group: string }), pair: object({ a_account: string, z_group: string }),
  ledger: object({ used: { type: "integer" } }),
  entry: object({ ledger: string, ordinal: { type: "integer", minimum: 0 } }),
} });

const accept = async ({ id, content }) => ({ ...content, id });
const run = options => generate({ model, apply: accept, ...options });

test("counts request new rows and schema references always use already accepted identities", async () => {
  const supplied = [{ id: new RecordId("parent", "seed"), name: "Existing" }];
  const known = new Set(supplied.map(row => String(row.id)));
  const result = await run({ seed: "quotas", space: supplied, counts: { child: 20, parent: 3 },
    apply: async row => {
      if (row.table === "child") assert(known.has(String(row.content.parent)));
      known.add(String(row.id));
      return accept(row);
    },
  });
  assert.equal(result.space.child.length, 20);
  assert.equal(result.space.parent.length, 4);
  assert.equal(result.created.length, 23);
  assert.equal(result.attempts, 23);
  assert.equal(supplied.length, 1);
  assert(supplied[0].id instanceof RecordId);
});

test("incremental seeds replay during independent asynchronous runs", async () => {
  const options = { seed: "replay", counts: { child: 10, parent: 3 }, rules: {
    parent: { values: async ({ faker }) => {
      const name = faker.person.fullName();
      await new Promise(resolve => setImmediate(resolve));
      return { name };
    } },
  } };
  const expected = await run(options);
  const [replayed, different] = await Promise.all([run(options), run({ ...options, seed: "different" })]);
  assert.deepEqual(replayed, expected);
  assert.notDeepEqual(different.rows, expected.rows);
});

test("required cycles need seeds, optional self references do not create artificial deadlocks", async () => {
  for (const counts of [{ node: 2 }, { left: 2, right: 2 }]) {
    await assert.rejects(run({ counts }), error => {
      assert(error instanceof FixtureStalledError);
      assert.equal(error.code, "FIXTURE_STALLED");
      assert.equal(error.attempts, 0);
      assert.deepEqual(error.remaining, counts);
      assert(error.blocked.every(row => row.reasons[0].includes("available 0")));
      return true;
    });
  }
  assert.equal((await run({ space: [{ id: "node:seed" }], counts: { node: 4 } })).rows.length, 4);
  assert.equal((await run({ space: [{ id: "right:seed" }], counts: { left: 2, right: 2 } })).rows.length, 4);
  const optional = await run({ counts: { optional_node: 2 } });
  assert(optional.rows.every(row => !Object.hasOwn(row.content, "parent")));
  await assert.rejects(run({ counts: { optional_node: 1 }, rules: { optional_node: { refs: { parent: {} } } } }),
    { code: "FIXTURE_STALLED" });
});

test("polymorphic defaults weight records equally and explicit zero biases exclude a target", async () => {
  const space = ["parent:a", "parent:b", "parent:c", "parent:d", "parent:e", "parent:f", "tag:a", "tag:b"].map(id => ({ id }));
  const result = await run({ space, seed: "polymorphic", counts: { link: 400 } });
  const parents = result.rows.filter(row => row.content.subject.table.name === "parent").length;
  assert(parents > 250 && parents < 350, `equal record weights should yield roughly 3:1, got ${parents}: ${400 - parents}`);
  const onlyTags = await run({ space, counts: { link: 20 }, rules: { link: { refs: { subject: { bias: { parent: 0 } } } } } });
  assert(onlyTags.rows.every(row => row.content.subject.table.name === "tag"));
});

test("array references honor native fixed length and distinct identities, including duplicate seeds and target alternatives", async () => {
  const space = [{ id: "parent:one" }, { id: "parent:one" }, { id: "tag:two" }];
  const result = await run({ space, counts: { peers: 8 } });
  assert.equal(result.space.parent.length, 1);
  for (const row of result.rows) assert.deepEqual(new Set(row.content.members.map(String)), new Set(["parent:one", "tag:two"]));
  await assert.rejects(run({ space: space.slice(0, 2), counts: { peers: 1 } }), { code: "FIXTURE_STALLED" });
});

test("usage is per reference role, initializes from known children, and accepts explicit totals", async () => {
  const space = [{ id: "parent:a" }, { id: "parent:b" }, { id: "link:old", subject: "parent:a" }];
  const popular = await run({ space, counts: { link: 100, child: 1 }, rules: {
    link: { refs: { subject: { usage: { "parent:a": 1000 }, skew: 1 } } },
    child: { refs: { parent: { usage: { "parent:a": 1000 }, skew: -2 } } },
  } });
  assert(popular.usage["link.subject"]["parent:a"] > 1090);
  assert.equal(popular.rows.find(row => row.table === "child").content.parent.toString(), "parent:b");
  assert.equal(popular.usage["child.parent"]["parent:a"], 1000);
  const inferred = await run({ space, counts: { link: 0 } });
  assert.deepEqual(inferred.usage["link.subject"], { "parent:a": 1 });
});

test("saved scalar references drive usage and the next parent selection", async () => {
  const observed = {};
  const result = await run({ space: [{ id: "parent:a" }, { id: "parent:b" }], counts: { child: 2 }, rules: {
    child: { refs: { parent: { skew: -1, weight: (parent, { index, uses }) => {
      if (index === 0) return Number(parent.id === "parent:a");
      observed[parent.id] = uses;
      return Number(uses === 0);
    } } } },
  }, apply: async (row, { index }) => ({ ...await accept(row),
    parent: index === 0 ? new RecordId("parent", "b") : row.content.parent,
  }) });
  assert.deepEqual(observed, { "parent:a": 0, "parent:b": 1 });
  assert.deepEqual(result.rows.map(row => String(row.content.parent)), ["parent:a", "parent:a"]);
  assert.deepEqual(result.created.map(row => String(row.parent)), ["parent:b", "parent:a"]);
  assert.deepEqual(result.space.child.map(row => row.parent), ["parent:b", "parent:a"]);
  assert.deepEqual(result.usage["child.parent"], { "parent:b": 1, "parent:a": 1 });
});

test("saved polymorphic arrays count each parent once without revalidating input-only uniqueness", async () => {
  const result = await run({ space: ["parent:a", "parent:b", "tag:c"].map(id => ({ id })), counts: { peers: 1 },
    rules: { peers: { values: { members: ["parent:a", "tag:c"] } } },
    apply: async row => ({ ...await accept(row), members: [new RecordId("parent", "b"), new RecordId("parent", "b")] }),
  });
  assert.deepEqual(result.usage["peers.members"], { "parent:b": 1 });
  assert.deepEqual(result.space.peers[0].members, ["parent:b", "parent:b"]);
});

test("saving can add or remove optional references", async t => {
  for (const remove of [false, true]) await t.test(remove ? "removed" : "added", async () => {
    const result = await run({ space: [{ id: "optional_node:seed" }], counts: { optional_node: 1 },
      rules: { optional_node: { values: remove ? { parent: "optional_node:seed" } : {} } },
      apply: async row => remove ? { id: row.id } : { id: row.id, parent: new RecordId("optional_node", "seed") },
    });
    assert.deepEqual(result.usage["optional_node.parent"], remove ? {} : { "optional_node:seed": 1 });
    assert.equal(result.space.optional_node[1].parent, remove ? undefined : "optional_node:seed");
  });
});

const nestedModel = createModel({ schema: `
  DEFINE TABLE parent SCHEMAFULL;
  DEFINE TABLE nested SCHEMAFULL;
  DEFINE FIELD details ON nested TYPE object;
  DEFINE FIELD details.parent ON nested TYPE record<parent>;
  DEFINE FIELD details.derived ON nested TYPE record<parent> VALUE parent:outside;
  DEFINE FIELD details.generated ON nested TYPE object VALUE { parent: parent:outside };
  DEFINE FIELD details.generated.parent ON nested TYPE record<parent>;
  DEFINE FIELD items ON nested TYPE array<object>;
  DEFINE FIELD items.*.parent ON nested TYPE record<parent>;
  DEFINE FIELD items.*.derived ON nested TYPE record<parent> VALUE parent:outside;
  DEFINE FIELD derived ON nested TYPE record<parent> VALUE parent:outside;
`, schemas: { parent: object({}), nested: object({
  details: object({ parent: { type: "string", pattern: "^parent:a$" } }),
  items: { type: "array", items: object({ parent: string }) },
}) } });

test("saved nested references allow normalization and ignore protected outputs and their descendants", async () => {
  const details = Object.freeze({ parent: new RecordId("parent", "b"), derived: new RecordId("parent", "outside"),
    generated: Object.freeze({ parent: new RecordId("parent", "outside") }) });
  const items = Object.freeze([Object.freeze({ parent: new RecordId("parent", "b"), derived: new RecordId("parent", "outside") })]);
  const result = await run({ model: nestedModel, space: [{ id: "parent:a" }, { id: "parent:b" }], counts: { nested: 1 },
    rules: { nested: { values: { details: { parent: "parent:a" }, items: [{ parent: "parent:a" }] } } },
    apply: async row => Object.freeze({ id: row.id, details, items, derived: new RecordId("parent", "outside") }),
  });
  assert.equal(result.space.nested[0].details.parent, "parent:b");
  assert.equal(result.space.nested[0].items[0].parent, "parent:b");
  assert.strictEqual(result.created[0].details, details);
  assert.strictEqual(result.created[0].items, items);
});

test("saved references cannot escape the pool through scalar, array, optional, or nested fields", async t => {
  const cases = [
    { table: "child", values: { parent: "parent:a" }, saved: { parent: new RecordId("parent", "outside") }, path: "parent" },
    { table: "peers", values: { members: ["parent:a", "parent:b"] }, saved: { members: [new RecordId("parent", "a"), new RecordId("tag", "outside")] }, path: "members.1" },
    { table: "optional_node", values: {}, saved: { parent: new RecordId("optional_node", "outside") }, path: "parent" },
    { table: "nested", values: { details: { parent: "parent:a" }, items: [] },
      saved: { details: { parent: new RecordId("parent", "outside") }, items: [] }, path: "details.parent" },
    { table: "nested", values: { details: { parent: "parent:a" }, items: [{ parent: "parent:a" }] },
      saved: { details: { parent: new RecordId("parent", "a") }, items: [{ parent: new RecordId("parent", "outside") }] }, path: "items.0.parent" },
  ];
  for (const { table, values, saved, path } of cases) await t.test(`${table}.${path}`, async () => {
    let calls = 0, context;
    await assert.rejects(run({ model: table === "nested" ? nestedModel : model,
      space: [{ id: "parent:a" }, { id: "parent:b" }], counts: { [table]: 2 }, rules: { [table]: { values } },
      apply: async (row, ctx) => { calls++; context = ctx; return { ...await accept(row), ...saved }; },
    }), error => {
      assert.match(error.message, /outside the supplied space or accepted rows/);
      assert(error.message.includes(path), error.message);
      assert.equal(error.sequence, 0);
      return true;
    });
    assert.equal(calls, 1, "a bad saved reference must abort before the next apply");
    assert.deepEqual(context.space[table], [], "reject before publishing the saved record");
    assert.equal(context.remaining[table], 2);
  });
});

test("compatibility follows declared field dependencies even when names have the opposite order", async () => {
  const space = [
    { id: "group:a" }, { id: "group:b" },
    { id: "account:a", group: "group:a" }, { id: "account:b", group: "group:b" },
  ];
  const result = await run({ space, counts: { pair: 30 }, rules: { pair: { refs: {
    a_account: { after: ["z_group"], weight: (account, { parents }) => Number(account.group === parents.z_group.id) },
  } } } });
  for (const row of result.rows) {
    const account = space.find(record => record.id === String(row.content.a_account));
    assert.equal(account.group, String(row.content.z_group));
  }
  await assert.rejects(run({ space, counts: { pair: 1 }, rules: { pair: { refs: {
    a_account: { after: ["z_group"] }, z_group: { after: ["a_account"] },
  } } } }), /Cyclic reference selection/);
});

test("declines preserve indices and quotas, and other accepted rows re-enable stalled choices", async () => {
  let declined = 0;
  const result = await run({ seed: "defer", maxAttempts: 2, counts: { tag: 1, parent: 1 }, rules: {
    tag: { priority: 1e12, values: ({ index, sequence, remaining, space }) => {
      assert.equal(index, 0); assert.equal(remaining.tag, 1);
      if (!space.parent.length) { declined++; assert.equal(sequence, 0); return null; }
      return { name: space.parent[0].name };
    } },
  } });
  assert.equal(declined, 2);
  assert.deepEqual(result.rows.map(row => row.table), ["parent", "tag"]);
  assert.equal(result.attempts, 4);
  await assert.rejects(run({ counts: { tag: 1 }, maxAttempts: 3, rules: { tag: { values: () => null } } }), error => {
    assert.equal(error.attempts, 3); assert.equal(error.completed, 0);
    assert.match(error.blocked[0].reasons[0], /values declined/); return true;
  });
});

test("pinned references can wait for generated parents and manual references still enforce space membership", async () => {
  const result = await run({ counts: { child: 2, parent: 1 }, rules: {
    parent: { id: "parent:pinned" }, child: { values: { parent: "parent:pinned" } },
  } });
  assert(result.rows.filter(row => row.table === "child").every(row => String(row.content.parent) === "parent:pinned"));
  const options = { counts: { child: 1 }, space: [{ id: "parent:known" }], rules: { child: {
    refs: { parent: false }, values: () => ({ parent: "parent:known" }),
  } } };
  assert.equal((await run(options)).rows.length, 1);
  await assert.rejects(run({ ...options, space: [] }), /outside the supplied space/);
  await assert.rejects(run({ counts: { child: 1 }, space: options.space,
    rules: { child: { values: () => ({ parent: "parent:different" }) } } }), /values replaced selected reference/);
});

test("selected parents are refreshed before values, through native identities, without mutating supplied input", async () => {
  const supplied = [{ id: "ledger:one", used: 0 }], observed = [];
  let used = 0;
  const result = await run({ space: supplied, counts: { entry: 3 },
    read: async ids => { assert(ids.every(id => id instanceof RecordId)); return [{ id: ids[0], used }]; },
    rules: { entry: { values: ({ parents }) => { observed.push(parents.ledger.used); return { ordinal: parents.ledger.used }; } } },
    apply: async row => { assert.equal(row.content.ordinal, used); used++; return accept(row); },
  });
  assert.deepEqual(observed, [0, 1, 2]);
  assert.deepEqual(supplied, [{ id: "ledger:one", used: 0 }]);
  assert.equal(result.space.ledger[0].used, 2, "returned space is the latest read snapshot, not a final aggregate query");
  for (const fresh of [[], [{ id: "ledger:wrong" }], [{ id: "ledger:one" }, { id: "ledger:one" }]]) {
    await assert.rejects(run({ space: supplied, counts: { entry: 1 }, read: async () => fresh,
      apply: () => assert.fail("invalid parent reads must fail before applying") }), /read (did not return|returned)/);
  }
});

test("invalid declarations and fatal errors are not retried", async () => {
  const invalid = [
    { counts: { missing: 1 } }, { counts: { tag: -1 } }, { counts: { tag: 1.5 } },
    { counts: { tag: 1 }, rules: { tag: { priorty: 3 } } },
    { counts: { child: 1 }, rules: { child: { refs: { name: {} } } } },
    { counts: { child: 1 }, rules: { child: { refs: { parent: { bias: { tag: 1 } } } } } },
    { counts: { child: 1 }, rules: { child: { refs: { parent: { offset: 0 } } } } },
  ];
  for (const options of invalid) await assert.rejects(run({ ...options, apply: () => assert.fail("invalid declarations must not write") }));
  let calls = 0;
  await assert.rejects(run({ counts: { tag: 2 }, rules: { tag: { values: () => { calls++; throw new Error("bad formula"); } } } }), /tag\[0\].*bad formula/);
  assert.equal(calls, 1);
  await assert.rejects(run({ counts: { tag: 1 }, rules: { tag: { priority: 0 } } }), { code: "FIXTURE_STALLED" });
  await assert.rejects(run({ counts: { tag: 1 }, apply: () => ({ id: "tag:wrong" }) }), /apply did not accept/);
  await assert.rejects(run({ counts: { tag: 1 }, assert: () => false }), /global assertion returned false/);
});

function database({ failAt } = {}) {
  const events = [], pending = [], committed = [];
  let used = 0;
  const transaction = {
    async query(sql, bindings) {
      if (sql.startsWith("SELECT")) { events.push(`read:${used}`); return [[{ id: new RecordId("ledger", "one"), used }]]; }
      if (pending.length === failAt) throw new Error("native guard rejected");
      const row = { ...bindings.content0, id: bindings.id0 };
      assert.equal(row.ordinal, used);
      pending.push(row); used++; events.push("write");
      return [[row]];
    },
    async commit() { events.push("commit"); committed.push(...pending.splice(0)); },
    async cancel() { events.push("cancel"); pending.length = 0; used = 0; },
  };
  return { transaction, events, pending, committed,
    db: { async beginTransaction() { events.push("begin"); return transaction; } } };
}

test("native population alternates reads and writes in one transaction, and cancels errors or stalls", async () => {
  for (const failure of [undefined, "native", "stalled", "assert"]) {
    const fake = database({ failAt: failure === "native" ? 2 : undefined });
    const options = { model, counts: { entry: 3 }, maxAttempts: 2,
      space: async tx => { assert.strictEqual(tx, fake.transaction); return [{ id: "ledger:one" }]; },
      rules: { entry: { values: ({ transaction, parents }) => {
        assert.strictEqual(transaction, fake.transaction);
        return failure === "stalled" && parents.ledger.used === 2 ? null : { ordinal: parents.ledger.used };
      } } }, assert: (result, { transaction }) => {
        assert.strictEqual(transaction, fake.transaction);
        assert.equal(result.created.length, 3);
        return failure !== "assert";
      },
    };
    if (failure) {
      await assert.rejects(populate(fake.db, options), /native guard rejected|generation stalled|global assertion/);
      assert.deepEqual(fake.committed, []); assert.deepEqual(fake.pending, []);
      assert.equal(fake.events.at(-1), "cancel");
    } else {
      assert.equal((await populate(fake.db, options)).created.length, 3);
      assert.deepEqual(fake.events, ["begin", "read:0", "write", "read:1", "write", "read:2", "write", "commit"]);
    }
  }
  const fake = database();
  await assert.rejects(populate(fake.db, { counts: {}, recipe: [] }), /either counts.*or recipe/);
  assert.deepEqual(fake.events, []);
});
