"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { DateTime, Decimal, Duration, RecordId, Uuid } = require("surrealdb");
const { loadClientSchemas } = require("../client-schemas");
const { loadMaterials } = require("../compiler/materials");
const { parseSchema } = require("../compiler/schema");
const { generateBundle } = require("../compiler/pipeline");
const { createModel, recordId } = require("../fixtures/model");

function example(schema) {
  const properties = { ...schema.properties };
  const required = new Set(schema.required || []);
  for (const keyword of ["oneOf", "anyOf"]) {
    const first = schema[keyword]?.[0];
    Object.assign(properties, first?.properties);
    for (const name of first?.required || []) required.add(name);
  }
  return Object.fromEntries([...required].map(name => {
    const property = properties[name];
    let value;
    if (property.enum) value = property.enum[0];
    else if (property.format === "date-time") value = "2027-01-01T00:00:00Z";
    else if (property.pattern?.startsWith("^(?:")) value = `${property.pattern.slice(4).split(/[|)]/)[0]}:example`;
    else if (property.pattern?.includes("[0-9]")) value = "0.5";
    else if (property.type === "integer" || property.type === "number") value = property.minimum ?? 0;
    else if (property.type === "boolean") value = false;
    else if (property.type === "string") value = "example";
    else assert.fail(`Add an example for ${name}`);
    return [name, value];
  }));
}

function sampleModel() {
  const schema = parseSchema(`
    DEFINE TABLE fixture SCHEMAFULL;
    DEFINE FIELD title ON fixture TYPE string READONLY;
    DEFINE FIELD normalized ON fixture TYPE option<string> VALUE string::trim($value);
    DEFINE FIELD amount ON fixture TYPE decimal;
    DEFINE FIELD at ON fixture TYPE datetime;
    DEFINE FIELD delay ON fixture TYPE option<duration>;
    DEFINE FIELD token ON fixture TYPE option<uuid>;
    DEFINE FIELD owner ON fixture TYPE option<record<account>>;
    DEFINE FIELD refs ON fixture TYPE array<record<account | person>>;
    DEFINE FIELD decimals ON fixture TYPE option<array<decimal>>;
    DEFINE FIELD details ON fixture TYPE option<object> FLEXIBLE;
    DEFINE FIELD details.price ON fixture TYPE decimal;
    DEFINE FIELD details.owner ON fixture TYPE record<account>;
    DEFINE FIELD children ON fixture TYPE option<array<object>>;
    DEFINE FIELD children.*.owner ON fixture TYPE record<person>;
    DEFINE FIELD children.*.amount ON fixture TYPE decimal;
    DEFINE FIELD derived ON fixture TYPE int VALUE 1;
    DEFINE FIELD virtual ON fixture COMPUTED 1;
    DEFINE FIELD tree ON fixture TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
    DEFINE FIELD system ON fixture TYPE string COMMENT '@rebase-system';
    DEFINE FIELD denied ON fixture TYPE string PERMISSIONS FOR select FULL FOR create NONE FOR update FULL;
    DEFINE FIELD details.hidden ON fixture TYPE string VALUE 'hidden';
    DEFINE FIELD unsupported ON fixture TYPE option<bytes>;
  `, "");
  return createModel({ schema, schemas: { fixture: {
    type: "object", additionalProperties: true,
    properties: {
      title: { type: "string" }, amount: { type: "string" }, at: { type: "string" },
      delay: { type: "string" }, token: { type: "string" }, owner: { type: "string" },
      refs: { type: "array", items: { type: "string" } },
      decimals: { type: "array", items: { type: "string" } },
      details: { type: "object" }, children: { type: "array", items: { type: "object" } },
    }, required: ["title", "amount", "at", "refs"],
  } } });
}

const uuid = "123e4567-e89b-12d3-a456-426614174000";
const minimal = () => ({ title: "Fixture", amount: "1.01", at: "2027-01-01T00:00:00Z", refs: [] });

test("record identities canonicalize quote spellings and preserve key types", () => {
  assert.equal(String(recordId("account:`custom key`")), String(recordId("account:⟨custom key⟩")));
  assert.equal(recordId("account:⟨a\\⟩b⟩").id, "a⟩b");
  assert.equal(recordId("`table name`:`key`").table.name, "table name");
  assert.equal(recordId(`account:u'${uuid}'`).id instanceof Uuid, true);
  assert.equal(recordId(`account:u"${uuid}"`).id instanceof Uuid, true);
  assert.equal(recordId(`account:${uuid}`).id, uuid);
  assert.equal(recordId(`account:⟨${uuid}⟩`).id, uuid);
  assert.notEqual(String(recordId(`account:${uuid}`)), String(recordId(`account:u"${uuid}"`)));
  assert.equal(recordId("account:9223372036854775807").id, 9223372036854775807n);
  assert.equal(recordId("account:⟨123⟩").id, "123");
  const native = new RecordId("account", "key");
  assert.equal(recordId(native), native);
  for (const value of ["", "account:", "account:a trailing", "account:⟨key⟩trailing", "account:`unclosed", "account:u'bad'", "account:01", "account:[1,2]", "account:{a:1}", "account:9223372036854775808", "account:a:b", "account:⟨bad\\q⟩", null]) {
    assert.throws(() => recordId(value), /record id/i, String(value));
  }
});

test("model binds exact native values from compiled types, nested paths and arrays", () => {
  const model = sampleModel();
  const exact = "9007199254740993.1234567890123456789012345678";
  const document = { ...minimal(), amount: exact, delay: "1h2m3s4ns", token: uuid,
    owner: "account:⟨owner key⟩", refs: ["account:first", "person:second"], decimals: ["0.335", "-10.0001"],
    details: { price: "0.00000000000000000001", owner: "account:details" },
    children: [{ owner: "person:child", amount: "10.01" }],
  };
  const snapshot = structuredClone(document);
  assert.equal(model.validate("fixture", document), document);
  const bound = model.bind("fixture", document);
  assert.equal(bound.amount instanceof Decimal, true);
  assert.equal(String(bound.amount), exact);
  assert.equal(bound.at instanceof Date, true);
  assert.equal(bound.at.toISOString(), "2027-01-01T00:00:00.000Z");
  assert.equal(bound.delay instanceof Duration, true);
  assert.equal(bound.token instanceof Uuid, true);
  assert.equal(bound.owner instanceof RecordId, true);
  assert.equal(bound.refs.every(value => value instanceof RecordId), true);
  assert.equal(bound.decimals.every(value => value instanceof Decimal), true);
  assert.equal(bound.details.price instanceof Decimal, true);
  assert.equal(bound.details.owner instanceof RecordId, true);
  assert.equal(bound.children[0].owner instanceof RecordId, true);
  assert.equal(bound.children[0].amount instanceof Decimal, true);
  assert.deepEqual(document, snapshot);
  assert.deepEqual(model.references("fixture", document).map(({ path: p, value }) => [p, value]), [
    [["refs", 0], "account:first"], [["refs", 1], "person:second"], [["owner"], "account:⟨owner key⟩"],
    [["details", "owner"], "account:details"], [["children", 0, "owner"], "person:child"],
  ]);
  assert.equal(model.tables.get("fixture").fields.get("title").protected, false, "creation permits READONLY fields");
  assert.equal(model.tables.get("fixture").fields.get("amount").type, "decimal");
});

test("model protects managed fields even when the input schema allows extra properties", () => {
  const model = sampleModel();
  for (const name of ["derived", "virtual", "tree", "system", "denied"]) {
    assert.throws(() => model.validate("fixture", { ...minimal(), [name]: 1 }), /protected input field/, name);
  }
  assert.throws(() => model.bind("fixture", { ...minimal(), details: { hidden: "override" } }), /protected input field/);
  assert.throws(() => model.validate("fixture", { ...minimal(), surprise: true }), /unknown input field/);
  assert.throws(() => model.validate("missing", {}), /No fixture input schema/);
  assert.equal(model.bind("fixture", { ...minimal(), normalized: "  input  " }).normalized, "  input  ");
  const prepared = model.prepare("fixture", { ...minimal(), owner: "account:owner" });
  assert.equal(prepared.content.amount instanceof Decimal, true);
  assert.equal(prepared.references[0].value, "account:owner");
});

test("model rejects invalid native inputs and never truncates submillisecond timestamps", () => {
  const model = sampleModel();
  for (const changes of [
    { amount: 0.335 }, { amount: "NaN" }, { amount: "1e40" }, { amount: new Decimal("1") },
    { at: "2027-02-30T00:00:00Z" }, { at: "2027-01-01" }, { at: new Date() },
    { delay: "forever" }, { delay: "" }, { delay: "1.5h" }, { token: "bad-uuid" }, { owner: "person:wrong" },
    { refs: ["account:ok", "other:wrong"] }, { unsupported: "bytes" },
    { children: [{ amount: "bad" }] }, { at: "2027-01-01T00:00:00.1234567890Z" },
    { at: "2016-12-31T23:59:60Z" },
  ]) assert.throws(() => model.bind("fixture", { ...minimal(), ...changes }), undefined, JSON.stringify(changes));
  const nanos = model.bind("fixture", { ...minimal(), at: "2027-01-01T00:00:00.123456789Z" }).at;
  assert.equal(nanos instanceof DateTime, true);
  assert.equal(nanos.toISOString(), "2027-01-01T00:00:00.123456789Z");
  for (const at of ["2027-01-01t00:00:00.123456789z", "2027-01-01 00:00:00.123456789Z"]) {
    assert.equal(model.bind("fixture", { ...minimal(), at }).at.toISOString(), "2027-01-01T00:00:00.123456789Z");
  }
  assert.throws(() => model.bind("fixture", { ...minimal(), at: "2027-01-01T00:00:00.123456789+02:00" }), /requires UTC Z/);
  const cyclic = minimal(); cyclic.details = cyclic;
  assert.throws(() => model.validate("fixture", cyclic), /cyclic JSON/);
});

test("public catalog validators are reused and plain schema cross-references compile once", () => {
  const schema = parseSchema("DEFINE TABLE first; DEFINE FIELD amount ON first TYPE decimal; DEFINE TABLE second; DEFINE FIELD amount ON second TYPE decimal;", "");
  const first = { $id: "urn:test:decimal", type: "object", properties: { amount: { type: "string", pattern: "^[0-9]+$" } }, required: ["amount"], additionalProperties: false };
  const second = { $ref: "urn:test:decimal" };
  const model = createModel({ schema, schemas: { first, second } });
  const validator = model.tables.get("second").validator;
  assert.equal(String(model.bind("second", { amount: "9007199254740993" }).amount), "9007199254740993");
  assert.throws(() => model.bind("second", { amount: "invalid" }), /Invalid second input/);
  assert.equal(model.tables.get("second").validator, validator);
  assert.throws(() => createModel({ schema, schemas: { first: { type: "object", properties: { owned_by: { type: "string" } } } } }), /complete emitted compiler bundle/);
});

test("overlapping nested array metadata does not duplicate or corrupt references", () => {
  const schema = parseSchema("DEFINE TABLE sample; DEFINE FIELD refs ON sample TYPE array<record<account>>; DEFINE FIELD refs.* ON sample TYPE record<account>;", "");
  const model = createModel({ schema, schemas: { sample: { type: "object", properties: { refs: { type: "array", items: { type: "string" } } } } } });
  const input = { refs: ["account:first", "account:second"] };
  assert.equal(model.references("sample", input).length, 2);
  assert.equal(model.bind("sample", input).refs.every(id => id instanceof RecordId), true);
});

test("all accounting public fields bind according to compiler metadata", () => {
  const root = path.resolve(__dirname, "../..");
  const materials = loadMaterials({ groups: [
    { name: "framework", roots: [path.join(root, "framework")] },
    { name: "project", roots: [path.join(root, "designs/all-in-accounting")] },
  ] });
  const schema = generateBundle(materials);
  const catalog = loadClientSchemas(path.join(root, "designs/all-in-accounting/schemas"));
  const model = createModel({ schema, schemas: catalog });
  assert.equal(model.tables.size, 48);
  assert.equal(model.tables.get("currency").validator, catalog.schemas.get("currency").validate);
  let fieldsChecked = 0;
  for (const [name, entry] of catalog.schemas) {
    const document = example(entry.schema);
    // Exercise every public field, including optional accounting limits,
    // durations, READONLY references, and all exact decimal quantities.
    for (const [fieldName, property] of Object.entries(entry.schema.properties)) {
      if (fieldName in document) continue;
      document[fieldName] = /duration/.test(fieldName) ? "1h" : example({ properties: { [fieldName]: property }, required: [fieldName] })[fieldName];
    }
    const bound = model.bind(name, document);
    for (const [fieldName, value] of Object.entries(bound)) {
      const field = model.tables.get(name).fields.get(fieldName);
      assert.ok(field, `${name}.${fieldName} metadata`);
      assert.equal(field.protected, false, `${name}.${fieldName} public input`);
      const type = field.type.replace(/^option\s*</, "").replace(/>$/, "");
      if (field.recordType) assert.ok(value instanceof RecordId, `${name}.${fieldName} record`);
      else if (type === "decimal") {
        assert.ok(value instanceof Decimal, `${name}.${fieldName} decimal`);
        assert.equal(String(value), document[fieldName]);
      } else if (type === "datetime") assert.ok(value instanceof Date, `${name}.${fieldName} date`);
      else if (type === "duration") assert.ok(value instanceof Duration, `${name}.${fieldName} duration`);
      else assert.equal(value, document[fieldName], `${name}.${fieldName} scalar`);
      fieldsChecked += 1;
    }
    assert.equal(model.references(name, document).length, Object.keys(document).filter(key => model.tables.get(name).fields.get(key).recordType).length, `${name} actual references`);
  }
  assert.ok(fieldsChecked > 300, `${fieldsChecked} accounting fields checked`);
});
