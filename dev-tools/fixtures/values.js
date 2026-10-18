"use strict";

const { createHash } = require("node:crypto");
const { RecordId, Decimal, Duration, Uuid, DateTime } = require("surrealdb");

const hash = value => createHash("sha256").update(value).digest();

// Recipes and validators see JSON; only the input model binds database values.
function json(value) {
  if (value instanceof DateTime || value instanceof Date) return value.toISOString();
  if (value instanceof RecordId || value instanceof Decimal || value instanceof Duration || value instanceof Uuid) return String(value);
  if (Array.isArray(value)) return value.map(json);
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new Error("Fixture values must be JSON objects or supported SDK values");
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, json(item)]));
  }
  return value;
}

async function createRandom(seed = 1) {
  if (typeof seed !== "string" && (typeof seed !== "number" || !Number.isFinite(seed))) throw new Error("seed must be a string or finite number");
  const { Faker, en } = require("@faker-js/faker");
  const numericSeed = hash(String(seed)).readUInt32BE();
  const faker = new Faker({ locale: [en] });
  faker.seed(numericSeed);
  faker.setDefaultRefDate("2020-01-01T00:00:00.000Z");
  const { createGenerator } = await import("json-schema-faker");
  const generator = createGenerator({ seed: numericSeed, optionalsProbability: 0, useDefaultValue: true });
  return { seed: String(seed), faker, generator };
}

async function generateInput(model, table, values, generator) {
  const entry = model.tables.get(table);
  const schema = structuredClone(entry.schema);
  schema.properties ||= {};
  const required = new Set(schema.required || []);
  for (const [name, field] of entry.fields) {
    if (!field.recordType || !Object.hasOwn(schema.properties, name) || Object.hasOwn(values, name)) continue;
    if (required.has(name)) throw new Error(`Required reference ${name} needs refs or values`);
    // Never fabricate a record ID from a schema pattern or default.
    schema.properties[name] = false;
  }
  for (const [path, field] of entry.nestedFields) {
    const root = path.split(".")[0];
    if (!field.recordType || !Object.hasOwn(schema.properties, root) || Object.hasOwn(values, root)) continue;
    if (required.has(root)) throw new Error(`Nested reference ${path} needs explicit values for ${root}`);
    schema.properties[root] = false;
  }
  for (const [name, value] of Object.entries(values)) {
    if (!Object.hasOwn(schema.properties, name)) throw new Error(`Unknown input field ${name}`);
    // Pin overrides before generation so JSON Schema conditionals see them.
    schema.properties[name] = { ...schema.properties[name], const: value };
    required.add(name);
  }
  schema.required = [...required];
  const document = { ...await generator.generate(schema), ...values };
  return { document, ...model.prepare(table, document) };
}

module.exports = { createRandom, generateInput, hash, json };
