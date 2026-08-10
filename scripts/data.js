const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { faker } = require("@faker-js/faker");
const jsf = require("json-schema-faker");
const seedrandom = require("seedrandom");
const { DateTime, Decimal, RecordId, Uuid } = require("surrealdb");

function parsePath(value) {
  if (typeof value !== "string" || !value.trim())
    throw new Error("Path must be a non-empty string");
  return value.split(".").map((part) => ({
    key: part.replace(/\[\]$/, ""),
    array: part.endsWith("[]"),
  }));
}

function splitDatasetPath(value) {
  const [dataset, ...tokens] = parsePath(value);
  if (!dataset?.key || dataset.array || !tokens.length)
    throw new Error(`Path must include a dataset and field: ${value}`);
  return { dataset: dataset.key, tokens };
}

function flatten(values) {
  return values
    .flat(Infinity)
    .filter((value) => value !== undefined && value !== null);
}

function getValues(value, tokens) {
  if (!tokens.length) return flatten([value]);
  if (Array.isArray(value))
    return flatten(value.map((item) => getValues(item, tokens)));
  if (!value || typeof value !== "object") return [];
  const [token, ...rest] = tokens;
  const next = value[token.key];
  if (token.array)
    return Array.isArray(next)
      ? flatten(next.map((item) => getValues(item, rest)))
      : [];
  return getValues(next, rest);
}

const configSchema = {
  type: "object",
  required: ["datasets"],
  properties: {
    seed: { anyOf: [{ type: "string" }, { type: "number" }] },
    cwd: { type: "string" },
    anchors: {
      type: "object",
      additionalProperties: {
        type: "array",
        items: { type: "string", minLength: 3 },
        uniqueItems: true,
      },
    },
    datasets: {
      type: "object",
      minProperties: 1,
      additionalProperties: {
        type: "object",
        required: ["schema", "count"],
        properties: {
          schema: { anyOf: [{ type: "string" }, { type: "object" }] },
          count: {
            anyOf: [
              { type: "integer", minimum: 0 },
              {
                type: "array",
                items: { type: "integer", minimum: 0 },
                minItems: 2,
                maxItems: 2,
              },
            ],
          },
          omit: {
            type: "array",
            items: { type: "string", minLength: 1 },
            uniqueItems: true,
          },
          batchSize: { type: "integer", minimum: 1 },
          unique: {
            type: "array",
            items: { type: "string", minLength: 1 },
            uniqueItems: true,
          },
        },
        additionalProperties: false,
      },
    },
    relations: {
      type: "array",
      items: {
        type: "object",
        required: ["from", "to"],
        properties: {
          from: { type: "string" },
          to: { type: "string" },
          cardinality: {
            anyOf: [
              { type: "integer", minimum: 0 },
              {
                type: "object",
                required: ["min", "max"],
                properties: {
                  min: { type: "integer", minimum: 0 },
                  max: { type: "integer", minimum: 0 },
                },
                additionalProperties: false,
              },
            ],
          },
          strictCardinality: { type: "boolean" },
        },
        additionalProperties: false,
      },
    },
    casts: { type: "array" },
  },
  additionalProperties: false,
};

function createAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv;
}

function formatErrors(errors) {
  return (errors || [])
    .map((error) => `${error.instancePath || "/"} ${error.message}`)
    .join("; ");
}

function validateConfig(config) {
  const validate = createAjv().compile(configSchema);
  if (!validate(config))
    throw new Error(
      `Invalid test-data config: ${formatErrors(validate.errors)}`,
    );
  for (const [name, dataset] of Object.entries(config.datasets)) {
    if (Array.isArray(dataset.count) && dataset.count[0] > dataset.count[1]) {
      throw new Error(`Invalid count range for dataset ${name}`);
    }
  }
}

function seedNumber(seed) {
  let hash = 2166136261;
  for (const character of String(seed)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function randomInt(random, min, max) {
  return min + Math.floor(random() * (max - min + 1));
}

function countFor(value, random) {
  return Array.isArray(value) ? randomInt(random, value[0], value[1]) : value;
}

function loadSchema(schema, cwd) {
  if (typeof schema !== "string") return schema;
  const schemaPath = path.resolve(cwd, schema);
  return JSON.parse(fs.readFileSync(schemaPath, "utf8"));
}

function removeSchemaPath(schema, tokens) {
  if (!tokens.length || !schema || typeof schema !== "object") return;
  if (schema.type === "array" && schema.items) {
    removeSchemaPath(schema.items, tokens);
    return;
  }
  if (!schema.properties) return;
  const [token, ...rest] = tokens;
  if (!Object.prototype.hasOwnProperty.call(schema.properties, token.key))
    return;
  if (!rest.length) {
    delete schema.properties[token.key];
    if (Array.isArray(schema.required)) {
      schema.required = schema.required.filter((name) => name !== token.key);
    }
    return;
  }
  removeSchemaPath(schema.properties[token.key], rest);
}

function payloadSchema(schema, omit = []) {
  const projected = structuredClone(schema);
  for (const pathValue of omit)
    removeSchemaPath(projected, parsePath(pathValue));
  return projected;
}

function relationTargetPaths(config) {
  return (config.relations || []).map((relation) => relation.to);
}

function payloadOmissions(config, dataset, omit = {}) {
  return [
    "id",
    ...relationTargetPaths(config)
      .map((value) => splitDatasetPath(value))
      .filter((value) => value.dataset === dataset)
      .map((value) =>
        value.tokens
          .map((token) => `${token.key}${token.array ? "[]" : ""}`)
          .join("."),
      ),
    ...(config.datasets[dataset].omit || []),
    ...(Array.isArray(omit[dataset]) ? omit[dataset] : []),
  ];
}

function generateData({ config, cwd, seed, counts = {}, omit = {} }) {
  validateConfig(config);
  const resolvedSeed = seed ?? config.seed ?? "rebase-test-data";
  const random = seedrandom(String(resolvedSeed));
  faker.seed(seedNumber(resolvedSeed));
  jsf.extend("faker", () => faker);
  jsf.option({
    random,
    alwaysFakeOptionals: true,
    useDefaultValue: true,
    failOnInvalidTypes: true,
  });
  const baseCwd = path.resolve(cwd || config.cwd || process.cwd());
  const data = {};
  for (const [name, definition] of Object.entries(config.datasets)) {
    const schema = payloadSchema(
      loadSchema(definition.schema, baseCwd),
      payloadOmissions(config, name, omit),
    );
    const requested = counts[name] ?? definition.count;
    const count = countFor(requested, random);
    const unique = (definition.unique || []).map((value) => ({
      path: value,
      tokens: parsePath(value),
      seen: new Set(),
    }));
    data[name] = Array.from({ length: count }, (_, index) => {
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const record = jsf.generate(schema);
        const signatures = unique.map((rule) => {
          const values = getValues(record, rule.tokens);
          return values.length ? JSON.stringify(values) : null;
        });
        if (
          signatures.every(
            (signature, uniqueIndex) =>
              signature == null || !unique[uniqueIndex].seen.has(signature),
          )
        ) {
          signatures.forEach((signature, uniqueIndex) => {
            if (signature != null) unique[uniqueIndex].seen.add(signature);
          });
          return record;
        }
      }
      throw new Error(
        `Unable to generate unique values for dataset ${name}[${index}]`,
      );
    });
  }
  return data;
}

function validateData({ data, config, cwd, omit = {} }) {
  validateConfig(config);
  const baseCwd = path.resolve(cwd || config.cwd || process.cwd());
  const ajv = createAjv();
  for (const [name, definition] of Object.entries(config.datasets)) {
    if (!Array.isArray(data[name]))
      throw new Error(`Payload dataset is missing array: ${name}`);
    const schema = payloadSchema(
      loadSchema(definition.schema, baseCwd),
      payloadOmissions(config, name, omit),
    );
    const check = ajv.compile(schema);
    data[name].forEach((record, index) => {
      if (!check(record))
        throw new Error(
          `Payload ${name}[${index}] failed schema validation: ${formatErrors(check.errors)}`,
        );
    });
  }
  return true;
}

function mapAtPath(value, tokens, convert, targetPath) {
  if (!tokens.length) return value == null ? value : convert(value);
  if (Array.isArray(value))
    return value.map((item) => mapAtPath(item, tokens, convert, targetPath));
  if (!value || typeof value !== "object") return value;
  const [token, ...rest] = tokens;
  if (!(token.key in value)) return value;
  const copy = { ...value };
  if (token.array) {
    if (Array.isArray(copy[token.key])) {
      copy[token.key] = copy[token.key].map((item) =>
        mapAtPath(item, rest, convert, targetPath),
      );
    }
  } else {
    copy[token.key] = mapAtPath(copy[token.key], rest, convert, targetPath);
  }
  return copy;
}

const casters = {
  record(value) {
    if (value instanceof RecordId) return value;
    if (typeof value !== "string" || !value.includes(":"))
      throw new Error(`Invalid record value: ${value}`);
    const separator = value.indexOf(":");
    return new RecordId(value.slice(0, separator), value.slice(separator + 1));
  },
  datetime(value) {
    if (value instanceof DateTime) return value;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.valueOf()))
      throw new Error(`Invalid datetime value: ${value}`);
    return new DateTime(date);
  },
  decimal(value) {
    if (value instanceof Decimal) return value;
    return new Decimal(value);
  },
  uuid(value) {
    if (value instanceof Uuid) return value;
    if (typeof value !== "string")
      throw new Error(`Invalid UUID value: ${value}`);
    return new Uuid(value);
  },
};

function castData({ data, rules = [] }) {
  return rules.reduce((result, rule) => {
    if (!rule || typeof rule.path !== "string")
      throw new Error("Casting rule requires a path");
    const convert = casters[rule.type];
    if (!convert)
      throw new Error(`Unsupported SurrealDB cast type: ${rule.type}`);
    return mapAtPath(result, parsePath(rule.path), convert, rule.path);
  }, data);
}

module.exports = {
  generateData,
  validateData,
  castData,
};
