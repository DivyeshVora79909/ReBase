#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { faker } = require("@faker-js/faker");
const jsf = require("json-schema-faker");
const seedrandom = require("seedrandom");
const { RecordId, Uuid } = require("surrealdb");
const { connectDatabase } = require("../gateway/connection");
const { queryResult } = require("../gateway/utils");
const { parseSchema } = require("../src/schema");
const {
  assertConnectionConfiguration,
  loadEnvironment,
  resolveConfiguration,
} = require("../config/environment");

function seedNumber(seed) {
  return crypto
    .createHash("sha256")
    .update(String(seed))
    .digest()
    .readUInt32BE(0);
}

function identifier(value, label) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return value;
}

function recordId(value) {
  const text = String(value);
  const separator = text.indexOf(":");
  if (separator < 1) throw new Error(`Invalid record id: ${text}`);
  const id = text.slice(separator + 1);
  const uuidText = /[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i.exec(id)?.[0];
  return new RecordId(text.slice(0, separator), uuidText ? new Uuid(uuidText) : id);
}

function nativeRecords(value, field, property = {}) {
  if (value == null) return value;
  if (field?.recordType?.targets?.length) {
    return field.recordType.isArray ? value.map(recordId) : recordId(value);
  }
  if (property.format === "date-time" && typeof value === "string")
    return new Date(value);
  if (Array.isArray(value))
    return value.map((item) => nativeRecords(item, null, property.items || {}));
  if (typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([name, item]) => [
      name,
      nativeRecords(item, null, property.properties?.[name] || {}),
    ]),
  );
}

class Reservoir {
  constructor(limit, random) {
    this.limit = limit;
    this.random = random;
    this.seen = 0;
    this.values = [];
  }

  add(value) {
    const text = String(value);
    this.seen += 1;
    if (this.values.includes(text)) return;
    if (this.values.length < this.limit) this.values.push(text);
    else {
      const index = Math.floor(this.random() * this.seen);
      if (index < this.limit) this.values[index] = text;
    }
  }

  sample(count = 1) {
    const available = [...this.values];
    const selected = [];
    while (available.length && selected.length < count) {
      selected.push(
        available.splice(Math.floor(this.random() * available.length), 1)[0],
      );
    }
    return selected;
  }
}

function parseArgs(argv) {
  const options = {
    project: "test",
    table: "all",
    count: 25,
    batchSize: 100,
    reservoirSize: 2000,
    pageSize: 500,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const next = () => {
      index += 1;
      if (argv[index] === undefined)
        throw new Error(`Missing value for ${option}`);
      return argv[index];
    };
    if (option === "--project") options.project = next();
    else if (option === "--source") options.sourceDir = next();
    else if (option === "--build") options.buildDir = next();
    else if (option === "--endpoint") options.endpoint = next();
    else if (option === "--namespace" || option === "--ns") options.namespace = next();
    else if (option === "--database" || option === "--db") options.database = next();
    else if (option === "--table") options.table = next();
    else if (option === "--count") options.count = Number(next());
    else if (option === "--batch-size") options.batchSize = Number(next());
    else if (option === "--reservoir-size")
      options.reservoirSize = Number(next());
    else if (option === "--page-size") options.pageSize = Number(next());
    else if (option === "--seed") options.seed = next();
    else if (option === "--help" || option === "-h") options.help = true;
    else throw new Error(`Unknown option: ${option}`);
  }
  for (const [name, value] of Object.entries({
    count: options.count,
    batchSize: options.batchSize,
    reservoirSize: options.reservoirSize,
    pageSize: options.pageSize,
  })) {
    if (!Number.isInteger(value) || value < 1)
      throw new Error(`${name} must be a positive integer`);
  }
  return options;
}

function usage() {
  console.log(`Usage: node dev-tools/populate.js [options]

Options:
  --env-file <path>          Load connection values from an environment profile
  --project <name|dir>       Design name or directory (default: test)
  --source <directory>       Explicit design source directory
  --build <directory>        Explicit compiled artifact directory
  --endpoint <url>           SurrealDB WebSocket endpoint
  --namespace <name>         Override profile namespace
  --database <name>          Override profile database
  --table <name|all>        Populate one table or every data schema
  --count <n>               Records per table (default: 25)
  --batch-size <n>          Insert batch size (default: 100)
  --reservoir-size <n>      Maximum sampled IDs per table (default: 2000)
  --page-size <n>           Keyset page size (default: 500)
  --seed <value>            Replay seed (random by default)`);
}

function projectPaths(project, overrides = {}) {
  const sourceDir = path.resolve(
    overrides.sourceDir ||
      (project.includes(path.sep) ? project : path.join("designs", project)),
  );
  const name = path.basename(sourceDir);
  return {
    sourceDir,
    buildDir: path.resolve(overrides.buildDir || path.join("build", name)),
    name,
  };
}

function loadDataSchemas(sourceDir) {
  const directory = path.join(sourceDir, "data");
  if (!fs.existsSync(directory)) return new Map();
  return new Map(
    fs
      .readdirSync(directory)
      .filter((name) => name.endsWith(".schema.json"))
      .sort()
      .map((name) => [
        name.slice(0, -".schema.json".length),
        JSON.parse(fs.readFileSync(path.join(directory, name), "utf8")),
      ]),
  );
}

async function loadReservoir(db, table, reservoir, pageSize) {
  let after;
  for (;;) {
    const rows =
      queryResult(
        await db.query(
          `SELECT VALUE <string>id FROM ${identifier(table, "table")} WHERE $after = NONE OR <string>id > $after ORDER BY id LIMIT $limit;`,
          { after, limit: pageSize },
        ),
      ) || [];
    for (const id of rows) reservoir.add(id);
    if (rows.length < pageSize) break;
    after = String(rows.at(-1));
  }
}

function generationSchema(schema, table, tableDefinition, pools, random, principals) {
  const generated = structuredClone(schema);
  generated.properties ||= {};
  const required = new Set(generated.required || []);
  const blocked = [];
  for (const [name, property] of Object.entries(generated.properties)) {
    const field = tableDefinition.fields.get(name);
    if (name === "id") continue;
    if (
      /PERMISSIONS[\s\S]*FOR\s+create\s*,\s*update\s+NONE/i.test(
        field?.definition || "",
      )
    ) {
      delete generated.properties[name];
      required.delete(name);
      continue;
    }
    if (name === "owned_by") {
      const owners = [
        ...(pools.get(principals.user)?.values || []),
        ...(pools.get(principals.group)?.values || []),
      ];
      if (!owners.length) blocked.push(`${table}.owned_by`);
      else {
        property.enum = owners;
        delete property.pattern;
        delete property.faker;
      }
      continue;
    }
    if (!field?.recordType?.targets?.length) continue;
    const candidates = field.recordType.targets.flatMap(
      (target) => pools.get(target)?.values || [],
    );
    if (field.recordType.isArray) {
      const minimum = property.minItems || 0;
      if (candidates.length < minimum) blocked.push(`${table}.${name}`);
      property.items = { ...(property.items || {}), enum: candidates };
      delete property.items.pattern;
      delete property.items.faker;
      property.maxItems = Math.min(
        property.maxItems || Math.min(8, candidates.length),
        candidates.length,
      );
      if (!property.maxItems) {
        property.maxItems = 0;
        property.minItems = 0;
      }
    } else if (candidates.length) {
      property.enum = candidates;
      delete property.pattern;
      delete property.faker;
    } else if (required.has(name)) {
      blocked.push(`${table}.${name}`);
    } else {
      delete generated.properties[name];
    }
  }
  if (table === principals.group || table === principals.user) {
    const parents = [
      ...(pools.get(principals.group)?.values || []),
      ...(pools.get(principals.user)?.values || []),
    ];
    if (!parents.length) blocked.push(`${table}.parents`);
    else
      generated.properties.parents = {
        type: "array",
        minItems: 1,
        maxItems: 5,
        uniqueItems: true,
        items: { enum: parents },
      };
  }
  generated.required = [...required];
  return { blocked, schema: generated, random };
}

function rowGenerationSchema(schema, random) {
  const generated = structuredClone(schema);
  const required = new Set(generated.required || []);
  for (const [name, property] of Object.entries(generated.properties || {})) {
    const probability = Number(property["x-rebase-optional-probability"]);
    delete property["x-rebase-optional-probability"];
    if (required.has(name) || !Number.isFinite(probability)) continue;
    if (probability < 0 || probability > 1) {
      throw new Error(`Optional probability for ${name} must be between 0 and 1`);
    }
    if (random() < probability) required.add(name);
    else delete generated.properties[name];
  }
  generated.required = [...required];
  return generated;
}

async function populate(options) {
  options = {
    project: "test",
    table: "all",
    count: 25,
    batchSize: 100,
    reservoirSize: 2000,
    pageSize: 500,
    ...options,
  };
  const { sourceDir, buildDir, name } = projectPaths(options.project, options);
  const configuration = options.configuration || resolveConfiguration({}, options);
  options.endpoint ||= configuration.surreal.endpoint;
  options.username ||= configuration.surreal.username;
  options.password ||= configuration.surreal.password;
  options.connectTimeoutMs ||= configuration.surreal.connectTimeoutMs;
  options.namespace ||= configuration.surreal.defaultContext?.namespace;
  options.database ||= configuration.surreal.defaultContext?.database;
  assertConnectionConfiguration({
    ...configuration,
    surreal: {
      ...configuration.surreal,
      endpoint: options.endpoint,
      username: options.username,
      password: options.password,
      defaultContext: options.namespace && options.database
        ? { namespace: options.namespace, database: options.database }
        : undefined,
    },
  });
  const compiledPath = path.join(buildDir, "schema.surql");
  if (!fs.existsSync(compiledPath))
    throw new Error(`Compiled schema not found: ${compiledPath}`);
  const dataSchemas = loadDataSchemas(sourceDir);
  if (!dataSchemas.size)
    throw new Error(`No data schemas found in ${path.join(sourceDir, "data")}`);
  const parsed = parseSchema(fs.readFileSync(compiledPath, "utf8"), "");
  const principalEntries = [...parsed.tables.values()]
    .filter((table) => table.principalKind)
    .map((table) => [table.principalKind, table.name]);
  const principals = Object.fromEntries(principalEntries);
  if (!principals.user || !principals.group) {
    throw new Error("Compiled schema must mark one user and one group principal table");
  }
  let tables =
    options.table === "all"
      ? [...dataSchemas.keys()].filter((table) => parsed.tables.has(table))
      : [identifier(options.table, "table")];
  for (const table of tables) {
    if (!dataSchemas.has(table))
      throw new Error(`Data schema not found for table: ${table}`);
    if (!parsed.tables.has(table))
      throw new Error(`Compiled table not found: ${table}`);
  }
  tables.sort((left, right) => {
    const rank = (value) => (value === principals.group ? 0 : value === principals.user ? 1 : 2);
    return rank(left) - rank(right) || left.localeCompare(right);
  });

  const seed = String(options.seed || crypto.randomUUID());
  const random = seedrandom(seed);
  faker.seed(seedNumber(seed));
  jsf.extend("faker", () => faker);
  jsf.option({
    random,
    alwaysFakeOptionals: false,
    optionalsProbability: 0.65,
    useDefaultValue: false,
    failOnInvalidTypes: true,
  });
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const validators = new Map(
    [...dataSchemas].map(([table, schema]) => [table, ajv.compile(schema)]),
  );

  const connection = await connectDatabase({
    endpoint: options.endpoint,
    username: options.username,
    password: options.password,
    namespace: options.namespace,
    database: options.database,
    connectTimeoutMs: options.connectTimeoutMs,
  });
  const db = connection.db;
  try {
    const targetTables = new Set([principals.group, principals.user]);
    for (const table of tables) {
      for (const field of parsed.tables.get(table).fields.values()) {
        for (const target of field.recordType?.targets || [])
          targetTables.add(target);
      }
    }
    const pools = new Map(
      [...targetTables].map((table) => [
        table,
        new Reservoir(options.reservoirSize, random),
      ]),
    );
    for (const [table, reservoir] of pools)
      await loadReservoir(db, table, reservoir, options.pageSize);

    const remaining = new Map(tables.map((table) => [table, options.count]));
    const created = Object.fromEntries(tables.map((table) => [table, 0]));
    while ([...remaining.values()].some(Boolean)) {
      let progressed = false;
      const blockers = new Map();
      for (const table of tables) {
        const pending = remaining.get(table);
        if (!pending) continue;
        const definition = parsed.tables.get(table);
        const prepared = generationSchema(
          dataSchemas.get(table),
          table,
          definition,
          pools,
          random,
          principals,
        );
        if (prepared.blocked.length) {
          blockers.set(table, prepared.blocked);
          continue;
        }
        const size = Math.min(pending, options.batchSize);
        const rows = [];
        for (let index = 0; index < size; index += 1) {
          const document = jsf.generate(rowGenerationSchema(prepared.schema, random));
          if (!validators.get(table)(document)) {
            throw new Error(
              `Generated invalid ${table}: ${ajv.errorsText(validators.get(table).errors)}`,
            );
          }
          const data = Object.fromEntries(
            Object.entries(document)
              .filter(([name]) => name !== "id")
              .map(([name, value]) => [
                name,
                nativeRecords(
                  value,
                  definition.fields.get(name),
                  dataSchemas.get(table).properties?.[name] || {},
                ),
              ]),
          );
          rows.push({ data });
        }
        const transaction = await db.beginTransaction();
        try {
          const inserted = queryResult(await transaction.query(
            `INSERT INTO ${identifier(table, "table")} $rows RETURN AFTER;`,
            { rows: rows.map((row) => row.data) },
          ));
          if (!Array.isArray(inserted) || inserted.length !== rows.length) {
            throw new Error(`SurrealDB returned ${inserted?.length || 0} rows for ${rows.length} inserts`);
          }
          rows.forEach((row, index) => {
            row.idText = String(inserted[index].id);
            row.id = recordId(row.idText);
          });
          await transaction.commit();
        } catch (error) {
          await transaction.cancel().catch(() => {});
          throw new Error(
            `Unable to insert ${table} batch: ${error.message}`,
            { cause: error },
          );
        }
        for (const row of rows) pools.get(table)?.add(row.idText);
        remaining.set(table, pending - rows.length);
        created[table] += rows.length;
        progressed = true;
      }
      if (!progressed) {
        const detail = [...blockers]
          .map(([table, fields]) => `${table}: ${fields.join(", ")}`)
          .join("; ");
        throw new Error(
          `Population is blocked by missing required reference candidates: ${detail}`,
        );
      }
    }
    return { project: name, seed, created };
  } finally {
    await connection.close();
  }
}

if (require.main === module) {
  const loaded = loadEnvironment(process.argv.slice(2));
  const options = parseArgs(loaded.args);
  options.configuration = resolveConfiguration(loaded.values, options);
  if (options.help) usage();
  else
    populate(options)
      .then((result) => {
        console.log(`Replay seed: ${result.seed}`);
        for (const [table, count] of Object.entries(result.created))
          console.log(`${table}: ${count}`);
      })
      .catch((error) => {
        console.error(`Population failed: ${error.stack || error.message}`);
        process.exitCode = 1;
      });
}

module.exports = { populate };
