"use strict";

const { RecordId } = require("surrealdb");
const { createModel, recordId } = require("./model");
const { withSolver } = require("./solver");
const { createRandom, generateInput, hash, json } = require("./values");
const { generate, FixtureStalledError } = require("./generate");

const own = (object, key) => Object.hasOwn(object, key);

function orderedSteps(recipe, space) {
  if (!Array.isArray(recipe)) throw new Error("recipe must be an array of named steps or a function returning one");
  const byName = new Map();
  for (const step of recipe) {
    if (!step || typeof step.name !== "string" || !step.name || byName.has(step.name) || own(space, step.name)) {
      throw new Error(`Fixture step needs a unique name separate from space pools: ${step?.name}`);
    }
    if (step.after !== undefined && (!Array.isArray(step.after) || step.after.some(name => typeof name !== "string"))) {
      throw new Error(`${step.name}.after must be an array of step names`);
    }
    if (step.refs !== undefined && (!step.refs || typeof step.refs !== "object" || Array.isArray(step.refs))) {
      throw new Error(`${step.name}.refs must map fields to pool names`);
    }
    byName.set(step.name, step);
  }
  const result = [], active = new Set(), done = new Set();
  function visit(name) {
    if (done.has(name)) return;
    if (active.has(name)) throw new Error(`Cyclic fixture prerequisites at ${name}; use existing records or an explicit staged scenario`);
    const step = byName.get(name);
    if (!step) throw new Error(`Unknown fixture prerequisite: ${name}`);
    active.add(name);
    for (const prerequisite of step.after || []) visit(prerequisite);
    for (const pool of Object.values(step.refs || {})) {
      if (typeof pool !== "string") throw new Error(`${name}.refs must contain pool names`);
      if (byName.has(pool)) visit(pool);
      else if (!own(space, pool)) throw new Error(`Unknown reference pool ${pool} in ${name}`);
    }
    active.delete(name); done.add(name); result.push(step);
  }
  for (const name of byName.keys()) visit(name);
  return result;
}

/** Offline, deterministic planning. No connections, reads, writes, or global RNG. */
async function plan({ model, seed = 1, space: suppliedSpace = {}, recipe, assert: assertPlan } = {}) {
  if (!model?.tables || typeof model.prepare !== "function") throw new Error("plan requires a fixture model from createModel");
  if (typeof seed !== "string" && (typeof seed !== "number" || !Number.isFinite(seed))) throw new Error("seed must be a string or finite number");
  if (!suppliedSpace || typeof suppliedSpace !== "object" || Array.isArray(suppliedSpace)) throw new Error("space must be an object of named record arrays");
  if (assertPlan !== undefined && typeof assertPlan !== "function") throw new Error("assert must be a function");
  const { seed: seedText, faker, generator } = await createRandom(seed);
  const space = Object.create(null), identities = new Set();
  for (const [name, pool] of Object.entries(suppliedSpace)) {
    if (!Array.isArray(pool)) throw new Error(`Space ${name} must be an array of records`);
    space[name] = pool.map(value => {
      if (!value || typeof value !== "object" || !value.id) throw new Error(`Space ${name} contains a record without id`);
      const row = json(value);
      row.id = String(recordId(row.id));
      identities.add(row.id);
      return row;
    });
  }
  const pick = candidates => {
    if (!Array.isArray(candidates) || !candidates.length) throw new Error("Cannot pick from an empty reference space");
    return faker.helpers.arrayElement(candidates);
  };
  const context = { seed: seedText, space, faker, pick };
  const steps = orderedSteps(typeof recipe === "function" ? await recipe(context) : recipe, space);
  const rows = [];
  for (const step of steps) {
    const entry = model.tables.get(step.table);
    if (!entry) throw new Error(`No fixture input schema for table ${step.table}`);
    const count = step.count ?? 1;
    if (!Number.isSafeInteger(count) || count < 0) throw new Error(`${step.name}.count must be a nonnegative safe integer`);
    space[step.name] = [];
    // Prerequisite pools are complete before a step starts. Filter each pool
    // once per field, rather than scanning it again for every generated row.
    const candidatePools = new Map();
    for (let index = 0; index < count; index++) {
      try {
        const rowContext = { ...context, index };
        const references = {};
        for (const [fieldName, poolName] of Object.entries(step.refs || {})) {
          const field = entry.fields.get(fieldName);
          if (!field?.recordType?.targets?.length) throw new Error(`${fieldName} is not a typed record reference`);
          if (!candidatePools.has(fieldName)) {
            candidatePools.set(fieldName, [...new Map(space[poolName]
              .filter(row => field.recordType.targets.includes(recordId(row.id).table.name))
              .map(row => [row.id, row])).values()]);
          }
          const candidates = candidatePools.get(fieldName);
          if (field.recordType.isArray) {
            const property = entry.schema.properties[fieldName];
            const min = property.minItems ?? 0, max = Math.min(property.maxItems ?? Math.max(min, 1), candidates.length);
            if (candidates.length < min) throw new Error(`${fieldName} needs ${min} distinct candidates in ${poolName}`);
            references[fieldName] = faker.helpers.arrayElements(candidates, { min, max }).map(row => row.id);
          } else references[fieldName] = pick(candidates).id;
        }
        const overrides = json(typeof step.values === "function" ? await step.values(rowContext) : step.values ?? {});
        if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) throw new Error("values must return an object");
        const values = { ...references, ...overrides };
        const prepared = await generateInput(model, step.table, values, generator);
        for (const ref of prepared.references) {
          if (!identities.has(ref.value)) throw new Error(`Reference ${ref.field}=${ref.value} is outside the supplied space or preceding steps`);
        }
        const key = typeof step.id === "function" ? await step.id(rowContext) : step.id;
        const id = key === undefined
          ? new RecordId(step.table, `fixture_${hash(`${seedText}:${step.name}:${index}`).toString("hex").slice(0, 24)}`)
          : recordId(key);
        if (id.table.name !== step.table) throw new Error(`Record id ${id} does not belong to ${step.table}`);
        if (identities.has(String(id))) throw new Error(`Duplicate fixture id ${id}`);
        rows.push({ table: step.table, id, content: prepared.content });
        space[step.name].push({ ...prepared.document, id: String(id) });
        identities.add(String(id));
      } catch (cause) {
        throw new Error(`Fixture ${step.name}[${index}] (${step.table}): ${cause.message}`, { cause });
      }
    }
  }
  const result = { seed: seedText, rows, space };
  if (assertPlan && await assertPlan(result) === false) throw new Error("Fixture global assertion returned false");
  return result;
}

/** Write in statement order; caller owns transaction, commit, and cancellation. */
async function insert(transaction, planned, { batchSize = 100 } = {}) {
  if (!transaction || typeof transaction.query !== "function") throw new Error("insert requires an SDK transaction");
  if (!Array.isArray(planned?.rows)) throw new Error("insert requires a fixture plan");
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) throw new Error("batchSize must be a positive safe integer");
  const created = [];
  for (let offset = 0; offset < planned.rows.length; offset += batchSize) {
    const batch = planned.rows.slice(offset, offset + batchSize), bindings = {};
    const statements = batch.map((row, index) => {
      if (!(row.id instanceof RecordId)) throw new Error("Fixture plan ids must be native RecordId values");
      bindings[`id${index}`] = row.id; bindings[`content${index}`] = row.content;
      return `CREATE $id${index} CONTENT $content${index} RETURN AFTER;`;
    });
    const results = await transaction.query(statements.join("\n"), bindings);
    if (!Array.isArray(results) || results.length !== batch.length) throw new Error("Database returned an incomplete fixture batch");
    results.forEach((result, index) => {
      const row = Array.isArray(result) && result.length === 1 ? result[0] : result;
      if (!row?.id || String(row.id) !== String(batch[index].id)) throw new Error(`Database did not create fixture ${batch[index].id}`);
      created.push(row);
    });
  }
  return created;
}

/** Populate from an offline recipe or incremental counts, in one transaction. */
async function populate(db, options = {}) {
  if (!db || typeof db.beginTransaction !== "function") throw new Error("populate requires a connected SurrealDB SDK client");
  const incremental = own(options, "counts");
  if (incremental && own(options, "recipe")) throw new Error("Use either counts for incremental generation or recipe for an offline plan");
  const transaction = await db.beginTransaction();
  try {
    const space = typeof options.space === "function" ? await options.space(transaction) : options.space;
    let result;
    if (incremental) {
      if (options.context !== undefined && (!options.context || typeof options.context !== "object" || Array.isArray(options.context))) throw new Error("context must be an object");
      result = await generate({ ...options, space, context: { ...options.context, transaction },
        read: async ids => (await transaction.query("SELECT * FROM $ids;", { ids }))[0],
        apply: async row => (await insert(transaction, { rows: [row] }))[0],
      });
    } else {
      const planned = await plan({ ...options, space });
      result = { ...planned, created: await insert(transaction, planned, options) };
    }
    await transaction.commit();
    return result;
  } catch (error) {
    try { await transaction.cancel(); } catch (cancelError) {
      throw new AggregateError([error, cancelError], "Fixture failed and transaction cancellation also failed", { cause: error });
    }
    throw error;
  }
}

module.exports = { createModel, plan, generate, insert, populate, withSolver, FixtureStalledError };
