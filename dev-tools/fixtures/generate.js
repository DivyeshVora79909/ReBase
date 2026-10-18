"use strict";

const { RecordId } = require("surrealdb");
const { recordId, savedReferences } = require("./model");
const { createRandom, generateInput, hash, json } = require("./values");
const { WeightedIndex, weightValue } = require("./weighted-index");

const own = (value, key) => Object.hasOwn(value, key);
function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`${label} must be an object`);
  return value;
}
function keys(value, allowed, label) {
  object(value, label);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Error(`Unknown ${label} option: ${key}`);
}
function countValue(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a nonnegative safe integer`);
  return value;
}
function references(relation, value) {
  if (value === undefined) return [];
  const values = relation.isArray ? value : [value];
  if (!Array.isArray(values)) throw new Error(`${relation.name} must be an array of references`);
  return values.map(value => {
    const id = recordId(value);
    if (!relation.targets.includes(id.table.name)) throw new Error(`${relation.name}: expected record<${relation.targets.join(" | ")}>`);
    return String(id);
  });
}

class FixtureStalledError extends Error {
  constructor({ seed, remaining, blocked, attempts, completed }) {
    super(`Fixture generation stalled after ${completed} accepted rows: ${blocked.map(row => `${row.table} (${row.remaining} remaining): ${row.reasons.join("; ")}`).join(" | ")}`);
    this.name = "FixtureStalledError";
    this.code = "FIXTURE_STALLED";
    Object.assign(this, { seed, remaining: { ...remaining }, blocked, attempts, completed });
  }
}

function definitions(model, counts, rules) {
  object(counts, "counts"); object(rules, "rules");
  for (const table of Object.keys(rules)) if (!model.tables.has(table)) throw new Error(`No fixture input schema for table ${table}`);
  let total = 0;
  return Object.entries(counts).map(([table, count]) => {
    total += countValue(count, `${table} count`);
    if (!Number.isSafeInteger(total)) throw new Error("Total requested count exceeds safe integer range");
    const entry = model.tables.get(table);
    if (!entry?.relations) throw new Error(`No fixture input schema for table ${table}; use createModel`);
    const rule = rules[table] ?? {};
    keys(rule, ["priority", "refs", "values", "id"], `${table} rule`);
    const priority = weightValue(rule.priority ?? 1);
    weightValue(count * priority);
    const policies = rule.refs ?? {};
    object(policies, `${table}.refs`);
    if (rule.values !== undefined && typeof rule.values !== "function") object(rule.values, `${table}.values`);
    const fixed = typeof rule.values === "function" ? {} : json(rule.values ?? {});
    for (const field of Object.keys(policies)) if (!entry.relations.has(field)) throw new Error(`${table}.${field} is not a public typed reference`);
    const roles = [...entry.relations].map(([name, relation]) => {
      const policy = policies[name] === false ? {} : policies[name] ?? {};
      keys(policy, ["bias", "skew", "offset", "weight", "after", "usage"], `${table}.${name}`);
      const bias = policy.bias ?? {}, usage = policy.usage ?? {};
      object(bias, `${table}.${name}.bias`); object(usage, `${table}.${name}.usage`);
      for (const [target, weight] of Object.entries(bias)) {
        if (!relation.targets.includes(target)) throw new Error(`${table}.${name}.bias has unknown target ${target}`);
        weightValue(weight);
      }
      const skew = policy.skew ?? 0, offset = policy.offset ?? 1;
      if (typeof skew !== "number" || !Number.isFinite(skew)) throw new Error(`${table}.${name}.skew must be finite`);
      if (typeof offset !== "number" || !Number.isFinite(offset) || offset <= 0) throw new Error(`${table}.${name}.offset must be positive and finite`);
      if (policy.weight !== undefined && typeof policy.weight !== "function") throw new Error(`${table}.${name}.weight must be a function`);
      const after = policy.after ?? [];
      if (!Array.isArray(after) || after.some(name => typeof name !== "string")) throw new Error(`${table}.${name}.after must contain reference field names`);
      const mode = own(fixed, name) ? "fixed" : policies[name] === false ? "manual"
        : relation.required || own(policies, name) ? "auto" : "omit";
      const suppliedUsage = new Map(Object.entries(usage).map(([id, count]) => [references(relation, relation.isArray ? [id] : id)[0], countValue(count, `${table}.${name} usage`)]));
      return { ...relation, key: `${table}.${name}`, mode, policy, bias, skew, offset, after,
        fixed: mode === "fixed" ? references(relation, fixed[name]) : [],
        usage: new Map(), suppliedUsage, ids: [], positions: new Map() };
    });
    const byName = new Map(roles.map(role => [role.name, role]));
    const ordered = [], active = new Set(), done = new Set();
    function visit(role) {
      if (done.has(role.name) || ["manual", "omit"].includes(role.mode)) return;
      if (active.has(role.name)) throw new Error(`Cyclic reference selection dependencies at ${table}.${role.name}`);
      active.add(role.name);
      for (const name of role.after) {
        const dependency = byName.get(name);
        if (!dependency || ["manual", "omit"].includes(dependency.mode)) throw new Error(`${table}.${role.name}.after needs an automatically selected or pinned reference: ${name}`);
        visit(dependency);
      }
      active.delete(role.name); done.add(role.name); ordered.push(role);
    }
    roles.forEach(visit);
    return { table, count, priority, rule, fixed, roles, ordered };
  });
}

/**
 * Select and accept rows sequentially. read/apply are explicit effects;
 * this function never starts or finishes a database transaction.
 */
async function generate({ model, seed = 1, space: supplied = [], counts, rules = {},
  read, apply, context: suppliedContext = {}, maxAttempts = 32, assert: assertResult } = {}) {
  if (!model?.tables || typeof model.prepare !== "function") throw new Error("generate requires a fixture model from createModel");
  if (!Array.isArray(supplied)) throw new Error("Incremental space must be an array of existing records");
  if (typeof apply !== "function") throw new Error("generate requires apply(row), or use populate for native transactions");
  if (read !== undefined && typeof read !== "function") throw new Error("read must be a function");
  if (assertResult !== undefined && typeof assertResult !== "function") throw new Error("assert must be a function");
  object(suppliedContext, "context");
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw new Error("maxAttempts must be a positive safe integer");
  const tables = definitions(model, counts, rules);
  const { seed: seedText, faker, generator } = await createRandom(seed);
  const space = Object.create(null), records = new Map(), watchers = new Map();
  const remaining = Object.fromEntries(tables.map(({ table, count }) => [table, count]));
  const rows = [], created = [], declined = new Map();
  let attempts = 0;

  function add(value) {
    object(value, "Space record");
    const row = json(value), id = recordId(row.id), key = String(id);
    if (records.has(key)) return; // Repeated query results do not bias selection.
    row.id = key;
    const pool = space[id.table.name] ||= [];
    records.set(key, { row, pool, index: pool.length });
    pool.push(row);
    for (const role of watchers.get(id.table.name) || []) {
      role.positions.set(key, role.ids.length); role.ids.push(key);
      role.index.append(baseWeight(role, key));
    }
  }
  function baseWeight(role, id) {
    return weightValue((role.bias[recordId(id).table.name] ?? 1) * ((role.usage.get(id) ?? 0) + role.offset) ** role.skew);
  }
  supplied.forEach(add);
  for (const definition of tables) {
    space[definition.table] ||= [];
    for (const role of definition.roles) {
      // Count known children once per role/parent, including array membership.
      for (const child of space[definition.table]) {
        for (const id of new Set(references(role, child[role.name]))) role.usage.set(id, (role.usage.get(id) ?? 0) + 1);
      }
      for (const [id, count] of role.suppliedUsage) role.usage.set(id, count);
      for (const target of role.targets) {
        for (const row of space[target] || []) {
          role.positions.set(row.id, role.ids.length); role.ids.push(row.id);
        }
        if (!watchers.has(target)) watchers.set(target, []);
        watchers.get(target).push(role);
      }
      role.index = new WeightedIndex(role.ids.map(id => baseWeight(role, id)));
    }
  }
  const context = { ...suppliedContext, seed: seedText, space, faker,
    pick: candidates => faker.helpers.arrayElement(candidates) };

  function blockers(definition) {
    const reasons = [];
    if (definition.priority === 0) reasons.push("priority is zero");
    for (const role of definition.ordered) {
      if (role.mode === "fixed") {
        const missing = role.fixed.filter(id => !records.has(id));
        if (missing.length) reasons.push(`${role.name}: pinned parents are not available (${missing.join(", ")})`);
      } else if (role.index.positive < (role.isArray ? role.min : 1)) {
        reasons.push(`${role.name}: needs ${role.isArray ? role.min : 1} distinct positive-weight parent(s) from ${role.targets.join(" | ")}; available ${role.index.positive}`);
      }
    }
    const failure = declined.get(definition.table);
    if (failure?.attempts >= maxAttempts) reasons.push(failure.reason);
    return reasons;
  }

  async function refresh(ids) {
    if (!read || !ids.length) return;
    const fresh = await read(ids.map(recordId));
    if (!Array.isArray(fresh)) throw new Error("read(ids) must return an array of records");
    const expected = new Set(ids);
    for (const value of fresh) {
      object(value, "Read record");
      const row = json(value), id = String(recordId(row.id));
      if (!expected.delete(id)) throw new Error(`read returned an unexpected or duplicate parent ${id}`);
      const slot = records.get(id);
      row.id = id; slot.row = row; slot.pool[slot.index] = row;
    }
    if (expected.size) throw new Error(`read did not return selected parents: ${[...expected].join(", ")}`);
  }

  while (tables.some(({ table }) => remaining[table] > 0)) {
    const eligible = tables.filter(definition => remaining[definition.table] > 0 && !blockers(definition).length);
    if (!eligible.length) throw new FixtureStalledError({ seed: seedText, remaining, attempts, completed: rows.length,
      blocked: tables.filter(({ table }) => remaining[table] > 0).map(definition => ({ table: definition.table,
        remaining: remaining[definition.table], attempts: declined.get(definition.table)?.attempts ?? 0, reasons: blockers(definition) })) });
    const tableWeights = eligible.map(definition => remaining[definition.table] * definition.priority);
    const definition = eligible[new WeightedIndex(tableWeights).pick(faker.number.float())];
    const { table, rule } = definition, index = definition.count - remaining[table];
    const rowContext = { ...context, table, index, sequence: rows.length, remaining: { ...remaining }, parents: {} };
    attempts++;
    try {
      let reason;
      const selected = new Map();
      for (const role of definition.ordered) {
        let ids;
        if (role.mode === "fixed") ids = role.fixed;
        else {
          const weights = role.policy.weight ? new WeightedIndex(role.ids.map((id, position) => role.index.get(position)
            * weightValue(role.policy.weight(records.get(id).row, { ...rowContext, uses: role.usage.get(id) ?? 0 })))) : role.index;
          if (weights.positive < (role.isArray ? role.min : 1)) { reason = `${role.name}: selected parents have no compatible candidates`; break; }
          const count = role.isArray ? faker.number.int({ min: role.min, max: Math.min(role.max, weights.positive) }) : 1;
          ids = weights.sample(count, () => faker.number.float()).map(position => role.ids[position]);
        }
        selected.set(role.name, ids);
        const parents = ids.map(id => records.get(id).row);
        rowContext.parents[role.name] = role.isArray ? parents : parents[0];
      }
      if (!reason) {
        await refresh([...new Set([...selected.values()].flat())]);
        for (const role of definition.ordered) {
          const parents = selected.get(role.name).map(id => records.get(id).row);
          rowContext.parents[role.name] = role.isArray ? parents : parents[0];
        }
        // Compatibility predicates may observe fields changed by earlier writes.
        for (const role of definition.ordered) {
          if (read && role.mode === "auto" && role.policy.weight && selected.get(role.name).some(id =>
            weightValue(role.policy.weight(records.get(id).row, { ...rowContext, uses: role.usage.get(id) ?? 0 })) === 0)) {
            reason = `${role.name}: refreshed parents are incompatible`; break;
          }
        }
      }
      const values = reason ? null : typeof rule.values === "function" ? await rule.values(rowContext) : definition.fixed;
      if (values === null) {
        declined.set(table, { attempts: (declined.get(table)?.attempts ?? 0) + 1, reason: reason || "values declined the selected parents within the attempt budget" });
        continue;
      }
      const overrides = json(object(values, `${table}.values result`));
      const links = Object.fromEntries(definition.ordered.map(role => [role.name, role.isArray ? selected.get(role.name) : selected.get(role.name)[0]]));
      for (const [field, value] of Object.entries(links)) {
        const relation = model.tables.get(table).relations.get(field);
        if (own(overrides, field) && JSON.stringify(references(relation, overrides[field])) !== JSON.stringify(references(relation, value))) {
          throw new Error(`values replaced selected reference ${field}; use refs: { ${field}: false } to select it explicitly`);
        }
      }
      const prepared = await generateInput(model, table, { ...links, ...overrides }, generator);
      for (const ref of prepared.references) if (!records.has(ref.value)) throw new Error(`Reference ${ref.field}=${ref.value} is outside the supplied space or accepted rows`);
      const key = typeof rule.id === "function" ? await rule.id(rowContext) : rule.id;
      const id = key === undefined ? new RecordId(table, `fixture_${hash(`${seedText}:${table}:${index}`).toString("hex").slice(0, 24)}`) : recordId(key);
      if (id.table.name !== table) throw new Error(`Record id ${id} does not belong to ${table}`);
      if (records.has(String(id))) throw new Error(`Duplicate fixture id ${id}`);
      const row = { table, id, content: prepared.content };
      const accepted = await apply(row, rowContext);
      if (!accepted?.id || String(recordId(accepted.id)) !== String(id)) throw new Error(`apply did not accept fixture ${id}`);
      const saved = savedReferences(model.tables.get(table), accepted);
      for (const ref of saved) if (!records.has(ref.value)) throw new Error(`Saved reference ${ref.path.join(".")}=${ref.value} is outside the supplied space or accepted rows`);
      add(accepted);
      for (const role of definition.roles) {
        for (const parent of new Set(saved.filter(ref => ref.field === role.name).map(ref => ref.value))) {
          const uses = countValue((role.usage.get(parent) ?? 0) + 1, `${role.key} usage`);
          role.usage.set(parent, uses);
          if (role.positions.has(parent)) role.index.set(role.positions.get(parent), baseWeight(role, parent));
        }
      }
      rows.push(row); created.push(accepted); remaining[table]--; declined.clear();
    } catch (cause) {
      const error = new Error(`Fixture ${table}[${index}] at sequence ${rows.length}: ${cause.message}`, { cause });
      Object.assign(error, { table, index, sequence: rows.length });
      if (cause.code) error.code = cause.code;
      throw error;
    }
  }
  const usage = Object.fromEntries(tables.flatMap(definition => definition.roles.map(role => [role.key, Object.fromEntries(role.usage)])));
  const result = { seed: seedText, rows, created, space, usage, attempts };
  if (assertResult && await assertResult(result, context) === false) throw new Error("Fixture global assertion returned false");
  return result;
}

module.exports = { generate, FixtureStalledError };
