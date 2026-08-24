const fs = require("node:fs");
const path = require("node:path");
const { loadTableHandlers } = require("../../gateway/handlers");

function isUuidId(field) {
  const definition = field?.definition || "";
  return /\bTYPE\s+uuid\b/i.test(definition) && /\brand::uuid::v7\s*\(/i.test(definition);
}

function deniedPermissions(field) {
  const definition = field?.definition || "";
  const allDenied = /\bPERMISSIONS\s+NONE\b/i.test(definition);
  const bothDenied = /\bFOR\s+create\s*,\s*update\s+NONE\b/i.test(definition)
    || /\bFOR\s+update\s*,\s*create\s+NONE\b/i.test(definition);
  return {
    create: allDenied || bothDenied || /\bFOR\s+create\s+NONE\b/i.test(definition),
    update: allDenied || bothDenied || /\bFOR\s+update\s+NONE\b/i.test(definition),
  };
}

function isImmutableAfterCreate(field) {
  return /\bREADONLY\b/i.test(field?.definition || "") || deniedPermissions(field).update;
}

function deniesClientCreateAndUpdate(field) {
  const denied = deniedPermissions(field);
  return denied.create && denied.update;
}

function validateEffectTable(table) {
  if (!isUuidId(table.fields.get("id"))) {
    throw new Error(`Effect table ${table.name} requires an id TYPE uuid with rand::uuid::v7()`);
  }
  const reserved = new Set([
    "rebase_cancel_requested", "rebase_lease_token", "rebase_lease_until", "rebase_outcome",
    "rebase_wake_at", "rebase_finished_at", "rebase_error", "rebase_status",
    "rebase_schedule_next_at", "rebase_schedule_index", "rebase_schedule_finished_at",
    "schedule",
  ]);
  const collision = [...table.fields.keys()].find((field) => reserved.has(field));
  if (collision) throw new Error(`${table.name}.${collision} collides with a reserved lifecycle field`);
  const outputs = [...table.fields.values()].filter((field) => field.effectOutput && !field.name.startsWith("rebase_"));
  const writable = outputs.find((field) => !deniesClientCreateAndUpdate(field));
  if (writable) throw new Error(`${table.name}.${writable.name} effect output must deny client create and update`);
  if (table.effectProcess === "sync" && ![...table.fields.values()].some((field) => field.effectInput)) {
    throw new Error(`Synchronous effect table ${table.name} requires at least one @rebase-effect-input field`);
  }
  const inputs = [...table.fields.values()].filter((field) => field.effectInput);
  const mutableInputs = inputs.filter((field) => !isImmutableAfterCreate(field));
  if (table.effectProcess === "async" && table.effectMutableInputs) {
    throw new Error(`${table.name} cannot use @rebase-mutable-inputs without an implemented generation policy`);
  }
  if (mutableInputs.length && !(table.effectProcess === "sync" && table.effectMutableInputs)) {
    throw new Error(`${table.name} effect inputs must be READONLY: ${mutableInputs.map((field) => field.name).join(", ")}`);
  }
}

function validateTableHandlers(projectDir, schema, runtimeContracts = { tables: {} }) {
  const directory = path.join(projectDir, "table-handlers");
  const effectTables = [...schema.tables.values()].filter((table) => table.effectProcess);
  if (!fs.existsSync(directory)) {
    if (effectTables.length) throw new Error("Effect tables require a table-handlers directory");
    return { get() { return null; }, list() { return []; }, tables: [] };
  }
  const contracts = new Map(Object.entries(runtimeContracts.tables || {}));
  const webhookRoutes = new Map();
  for (const [table, contract] of contracts) {
    if (!contract.webhook) continue;
    const key = `${contract.webhook.provider}/${contract.webhook.route}`;
    if (webhookRoutes.has(key)) throw new Error(`Duplicate webhook route ${key}: ${webhookRoutes.get(key)}, ${table}`);
    webhookRoutes.set(key, table);
  }
  const handlers = loadTableHandlers(directory, { contracts });
  for (const table of effectTables) {
    validateEffectTable(table);
    const handler = handlers.get(table.name);
    if (!handler) throw new Error(`Effect table ${table.name} has no table handler`);
    if (handler.process && handler.process !== table.effectProcess) {
      throw new Error(`${table.name} process mismatch: schema=${table.effectProcess}, handler=${handler.process}`);
    }
    const contract = contracts.get(table.name);
    if (contract?.webhook && (!handler.verifyWebhook || !handler.correlateWebhook)) {
      throw new Error(`${table.name} webhook contract requires verifyWebhook() and correlateWebhook()`);
    }
  }
  for (const handler of handlers.list()) {
    for (const tableName of handler.tables || [handler.table]) {
      const table = schema.tables.get(tableName);
      if (!table?.effectProcess) throw new Error(`Table handler ${tableName} has no @rebase-effect declaration`);
    }
  }
  return handlers;
}

module.exports = { validateEffectTable, validateTableHandlers };
