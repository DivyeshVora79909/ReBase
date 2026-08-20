const fs = require("node:fs");
const path = require("node:path");
const { loadTableHandlers } = require("../../gateway/handlers");

function isUuidId(field) {
  const definition = field?.definition || "";
  return /\bTYPE\s+uuid\b/i.test(definition) && /\brand::uuid::v7\s*\(/i.test(definition);
}

function isClientReadOnly(field) {
  return /\bPERMISSIONS\b[\s\S]*\bFOR\s+create\s*,\s*update\s+NONE\b/i.test(field?.definition || "");
}

function validateEffectTable(table) {
  if (!isUuidId(table.fields.get("id"))) {
    throw new Error(`Effect table ${table.name} requires an id TYPE uuid with rand::uuid::v7()`);
  }
  const state = table.fields.get("effect_state");
  if (!state?.effectOutput || !/\bTYPE\s+string\b/i.test(state.definition)) {
    throw new Error(`Effect table ${table.name} requires an output-marked string effect_state`);
  }
  const outputs = [...table.fields.values()].filter((field) => field.effectOutput);
  const writable = outputs.find((field) => !isClientReadOnly(field));
  if (writable) throw new Error(`${table.name}.${writable.name} effect output must deny client create and update`);
  if (table.effectProcess === "sync" && ![...table.fields.values()].some((field) => field.effectInput)) {
    throw new Error(`Synchronous effect table ${table.name} requires at least one @rebase-effect-input field`);
  }
  if (table.effectProcess === "async") {
    for (const stateName of ["pending", "processing", "waiting", "succeeded", "failed"]) {
      if (!new RegExp(`['\"]${stateName}['\"]`, "i").test(state.definition)) {
        throw new Error(`${table.name}.effect_state must allow ${stateName}`);
      }
    }
  }
}

function validateTableHandlers(projectDir, schema) {
  const directory = path.join(projectDir, "table-handlers");
  const effectTables = [...schema.tables.values()].filter((table) => table.effectProcess);
  if (!fs.existsSync(directory)) {
    if (effectTables.length) throw new Error("Effect tables require a table-handlers directory");
    return { get() { return null; }, list() { return []; }, tables: [] };
  }
  const handlers = loadTableHandlers(directory);
  for (const table of effectTables) {
    validateEffectTable(table);
    const handler = handlers.get(table.name);
    if (!handler) throw new Error(`Effect table ${table.name} has no table handler`);
    if (handler.process !== table.effectProcess) {
      throw new Error(`${table.name} process mismatch: schema=${table.effectProcess}, handler=${handler.process}`);
    }
    const markedOutputs = [...table.fields.values()].filter((field) => field.effectOutput).map((field) => field.name).sort();
    const handlerOutputs = [...handler.outputs].sort();
    if (JSON.stringify(markedOutputs) !== JSON.stringify(handlerOutputs)) {
      throw new Error(`${table.name} handler outputs must exactly match @rebase-effect-output fields`);
    }
  }
  for (const handler of handlers.list()) {
    const table = schema.tables.get(handler.table);
    if (!table?.effectProcess) throw new Error(`Table handler ${handler.table} has no @rebase-effect declaration`);
  }
  return handlers;
}

module.exports = { validateEffectTable, validateTableHandlers };
