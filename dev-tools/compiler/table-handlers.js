const fs = require("node:fs");
const path = require("node:path");
const { loadTableHandlers } = require("../../gateway/handlers");
const { loadWebhookHandlers } = require("../../gateway/webhooks");
const { assertGrantAdapters } = require("../../src/operation-adapters");

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
  const reserved = new Set([
    "execution_id", "revision", "execute_at", "priority",
    "rebase_cancel_requested", "rebase_lease_token", "rebase_lease_until", "rebase_outcome", "rebase_attempt",
    "rebase_wake_at", "rebase_finished_at", "rebase_error", "rebase_status",
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
  const events = table.effectEvents?.length ? table.effectEvents : ["CREATE"];
  if (table.effectProcess === "async" && (events.length !== 1 || events[0] !== "CREATE")) {
    throw new Error(`${table.name} asynchronous effects support only CREATE events`);
  }
  if (events.includes("UPDATE") && !inputs.length) {
    throw new Error(`${table.name} UPDATE effects require at least one @rebase-effect-input field`);
  }
  if (events.includes("UPDATE") && !mutableInputs.length) {
    throw new Error(`${table.name} UPDATE effects require at least one mutable effect input`);
  }
  if (table.effectProcess === "async" && table.effectMutableInputs) {
    throw new Error(`${table.name} cannot use @rebase-mutable-inputs without an implemented generation policy`);
  }
  if (mutableInputs.length && !(table.effectProcess === "sync" && table.effectMutableInputs)) {
    throw new Error(`${table.name} effect inputs must be READONLY: ${mutableInputs.map((field) => field.name).join(", ")}`);
  }
}

function validateOperationTable(table) {
  const reserved = new Set([
    "execution_id", "revision", "execute_at", "priority",
    "rebase_cancel_requested", "rebase_lease_token", "rebase_lease_until", "rebase_outcome", "rebase_attempt",
    "rebase_wake_at", "rebase_finished_at", "rebase_error", "rebase_status",
  ]);
  const collision = [...table.fields.keys()].find((field) => reserved.has(field));
  if (collision) throw new Error(`${table.name}.${collision} collides with a reserved lifecycle field`);
  const inputs = [...table.fields.values()].filter((field) => field.operationInput);
  const outputs = [...table.fields.values()].filter((field) => field.operationOutput);
  const writableOutput = outputs.find((field) => !deniesClientCreateAndUpdate(field));
  if (writableOutput) {
    throw new Error(`${table.name}.${writableOutput.name} operation output must deny client create and update`);
  }
  const overlap = inputs.find((field) => field.operationOutput);
  if (overlap) throw new Error(`${table.name}.${overlap.name} cannot be both an operation input and output`);
  if (table.operation.mode === "grant") {
    if (!outputs.length) throw new Error(`${table.name} grant operation requires at least one @rebase-operation-output field`);
    assertGrantAdapters(table.name, table.effectAdapters || []);
  } else {
    const mutableInputs = inputs.filter((field) => !isImmutableAfterCreate(field));
    if (mutableInputs.length) {
      throw new Error(`${table.name} task inputs must be immutable after create: ${mutableInputs.map((field) => field.name).join(", ")}`);
    }
  }
}

function validateTableHandlers(projectDir, schema, runtimeContracts = { tables: {} }) {
  const directory = path.join(projectDir, "table-handlers");
  const effectTables = [...schema.tables.values()].filter((table) => table.effectProcess);
  const operationTables = [...schema.tables.values()].filter((table) => table.operation);
  const declaredTables = [...effectTables, ...operationTables];
  for (const table of effectTables) validateEffectTable(table);
  for (const table of operationTables) validateOperationTable(table);
  const contracts = new Map(Object.entries(runtimeContracts.tables || {}));
  const handlers = loadTableHandlers(directory, { contracts });
  for (const table of declaredTables) {
    const handler = handlers.get(table.name);
    if (!handler) throw new Error(`Effect or operation table ${table.name} has no table handler`);
    if (table.operation && handler.mode !== table.operation.mode) {
      throw new Error(`${table.name} mode mismatch: schema=${table.operation.mode}, handler=${handler.mode || "legacy"}`);
    }
    if (table.effectProcess && handler.process && handler.process !== table.effectProcess) {
      throw new Error(`${table.name} process mismatch: schema=${table.effectProcess}, handler=${handler.process}`);
    }
  }
  for (const handler of handlers.list()) {
    for (const tableName of handler.tables || [handler.table]) {
      const table = schema.tables.get(tableName);
      if (!table?.effectProcess && !table?.operation) {
        throw new Error(`Table handler ${tableName} has no @rebase-effect or @rebase-operation declaration`);
      }
    }
  }
  for (const table of schema.tables.values()) {
    if (!table.effectProcess && table.effectEvents?.length) {
      throw new Error(`${table.name} declares @rebase-events without @rebase-effect`);
    }
  }
  return handlers;
}

function validateWebhookHandlers(projectDir) {
  const directory = path.join(projectDir, "webhook-handlers");
  return loadWebhookHandlers(directory);
}

module.exports = { validateEffectTable, validateOperationTable, validateTableHandlers, validateWebhookHandlers };
