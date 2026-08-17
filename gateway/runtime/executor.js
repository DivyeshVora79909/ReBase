const { GatewayError } = require("./errors");
const { hasCapability } = require("./access");
const { assertNoCredentials, withTimeout } = require("./utils");

function tableOf(id) {
  const separator = id.indexOf(":");
  return separator > 0 ? id.slice(0, separator) : "";
}

function normalizeRecordIds(handler, supplied = {}) {
  if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
    throw new GatewayError("RECORDS_INVALID", "records must be an object", 400);
  }
  const unknown = Object.keys(supplied).find((slot) => !handler.records[slot]);
  if (unknown) throw new GatewayError("RECORD_SLOT_UNKNOWN", `Unknown record slot: ${unknown}`, 400);
  const normalized = {};
  const ids = [];
  const validateId = (slot, definition, id) => {
    if (typeof id !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*:.+/.test(id)) {
      throw new GatewayError("RECORD_ID_INVALID", `${slot} contains an invalid record id`, 400);
    }
    if (!definition.tables.includes(tableOf(id))) {
      throw new GatewayError("RECORD_TABLE_MISMATCH", `Invalid table for record slot ${slot}`, 400);
    }
  };
  for (const [slot, definition] of Object.entries(handler.records)) {
    const value = supplied[slot];
    if (definition.many) {
      if (value === undefined && !definition.required) {
        normalized[slot] = [];
        continue;
      }
      if (!Array.isArray(value)) throw new GatewayError("RECORD_CARDINALITY", `${slot} must be an array`, 400);
      if (value.length < definition.min || value.length > definition.max) {
        throw new GatewayError("RECORD_CARDINALITY", `${slot} has invalid cardinality`, 400);
      }
      if (new Set(value).size !== value.length) {
        throw new GatewayError("RECORD_DUPLICATE", `${slot} contains duplicate record ids`, 400);
      }
      for (const id of value) validateId(slot, definition, id);
      normalized[slot] = [...value];
      ids.push(...value);
      continue;
    }
    if (value === undefined && !definition.required) {
      normalized[slot] = null;
      continue;
    }
    if (typeof value !== "string") throw new GatewayError("RECORD_REQUIRED", `${slot} requires one record id`, 400);
    validateId(slot, definition, value);
    normalized[slot] = value;
    ids.push(value);
  }
  return { ids, normalized };
}

function normalizeArgs(args) {
  if (args === undefined) return {};
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new GatewayError("ARGS_INVALID", "args must be an object", 400);
  }
  assertNoCredentials(args);
  return structuredClone(args);
}

function createExecutor({ database, handlers, providers }) {
  async function prepare({ caller, handler, args, recordIds = {}, auth: loadedAuth }) {
    const auth = loadedAuth || await database.actor(caller);
    if (!hasCapability(auth, handler.capability)) throw new GatewayError("FORBIDDEN", "Forbidden", 403);
    const validArgs = normalizeArgs(args);
    const normalized = normalizeRecordIds(handler, recordIds);
    const state = await database.resolveRecords(caller, normalized.ids);
    if (!hasCapability(state.auth, handler.capability)) throw new GatewayError("FORBIDDEN", "Forbidden", 403);
    const requested = new Set(normalized.ids);
    if (state.records.size !== requested.size || [...requested].some((id) => !state.records.has(id))) {
      throw new GatewayError("RECORD_UNAVAILABLE", "Record is unavailable", 404);
    }
    const records = {};
    for (const [slot, definition] of Object.entries(handler.records)) {
      const slotIds = definition.many ? normalized.normalized[slot] : [normalized.normalized[slot]].filter(Boolean);
      const values = slotIds.map((id) => state.records.get(id));
      records[slot] = definition.many ? values : values[0] || null;
    }
    if (typeof handler.implementation.authorize === "function") {
      const allowed = await handler.implementation.authorize({ auth: state.auth, args: validArgs, records });
      if (allowed === false) throw new GatewayError("FORBIDDEN", "Forbidden", 403);
    }
    return { args: validArgs, auth: state.auth, recordIds: normalized.normalized, records };
  }

  async function execute({ caller, handler, args, recordIds = {}, auth, execution = {}, signal }) {
    const prepared = await prepare({ caller, handler, args, recordIds, auth });
    const invoke = (activeSignal) => handler.implementation.execute({
      auth: prepared.auth,
      args: prepared.args,
      records: prepared.records,
      providers,
      signal: activeSignal,
      execution: { capability: handler.capability, mode: handler.mode, ...execution },
    });
    return signal ? invoke(signal) : withTimeout(handler.timeoutMs, invoke);
  }

  async function executeWebhook({ handler, args, execution = {}, signal }) {
    const invoke = (activeSignal) => handler.implementation.execute({
      auth: null,
      args,
      records: {},
      providers,
      signal: activeSignal,
      execution: { capability: handler.capability, mode: "webhook", ...execution },
    });
    return signal ? invoke(signal) : withTimeout(handler.timeoutMs, invoke);
  }

  return { execute, executeWebhook, prepare };
}

module.exports = { createExecutor, normalizeArgs, normalizeRecordIds };
