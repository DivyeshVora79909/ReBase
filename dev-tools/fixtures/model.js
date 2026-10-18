"use strict";

const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { DateTime, Decimal, Duration, RecordId, Uuid } = require("surrealdb");
const { SYSTEM_FIELDS, valueExpression } = require("../compiler/fields");
const { parseSchema } = require("../compiler/schema");
const { extractClauseExpression, findTopLevelKeyword, parseRecordType, sqlCode } = require("../compiler/surql");

const TYPE_CLAUSES = ["DEFAULT", "VALUE", "COMPUTED", "ASSERT", "REFERENCE", "READONLY", "PERMISSIONS", "COMMENT", "FLEXIBLE"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function quotedIdentifier(source, start) {
  const open = source[start];
  const close = open === "⟨" ? "⟩" : "`";
  let value = "";
  for (let index = start + 1; index < source.length; index += 1) {
    const char = source[index];
    if (char === close) return { value, end: index + 1 };
    if (char === "\\") {
      const next = source[++index];
      if (next !== close && next !== "\\") throw new Error("Unsupported record id escape");
      value += next;
    } else {
      if (/[\r\n\x00-\x1f]/.test(char)) throw new Error("Control character in record id");
      value += char;
    }
  }
  throw new Error("Unclosed record id quote");
}

// SDK 2.x has no public SurrealQL text parser. Keep this fallback deliberately
// narrow: unsupported compound IDs must never silently become string keys.
function recordId(value) {
  if (value instanceof RecordId) return value;
  if (typeof value !== "string" || !value.length) throw new Error("Invalid record id: expected a nonempty string");
  if (typeof RecordId.parse === "function") return RecordId.parse(value);
  try {
    let table;
    let separator;
    if (value[0] === "⟨" || value[0] === "`") {
      const quoted = quotedIdentifier(value, 0);
      table = quoted.value;
      separator = quoted.end;
    } else {
      separator = value.indexOf(":");
      table = value.slice(0, separator);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) throw new Error("Invalid table");
    }
    if (!table || value[separator] !== ":") throw new Error("Missing table or colon");
    const key = value.slice(separator + 1);
    let id;
    if (key[0] === "⟨" || key[0] === "`") {
      const quoted = quotedIdentifier(key, 0);
      if (quoted.end !== key.length) throw new Error("Trailing record id text");
      id = quoted.value;
    } else if (/^u["']/.test(key)) {
      const match = /^u(["'])([^"']+)\1$/.exec(key);
      if (!match || !UUID.test(match[2])) throw new Error("Invalid typed UUID");
      id = new Uuid(match[2]);
    } else if (/^-?(?:0|[1-9][0-9]*)$/.test(key)) {
      id = BigInt(key);
      if (id < -(2n ** 63n) || id > 2n ** 63n - 1n) throw new Error("Numeric record id exceeds int64");
    } else if ((/^[A-Za-z0-9_]+$/.test(key) && !/^[0-9]+$/.test(key)) || UUID.test(key)) {
      id = key;
    } else {
      throw new Error("Unsupported or malformed record id key; quote string keys with ⟨…⟩ or backticks");
    }
    return new RecordId(table, id);
  } catch (error) {
    throw new Error(`Invalid record id ${JSON.stringify(value)}: ${error.message}`, { cause: error });
  }
}

function fieldClauses(definition) {
  return String(definition || "").replace(/^[\s\S]*?\bDEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?\S+\s+ON\s+(?:TABLE\s+)?[A-Za-z0-9_]+/i, "");
}

function compileField(field) {
  const clauses = fieldClauses(field.definition);
  const type = extractClauseExpression(clauses, "TYPE", TYPE_CLAUSES) || "any";
  // Compiler businessFields applies the same distinction: VALUE over $value
  // normalizes a public input, while a VALUE over other fields derives output.
  const normalizer = /\$value\b/.test(sqlCode(valueExpression(field) || ""));
  const permissions = extractClauseExpression(clauses, "PERMISSIONS", ["COMMENT"]);
  const createDenied = /^NONE$/i.test(permissions || "")
    || /\bFOR\s+(?:[a-z]+\s*,\s*)*create\s*(?:,\s*[a-z]+\s*)*\s+NONE\b/i.test(permissions || "");
  return {
    ...field,
    type,
    binding: compileType(type),
    recordType: field.recordType || parseRecordType(field.definition || ""),
    protected: Boolean(SYSTEM_FIELDS.has(field.name) || (field.derived && !normalizer) || field.computed || field.reactive || field.system || field.treeRoot || field.treeNode
      || createDenied || field.operationOutput || field.effectOutput || (findTopLevelKeyword(clauses, "VALUE") >= 0 && !normalizer)
      || findTopLevelKeyword(clauses, "COMPUTED") >= 0 || /@rebase-(?:system|derived|tree-|operation-output|effect-output)/i.test(field.comment || "")),
  };
}

function assertJson(value, path, seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object" || (Object.getPrototypeOf(value) !== Object.prototype
    && Object.getPrototypeOf(value) !== null && !Array.isArray(value))) {
    throw new Error(`${path}: expected JSON input (native SDK values are output only)`);
  }
  if (seen.has(value)) throw new Error(`${path}: cyclic JSON input`);
  seen.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) assertJson(value[index], `${path}.${index}`, seen);
  } else {
    for (const [name, item] of Object.entries(value)) assertJson(item, `${path}.${name}`, seen);
  }
  seen.delete(value);
}

function splitType(source, separator) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "<") depth += 1;
    if (source[index] === ">") depth -= 1;
    if (depth === 0 && source[index] === separator) {
      parts.push(source.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(source.slice(start).trim());
  return parts;
}

function compileType(type) {
  const source = type.trim();
  const optional = /^option\s*<([\s\S]+)>$/i.exec(source);
  if (optional) return { source, kind: "option", item: compileType(optional[1]) };
  const alternatives = splitType(source, "|");
  if (alternatives.length > 1) return { source, kind: "union", alternatives: alternatives.map(compileType) };
  const container = /^(array|set)\s*(?:<([\s\S]+)>)?$/i.exec(source);
  if (container) {
    const [itemType = "any", length] = container[2] ? splitType(container[2], ",") : [];
    return { source, kind: container[1].toLowerCase(), item: compileType(itemType), length };
  }
  const record = /^record(?:\s*<[^>]+>)?$/i.test(source)
    ? parseRecordType(`DEFINE FIELD fixture ON fixture TYPE ${source};`) : null;
  return { source, kind: record ? "record" : source.toLowerCase(), record };
}

function convertType(type, value, path, references) {
  const { source, kind } = type;
  if (kind === "option") {
    if (value === null) throw new Error(`${path.join(".")}: option<T> accepts omitted inputs, not JSON null`);
    return convertType(type.item, value, path, references);
  }
  if (kind === "union") {
    const errors = [];
    for (const alternative of type.alternatives) {
      const found = [];
      try {
        const result = convertType(alternative, value, path, found);
        references.push(...found);
        return result;
      } catch (error) { errors.push(error.message); }
    }
    throw new Error(`${path.join(".")}: value does not match ${source}: ${errors.join("; ")}`);
  }
  if (kind === "array" || kind === "set") {
    if (!Array.isArray(value)) throw new Error(`${path.join(".")}: expected ${kind}`);
    const { length } = type;
    if (length !== undefined && (!/^\d+$/.test(length) || value.length !== Number(length))) throw new Error(`${path.join(".")}: expected array length ${length}`);
    return value.map((item, index) => convertType(type.item, item, [...path, index], references));
  }
  if (kind === "record") {
    const { record } = type;
    const id = recordId(value);
    const table = id.table.name;
    if (record.targets.length && !record.targets.includes(table)) throw new Error(`${path.join(".")}: expected record<${record.targets.join(" | ")}>`);
    references.push({ field: path[0], path: [...path], id, table, value: String(id) });
    return id;
  }
  const fail = () => { throw new Error(`${path.join(".")}: invalid ${source} input`); };
  switch (kind) {
    case "decimal":
      if (typeof value !== "string" || !/^-?\d+(?:\.\d+)?$/.test(value)) return fail();
      return new Decimal(value);
    case "datetime": {
      if (typeof value !== "string" || !addFormats.get("date-time", "full").validate(value)) return fail();
      if (/\.\d{10,}/.test(value)) throw new Error(`${path.join(".")}: datetime precision exceeds nanoseconds`);
      // Preserve nanoseconds through the SDK instead of silently truncating to Date.
      if (/\.\d{4,}(?:z|[+-]\d\d:\d\d)$/i.test(value)) {
        if (!/Z$/i.test(value)) throw new Error(`${path.join(".")}: submillisecond datetime requires UTC Z`);
        return new DateTime(`${value.slice(0, 10)}T${value.slice(11, -1)}Z`);
      }
      const date = new Date(value);
      if (!Number.isFinite(date.getTime())) return fail();
      return date;
    }
    case "duration":
      // The SDK accepts fractional spellings but truncates their fraction.
      if (typeof value !== "string" || !/^(?:\d+(?:ns|µs|μs|us|ms|s|m|h|d|w|y))+$/.test(value)) return fail();
      return new Duration(value);
    case "uuid":
      if (typeof value !== "string" || !UUID.test(value)) return fail();
      return new Uuid(value);
    case "string": if (typeof value !== "string") return fail(); return value;
    case "bool": if (typeof value !== "boolean") return fail(); return value;
    case "int": if (!Number.isSafeInteger(value)) return fail(); return value;
    case "float":
    case "number": if (typeof value !== "number" || !Number.isFinite(value)) return fail(); return value;
    case "object": if (!value || typeof value !== "object" || Array.isArray(value)) return fail(); return structuredClone(value);
    case "null": if (value !== null) return fail(); return value;
    case "any": return structuredClone(value);
    default: throw new Error(`${path.join(".")}: unsupported database input type ${source}`);
  }
}

function visitPath(document, parts, callback, path = []) {
  if (!parts.length) return callback(document, path);
  if (document === null || typeof document !== "object") return document;
  const [part, ...rest] = parts;
  const keys = part === "*" ? Object.keys(document) : [part];
  for (const key of keys) {
    if (Object.hasOwn(document, key)) document[key] = visitPath(document[key], rest, callback, [...path, Array.isArray(document) ? Number(key) : key]);
  }
  return document;
}

function createModel({ schema, schemas }) {
  if (typeof schema === "string") schema = parseSchema(schema, "");
  else if (typeof schema?.bundle === "string") schema = parseSchema(schema.bundle, "");
  if (!(schema?.tables instanceof Map)) throw new Error("createModel requires compiler schema.tables Map");
  const catalog = schemas?.schemas instanceof Map ? schemas : null;
  const ajv = catalog?.ajv || new Ajv({ allErrors: true, strict: true, validateSchema: true });
  if (!catalog) addFormats(ajv);
  const entries = catalog ? [...catalog.schemas].map(([name, entry]) => [name, entry.schema, entry.validate])
    : Object.entries(schemas || {}).map(([name, inputSchema]) => [name, inputSchema]);
  if (!catalog) for (const [name, inputSchema] of entries) ajv.addSchema(inputSchema, inputSchema.$id || `urn:rebase:fixture:${name}`);
  const tables = new Map();
  for (const [name, inputSchema, validator] of entries) {
    const table = schema.tables.get(name);
    if (!table) throw new Error(`Client input schema has no compiled table: ${name}`);
    const fields = new Map([...table.fields].map(([key, field]) => [key, compileField(field)]));
    const nestedFields = new Map([...(table.nestedFields || [])].map(([key, field]) => [key, compileField(field)]));
    for (const property of Object.keys(inputSchema.properties || {})) {
      if (!fields.has(property)) throw new Error(`${name}.${property}: input field has no compiled database metadata; pass the complete emitted compiler bundle to createModel`);
    }
    const relations = new Map();
    for (const [fieldName, field] of fields) {
      if (field.protected || !field.recordType?.targets?.length || !Object.hasOwn(inputSchema.properties || {}, fieldName)) continue;
      const property = inputSchema.properties[fieldName];
      let binding = field.binding;
      while (binding.kind === "option") binding = binding.item;
      const fixed = binding.length === undefined ? undefined : Number(binding.length);
      const min = Math.max(property.minItems ?? 0, fixed ?? 0);
      const max = Math.min(property.maxItems ?? fixed ?? Math.max(min, 1), fixed ?? Infinity);
      if (field.recordType.isArray && (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 0 || max < min)) {
        throw new Error(`${name}.${fieldName}: incompatible reference array cardinality`);
      }
      relations.set(fieldName, { ...field.recordType, targets: [...new Set(field.recordType.targets)], name: fieldName,
        required: (inputSchema.required || []).includes(fieldName), min, max });
    }
    tables.set(name, { schema: inputSchema, inputSchema, validator: validator || ajv.getSchema(inputSchema.$id || `urn:rebase:fixture:${name}`), fields, nestedFields, relations });
  }

  function input(table, document) {
    const entry = tables.get(table);
    if (!entry) throw new Error(`No fixture input schema for table: ${table}`);
    assertJson(document, table);
    if (!document || typeof document !== "object" || Array.isArray(document)) throw new Error(`${table}: expected a JSON object`);
    for (const name of Object.keys(document)) {
      const field = entry.fields.get(name);
      if (!field) throw new Error(`${table}.${name}: unknown input field`);
      if (field.protected) throw new Error(`${table}.${name}: protected input field`);
    }
    for (const [name, field] of entry.nestedFields) {
      if (field.protected) visitPath(structuredClone(document), name.split("."), () => { throw new Error(`${table}.${name}: protected input field`); });
    }
    if (!entry.validator(document)) throw new Error(`Invalid ${table} input: ${ajv.errorsText(entry.validator.errors)}`);
    return entry;
  }

  function convert(entry, document) {
    const references = [];
    const bound = Object.fromEntries(Object.entries(document).map(([name, value]) => [name, convertType(entry.fields.get(name).binding, value, [name], references)]));
    for (const [name, field] of entry.nestedFields) {
      visitPath(structuredClone(document), name.split("."), (value, path) => {
        const converted = convertType(field.binding, value, path, references);
        let parent = bound;
        for (const key of path.slice(0, -1)) parent = parent[key];
        parent[path.at(-1)] = converted;
        return value;
      });
    }
    return { bound, references: [...new Map(references.map(reference => [JSON.stringify(reference.path), reference])).values()] };
  }

  function prepare(table, document) {
    const { bound, references } = convert(input(table, document), document);
    return { content: bound, references };
  }

  return {
    tables,
    prepare,
    validate(table, document) { convert(input(table, document), document); return document; },
    bind(table, document) { return convert(input(table, document), document).bound; },
    references(table, document) { return convert(input(table, document), document).references; },
  };
}

module.exports = { createModel, recordId };
