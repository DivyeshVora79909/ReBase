"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { compileField, SYSTEM_FIELDS, valueExpression } = require("./fields");
const { functions } = require("./read-only");
const { parseSchema } = require("./schema");
const { extractClauseExpression, splitStatementsWithLocations, sqlCode } = require("./surql");

const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const sorted = values => [...new Set(values)].sort(compare);
const MONOID = { identity: "fn::tree::empty", value: "fn::tree::value", combine: "fn::tree::combine" };

function location(value) {
  return value?.relative ? { group: value.group || "project", file: value.relative, line: value.line } : null;
}

// Use the same parsed native types as fixture binding. A string pattern in a
// JSON Schema is validation, not a declaration of a database relationship.
function referenceType(binding) {
  const references = [];
  function visit(type, array = false, optional = false) {
    if (type.kind === "record") references.push({ ...type.record, array, optional });
    if (type.item) visit(type.item, array || ["array", "set"].includes(type.kind), optional || type.kind === "option");
    for (const alternative of type.alternatives || []) visit(alternative, array, optional);
  }
  visit(binding);
  if (!references.length) return null;
  return {
    targets: sorted(references.flatMap(value => value.targets)),
    many: references.some(value => value.array),
    optional: references.some(value => value.optional),
    unrestricted: references.some(value => !value.targets.length),
  };
}

function fieldCatalog(field, authored, inputSchema) {
  const metadata = compileField({ ...field, ...authored });
  const expression = valueExpression(metadata);
  const kind = metadata.treeRoot ? "root" : metadata.treeNode ? "member"
    : metadata.privateDependency ? "query"
    : metadata.effectOutput || metadata.operationOutput ? "output"
    : metadata.system || SYSTEM_FIELDS.has(metadata.name) ? "system"
    : metadata.computed ? "computed"
    : metadata.reactive || metadata.derived && !/\$value\b/.test(sqlCode(expression || "")) ? "derived" : "input";
  const clauses = metadata.definition.replace(/^[\s\S]*?\bDEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?\S+\s+ON\s+(?:TABLE\s+)?\S+\s*/i, "");
  return {
    name: metadata.name, type: metadata.type, kind,
    generated: !authored || Boolean(authored.internal),
    publicInput: Object.hasOwn(inputSchema?.properties || {}, metadata.name),
    required: (inputSchema?.required || []).includes(metadata.name),
    readonly: /\bREADONLY\b/.test(sqlCode(clauses)),
    reference: referenceType(metadata.binding),
    expression,
    assertion: extractClauseExpression(clauses, "ASSERT", ["REFERENCE", "READONLY", "PERMISSIONS", "COMMENT"]),
    permissions: extractClauseExpression(clauses, "PERMISSIONS", ["COMMENT"]),
    comment: metadata.comment || "",
    source: location(authored?.location),
  };
}

function functionCatalog(materials) {
  const result = new Map();
  const files = [...materials.files, {
    group: "compiler", relative: "temporal.surql",
    source: fs.readFileSync(path.join(__dirname, "temporal.surql"), "utf8"),
    monoid: true,
  }];
  for (const file of files) {
    for (const statement of splitStatementsWithLocations(file.source)) {
      for (const fn of functions(statement.source).values()) {
        if (file.monoid && !Object.values(MONOID).includes(fn.name)) continue;
        result.set(fn.name, {
          name: fn.name, parameters: fn.params, body: fn.body.trim(), calls: sorted(fn.calls),
          source: { group: file.group, file: file.relative, line: statement.line },
        });
      }
    }
  }
  return [...result.values()].sort((a, b) => compare(a.name, b.name));
}

/** A projection of compiler facts, never a second schema or an executable UI DSL. */
function developerCatalog(compiled, { project, schemas = new Map() } = {}) {
  // Native common/generated fields belong in the inventory too. Keep authored
  // metadata for semantic ordering and locations; the emitted bundle supplies
  // fields added by generators. No bundle or process configuration is exported.
  const native = parseSchema(compiled.bundle, compiled.bundle);
  const views = new Map([...compiled.schema.views, ...native.views].map(view => [view.name, view]));
  const definitions = new Map();
  const indexes = new Map();
  for (const { source } of splitStatementsWithLocations(compiled.bundle)) {
    const code = sqlCode(source);
    const table = /^\s*DEFINE\s+TABLE\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?(\w+)/i.exec(code);
    if (table) definitions.set(table[1], { source, code });
    const index = /^\s*DEFINE\s+INDEX\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?(\w+)\s+ON\s+(?:TABLE\s+)?(\w+)/i.exec(code);
    if (index) {
      if (!indexes.has(index[2])) indexes.set(index[2], new Map());
      indexes.get(index[2]).set(index[1], { name: index[1], definition: source.trim() });
    }
  }
  const names = sorted([...native.tables.keys(), ...definitions.keys(), ...views.keys()]);
  const tables = names.map(name => {
    const authored = compiled.schema.tables.get(name);
    const emitted = native.tables.get(name);
    const definition = definitions.get(name);
    const view = views.get(name);
    const inputSchema = schemas.get(name)?.schema || schemas.get(name) || null;
    const fields = new Map([...(authored?.fields || []), ...(authored?.nestedFields || [])]);
    for (const [key, field] of [...(emitted?.fields || []), ...(emitted?.nestedFields || [])]) {
      if (!fields.has(key)) fields.set(key, field);
    }
    const kind = view || /\bAS\s+SELECT\b/i.test(definition?.code || "") ? "view"
      : /\bTYPE\s+RELATION\b/i.test(definition?.code || "") ? "relation" : "table";
    const source = location(authored?.location);
    return {
      name, kind,
      group: source?.group || (compiled.analysis.systemTables.has(name) ? "framework" : "project"),
      source, comment: authored?.comment || "",
      schema: inputSchema,
      fields: [...fields.values()].map(field => fieldCatalog(field,
        authored?.fields.get(field.name) || authored?.nestedFields?.get(field.name), inputSchema)),
      dependencies: compiled.dependencyPlan.tables[name] || null,
      indexes: [...(indexes.get(name)?.values() || [])].sort((a, b) => compare(a.name, b.name)),
      view: kind === "view" ? {
        source: view?.sourceTable || null,
        groups: view?.groupKeys || [],
        projections: [...(view?.projections || [])].map(([field, expression]) => ({ field, expression })),
        definition: view?.statement || definition?.source || "",
      } : null,
      effect: authored?.operation || (authored?.effectProcess
        ? { mode: authored.effectProcess, events: authored.effectEvents, adapters: authored.effectAdapters } : null),
    };
  });
  const trees = compiled.temporalModel.trees;
  return {
    format: "rebase-devtools", version: 1, project: project || "design",
    tables,
    roots: trees.roots.map(root => ({
      id: root.name, table: root.table, field: root.slot, key: root.keyParts,
      unique: root.unique, generated: Boolean(root.field.internal),
      members: root.nodes.map(node => node.name).sort(compare),
    })).sort((a, b) => compare(a.id, b.id)),
    memberships: trees.nodes.map(node => ({
      id: node.name, table: node.table, field: node.slot, key: node.keyParts,
      roots: [...node.ownerNames].sort(compare), generated: Boolean(node.field.internal),
      reader: !node.field.treeNoReader,
      provider: compiled.schema.tables.get(node.table)?.treeMembers || null,
    })).sort((a, b) => compare(a.id, b.id)),
    functions: functionCatalog(compiled.materials), monoid: MONOID,
  };
}

module.exports = { developerCatalog, referenceType };
