const { extractClauseExpression, findTopLevelKeyword, parseRecordType, sqlCode } = require('./surql');

const SYSTEM_FIELDS = new Set([
  'id', 'created_at', 'updated_at', 'created_by', 'updated_by', 'system_ping',
  'tenant', 'read_by', 'rebase_reader_sources', 'rebase_dependency_sources', 'rebase_derived_ready', 'rebase_dependency_revision',
]);
const VALUE_END = ['ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT'];

function valueExpression(field) {
  const clauses = field.definition.replace(/^\s*(?:--[^\n]*\n\s*)*DEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?\S+\s+ON\s+(?:TABLE\s+)?\S+\s+/i, '');
  return extractClauseExpression(clauses, 'VALUE', VALUE_END);
}

function businessFields(table) {
  return [...table.fields.values()].filter((field) => {
    if (SYSTEM_FIELDS.has(field.name) || field.computed || field.system || field.reactive
        || field.treeRoot || field.treeNode || field.effectOutput) return false;
    // A VALUE normalizer over $value is still a client input.
    return !field.derived || /\$value\b/.test(sqlCode(valueExpression(field) || ''));
  }).map((field) => field.name);
}

function changedFields(fields, before = '$before', after = '$after') {
  return [...new Set(fields)].map((field) => `${before}.${field} != ${after}.${field}`).join(' OR ') || 'false';
}

function fieldSelectPolicy(field) {
  if (field.privateDependency) return 'NONE';
  const policy = extractClauseExpression(field.definition, 'PERMISSIONS', ['COMMENT']);
  if (!policy || /^FULL$/i.test(policy)) return 'WHERE true';
  if (/^NONE$/i.test(policy)) return 'NONE';
  let start = findTopLevelKeyword(policy, 'FOR');
  while (start >= 0) {
    const next = findTopLevelKeyword(policy, 'FOR', start + 3);
    const clause = policy.slice(start, next < 0 ? undefined : next).trim();
    const match = /^FOR\s+([a-z_,\s]+?)\s+(WHERE\b[\s\S]*|NONE|FULL)$/i.exec(clause);
    if (match && match[1].toLowerCase().split(/\s*,\s*/).includes('select')) return match[2];
    start = next;
  }
  return 'WHERE true';
}

const TYPE_CLAUSES = ["DEFAULT", "VALUE", "COMPUTED", "ASSERT", "REFERENCE", "READONLY", "PERMISSIONS", "COMMENT", "FLEXIBLE"];

function fieldClauses(definition) {
  return String(definition || "").replace(/^[\s\S]*?\bDEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?\S+\s+ON\s+(?:TABLE\s+)?[A-Za-z0-9_]+/i, "");
}

function compileField(field) {
  const clauses = fieldClauses(field.definition);
  const type = extractClauseExpression(clauses, "TYPE", TYPE_CLAUSES) || "any";
  // businessFields applies the same distinction: VALUE over $value
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

module.exports = { SYSTEM_FIELDS, VALUE_END, businessFields, changedFields, valueExpression, fieldSelectPolicy, compileField, compileType };
