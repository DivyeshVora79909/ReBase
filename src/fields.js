const { extractClauseExpression, findTopLevelKeyword, sqlCode } = require('./surql');

const SYSTEM_FIELDS = new Set([
  'id', 'created_at', 'updated_at', 'created_by', 'updated_by', 'system_ping',
  'readers_index', 'rebase_reader_sources', 'rebase_dependency_sources', 'rebase_derived_ready',
]);
const VALUE_END = ['ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT'];

function valueExpression(field) {
  return extractClauseExpression(field.definition, 'VALUE', VALUE_END);
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

module.exports = { SYSTEM_FIELDS, VALUE_END, businessFields, changedFields, valueExpression, fieldSelectPolicy };
