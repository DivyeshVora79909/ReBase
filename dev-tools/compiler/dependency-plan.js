'use strict';
const { valueExpression } = require('./fields');
const { localDependencies } = require('./derived-order');
const { functions } = require('./read-only');

function dependencyPlan(schema, model, functionSource = '') {
  const tables = {};
  const declared = functions(functionSource);
  for (const [name, table] of schema.tables) {
    const queries = model.dependencyModel.declarations.filter(query => query.table === name);
    const calculations = (model.derivedOrder.get(name) || []).map(field => ({
      field: field.name, phase: field.dependency?.phase || 'refresh', expression: valueExpression(field),
      inputs: localDependencies(valueExpression(field), table.fields, declared, `${name}.${field.name}`),
      ...(field.location?.relative ? { source: field.location.relative, line: field.location.line } : {}),
    }));
    const references = model.routes.filter(route => route.table === name).map(route => ({
      reference: route.reference, table: route.target, fields: [...route.fields].sort(), consumers: [...route.consumers].sort(),
    }));
    const roots = model.trees.roots.filter(root => root.table === name).map(root => ({ slot: root.slot, key: root.keyType }));
    if (!calculations.length && !references.length && !roots.length && !table.treeMembers && !table.validate) continue;
    tables[name] = {
      calculations, references,
      queries: queries.map(query => ({ field: query.field, operation: query.kind, phase: query.phase, node: query.node,
        sources: query.sources.map(source => ({ table: source.table, root: source.slot, index: source.index })) })),
      maximumQuerySlots: queries.length, roots,
      ...(table.treeMembers ? { memberships: table.treeMembers } : {}),
      ...(table.validate ? { invariant: table.validate } : {}),
      ...(table.requiredOutputs ? { requiredOutputs: table.requiredOutputs } : {}),
    };
  }
  return { version: 1, tables };
}

function explainDependency(plan, subject) {
  if (subject === '*') return plan;
  const [table, field, extra] = String(subject).split('.');
  const result = plan.tables[table];
  if (!result || extra) throw new Error(`Unknown dependency subject: ${subject}; use a table or table.field`);
  if (!field) return { table, ...result };
  const calculation = result.calculations.find(item => item.field === field);
  if (!calculation) throw new Error(`Unknown calculation: ${subject}`);
  const required = new Set();
  const visit = name => {
    if (required.has(name)) return;
    required.add(name);
    for (const input of result.calculations.find(item => item.field === name)?.inputs || []) visit(input);
  };
  visit(field);
  return { table, ...calculation, queries: result.queries.filter(item => required.has(item.field)),
    evaluation: result.calculations.filter(item => required.has(item.field)).map(item => item.field),
    references: result.references.filter(item => item.consumers.some(name => required.has(name))) };
}

module.exports = { dependencyPlan, explainDependency };
