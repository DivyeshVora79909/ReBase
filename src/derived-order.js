'use strict';

const { sqlCode } = require('./surql');
const { valueExpression } = require('./fields');

function resolveDerivedOrder(table) {
  const reactive = [...table.fields.values()].filter(field => field.reactive);
  const byName = new Map(reactive.map(field => [field.name, field]));
  const dependencies = new Map();
  for (const field of reactive) {
    const expression = valueExpression(field);
    if (!expression) throw new Error(`${table.name}.${field.name}: @rebase-derived requires VALUE`);
    const local = new Set([...sqlCode(expression).matchAll(/\$this\.([A-Za-z_][A-Za-z0-9_]*)/g)]
      .map(match => match[1]).filter(name => byName.has(name)));
    dependencies.set(field.name, [...local].sort((a, b) => a.localeCompare(b)));
  }

  const ordered = [];
  const active = [];
  const visited = new Set();
  const visit = name => {
    if (visited.has(name)) return;
    const cycleAt = active.indexOf(name);
    if (cycleAt >= 0) {
      const cycle = [...active.slice(cycleAt), name];
      throw new Error(`${table.name}: derived field cycle ${cycle.join(' -> ')}`);
    }
    active.push(name);
    for (const dependency of dependencies.get(name) || []) visit(dependency);
    active.pop();
    visited.add(name);
    ordered.push(byName.get(name));
  };
  for (const name of [...byName.keys()].sort((a, b) => a.localeCompare(b))) visit(name);
  return ordered;
}

module.exports = { resolveDerivedOrder };
