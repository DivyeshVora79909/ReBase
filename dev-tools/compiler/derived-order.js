'use strict';

const { splitTopLevel, sqlCode } = require('./surql');
const { functions } = require('./observed-reads');
const { valueExpression } = require('./fields');

function closeCall(code, open) {
  let depth = 0;
  for (let index = open; index < code.length; index += 1) {
    if (code[index] === '(') depth += 1;
    else if (code[index] === ')' && --depth === 0) return index;
  }
  throw new Error('Unclosed helper call while resolving derived fields');
}

function calls(source) {
  const code = sqlCode(source), found = [];
  for (const match of code.matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)) {
    const open = code.indexOf('(', match.index + match[0].length - 1);
    const close = closeCall(code, open);
    found.push({ name: match[1], args: splitTopLevel(code.slice(open + 1, close)) });
  }
  return found;
}

function parameters(fn) {
  return [...sqlCode(fn.params).matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)\s*:/g)].map(match => `$${match[1]}`);
}

function origin(expression, environment) {
  const code = sqlCode(expression).trim();
  const match = code.match(/^(\$this|\$[A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*))?$/);
  if (!match) return null;
  const base = match[1] === '$this' ? { row: true, path: [] } : environment.get(match[1]);
  if (!base) return null;
  return { row: base.row, path: [...base.path, ...(match[2] ? match[2].split('.') : [])] };
}

function localDependencies(expression, byName, declared, subject) {
  const dependencies = new Set();

  const inspect = (source, environment, active) => {
    const code = sqlCode(source);
    for (const match of code.matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)/g)) {
      const variable = `$${match[1]}`;
      const base = variable === '$this' ? { row: true, path: [] } : environment.get(variable);
      if (!base?.row) continue;
      const field = base.path[0] || match[2].split('.')[0];
      if (byName.has(field)) dependencies.add(field);
    }

    for (const call of calls(source)) {
      const helper = declared.get(call.name);
      if (!helper) {
        const opaqueRow = call.args.some(argument => {
          const actual = origin(argument, environment);
          return actual?.row && actual.path.length === 0;
        });
        if (opaqueRow) {
          throw new Error(`${subject}: cannot infer derived-field dependencies through opaque helper ${call.name}; define the helper in schema source or pass explicit field values`);
        }
        continue;
      }
      if (active.includes(call.name)) {
        throw new Error(`${subject}: recursive helper call is outside derived dependency analysis: ${[...active, call.name].join(' -> ')}`);
      }
      const names = parameters(helper), child = new Map();
      for (let index = 0; index < Math.min(names.length, call.args.length); index += 1) {
        const actual = origin(call.args[index], environment);
        if (actual) child.set(names[index], actual);
        else if (/\$this|\$[A-Za-z_][A-Za-z0-9_]*/.test(call.args[index])
            && new RegExp(`${names[index]}\\s*(?:\\.|\\[)`).test(sqlCode(helper.body))) {
          throw new Error(`${subject}: cannot infer local dependencies through argument ${index + 1} of ${call.name}; pass the row or a field reference directly`);
        }
      }
      const rowParameters = new Set(names.filter(name => child.get(name)?.row));
      for (const parameter of rowParameters) {
        if (new RegExp(`${parameter.replace('$', '\\$')}\\s*\\[`).test(sqlCode(helper.body))) {
          throw new Error(`${subject}: dynamic field access through ${call.name}${parameter} is outside derived dependency analysis`);
        }
      }
      inspect(helper.body, child, [...active, call.name]);
    }
  };

  inspect(expression, new Map(), []);
  return [...dependencies].sort((a, b) => a.localeCompare(b));
}

function resolveDerivedOrder(table, functionSource = '') {
  const reactive = [...table.fields.values()].filter(field => field.reactive);
  const byName = new Map(reactive.map(field => [field.name, field]));
  const declared = functions(functionSource);
  const dependencies = new Map();
  for (const field of reactive) {
    const expression = valueExpression(field);
    if (!expression) throw new Error(`${table.name}.${field.name}: @rebase-derived requires VALUE`);
    dependencies.set(field.name, localDependencies(expression, byName, declared, `${table.name}.${field.name}`));
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

module.exports = { resolveDerivedOrder, localDependencies };
