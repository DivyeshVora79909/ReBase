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
    // Keep literals in their argument positions. Masked strings are useful for
    // locating calls, but splitTopLevel drops empty (masked) arguments.
    const args = splitTopLevel(source.slice(open + 1, close));
    let cursor = open + 1;
    const starts = args.map(argument => {
      const start = source.indexOf(argument, cursor);
      cursor = start + argument.length;
      return start;
    });
    found.push({ name: match[1], args, starts });
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
    const directArguments = new Set();
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
        if (actual) {
          child.set(names[index], actual);
          if (actual.path.length === 0) {
            const offset = sqlCode(call.args[index]).search(/\$[A-Za-z_]/);
            directArguments.add(call.starts[index] + offset);
          }
        }
      }
      inspect(helper.body, child, [...active, call.name]);
    }

    // Whole local rows may only be projected statically or forwarded directly
    // to a declared helper. Reject aliases, wrappers and escaping rows until a
    // scope-aware analyser can prove their dependencies. Never guess an order.
    for (const match of code.matchAll(/\$[A-Za-z_][A-Za-z0-9_]*/g)) {
      const base = match[0] === '$this' ? { row: true, path: [] } : environment.get(match[0]);
      if (!base?.row || base.path.length > 0) continue;
      const suffix = code.slice(match.index + match[0].length);
      const field = /^\.([A-Za-z_][A-Za-z0-9_]*)/.exec(suffix)?.[1];
      if (field) {
        if (byName.has(field)) dependencies.add(field);
      } else if (!directArguments.has(match.index)) {
        throw new Error(`${subject}: cannot infer derived-field dependencies for ${match[0]} in ${active.at(-1) || 'VALUE'}; use a static field or pass the row directly to a declared helper (whole-row aliases, wrappers and dynamic access are unsupported)`);
      }
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
