'use strict';

const { splitStatements, splitTopLevel, sqlCode, mapSqlCode } = require('./surql');

const GENERATED_PURE_HELPERS = new Set(['fn::tree::member', 'fn::tree::ordered_member', 'fn::tree::int_member',
  'fn::tree::interval_member', 'fn::dependency::value', 'fn::value::at',
  'fn::tree::empty', 'fn::tree::value', 'fn::tree::combine', 'fn::tree::coalesce']);
const WRITE_STATEMENTS = new Set(['CREATE', 'INSERT', 'UPDATE', 'UPSERT', 'DELETE', 'RELATE',
  'DEFINE', 'ALTER', 'REMOVE', 'REBUILD', 'ACCESS', 'BEGIN', 'COMMIT', 'CANCEL',
  'USE', 'OPTION', 'LIVE', 'KILL', 'SLEEP']);
const TRANSACTION_STATEMENTS = new Set(['BEGIN', 'COMMIT', 'CANCEL']);

function reactiveEffect(source) {
  // Token boundaries distinguish statements/subqueries from $row.update,
  // { update: ... }, table:UPDATE and qualified function names. Reuse the SQL
  // masking of strings, quoted identifiers and comments. Retain a literal token so
  // a quoted mutation target cannot disappear during the boundary check.
  const hidden = value => '0' + ' '.repeat(value.length - 1);
  const code = mapSqlCode(source, value => value, value => /^(?:--|\/\*)/.test(value)
    ? ' '.repeat(value.length) : hidden(value)).replace(/⟨[^⟩]*⟩/g, hidden);
  for (const match of code.matchAll(/\bfn::/g)) {
    if (!/^fn::[A-Za-z_][\w:]*\s*\(/.test(code.slice(match.index))) return 'opaque custom helper reference';
  }
  const tokens = [...code.matchAll(/\$?[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)*|[^\s]/g)];
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index], word = token[0], upper = word.toUpperCase();
    const previous = tokens[index - 1]?.[0], next = tokens[index + 1]?.[0];
    if (next === '(' && (/^(?:http|api)::/i.test(word) || upper === 'FUNCTION' || word.startsWith('$'))) {
      return `opaque or effectful call ${word}`;
    }
    if (!WRITE_STATEMENTS.has(upper) || next === ':' || previous === '.') continue;
    if (previous === ':' && tokens[index - 1].index + 1 === token.index) continue;
    const transactionEnd = TRANSACTION_STATEMENTS.has(upper) && (!next || next === ';');
    if ((!transactionEnd && !/^(?:\$?[A-Za-z_0-9]|[[(])/.test(next || '')) || /^(?:AS|FROM|END)$/i.test(next)) continue;
    // SQL statements can appear in nested expression positions as well as at
    // the start of a block. SELECT projection/target names are not statements.
    if (!previous || /^[;({\[,:=|?}]$/.test(previous) || /^(?:RETURN|THEN|ELSE|IF)$/i.test(previous)) {
      return `${upper} statement`;
    }
  }
  return null;
}

function closeDelimiter(code, start, opening, closing) {
  let depth = 0;
  for (let index = start; index < code.length; index++) {
    if (code[index] === opening) depth++;
    if (code[index] === closing && --depth === 0) return index;
  }
  throw new Error('Unclosed SurrealQL function declaration');
}

function functions(source) {
  const result = new Map();
  for (const statement of splitStatements(source)) {
    const code = sqlCode(statement);
    const declaration = /^\s*DEFINE\s+FUNCTION\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?(fn::[A-Za-z_][\w:]*)\s*\(/i.exec(code);
    if (!declaration) continue;
    const name = declaration[1];
    const paramsStart = declaration.index + declaration[0].lastIndexOf('(');
    const paramsEnd = closeDelimiter(code, paramsStart, '(', ')');
    const bodyStart = code.indexOf('{', paramsEnd);
    if (bodyStart < 0) throw new Error(`${name}: function requires a body`);
    const bodyEnd = closeDelimiter(code, bodyStart, '{', '}');
    const body = statement.slice(bodyStart + 1, bodyEnd);
    result.set(name, { name, params: statement.slice(paramsStart + 1, paramsEnd), body,
      calls: new Set([...sqlCode(body).matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)].map(match => match[1])) });
  }
  return result;
}

function resolveReadOnly(source) {
  const declared = functions(source);
  const validate = (expression, subject, { allowLocalTreeReads = false, allowLocalRecordReads = false, allowRecordReads = false } = {}) => {
    const seen = new Set();
    const origin = (argument, bindings) => {
      const value = sqlCode(argument).trim();
      if (value === '$this') return 'row';
      if (value === '$this.id') return 'id';
      const match = /^(\$\w+)(\.id)?$/.exec(value);
      if (!match) return null;
      const base = bindings.get(match[1]);
      return match[2] ? base === 'row' ? 'id' : null : base;
    };
    const visit = (body, caller, bindings = new Map()) => {
      const effect = reactiveEffect(body);
      if (effect) throw new Error(`${subject}: reactive expressions must be read-only; ${effect}${caller ? ` in ${caller}` : ''}`);
      const code = sqlCode(body);
      for (const match of code.matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)) {
        const name = match[1];
        const start = code.indexOf('(', match.index);
        const end = closeDelimiter(code, start, '(', ')');
        const args = splitTopLevel(body.slice(start + 1, end));
        if (/^fn::tree::(?:read|read_value|before|range|get|load|seek|find|select|page|rank)$/.test(name)) {
          if (allowLocalTreeReads && ['fn::tree::read', 'fn::tree::read_value'].includes(name)
              && origin(args[0] || '', bindings) === 'id') continue;
          throw new Error(`${subject}: declare an @rebase-dependency and consume fn::dependency::value; ${name} is an undeclared ordered read`);
        }
        if (name === 'fn::record::read_value') {
          if (allowRecordReads || allowLocalRecordReads && origin(args[0] || '', bindings) === 'id') continue;
          throw new Error(`${subject}: declare a typed reference dependency with @rebase-depends for ${name}`);
        }
        const fn = declared.get(name);
        const params = fn ? [...sqlCode(fn.params).matchAll(/(\$\w+)\s*:/g)].map(match => match[1]) : [];
        const child = new Map(params.map((param, index) => [param, origin(args[index] || '', bindings)]));
        const identity = JSON.stringify([name, [...child]]);
        if (seen.has(identity)) continue;
        seen.add(identity);
        if (fn) visit(fn.body, name, child);
        else if (!GENERATED_PURE_HELPERS.has(name)) {
          throw new Error(`${subject}: reactive expressions must be read-only; cannot inspect undeclared helper ${name}${caller ? ` called by ${caller}` : ''}`);
        }
      }
    };
    visit(expression);
  };
  return { declared, validate };
}

module.exports = { functions, reactiveEffect, resolveReadOnly };
