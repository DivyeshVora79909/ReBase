'use strict';

const { splitStatements, sqlCode, mapSqlCode } = require('./surql');

const INTRINSICS = new Map([
  ['fn::tree::read_value', 'fn::reads::tree'],
  ['fn::record::read_value', 'fn::reads::record'],
  ['fn::tree::before', 'fn::reads::before'],
  ['fn::tree::range', 'fn::reads::range'],
]);
const PRIVATE_TABLES = new Set(['rebase_read', 'rebase_read_frame', 'rebase_read_group', 'rebase_read_lock', 'rebase_read_stage']);
// These constructors are emitted later, rather than supplied by the project.
// All other custom helpers must have a body available for inspection.
const GENERATED_PURE_HELPERS = new Set(['fn::tree::member', 'fn::tree::ordered_member', 'fn::tree::int_member',
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

function resolveObservedReads(source) {
  const declared = functions(source), tracked = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const [name, fn] of declared) {
      if (name.startsWith('fn::reads::') || INTRINSICS.has(name) || tracked.has(name)) continue;
      if ([...fn.calls].some(call => INTRINSICS.has(call) || tracked.has(call))) {
        tracked.add(name); changed = true;
      }
    }
  }
  const cloneName = name => `fn::reads::captured::${name.slice(4)}`;
  const rewrite = (source, observer) => {
    const code = sqlCode(source), edits = [];
    for (const match of code.matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)) {
      const name = match[1];
      const replacement = INTRINSICS.get(name) || (tracked.has(name) && cloneName(name));
      if (!replacement) continue;
      const afterOpen = match.index + match[0].length;
      const empty = /^\s*\)/.test(code.slice(afterOpen));
      edits.push({ start: match.index, end: afterOpen, value: `${replacement}(${observer}${empty ? '' : ', '}` });
    }
    for (const edit of edits.reverse()) source = source.slice(0, edit.start) + edit.value + source.slice(edit.end);
    return source;
  };
  const generated = [...tracked].sort().map(name => {
    const fn = declared.get(name);
    if (/\$__rebase_observer\b/.test(sqlCode(fn.params + fn.body))) {
      throw new Error(`${name}: $__rebase_observer is reserved for automatic read capture`);
    }
    return `DEFINE FUNCTION OVERWRITE ${cloneName(name)}($__rebase_observer: object${fn.params.trim() ? ', ' + fn.params : ''}) {\n${rewrite(fn.body, '$__rebase_observer')}\n} PERMISSIONS NONE;`;
  }).join('\n');
  const validate = (source, subject) => {
    const seen = new Set();
    const visit = (body, caller) => {
      const effect = reactiveEffect(body);
      if (effect) throw new Error(`${subject}: reactive expressions must be read-only; ${effect}${caller ? ` in ${caller}` : ''}`);
      for (const match of sqlCode(body).matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)) {
        const name = match[1];
        if (INTRINSICS.has(name)) continue;
        if (/^fn::tree::(?:read|get|load|seek|find|select|page|rank)$/.test(name)) {
          throw new Error(`${subject}: use fn::tree::read_value for an ordered calculation; ${name} does not capture a logical read`);
        }
        if (seen.has(name)) continue;
        seen.add(name);
        if (declared.has(name)) visit(declared.get(name).body, name);
        else if (!GENERATED_PURE_HELPERS.has(name)) {
          throw new Error(`${subject}: reactive expressions must be read-only; cannot inspect undeclared helper ${name}${caller ? ` called by ${caller}` : ''}`);
        }
      }
    };
    visit(source);
  };
  const uses = source => [...sqlCode(source).matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)]
    .some(match => INTRINSICS.has(match[1]) || tracked.has(match[1]));
  return { declared, tracked, rewrite, generated, validate, uses };
}

module.exports = { INTRINSICS, PRIVATE_TABLES, functions, resolveObservedReads };
