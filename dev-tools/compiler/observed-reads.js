'use strict';

const { splitStatements, sqlCode } = require('./surql');

const INTRINSICS = new Map([
  ['fn::tree::read_value', 'fn::reads::tree'],
  ['fn::record::read_value', 'fn::reads::record'],
  ['fn::tree::before', 'fn::reads::before'],
  ['fn::tree::range', 'fn::reads::range'],
]);
const PRIVATE_TABLES = new Set(['rebase_read', 'rebase_read_frame', 'rebase_read_group', 'rebase_read_lock', 'rebase_read_stage']);

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
    const visit = body => {
      for (const match of sqlCode(body).matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)) {
        const name = match[1];
        if (INTRINSICS.has(name)) continue;
        if (/^fn::tree::(?:read|get|load|seek|find|select|page|rank)$/.test(name)) {
          throw new Error(`${subject}: use fn::tree::read_value for an ordered calculation; ${name} does not capture a logical read`);
        }
        if (seen.has(name)) continue;
        seen.add(name);
        if (declared.has(name)) visit(declared.get(name).body);
      }
    };
    visit(source);
  };
  const uses = source => [...sqlCode(source).matchAll(/\b(fn::[A-Za-z_][\w:]*)\s*\(/g)]
    .some(match => INTRINSICS.has(match[1]) || tracked.has(match[1]));
  return { declared, tracked, rewrite, generated, validate, uses };
}

module.exports = { INTRINSICS, PRIVATE_TABLES, functions, resolveObservedReads };
