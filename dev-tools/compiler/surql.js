function splitStatements(source) {
  return splitStatementsWithLocations(source).map((entry) => entry.source);
}

function sourceLocation(source, offset) {
  const lineStarts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") lineStarts.push(index + 1);
  }
  return locationFromLineStarts(source.length, lineStarts, offset);
}

function locationFromLineStarts(length, lineStarts, offset) {
  const bounded = Math.max(0, Math.min(length, offset));
  let low = 0;
  let high = lineStarts.length;
  while (low + 1 < high) {
    const middle = (low + high) >> 1;
    if (lineStarts[middle] <= bounded) low = middle;
    else high = middle;
  }
  return { offset: bounded, line: low + 1, column: bounded - lineStarts[low] + 1 };
}

function splitStatementsWithLocations(source) {
  const statements = [];
  let start = 0;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  let depth = 0;
  const lineStarts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") lineStarts.push(index + 1);
  }

  const addStatement = (end) => {
    const statement = source.slice(start, end).trim();
    if (!statement) return;
    let offset = start;
    while (offset < end) {
      while (offset < end && /\s/.test(source[offset])) offset += 1;
      if (source.startsWith("--", offset)) {
        const newline = source.indexOf("\n", offset + 2);
        offset = newline < 0 || newline >= end ? end : newline + 1;
        continue;
      }
      if (source.startsWith("/*", offset)) {
        const close = source.indexOf("*/", offset + 2);
        offset = close < 0 || close >= end ? end : close + 2;
        continue;
      }
      break;
    }
    statements.push({ source: statement, startOffset: start, endOffset: end,
      ...locationFromLineStarts(source.length, lineStarts, offset) });
  };

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === "-" && next === "-") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index += 1;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") quote = char;
    else if (char === "{" || char === "(" || char === "[") depth += 1;
    else if (char === "}" || char === ")" || char === "]") depth -= 1;
    else if (char === ";" && depth === 0) {
      addStatement(index + 1);
      start = index + 1;
    }
  }
  addStatement(source.length);
  return statements;
}

// Transform executable text without rewriting quoted values or comments.
function mapSqlCode(source, transform, literal = (value) => value) {
  const pattern = /'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"|`(?:\\[\s\S]|[^`\\])*`|--[^\r\n]*|\/\*[\s\S]*?\*\//g;
  let result = '', cursor = 0;
  for (const match of source.matchAll(pattern)) {
    result += transform(source.slice(cursor, match.index)) + literal(match[0]);
    cursor = match.index + match[0].length;
  }
  return result + transform(source.slice(cursor));
}

function sqlCode(source) {
  return mapSqlCode(source, (value) => value, (value) => ' '.repeat(value.length));
}

function splitTopLevel(value, separator = ",") {
  const parts = [];
  let start = 0;
  let quote = null;
  let depth = 0;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quote) {
      if (char === quote && value[index - 1] !== "\\") quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") quote = char;
    else if (char === "(" || char === "[" || char === "{") depth += 1;
    else if (char === ")" || char === "]" || char === "}") depth -= 1;
    else if (char === separator && depth === 0) {
      parts.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(value.slice(start).trim());
  return parts.filter(Boolean);
}

function findTopLevelKeyword(source, keyword, fromIndex = 0) {
  const upperKeyword = keyword.toUpperCase();
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  let depth = 0;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === "-" && next === "-") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index += 1;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
      continue;
    }
    if (char === "{" || char === "(" || char === "[") {
      depth += 1;
      continue;
    }
    if (char === "}" || char === ")" || char === "]") {
      depth -= 1;
      continue;
    }
    if (index < fromIndex || depth !== 0) continue;
    if (source.slice(index, index + keyword.length).toUpperCase() !== upperKeyword) continue;
    const before = source[index - 1];
    const after = source[index + keyword.length];
    if ((!before || /\s/.test(before)) && (!after || !/[A-Za-z0-9_]/.test(after))) {
      return index;
    }
  }
  return -1;
}

function extractClauseExpression(statement, clause, followingClauses = []) {
  const clauseIndex = findTopLevelKeyword(statement, clause);
  if (clauseIndex < 0) return null;
  const expressionStart = clauseIndex + clause.length;
  let expressionEnd = statement.length;
  for (const nextClause of followingClauses) {
    const index = findTopLevelKeyword(statement, nextClause, expressionStart);
    if (index >= 0 && index < expressionEnd) expressionEnd = index;
  }
  return statement
    .slice(expressionStart, expressionEnd)
    .replace(/;\s*$/, "")
    .trim() || null;
}

function parseRecordType(fieldDefinition) {
  const match = /\bTYPE\s+([\s\S]*?)(?=\s+(?:DEFAULT|VALUE|COMPUTED|ASSERT|REFERENCE|READONLY|PERMISSIONS|COMMENT|FLEXIBLE)\b|\s*;)/i.exec(fieldDefinition);
  if (!match) return null;
  const type = match[1].trim();
  const recordMatch = /^(?:none\s*\|\s*)?(?:option\s*<\s*)?(?:(array|set)\s*<\s*)?record(?:\s*<([^>]+)>)?/i.exec(type);
  if (!recordMatch) return null;
  return {
    type,
    targets: (recordMatch[2] || "").split("|").map((target) => target.trim()).filter(Boolean),
    isArray: Boolean(recordMatch[1]),
    isOptional: /\boption\s*</i.test(type) || /\bnone\b/i.test(type),
  };
}

module.exports = {
  mapSqlCode,
  sqlCode,
  extractClauseExpression,
  findTopLevelKeyword,
  parseRecordType,
  splitStatements,
  splitStatementsWithLocations,
  sourceLocation,
  splitTopLevel,
};
