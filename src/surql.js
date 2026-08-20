function splitStatements(source) {
  const statements = [];
  let start = 0;
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
    if (char === "'" || char === '"' || char === "`") quote = char;
    else if (char === "{" || char === "(" || char === "[") depth += 1;
    else if (char === "}" || char === ")" || char === "]") depth -= 1;
    else if (char === ";" && depth === 0) {
      const statement = source.slice(start, index + 1).trim();
      if (statement) statements.push(statement);
      start = index + 1;
    }
  }
  const remainder = source.slice(start).trim();
  if (remainder) statements.push(remainder);
  return statements;
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

function scopeSource(source, namespace, database) {
  const scoped = `USE NS ${namespace} DB ${database};`;
  const usePattern = /\bUSE\s+NS\s+[^\s;]+\s+DB\s+[^\s;]+\s*;/gi;
  if (usePattern.test(source)) return source.replace(usePattern, scoped);
  return `${scoped}\n\n${source}`;
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
  extractClauseExpression,
  findTopLevelKeyword,
  parseRecordType,
  scopeSource,
  splitStatements,
  splitTopLevel,
};
