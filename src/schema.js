const { parseRecordType, splitStatements, splitTopLevel } = require("./surql");

function parseSchema(schemaSource, viewsSource) {
  const tables = new Map();
  for (const statement of splitStatements(schemaSource)) {
    const tableMatch = /\bDEFINE\s+TABLE\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_]+)/i.exec(statement);
    if (tableMatch && !/\bAS\s+SELECT\b/i.test(statement)) {
      const table = tables.get(tableMatch[1]) || { name: tableMatch[1], fields: new Map(), definitions: [] };
      table.definitions.push(statement);
      table.definition = statement;
      table.comment = [table.comment, extractComment(statement)].filter(Boolean).join(" ");
      table.audit = /@rebase-audit(?![-\w])/i.test(table.comment);
      tables.set(tableMatch[1], table);
    }
    const fieldMatch = /\bDEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_]+)\s+ON\s+(?:TABLE\s+)?([A-Za-z0-9_]+)/i.exec(statement);
    if (!fieldMatch) continue;
    const [, fieldName, tableName] = fieldMatch;
    if (!tables.has(tableName)) tables.set(tableName, { name: tableName, fields: new Map(), definitions: [] });
    const fieldComment = extractComment(statement);
    tables.get(tableName).fields.set(fieldName, {
      name: fieldName,
      definition: statement,
      recordType: parseRecordType(statement),
      comment: fieldComment,
      auditOmit: /@rebase-audit-omit\b/i.test(fieldComment),
      auditRedact: /@rebase-audit-redact\b/i.test(fieldComment),
    });
  }

  const views = [];
  for (const statement of splitStatements(viewsSource)) {
    const match = /\bDEFINE\s+TABLE\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?(v_[A-Za-z0-9_]+)\s+AS\s+SELECT\s+([\s\S]+?)\s+FROM\s+([A-Za-z0-9_]+)([\s\S]*?)\bGROUP\s+BY\s+([\s\S]+?);?$/i.exec(statement);
    if (!match) continue;
    const [, name, projectionSource, sourceTable, between, groupSource] = match;
    const projections = new Map();
    for (const projection of splitTopLevel(projectionSource)) {
      const alias = /^([\s\S]+?)\s+AS\s+([A-Za-z0-9_]+)$/i.exec(projection);
      if (alias) projections.set(alias[2], alias[1].trim());
      else if (/^[A-Za-z0-9_.]+$/.test(projection)) projections.set(projection.split(".").at(-1), projection);
    }
    views.push({
      name,
      sourceTable,
      statement,
      projections,
      groupKeys: splitTopLevel(groupSource.replace(/;$/, "")),
      hasWhere: /\bWHERE\b/i.test(between),
    });
  }
  return { tables, views, rawViews: viewsSource };
}

function extractComment(statement) {
  const match = /\bCOMMENT\s+(['"])([\s\S]*?)\1\s*;?\s*$/i.exec(statement);
  return match ? match[2] : "";
}

function resolveRecordTargets(schema, sourceTable, expression) {
  if (!/^[A-Za-z_][A-Za-z0-9_.]*$/.test(expression)) return [];
  let currentTables = [sourceTable];
  for (const segment of expression.split(".")) {
    const targets = new Set();
    for (const tableName of currentTables) {
      const field = schema.tables.get(tableName)?.fields.get(segment);
      for (const target of field?.recordType?.targets || []) targets.add(target);
    }
    if (!targets.size) return [];
    currentTables = [...targets];
  }
  return currentTables;
}

module.exports = { parseSchema, resolveRecordTargets };
