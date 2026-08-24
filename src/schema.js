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
      table.principalKind = extractPrincipalKind(table.comment, table.name);
      table.effectProcess = extractEffectProcess(table.comment, table.name);
      table.effectTimeoutMs = extractEffectTimeout(table.comment, table.name);
      table.effectProviders = extractEffectProviders(table.comment);
      table.effectMutableInputs = /@rebase-mutable-inputs\b/i.test(table.comment);
      table.webhook = extractWebhook(table.comment, table.name);
      table.webhookAccountPath = extractWebhookAccountPath(table.comment, table.name);
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
      changeLog: /@rebase-change-log\b/i.test(fieldComment),
      inheritReaders: /@rebase-readers\b/i.test(fieldComment),
      effectInput: /@rebase-effect-input\b/i.test(fieldComment),
      effectOutput: /@rebase-effect-output\b/i.test(fieldComment),
      webhookEvent: /@rebase-webhook-event\b/i.test(fieldComment),
      webhookOrder: /@rebase-webhook-order\b/i.test(fieldComment),
      auditPolicy: parseAuditPolicy(fieldComment),
    });
  }

  for (const table of tables.values()) {
    const fieldPolicies = [...table.fields.values()].map((field) => field.auditPolicy);
    const markedField = fieldPolicies.some((policy) => policy.marked);
    table.audit = table.audit || markedField;
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

function extractPrincipalKind(comment, tableName) {
  const matches = [...String(comment || "").matchAll(/@rebase-principal\s*[:=]?\s*(user|group)\b/gi)]
    .map((match) => match[1].toLowerCase());
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting principal markers on table ${tableName}`);
  return unique[0] || null;
}

function extractEffectProcess(comment, tableName) {
  const matches = [...String(comment || "").matchAll(/@rebase-effect\s*[:=]?\s*(sync|async)\b/gi)]
    .map((match) => match[1].toLowerCase());
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting effect process markers on table ${tableName}`);
  return unique[0] || null;
}

function extractEffectTimeout(comment, tableName) {
  const matches = [...String(comment || "").matchAll(/@rebase-timeout\s*[:=]?\s*(\d+)\s*(ms|s)?\b/gi)]
    .map((match) => Number(match[1]) * (match[2]?.toLowerCase() === "s" ? 1000 : 1));
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting @rebase-timeout markers on table ${tableName}`);
  const timeout = unique[0] || null;
  if (timeout !== null && (!Number.isInteger(timeout) || timeout < 1 || timeout > 300000)) {
    throw new Error(`Invalid @rebase-timeout on table ${tableName}`);
  }
  return timeout;
}

function extractEffectProviders(comment) {
  return [...new Set(
    [...String(comment || "").matchAll(/@rebase-provider\s*[:=]?\s*([A-Za-z][A-Za-z0-9_-]*)\b/gi)]
      .map((match) => match[1].toLowerCase()),
  )].sort();
}

function extractWebhook(comment, tableName) {
  const matches = [...String(comment || "").matchAll(/@rebase-webhook\s*[:=]?\s*([A-Za-z][A-Za-z0-9_-]*)\/([A-Za-z][A-Za-z0-9_-]*)\b/gi)]
    .map((match) => ({ provider: match[1].toLowerCase(), route: match[2].toLowerCase() }));
  const unique = new Map(matches.map((value) => [`${value.provider}/${value.route}`, value]));
  if (unique.size > 1) throw new Error(`Conflicting @rebase-webhook markers on table ${tableName}`);
  return [...unique.values()][0] || null;
}

function extractWebhookAccountPath(comment, tableName) {
  const matches = [...String(comment || "").matchAll(/@rebase-webhook-account\s*[:=]?\s*([A-Za-z_][A-Za-z0-9_.]*)\b/gi)]
    .map((match) => match[1]);
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting @rebase-webhook-account markers on table ${tableName}`);
  return unique[0] || null;
}

function parseAuditPolicy(comment = "") {
  const normalized = String(comment);
  const policy = {
    marked: false,
    include: false,
    exclude: false,
    redact: false,
    change: false,
  };
  if (/@rebase-audit\b/i.test(normalized)) policy.marked = true;
  if (/@rebase-audit-omit\b/i.test(normalized)) {
    policy.marked = true;
    policy.exclude = true;
  }
  if (/@rebase-audit-redact\b/i.test(normalized)) {
    policy.marked = true;
    policy.redact = true;
  }
  if (/@rebase-change-log\b/i.test(normalized)) policy.change = true;
  for (const match of normalized.matchAll(/@rebase-audit\s*[:=]?\s*(include|exclude|redact|change)\b/gi)) {
    policy.marked = true;
    policy[match[1].toLowerCase()] = true;
  }
  return policy;
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

module.exports = {
  extractEffectProcess,
  extractEffectProviders,
  extractEffectTimeout,
  extractPrincipalKind,
  extractWebhook,
  extractWebhookAccountPath,
  parseAuditPolicy,
  parseSchema,
  resolveRecordTargets,
};
