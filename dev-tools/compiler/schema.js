const { findTopLevelKeyword, parseRecordType, splitStatements, splitStatementsWithLocations, splitTopLevel } = require("./surql");

function parseSchema(schemaSource, viewsSource) {
  const tables = new Map();
  const sourceStatements = Array.isArray(schemaSource)
    ? schemaSource.map(item => typeof item === 'string' ? { source: item, location: null } : item)
    : splitStatementsWithLocations(String(schemaSource || '')).map(item => ({
      source: item.source,
      location: { source: '<input>', line: item.line, column: item.column, offset: item.offset },
    }));
  for (const entry of sourceStatements) {
    const statement = entry.source;
    const location = entry.location || null;
    const tableMatch = /\bDEFINE\s+TABLE\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_]+)/i.exec(statement);
    if (tableMatch && !/\bAS\s+SELECT\b/i.test(statement)) {
      const table = tables.get(tableMatch[1]) || { name: tableMatch[1], fields: new Map(), nestedFields: new Map(), definitions: [], definitionLocations: [] };
      table.definitions ||= [];
      table.definitionLocations ||= [];
      table.nestedFields ||= new Map();
      table.definitions.push(statement);
      table.definitionLocations.push(location);
      table.definition = statement;
      table.location = table.location || location;
      table.definitionLocation = location;
      table.comment = [table.comment, extractComment(statement)].filter(Boolean).join(" ");
      validateRetiredMarkers(table.comment, `table ${table.name}`);
      if (/@rebase-audit(?![-\w])/i.test(table.comment)) {
        throw new Error(`Table ${table.name}: @rebase-audit is field-only; annotate concrete fields`);
      }
      if (/@rebase-change-log\b/i.test(table.comment)) {
        throw new Error(`Table ${table.name}: @rebase-change-log is field-only`);
      }
      table.treeMembers = extractFunctionMarker(table.comment, 'members', table.name);
      table.validate = extractFunctionMarker(table.comment, 'validate', table.name);
      table.requiredOutputs = extractFunctionMarker(table.comment, 'required-outputs', table.name);
      table.managedOutput = /@rebase-managed-output\b/i.test(table.comment);
      table.operation = extractOperation(table.comment, table.name);
      table.effectProcess = extractEffectProcess(table.comment, table.name);
      table.effectEvents = extractEffectEvents(table.comment, table.name, table.effectProcess);
      table.effectTimeoutMs = extractEffectTimeout(table.comment, table.name);
      table.effectAdapters = extractEffectAdapters(table.comment, table.name);
      table.effectMutableInputs = /@rebase-mutable-inputs\b/i.test(table.comment);
      if (table.operation && (/@rebase-effect(?![-\w])/i.test(table.comment)
        || /@rebase-events\b/i.test(table.comment)
        || /@rebase-mutable-inputs\b/i.test(table.comment))) {
        throw new Error(`Table ${table.name}: @rebase-operation cannot be combined with legacy effect declarations`);
      }
      tables.set(tableMatch[1], table);
    }
    const fieldMatch = /\bDEFINE\s+FIELD\s+(?:OVERWRITE\s+|IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_*]+(?:\.[A-Za-z0-9_*]+)*)\s+ON\s+(?:TABLE\s+)?([A-Za-z0-9_]+)/i.exec(statement);
    if (!fieldMatch && /\bDEFINE\s+FIELD\b/i.test(statement) && /@rebase-tree-/i.test(extractComment(statement))) {
      throw new Error('Tree storage requires a top-level named field');
    }
    if (!fieldMatch) continue;
    const [, fieldName, tableName] = fieldMatch;
    if (!tables.has(tableName)) tables.set(tableName, { name: tableName, fields: new Map(), nestedFields: new Map(), definitions: [], definitionLocations: [] });
    const fieldComment = extractComment(statement);
    validateRetiredMarkers(fieldComment, `${tableName}.${fieldName}`);
    if (fieldName.includes('.')) {
      if (/@rebase-tree-/i.test(fieldComment)) {
        throw new Error(`${tableName}.${fieldName}: tree storage annotations require a top-level named field`);
      }
      const nestedFields = tables.get(tableName).nestedFields ||= new Map();
      nestedFields.set(fieldName, {
        name: fieldName,
        definition: statement,
        definitions: [...(nestedFields.get(fieldName)?.definitions || []), statement],
        definitionLocations: [...(nestedFields.get(fieldName)?.definitionLocations || []), location],
        location,
        comment: fieldComment,
        auditPolicy: parseAuditPolicy(fieldComment),
      });
      continue;
    }
    const computed = findTopLevelKeyword(statement, 'COMPUTED') >= 0;
    const derived = computed || findTopLevelKeyword(statement, 'VALUE') >= 0;
    tables.get(tableName).fields.set(fieldName, {
      name: fieldName,
      definition: statement,
      definitions: [...(tables.get(tableName).fields.get(fieldName)?.definitions || []), statement],
      definitionLocations: [...(tables.get(tableName).fields.get(fieldName)?.definitionLocations || []), location],
      location,
      recordType: parseRecordType(statement),
      comment: fieldComment,
      inheritReaders: /@rebase-readers\b/i.test(fieldComment),
      treeRoot: /@rebase-tree-root\b/i.test(fieldComment),
      treeNode: /@rebase-tree-node\b/i.test(fieldComment),
      reactive: /@rebase-derived\b/i.test(fieldComment),
      system: /@rebase-system\b/i.test(fieldComment),
      derived,
      computed,
      operationInput: /@rebase-operation-input\b/i.test(fieldComment),
      operationOutput: /@rebase-operation-output\b/i.test(fieldComment),
      effectInput: /@rebase-effect-input\b/i.test(fieldComment),
      effectOutput: /@rebase-effect-output\b/i.test(fieldComment),
      auditPolicy: parseAuditPolicy(fieldComment),
    });
  }

  for (const table of tables.values()) {
    const operationFields = [...table.fields.values()];
    const markedOperationField = operationFields.find((field) => field.operationInput || field.operationOutput);
    if (markedOperationField && !table.operation) {
      throw new Error(`${table.name}.${markedOperationField.name}: @rebase-operation field markers require a table @rebase-operation declaration`);
    }
    if (table.operation) {
      const legacyOperationField = operationFields.find((field) => field.effectInput || field.effectOutput);
      if (legacyOperationField) {
        throw new Error(`${table.name}.${legacyOperationField.name}: legacy @rebase-effect field markers cannot be used with @rebase-operation`);
      }
      if (!operationFields.some((field) => field.operationInput)) {
        throw new Error(`Operation table ${table.name} requires at least one @rebase-operation-input field`);
      }
    }
    const included = [
      ...table.fields.values(), ...table.nestedFields.values(),
    ].filter(field => field.auditPolicy?.value);
    for (const field of [...table.fields.values(), ...table.nestedFields.values()]) {
      const policy = field.auditPolicy || {};
      if (policy.value && policy.change) {
        throw new Error(`${table.name}.${field.name}: choose either @rebase-audit or @rebase-change-log`);
      }
      if ((policy.value || policy.change) && (field.system || field.treeRoot || field.treeNode || field.effectOutput || field.operationOutput)) {
        throw new Error(`${table.name}.${field.name}: technical fields cannot be audited`);
      }
    }
    for (const field of included) {
      if (field.name.split('.').includes('*')) {
        throw new Error(`${table.name}.${field.name}: wildcard @rebase-audit paths are unsupported; annotate each concrete leaf`);
      }
    }
    const paths = included.map(field => field.name).sort();
    for (let index = 0; index < paths.length; index += 1) {
      const child = paths.find(path => path.startsWith(`${paths[index]}.`));
      if (child) {
        throw new Error(`${table.name}.${paths[index]}: @rebase-audit selection overlaps ${child}; annotate concrete leaf fields only`);
      }
    }
    for (const field of included) {
      const type = /\bTYPE\s+([A-Za-z_]+)/i.exec(field.definition)?.[1]?.toLowerCase();
      if (type === 'object') {
        throw new Error(`${table.name}.${field.name}: @rebase-audit requires a concrete leaf field, not an object container`);
      }
    }
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

function extractFunctionMarker(comment, marker, table) {
  const pattern = new RegExp(`@rebase-${marker}\\s+(fn::[A-Za-z_][A-Za-z0-9_:]*)`, 'g');
  const found = [...String(comment || '').matchAll(pattern)].map((m) => m[1]);
  if (new Set(found).size > 1) throw new Error(`Conflicting @rebase-${marker} on ${table}`);
  if (new RegExp(`@rebase-${marker}\\b`).test(comment || '') && !found.length) {
    throw new Error(`@rebase-${marker} on ${table} requires a SurrealQL function`);
  }
  return found[0] || null;
}

function extractEffectProcess(comment, tableName) {
  const matches = [...String(comment || "").matchAll(/@rebase-effect\s*[:=]?\s*(sync|async)\b/gi)]
    .map((match) => match[1].toLowerCase());
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting effect process markers on table ${tableName}`);
  return unique[0] || null;
}

function extractOperation(comment, tableName) {
  const markers = [...String(comment || "").matchAll(/@rebase-operation(?![-\w])\b([^@]*)/gi)];
  if (!markers.length) return null;
  if (markers.length > 1) throw new Error(`Duplicate @rebase-operation declaration on table ${tableName}`);
  const tokens = String(markers[0][1] || "").trim().split(/[\s,|]+/).filter(Boolean);
  const mode = String(tokens.shift() || "").toLowerCase();
  if (!["grant", "inline", "queued"].includes(mode)) {
    throw new Error(`Invalid @rebase-operation mode on table ${tableName}: ${mode || "missing"}`);
  }
  const events = tokens.map((event) => event.toUpperCase());
  const invalid = events.find((event) => !["CREATE", "UPDATE", "DELETE"].includes(event));
  if (invalid) throw new Error(`Invalid @rebase-operation event on table ${tableName}: ${invalid}`);
  if (!events.length) throw new Error(`@rebase-operation on table ${tableName} requires explicit CREATE or UPDATE events`);
  if (new Set(events).size !== events.length) throw new Error(`Duplicate @rebase-operation event on table ${tableName}`);
  const orderedEvents = ["CREATE", "UPDATE", "DELETE"].filter((event) => events.includes(event));
  if (mode === "grant" && orderedEvents.includes("DELETE")) {
    throw new Error(`Grant operation ${tableName} cannot handle DELETE; provider mutations require a task`);
  }
  if (mode !== "grant" && (orderedEvents.length !== 1 || orderedEvents[0] !== "CREATE")) {
    throw new Error(`${mode} operation ${tableName} supports CREATE only`);
  }
  return Object.freeze({ mode, events: Object.freeze(orderedEvents) });
}

function extractEffectEvents(comment, tableName, process) {
  const markers = [...String(comment || "").matchAll(/@rebase-events\b([^@]*)/gi)];
  if (!markers.length) return process ? ["CREATE"] : [];
  const declarations = markers.map((match) => {
    const events = String(match[1] || "")
      .split(/[\s,|]+/)
      .filter(Boolean)
      .map((event) => event.toUpperCase());
    const invalid = events.find((event) => !["CREATE", "UPDATE", "DELETE"].includes(event));
    if (invalid) throw new Error(`Invalid @rebase-events value on table ${tableName}: ${invalid}`);
    if (!events.length) throw new Error(`@rebase-events on table ${tableName} requires at least one event`);
    return [...new Set(events)].sort((left, right) => (
      ["CREATE", "UPDATE", "DELETE"].indexOf(left) - ["CREATE", "UPDATE", "DELETE"].indexOf(right)
    ));
  });
  if (new Set(declarations.map((events) => events.join(","))).size > 1) {
    throw new Error(`Conflicting @rebase-events markers on table ${tableName}`);
  }
  return declarations[0];
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

function extractEffectAdapters(comment, tableName = "unknown") {
  const source = String(comment || "");
  if (/@rebase-provider\b/i.test(source)) {
    throw new Error(`Retired @rebase-provider marker on table ${tableName}; use @rebase-adapter`);
  }
  const names = [...source.matchAll(/@rebase-adapter\s*[:=]?\s*([^\s@]+)/gi)]
    .map((match) => match[1]);
  const markerCount = [...source.matchAll(/@rebase-adapter\b/gi)].length;
  if (names.length !== markerCount) throw new Error(`Invalid @rebase-adapter marker on table ${tableName}`);
  const invalid = names.find((name) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
  if (invalid) throw new Error(`Invalid @rebase-adapter value on table ${tableName}: ${invalid}`);
  return [...new Set(names)].sort();
}

function parseAuditPolicy(comment = "") {
  const normalized = String(comment);
  const policy = {
    value: /@rebase-audit(?![-\w])/i.test(normalized),
    change: /@rebase-change-log\b/i.test(normalized),
  };
  policy.marked = policy.value || policy.change;
  return policy;
}

function validateRetiredMarkers(comment, subject) {
  const source = String(comment || "");
  const retired = [
    [/@rebase-principal\b/i, "fixed rebase_user/rebase_group table names"],
    [/@rebase-internal\b/i, "native PERMISSIONS NONE"],
    [/@rebase-authentication-private\b/i, "native field permissions"],
    [/@rebase-audit-(?:omit|redact)\b/i, "field @rebase-audit or native field permissions"],
    [/@rebase-audit\s*[:=]?\s*(?:include|exclude|redact|change)\b/i, "field @rebase-audit or @rebase-change-log"],
  ];
  for (const [pattern, replacement] of retired) {
    if (pattern.test(source)) throw new Error(`${subject}: retired annotation; use ${replacement}`);
  }
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
  extractOperation,
  extractEffectEvents,
  extractEffectProcess,
  extractEffectAdapters,
  extractEffectTimeout,
  parseAuditPolicy,
  parseSchema,
  resolveRecordTargets,
};
