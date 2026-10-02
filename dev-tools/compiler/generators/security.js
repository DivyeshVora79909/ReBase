function use(namespace, database) {
  if (!namespace || !database) return "";
  return `USE NS ${namespace} DB ${database};\n\n`;
}

const { tableSelectPredicate } = require("../security-policy");
const { contributesReaders } = require("../readers");
const { businessFields, changedFields } = require("../fields");

function readerExpression(field, systemTables) {
  if (!contributesReaders(field, systemTables)) return null;
  const reference = `$this.${field.name}`;
  const branch = field.recordType.isArray ? "$reference" : reference;
  const inherited = `[<string>${branch}.owned_by]`;
  if (!field.recordType.isArray) {
    return `IF ${reference} != NONE THEN ${inherited} ELSE [] END`;
  }
  return `(${reference} ?? []).fold([], |$readers, $reference| array::concat($readers, ${inherited}))`;
}

function readerSourceExpression(field, systemTables, record = "$this") {
  if (!contributesReaders(field, systemTables)) return null;
  const reference = `${record}.${field.name}`;
  return field.recordType.isArray
    ? `(${reference} ?? [])`
    : `IF ${reference} != NONE THEN [${reference}] ELSE [] END`;
}

function combineArrays(expressions) {
  if (!expressions.length) return "[]";
  return expressions.length === 1
    ? expressions[0]
    : `array::concat(${expressions.join(", ")})`;
}

function hasNativePrivateTablePermissions(table) {
  return (table.definitions || [table.definition || ""]).some((definition) =>
    /\bPERMISSIONS\s+NONE\b/i.test(definition),
  );
}

function generateSecurity(schema, options, systemTables) {
  let output = use(options.namespace, options.database);
  const [userTable, groupTable] = options.principalTables || ["rebase_user", "rebase_group"];
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name)) continue;
    if (hasNativePrivateTablePermissions(table)) {
      output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS NONE;\n\n`;
    } else if (table.managedOutput) {
      output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS NONE;\n\n`;
    } else {
      const ownerAccess = "(owned_by = $auth OR owned_by IN $auth.parent_groups OR owned_by IN $auth.dominates)";
      const selectPredicate = tableSelectPredicate(table.name, { selectPolicy: options.selectPolicy });
      output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS\n`;
      output += `    FOR select WHERE ${selectPredicate}\n`;
      output += `    FOR create WHERE '${table.name}_create' IN $auth.permissions AND ${ownerAccess}\n`;
      output += `    FOR update WHERE '${table.name}_update' IN $auth.permissions AND ${ownerAccess}\n`;
      output += `    FOR delete WHERE '${table.name}_delete' IN $auth.permissions AND (owned_by = $auth OR owned_by IN $auth.dominates);\n\n`;
    }

    const inherited = [];
    const sources = [];
    for (const field of table.fields.values()) {
      const expression = readerExpression(field, systemTables);
      if (expression) inherited.push(expression);
      const source = readerSourceExpression(field, systemTables);
      if (source) sources.push(source);
    }
    const combinedReaders = combineArrays(inherited);
    const readersValue = inherited.length
      ? `array::distinct(${combinedReaders}).filter(|$reader| $reader != NONE)`
      : "[]";
    output += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${table.name} TYPE record<${userTable} | ${groupTable}> ASSERT record::exists($value) REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update WHERE $value = $before OR $before = $auth OR $before IN $auth.dominates;\n`;
    output += `DEFINE FIELD OVERWRITE readers_index ON TABLE ${table.name} TYPE array<string> VALUE ${readersValue} PERMISSIONS NONE;\n\n`;
    if (sources.length) {
      // SurrealDB 3.2 creates an automatic .* definition for typed arrays;
      // it must be removed before overwriting the COMPUTED parent field.
      output += `REMOVE FIELD IF EXISTS rebase_reader_sources.* ON TABLE ${table.name};\n`;
      output += `DEFINE FIELD OVERWRITE rebase_reader_sources ON TABLE ${table.name} TYPE array<record> COMPUTED array::distinct(${combineArrays(sources)}).filter(|$source| $source != NONE) PERMISSIONS NONE;\n\n`;
    }

    output += `DEFINE FIELD OVERWRITE created_at ON TABLE ${table.name} TYPE datetime VALUE $before OR time::now() READONLY;\n`;
    output += `DEFINE FIELD OVERWRITE updated_at ON TABLE ${table.name} TYPE datetime VALUE IF $before = NONE THEN time::now() ELSE $value END PERMISSIONS FOR select, create WHERE true FOR update NONE;\n`;
    output += `DEFINE FIELD OVERWRITE created_by ON TABLE ${table.name} TYPE option<record<${userTable}>> VALUE $before OR $auth READONLY;\n`;
    output += `DEFINE FIELD OVERWRITE updated_by ON TABLE ${table.name} TYPE option<record<${userTable}>> PERMISSIONS FOR select WHERE true FOR create, update NONE;\n`;
    output += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${table.name} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;
    const changed = changedFields([...businessFields(table), 'owned_by']);
    output += `DEFINE EVENT OVERWRITE rebase_touch ON ${table.name} WHEN $event = 'CREATE' OR ($event = 'UPDATE' AND (${changed})) THEN {\n`;
    output += `    UPDATE $after.id SET updated_at = time::now(), updated_by = $auth RETURN NONE;\n};\n\n`;
  }
  return output;
}

function generateRootPermissions(schema, options, systemTables) {
  const permissions = ["node_create", "node_select", "node_update", "node_delete"];
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name) || hasNativePrivateTablePermissions(table)) continue;
    for (const operation of ["select", "create", "update", "delete"]) {
      permissions.push(`${table.name}_${operation}`);
    }
  }
  let output = use(options.namespace, options.database);
  output += `UPDATE ${options.rootGroupId || "rebase_group:root"} SET role = [\n`;
  output += permissions.map((permission) => `    '${permission}'`).join(",\n");
  return `${output}\n];\n`;
}

module.exports = { generateRootPermissions, generateSecurity, readerSourceExpression, use };
