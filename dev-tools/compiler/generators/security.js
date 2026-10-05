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
  const inherited = `[${branch}.owned_by]`;
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
  const tenantTable = options.principalTables?.[2] || "rebase_tenant";
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name)) continue;
    if (table.fields.has('visibility')) {
      throw new Error(`${table.name}.visibility: visibility was removed; use explicit ownership or reader relations`);
    }
    if (!table.fields.has('id')) {
      output += `DEFINE FIELD OVERWRITE id ON TABLE ${table.name} TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();\n`;
    }
    if (hasNativePrivateTablePermissions(table)) {
      output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS NONE;\n\n`;
    } else if (table.managedOutput) {
      output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS NONE;\n\n`;
    } else {
      const ownerAccess = "(tenant = $auth.tenant AND fn::rebase::can_access($auth, owned_by))";
      const selectPredicate = tableSelectPredicate(table.name, { selectPolicy: options.selectPolicy });
      output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS\n`;
      output += `    FOR select WHERE ${selectPredicate}\n`;
      output += `    FOR create WHERE '${table.name}_create' IN $auth.permissions AND ${ownerAccess}\n`;
      output += `    FOR update WHERE '${table.name}_update' IN $auth.permissions AND ${ownerAccess}\n`;
      output += `    FOR delete WHERE '${table.name}_delete' IN $auth.permissions AND tenant = $auth.tenant AND (owned_by = $auth OR fn::rebase::dominates($auth, owned_by));\n\n`;
    }

    const inherited = [];
    const sources = [];
    for (const field of table.fields.values()) {
      const expression = readerExpression(field, systemTables);
      if (expression) inherited.push(expression);
      const source = readerSourceExpression(field, systemTables);
      if (source) sources.push(source);
    }
    if ([...table.fields.values()].some(field => field.treeNode)) {
      sources.push('fn::rebase::tree_roots($this)');
      inherited.push('(fn::rebase::tree_roots($this)).map(|$root| $root.owned_by)');
    }
    const combinedReaders = combineArrays(inherited);
    const readersValue = inherited.length
      ? `array::distinct(${combinedReaders}).filter(|$reader| $reader != NONE)`
      : "[]";
    output += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${table.name} TYPE record<${userTable} | ${groupTable} | ${tenantTable}> ASSERT ($auth != NONE AND fn::rebase::can_access($auth, $value)) OR record::exists($value) REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update WHERE $value = $before OR $before = $auth OR fn::rebase::dominates($auth, $before);\n`;
    output += `DEFINE FIELD OVERWRITE tenant ON TABLE ${table.name} TYPE record<${tenantTable}> VALUE {
    LET $tenant = fn::rebase::owner_tenant($this.owned_by);
    IF $tenant = NONE { THROW 'REBASE_TENANT_REQUIRED'; };
    IF $before != NONE AND $before != $tenant { THROW 'REBASE_TENANT_IMMUTABLE'; };
    RETURN $tenant;
} ASSERT record::exists($value) READONLY PERMISSIONS FOR select, create WHERE true FOR update NONE;\n`;
    output += `DEFINE FIELD OVERWRITE readers_index ON TABLE ${table.name} TYPE array<record<${userTable} | ${groupTable} | ${tenantTable}>> VALUE ${readersValue} PERMISSIONS NONE;\n\n`;
    if (sources.length) {
      // Native reference entries index this bounded set of immediate roots.
      // A root's owner change can refresh its members without a table scan.
      output += `REMOVE FIELD IF EXISTS rebase_reader_sources.* ON TABLE ${table.name};\n`;
      output += `DEFINE FIELD OVERWRITE rebase_reader_sources ON TABLE ${table.name} TYPE array<record> VALUE array::distinct(${combineArrays(sources)}).filter(|$source| $source != NONE) REFERENCE ON DELETE IGNORE PERMISSIONS NONE;\n\n`;
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
  const publishedSystemViews = [...new Set(schema.views
    .filter(view => view.tenantPublished && systemTables.has(view.sourceTable))
    .map(view => `${view.sourceTable}_select`))];
  permissions.push(...publishedSystemViews);
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name) || hasNativePrivateTablePermissions(table)) continue;
    for (const operation of ["select", "create", "update", "delete"]) {
      permissions.push(`${table.name}_${operation}`);
    }
  }
  let output = use(options.namespace, options.database);
  output += `DEFINE FUNCTION OVERWRITE fn::rebase::tenant_permissions() { RETURN [\n`;
  output += permissions.map((permission) => `    '${permission}'`).join(",\n");
  return `${output}\n]; } PERMISSIONS FULL;\nUPDATE rebase_tenant;\n`;
}

module.exports = { generateRootPermissions, generateSecurity, readerSourceExpression, use };
