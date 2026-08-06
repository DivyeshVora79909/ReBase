function use(namespace, database) {
  return `USE NS ${namespace} DB ${database};\n\n`;
}

function generateSecurity(schema, options, systemTables) {
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name)) continue;
    output += `DEFINE TABLE OVERWRITE ${table.name} SCHEMAFULL PERMISSIONS\n`;
    output += `    FOR select WHERE '${table.name}_select' IN $auth.permissions AND readers_index CONTAINSANY $auth.z_access_index\n`;
    output += `    FOR create WHERE '${table.name}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n`;
    output += `    FOR update WHERE '${table.name}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n`;
    output += `    FOR delete WHERE '${table.name}_delete' IN $auth.permissions AND owned_by IN $auth.dominates;\n\n`;

    const inherited = ["$this.owned_by"];
    for (const field of table.fields.values()) {
      if (!field.recordType) continue;
      if (field.recordType.targets.some((target) => systemTables.has(target))) continue;
      if (field.recordType.isArray && !options.includeArrayReaders) continue;
      inherited.push(`$this.${field.name}.readers`);
    }
    output += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${table.name} TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;\n`;
    output += `DEFINE FIELD OVERWRITE readers ON TABLE ${table.name} TYPE array<record<groups>> VALUE array::distinct(array::flatten([${inherited.join(", ")}])).filter(|$reader| $reader != NONE);\n`;
    output += `DEFINE FIELD OVERWRITE readers_index ON TABLE ${table.name} TYPE array<string> VALUE ($this.readers ?? []).map(|$reader| <string>$reader) PERMISSIONS FOR create, update NONE;\n\n`;

    output += `DEFINE FIELD OVERWRITE created_at ON TABLE ${table.name} TYPE datetime VALUE $before OR time::now() READONLY;\n`;
    output += `DEFINE FIELD OVERWRITE updated_at ON TABLE ${table.name} TYPE datetime VALUE time::now();\n`;
    output += `DEFINE FIELD OVERWRITE created_by ON TABLE ${table.name} TYPE option<record<user>> VALUE $before OR $auth READONLY;\n`;
    output += `DEFINE FIELD OVERWRITE updated_by ON TABLE ${table.name} TYPE option<record<user>> VALUE $auth;\n`;
    output += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${table.name} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;
  }
  return output;
}

function generateRootPermissions(schema, options, systemTables) {
  const permissions = ["node_create", "node_select", "node_update", "node_delete"];
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name)) continue;
    for (const operation of ["select", "create", "update", "delete"]) {
      permissions.push(`${table.name}_${operation}`);
    }
  }
  let output = use(options.namespace, options.database);
  output += "UPDATE groups:root SET role = [\n";
  output += permissions.map((permission) => `    '${permission}'`).join(",\n");
  return `${output}\n];\n`;
}

module.exports = { generateRootPermissions, generateSecurity, use };
