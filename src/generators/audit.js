const { use } = require("./security");

const DEFAULT_OMIT_FIELDS = new Set([
  "readers",
  "readers_index",
  "parent_groups",
  "permissions",
  "dominates",
  "z_access_index",
  "system_ping",
  "updated_at",
  "updated_by",
]);

function auditTables(schema, excludedTables = new Set()) {
  return [...schema.tables.values()].filter((table) => table.audit && !excludedTables.has(table.name));
}

function quotedList(values) {
  return `[${values.map((value) => `'${value.replaceAll("'", "\\'")}'`).join(", ")}]`;
}

function generateAuditEvents(schema, options, excludedTables = new Set()) {
  let output = use(options.namespace, options.database);
  for (const table of auditTables(schema, excludedTables)) {
    const omitted = [...DEFAULT_OMIT_FIELDS];
    const trackedChanges = [];
    for (const field of table.fields.values()) {
      const policy = field.auditPolicy || {};
      if ((field.auditOmit || policy.exclude || policy.redact || policy.change) && !omitted.includes(field.name))
        omitted.push(field.name);
      if (field.auditRedact || policy.redact || policy.change) trackedChanges.push(field.name);
    }
    const omitExpression = quotedList([...new Set(omitted)]);
    const trackedExpression = quotedList([...new Set(trackedChanges)]);
    output += `DEFINE EVENT OVERWRITE rebase_audit_${table.name} ON TABLE ${table.name}\n`;
    output += "    ASYNC RETRY 0 MAXDEPTH 0\n";
    output += "    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {\n";
    output += "        LET $audit_now = time::now();\n";
    output += `        LET $audit_before = IF $event = 'CREATE' THEN NONE ELSE object::remove($before, ${omitExpression}) END;\n`;
    output += `        LET $audit_after = IF $event = 'DELETE' THEN NONE ELSE object::remove($after, ${omitExpression}) END;\n`;
    output += `        LET $changed_tracked = ${trackedExpression}.filter(|$field| ($before[$field] ?? NONE) != ($after[$field] ?? NONE));\n`;
    output +=
      "        IF $event != 'UPDATE' OR $audit_before != $audit_after OR $changed_tracked {\n";
    output +=
      "            CREATE audit_mutation CONTENT {\n";
    output += "                at: $audit_now,\n";
    output += "                event: $event,\n";
    output += `                table_name: '${table.name}',\n`;
    output +=
      "                target: IF $event = 'DELETE' THEN $before.id ELSE $after.id END,\n";
    output += "                actor: $auth,\n";
    output += "                changed_fields: $changed_tracked,\n";
    output += "                before: $audit_before,\n";
    output += "                after: $audit_after\n";
    output += "            };\n";
    output += "        };\n";
    output += "    };\n\n";
  }
  return output;
}

function changeLogFields(table) {
  return [...table.fields.values()].filter((field) => field.changeLog);
}

function generateChangeLogEvents(schema, options) {
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    const fields = changeLogFields(table);
    if (!fields.length) continue;
    const names = quotedList(fields.map((field) => field.name));
    const changed = fields
      .map((field) => `($before.${field.name} ?? NONE) != ($after.${field.name} ?? NONE)`)
      .join(" OR ");
    output += `DEFINE EVENT OVERWRITE rebase_change_log_${table.name} ON TABLE ${table.name}\n`;
    output += "    ASYNC RETRY 0 MAXDEPTH 0\n";
    output += `    WHEN $event = 'UPDATE' AND (${changed}) THEN {\n`;
    output += `        LET $changed = ${names}.filter(|$field| ($before[$field] ?? NONE) != ($after[$field] ?? NONE));\n`;
    output += "        IF $changed {\n";
    output += "            LET $change_now = time::now();\n";
    output += "            CREATE change_logs CONTENT {\n";
    output += "                target: $after.id,\n";
    output += "                at: $change_now,\n";
    output += `                table_name: '${table.name}',\n`;
    output += "                before: object::from_entries($changed.map(|$field| [$field, $before[$field] ?? NONE])),\n";
    output += "                actor: $auth\n";
    output += "            };\n";
    output += "        };\n";
    output += "    };\n\n";
  }
  return output;
}

module.exports = { auditTables, changeLogFields, generateAuditEvents, generateChangeLogEvents };
