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
    const redacted = [];
    for (const field of table.fields.values()) {
      if (field.auditOmit && !omitted.includes(field.name))
        omitted.push(field.name);
      if (field.auditRedact) {
        redacted.push(field.name);
        if (!omitted.includes(field.name)) omitted.push(field.name);
      }
    }
    const omitExpression = quotedList([...new Set(omitted)]);
    const redactExpression = quotedList([...new Set(redacted)]);
    const retries = process.env.AUDIT_EVENT_RETRIES || "0";
    output += `DEFINE EVENT OVERWRITE rebase_audit_${table.name} ON TABLE ${table.name}\n`;
    output += `    ASYNC RETRY ${retries} MAXDEPTH 0\n`;
    output += "    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {\n";
    output += "        LET $audit_now = time::now();\n";
    output += `        LET $audit_before = IF $event = 'CREATE' THEN NONE ELSE object::remove($before, ${omitExpression}) END;\n`;
    output += `        LET $audit_after = IF $event = 'DELETE' THEN NONE ELSE object::remove($after, ${omitExpression}) END;\n`;
    output += `        LET $changed_redacted = ${redactExpression}.filter(|$field| ($before[$field] ?? NONE) != ($after[$field] ?? NONE));\n`;
    output +=
      "        IF $event != 'UPDATE' OR $audit_before != $audit_after OR $changed_redacted {\n";
    output +=
      "            CREATE type::record('audit_mutation', rand::uuid::v7($audit_now)) CONTENT {\n";
    output += "                at: $audit_now,\n";
    output += "                event: $event,\n";
    output += `                table_name: '${table.name}',\n`;
    output +=
      "                target: IF $event = 'DELETE' THEN $before.id ELSE $after.id END,\n";
    output += "                actor: $auth,\n";
    output += "                changed_fields: $changed_redacted,\n";
    output += "                before: $audit_before,\n";
    output += "                after: $audit_after\n";
    output += "            };\n";
    output += "        };\n";
    output += "    };\n\n";
  }
  return output;
}

module.exports = { auditTables, generateAuditEvents };
