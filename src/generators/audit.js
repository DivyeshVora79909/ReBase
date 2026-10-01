const { use } = require("./security");

function selectedFields(table) {
  return [...table.fields.values(), ...(table.nestedFields?.values() || [])]
    .filter((field) => field.auditPolicy?.value || field.auditPolicy?.change)
    .filter((field) => !field.system && !field.treeRoot && !field.treeNode && !field.effectOutput);
}

function auditTables(schema, excludedTables = new Set()) {
  return [...schema.tables.values()].filter((table) =>
    !excludedTables.has(table.name) && selectedFields(table).length > 0,
  );
}

function projectionTree(fields) {
  const root = new Map();
  for (const field of fields) {
    const segments = field.name.split('.');
    let node = root;
    for (const segment of segments.slice(0, -1)) {
      if (!node.has(segment)) node.set(segment, new Map());
      node = node.get(segment);
    }
    node.set(segments.at(-1), null);
  }
  return root;
}

function auditProjection(fields, row) {
  const tree = projectionTree(fields);
  const decorate = (node, prefix = []) => new Map([...node].map(([key, child]) => [
    key,
    child === null ? { path: [...prefix, key].join('.') } : decorate(child, [...prefix, key]),
  ]));
  const render = node => `{ ${[...node].map(([key, child]) =>
    `${key}: ${child?.path ? `${row}.${child.path}` : render(child)}`,
  ).join(', ')} }`;
  return render(decorate(tree));
}

function fieldChanged(field) {
  return `($before.${field.name} ?? NONE) != ($after.${field.name} ?? NONE)`;
}

function generateAuditEvents(schema, options, excludedTables = new Set()) {
  let output = use(options.namespace, options.database);
  for (const table of auditTables(schema, excludedTables)) {
    const fields = selectedFields(table);
    const valueFields = fields.filter((field) => field.auditPolicy?.value);
    const changed = fields.map(fieldChanged).join(' OR ') || 'false';
    const changedFields = `[${fields.map((field) =>
      `IF ${fieldChanged(field)} THEN '${field.name}' ELSE NONE END`,
    ).join(', ')}].filter(|$field| $field != NONE)`;
    const beforeProjection = valueFields.length ? auditProjection(valueFields, '$before') : 'NONE';
    const afterProjection = valueFields.length ? auditProjection(valueFields, '$after') : 'NONE';

    output += `DEFINE EVENT OVERWRITE rebase_audit_${table.name} ON TABLE ${table.name}\n`;
    output += `    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND (${changed})) THEN {\n`;
    output += `        LET $audit_changed_fields = ${changedFields};\n`;
    output += `        LET $audit_before = IF $event = 'CREATE' THEN NONE ELSE ${beforeProjection} END;\n`;
    output += `        LET $audit_after = IF $event = 'DELETE' THEN NONE ELSE ${afterProjection} END;\n`;
    output += '        CREATE audit_mutation CONTENT {\n';
    output += '            at: time::now(),\n';
    output += '            event: $event,\n';
    output += `            table_name: '${table.name}',\n`;
    output += '            target: IF $event = \'DELETE\' THEN $before.id ELSE $after.id END,\n';
    output += '            actor: $auth,\n';
    output += '            changed_fields: $audit_changed_fields,\n';
    output += '            before: $audit_before,\n';
    output += '            after: $audit_after\n';
    output += '        };\n';
    output += '    };\n\n';
  }
  return output;
}

module.exports = { auditTables, auditProjection, generateAuditEvents, selectedFields };
