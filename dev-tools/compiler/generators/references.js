const { extractClauseExpression, parseRecordType } = require("../surql");
const { use } = require("./security");

const ASSERT_FOLLOWING_CLAUSES = [
  "DEFAULT",
  "READONLY",
  "VALUE",
  "COMPUTED",
  "REFERENCE",
  "FLEXIBLE",
  "PERMISSIONS",
  "COMMENT",
];

function existenceAssertion(field) {
  if (!field?.recordType) return null;
  if (field.recordType.isArray) {
    return "array::all($value ?? [], |$reference| record::exists($reference))";
  }
  if (field.recordType.isOptional) {
    return "$value = NONE OR record::exists($value)";
  }
  return "record::exists($value)";
}

function combinedAssertion(field) {
  const existence = existenceAssertion(field);
  if (!existence) return null;
  const existing = extractClauseExpression(
    field.definition,
    "ASSERT",
    ASSERT_FOLLOWING_CLAUSES,
  );
  if (existing?.replace(/\s+/g, " ") === existence.replace(/\s+/g, " ")) return existing;
  return existing ? `(${existing}) AND (${existence})` : existence;
}

function generateReferenceAssertions(schema, options = {}) {
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    for (const field of table.fields.values()) {
      if (!field.recordType || field.treeRoot || field.treeNode || /@rebase-reference-delta\b/i.test(field.comment)) continue;
      output += `ALTER FIELD ${field.name} ON TABLE ${table.name} ASSERT ${combinedAssertion(field)};\n`;
    }
  }
  return output;
}

// Run after native field materialization, including derived reference fields.
// Events execute on the full record; hidden unchanged references cannot make a
// valid client update fail, and privileged imports cannot cross this boundary.
function generateTenantReferenceGuards(schema, options, systemTables) {
  let output = use(options.namespace, options.database);
  const scoped = new Set([...schema.tables.values()].filter(table =>
    !systemTables.has(table.name) || table.fields.has('tenant')
  ).map(table => table.name));
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name) && !['rebase_user', 'rebase_group', 'rebase_tenant'].includes(table.name)) continue;
    const candidates = [...table.fields.values(), ...[...table.nestedFields.values()].map(field => ({
      ...field, recordType: parseRecordType(field.definition),
    }))];
    const fields = candidates.filter(field => field.recordType
      && !field.treeNode && !field.treeRoot && !field.computed
      && !['id', 'tenant', 'owned_by', 'parents', 'parent_groups', 'created_by', 'updated_by'].includes(field.name)
      && field.recordType.targets.some(target => scoped.has(target)));
    const owned = !systemTables.has(table.name);
    if (!fields.length && !owned) continue;
    const changed = [...new Set(fields.map(field => field.name.split('.')[0]))]
      .map(name => `$before.${name} != $after.${name}`).join(' OR ') || 'false';
    output += `DEFINE EVENT OVERWRITE rebase_tenant_references ON ${table.name}
WHEN $event = 'CREATE' OR ($event = 'UPDATE' AND (${changed} OR $before.owned_by != $after.owned_by)) THEN {\n`;
    if (owned) output += "    IF fn::rebase::owner_tenant($after.owned_by) != $after.tenant { THROW 'REBASE_TENANT_IMMUTABLE'; };\n";
    for (const field of fields) {
      const value = `$after.${field.name.replaceAll('.*', '')}`;
      // Record projections through nested arrays retain one array layer per
      // wildcard. Flatten the schema's finite depth, including empty branches.
      let projected = `[${value}]`;
      const projectionDepth = field.name.split('.').filter(part => part === '*').length
        + Number(field.recordType.isArray);
      for (let depth = 0; depth < projectionDepth + 1; depth += 1) projected = `array::flatten(${projected})`;
      const references = field.name.includes('.*')
        ? `${projected}.filter(|$ref| $ref != NONE)`
        : field.recordType.isArray ? `(${value} ?? [])` : `IF ${value} = NONE THEN [] ELSE [${value}] END`;
      const tables = field.recordType.targets.filter(target => scoped.has(target)).map(target => `'${target}'`).join(', ');
      output += `    FOR $reference IN ${references} {
        IF record::tb($reference) IN [${tables}] AND $reference.tenant != $after.tenant { THROW 'REBASE_TENANT_REFERENCE_MISMATCH: ${table.name}.${field.name}'; };
    };\n`;
    }
    output += '};\n\n';
  }
  return output;
}

module.exports = { combinedAssertion, existenceAssertion, generateReferenceAssertions, generateTenantReferenceGuards };
