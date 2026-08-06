const SYSTEM_TABLES = new Set(["user", "groups"]);

function analyzeSchema(schema) {
  validateSystemExtensions(schema);
  const reverseReferences = new Map();
  for (const table of schema.tables.values()) {
    for (const field of table.fields.values()) {
      for (const target of field.recordType?.targets || []) {
        if (!reverseReferences.has(target)) reverseReferences.set(target, []);
        reverseReferences.get(target).push({
          sourceTable: table.name,
          sourceField: field.name,
          sourceIsSystem: SYSTEM_TABLES.has(table.name),
        });
      }
    }
  }
  return { reverseReferences, systemTables: SYSTEM_TABLES };
}

function validateSystemExtensions(schema) {
  for (const tableName of SYSTEM_TABLES) {
    const table = schema.tables.get(tableName);
    if (!table) continue;
    for (const field of table.fields.values()) {
      const safe = /\bTYPE\s+(?:option<|none\s*\|)/i.test(field.definition)
        || /\bDEFAULT\b/i.test(field.definition)
        || /\b(?:VALUE|COMPUTED)\b/i.test(field.definition);
      if (!safe) {
        throw new Error(`System-table extension ${tableName}.${field.name} must be optional, computed, or have a default`);
      }
    }
  }
}

module.exports = { SYSTEM_TABLES, analyzeSchema };
