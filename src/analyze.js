const EXTENSION_TABLES = new Set(["user", "groups"]);
const { contributesReaders } = require("./readers");

function analyzeSchema(schema, frameworkTables = EXTENSION_TABLES) {
  const extensionTables = new Set(
    [...schema.tables.values()]
      .filter((table) => table.principalKind)
      .map((table) => table.name),
  );
  validateSystemExtensions(schema, extensionTables.size ? extensionTables : EXTENSION_TABLES);
  const reverseReferences = new Map();
  for (const table of schema.tables.values()) {
    for (const field of table.fields.values()) {
      if (!contributesReaders(field, frameworkTables)) continue;
      if (!/\bREFERENCE\b/i.test(field.definition)) {
        throw new Error(
          `Reader field ${table.name}.${field.name} must declare REFERENCE`,
        );
      }
      for (const target of field.recordType.targets) {
        if (!reverseReferences.has(target)) reverseReferences.set(target, []);
        reverseReferences.get(target).push({
          sourceTable: table.name,
          sourceField: field.name,
          sourceIsSystem: frameworkTables.has(table.name),
        });
      }
    }
  }
  return { reverseReferences, systemTables: frameworkTables };
}

function validateSystemExtensions(schema, extensionTables) {
  for (const tableName of extensionTables) {
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

module.exports = { EXTENSION_TABLES, analyzeSchema };
