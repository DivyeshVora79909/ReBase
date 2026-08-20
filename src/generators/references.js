const { extractClauseExpression } = require("../surql");
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
      if (!field.recordType || /@rebase-reference-delta\b/i.test(field.comment)) continue;
      output += `ALTER FIELD ${field.name} ON TABLE ${table.name} ASSERT ${combinedAssertion(field)};\n`;
    }
  }
  return output;
}

module.exports = { combinedAssertion, existenceAssertion, generateReferenceAssertions };
