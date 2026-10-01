const PRINCIPAL_TABLES = Object.freeze({ user: "rebase_user", group: "rebase_group" });
const PRINCIPAL_NAMES = Object.freeze([PRINCIPAL_TABLES.user, PRINCIPAL_TABLES.group]);

function validatePrincipalTables(schema) {
  for (const table of PRINCIPAL_NAMES) {
    if (!schema.tables.has(table)) {
      throw new Error(`Framework schema must define fixed principal table ${table}`);
    }
  }
  return PRINCIPAL_TABLES;
}

function detectSelectPolicy(source) {
  const matches = [...String(source).matchAll(/@rebase-select\s+(owner|readers)\b/gi)]
    .map((match) => match[1].toLowerCase());
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting @rebase-select policies: ${unique.join(", ")}`);
  return unique[0] || "readers";
}

module.exports = { PRINCIPAL_NAMES, PRINCIPAL_TABLES, detectSelectPolicy, validatePrincipalTables };
