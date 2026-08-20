const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function discoverPrincipalTables(schema) {
  const found = { user: [], group: [] };
  for (const table of schema.tables.values()) {
    if (table.principalKind) found[table.principalKind].push(table.name);
  }
  for (const kind of ["user", "group"]) {
    if (found[kind].length !== 1) {
      throw new Error(
        `Expected exactly one @rebase-principal ${kind} table, found ${found[kind].length}`,
      );
    }
  }
  if (found.user[0] === found.group[0]) {
    throw new Error("User and group principal tables must be different");
  }
  return Object.freeze({ user: found.user[0], group: found.group[0] });
}

function replaceToken(source, token, replacement) {
  if (!IDENTIFIER.test(replacement)) throw new Error(`Invalid principal table: ${replacement}`);
  return source.replace(new RegExp(`\\b${token}\\b`, "g"), replacement);
}

function bindFrameworkPrincipals(source, principals) {
  const placeholders = {
    user: "__REBASE_PRINCIPAL_USER__",
    group: "__REBASE_PRINCIPAL_GROUP__",
  };
  let output = replaceToken(source, "user", placeholders.user);
  output = replaceToken(output, "groups", placeholders.group);
  output = output.replaceAll(placeholders.user, principals.user);
  output = output.replaceAll(placeholders.group, principals.group);
  return output;
}

function detectSelectPolicy(source) {
  const matches = [...String(source).matchAll(/@rebase-select\s+(owner|readers)\b/gi)]
    .map((match) => match[1].toLowerCase());
  const unique = [...new Set(matches)];
  if (unique.length > 1) throw new Error(`Conflicting @rebase-select policies: ${unique.join(", ")}`);
  return unique[0] || "readers";
}

module.exports = {
  bindFrameworkPrincipals,
  detectSelectPolicy,
  discoverPrincipalTables,
};
