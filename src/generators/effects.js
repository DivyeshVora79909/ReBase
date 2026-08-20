function use(namespace, database) {
  if (!namespace || !database) return "";
  return `USE NS ${namespace} DB ${database};\n\n`;
}

function quote(value) {
  return `'${String(value).replaceAll("'", "\\'")}'`;
}

function outputExpression(field) {
  const value = `$response.patch.${field.name}`;
  const definition = field.definition || "";
  const optional = /\bTYPE\s+(?:option<|none\s*\|)/i.test(definition);
  let converted = value;
  if (/\bTYPE\s+(?:option<)?datetime\b/i.test(definition)) converted = `type::datetime(${value})`;
  else if (/\bTYPE\s+(?:option<)?uuid\b/i.test(definition)) converted = `type::uuid(${value})`;
  else if (/\bTYPE\s+(?:option<)?duration\b/i.test(definition)) converted = `type::duration(${value})`;
  else if (/\bTYPE\s+(?:option<)?record(?:<|\b)/i.test(definition)) converted = `type::record(${value})`;
  else if (/\bTYPE\s+(?:option<)?decimal\b/i.test(definition)) converted = `<decimal>${value}`;
  return optional && converted !== value ? `IF ${value} = NONE THEN NONE ELSE ${converted} END` : converted;
}

function generateEffectEvents(schema, options = {}) {
  if (!options.runtimeUrl || !options.runtimeSecret || !options.namespace || !options.database) return "";
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    if (!table.effectProcess) continue;
    const inputFields = [...table.fields.values()].filter((field) => field.effectInput).map((field) => field.name);
    const outputFields = [...table.fields.values()].filter((field) => field.effectOutput);
    const changed = inputFields.map((field) => `$before.${field} != $after.${field}`).join(" OR ");
    const when = table.effectProcess === "sync" && changed
      ? `$event = 'CREATE' OR ($event = 'UPDATE' AND (${changed}))`
      : "$event = 'CREATE'";
    const snapshotFields = ["id: $after.id", "owned_by: $after.owned_by", ...inputFields.map((field) => `${field}: $after.${field}`)];
    const patchFields = outputFields.map((field) => `${field.name}: ${outputExpression(field)}`);
    const body = table.effectProcess === "sync"
      ? `
        LET $response = http::post(${quote(options.runtimeUrl + "/internal/sync")}, {
            namespace: ${quote(options.namespace)},
            database: ${quote(options.database)},
            id: <string>$after.id,
            event: $event,
            record: { ${snapshotFields.join(", ")} }
        }, { authorization: ${quote(`Bearer ${options.runtimeSecret}`)} });
        IF $response.patch { UPDATE $after.id MERGE { ${patchFields.join(", ")} }; };
      `
      : `
        LET $response = http::post(${quote(options.runtimeUrl + "/internal/async")}, {
            namespace: ${quote(options.namespace)},
            database: ${quote(options.database)},
            id: <string>$after.id
        }, { authorization: ${quote(`Bearer ${options.runtimeSecret}`)} });
      `;
    output += `DEFINE EVENT OVERWRITE rebase_effect_${table.name} ON TABLE ${table.name}\n`;
    const asyncClause = table.effectProcess === "async" ? " ASYNC RETRY 0 MAXDEPTH 0" : "";
    output += `    WHEN ${when}${asyncClause} THEN {${body}};\n\n`;
  }
  return output;
}

module.exports = { generateEffectEvents };
