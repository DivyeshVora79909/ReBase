const { resolveRecordTargets } = require("../schema");
const { contributesReaders } = require("../readers");
const { readerSourceExpression, use } = require("./security");

function generateViews(schema, options, systemTables = new Set(["user", "groups"])) {
  let definitions = schema.rawViews.trimEnd();
  let events = use(options.namespace, options.database);
  let computed = use(options.namespace, options.database);
  const viewIndexes = [];

  for (const view of schema.views) {
    const definition = view.statement.replace(/;\s*$/, "");
    definitions = definitions.replace(
      view.statement,
      `${definition}\n    PERMISSIONS FOR select WHERE '${view.sourceTable}_select' IN $auth.permissions\n    FOR create, update, delete NONE;`,
    );
    for (const groupKey of view.groupKeys) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(groupKey)) continue;
      viewIndexes.push({ table: view.name, fields: [groupKey] });
      const expression = view.projections.get(groupKey);
      const targets = expression
        ? resolveRecordTargets(schema, view.sourceTable, expression).filter((target) => !systemTables.has(target))
        : [];
      if (!targets.length) continue;
      events += `DEFINE EVENT OVERWRITE ping_${view.name}_${groupKey} ON TABLE ${view.name} WHEN $event != 'NONE' THEN {\n`;
      events += `    LET $target = $after.${groupKey} ?? $before.${groupKey};\n`;
      events += "    IF $target {\n";
      events += "        IF record::tb($target) IN ['user', 'groups'] { UPDATE $target; }\n";
      events += "        ELSE { UPDATE $target SET system_ping = time::now(); };\n";
      events += "    };\n};\n\n";
      for (const target of targets) {
        computed += `DEFINE FIELD OVERWRITE c_${view.name}_${groupKey} ON TABLE ${target} COMPUTED (SELECT * FROM ${view.name} WHERE ${groupKey} = $parent.id);\n`;
      }
      computed += "\n";
    }
  }
  return { definitions: `${definitions}\n`, events, computed, viewIndexes };
}

function generateCascades(analysis, options) {
  let output = use(options.namespace, options.database);
  for (const [targetTable, references] of analysis.reverseReferences.entries()) {
    if (analysis.systemTables.has(targetTable)) continue;
    const businessReferences = references.filter((reference) => !reference.sourceIsSystem);
    if (!businessReferences.length) continue;
    output += `DEFINE EVENT OVERWRITE rebase_cascade_downward ON TABLE ${targetTable}\n`;
    output += "    WHEN $event = 'UPDATE' AND ($before.owned_by != $after.owned_by OR $before.readers_index != $after.readers_index) THEN {\n";
    for (const [index, reference] of businessReferences.entries()) {
      const variable = `$targets_${index + 1}`;
      output += `    LET ${variable} = $after.id<~(${reference.sourceTable} FIELD ${reference.sourceField});\n`;
      output += `    IF ${variable} { UPDATE ${variable} SET system_ping = time::now(); };\n`;
    }
    output += "};\n\n";
  }
  return output;
}

function generateReaderCycleGuards(schema, options, systemTables) {
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name)) continue;
    const fields = [...table.fields.values()].filter((field) =>
      contributesReaders(field, systemTables),
    );
    if (!fields.length) continue;
    const sources = fields.map((field) =>
      readerSourceExpression(field, systemTables, "$after"),
    );
    const combined = sources.length === 1
      ? sources[0]
      : `array::concat(${sources.join(", ")})`;
    const changed = fields
      .map((field) => `$before.${field.name} != $after.${field.name}`)
      .join(" OR ");
    output += `DEFINE EVENT OVERWRITE rebase_prevent_reader_cycle ON TABLE ${table.name}\n`;
    output += `    WHEN $event IN ['CREATE', 'UPDATE'] AND (${changed}) THEN {\n`;
    output += `    LET $sources = array::distinct(${combined}).filter(|$source| $source != NONE);\n`;
    output += "    LET $reachable = array::flatten($sources.{..+collect}.rebase_reader_sources);\n";
    output += "    IF $after.id IN $reachable { THROW 'REBASE_READER_CYCLE'; };\n";
    output += "};\n\n";
  }
  return output;
}

module.exports = { generateCascades, generateReaderCycleGuards, generateViews };
