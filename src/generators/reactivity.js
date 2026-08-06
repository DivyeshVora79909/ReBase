const { resolveRecordTargets } = require("../schema");
const { use } = require("./security");

function generateViews(schema, options) {
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
      const targets = expression ? resolveRecordTargets(schema, view.sourceTable, expression) : [];
      if (!targets.length) continue;
      events += `DEFINE EVENT OVERWRITE ping_${view.name}_${groupKey} ON TABLE ${view.name} WHEN $event != 'NONE' THEN {\n`;
      events += "    IF $__rebase_halt_cascade != true {\n";
      events += `        LET $target = $after.${groupKey} ?? $before.${groupKey};\n`;
      events += "        IF $target {\n";
      events += "            LET $__rebase_halt_cascade = true;\n";
      events += "            IF record::tb($target) IN ['user', 'groups'] { UPDATE $target; }\n";
      events += "            ELSE { UPDATE $target SET system_ping = time::now(); };\n";
      events += "        };\n    };\n};\n\n";
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
    const businessReferences = references.filter((reference) => !reference.sourceIsSystem);
    if (!businessReferences.length) continue;
    output += `DEFINE EVENT OVERWRITE rebase_cascade_downward ON TABLE ${targetTable} WHEN $event = 'UPDATE' THEN {\n`;
    output += "    IF $__rebase_halt_cascade != true {\n";
    output += "        LET $__rebase_halt_cascade = true;\n";
    for (const [index, reference] of businessReferences.entries()) {
      const variable = `$targets_${index + 1}`;
      output += `        LET ${variable} = $after.id<~(${reference.sourceTable} FIELD ${reference.sourceField});\n`;
      output += `        IF ${variable} { UPDATE ${variable} SET system_ping = time::now(); };\n`;
    }
    output += "    };\n};\n\n";
  }
  return output;
}

module.exports = { generateCascades, generateViews };
