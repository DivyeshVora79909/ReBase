const { resolveRecordTargets } = require("../schema");
const { use } = require("./security");
const { tableSelectPredicate } = require("../security-policy");

function generateViews(schema, options, systemTables = new Set(["rebase_user", "rebase_group"])) {
  let definitions = schema.rawViews.trimEnd();
  let events = use(options.namespace, options.database);
  let computed = use(options.namespace, options.database);
  const viewIndexes = [];

  for (const view of schema.views) {
    if (!view.groupKeys.includes('tenant') || !view.projections.has('tenant')) {
      throw new Error(`${view.name}: materialized views must select and group by tenant`);
    }
    if (view.tenantPublished === view.recordScoped) {
      throw new Error(`${view.name}: declare exactly one of @rebase-view-tenant-published or @rebase-view-record-scoped`);
    }
    if (systemTables.has(view.sourceTable) && !view.tenantPublished) {
      throw new Error(`${view.name}: views over system tables must be explicitly tenant-published`);
    }
    if (view.recordScoped) {
      for (const field of ['owned_by', 'readers_index']) {
        if (!view.groupKeys.includes(field) || view.projections.get(field) !== field) {
          throw new Error(`${view.name}: @rebase-view-record-scoped requires ${field} as a direct projection and GROUP BY key`);
        }
      }
    }
    const definition = view.statement.replace(/;\s*$/, "");
    const selectPolicy = view.tenantPublished
      ? `$auth != NONE AND $this.tenant = $auth.tenant AND '${view.sourceTable}_select' IN $auth.permissions`
      : tableSelectPredicate(view.sourceTable, { ...options, row: '$this' });
    definitions = definitions.replace(
      view.statement,
      `${definition}\n    PERMISSIONS FOR select WHERE ${selectPolicy}\n    FOR create, update, delete NONE;`,
    );
    for (const groupKey of view.groupKeys) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(groupKey)) continue;
      viewIndexes.push({ table: view.name, fields: [groupKey] });
      const expression = view.projections.get(groupKey);
      const targets = expression
        ? resolveRecordTargets(schema, view.sourceTable, expression).filter((target) => !systemTables.has(target))
        : [];
      if (!targets.length) continue;
      events += `DEFINE EVENT OVERWRITE ping_${view.name}_${groupKey} ON TABLE ${view.name} WHEN $event != 'NONE' AND $before != $after THEN {\n`;
      events += `    LET $target = $after.${groupKey} ?? $before.${groupKey};\n`;
      events += "    IF $target {\n";
      const principalNames = options.principalTables || ["rebase_user", "rebase_group"];
      events += `        IF record::tb($target) IN [${principalNames.map((name) => `'${name}'`).join(", ")}] { UPDATE $target; }\n`;
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

function generateCascades(analysis, options, trees = { roots: [] }) {
  let output = use(options.namespace, options.database);
  const sourcesByTarget = new Map();
  for (const [target, references] of analysis.reverseReferences) {
    sourcesByTarget.set(target, new Set(references.filter(r => !r.sourceIsSystem).map(r => r.sourceTable)));
  }
  for (const root of trees.roots) {
    if (!sourcesByTarget.has(root.table)) sourcesByTarget.set(root.table, new Set());
    for (const node of root.nodes) sourcesByTarget.get(root.table).add(node.table);
  }
  for (const [targetTable, sources] of sourcesByTarget) {
    if (analysis.systemTables.has(targetTable)) continue;
    if (!sources.size) continue;
    output += `DEFINE EVENT OVERWRITE rebase_cascade_downward ON TABLE ${targetTable}\n`;
    output += "    WHEN $event = 'UPDATE' AND $before.owned_by != $after.owned_by THEN {\n";
    for (const [index, sourceTable] of [...sources].entries()) {
      const variable = `$targets_${index + 1}`;
      output += `    LET ${variable} = $after.id<~(${sourceTable} FIELD rebase_reader_sources);\n`;
      output += `    IF ${variable} { UPDATE ${variable} SET system_ping = time::now(); };\n`;
    }
    output += "};\n\n";
  }
  return output;
}

module.exports = { generateCascades, generateViews };
