const { use } = require("./security");

function generateIndexes(schema, viewIndexes, options, systemTables) {
  let output = use(options.namespace, options.database);
  const indexes = [];
  const seen = new Set();
  const add = (name, table, fields, purpose) => {
    const key = `${table}:${fields.join(",")}`;
    if (seen.has(key)) return;
    seen.add(key);
    indexes.push({ name, table, fields, purpose });
    output += `DEFINE INDEX OVERWRITE ${name} ON TABLE ${table} FIELDS ${fields.join(", ")};\n`;
  };

  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name)) continue;
    add(`idx_${table.name}_owned_by`, table.name, ["owned_by"], "ownership");
    add(`idx_${table.name}_readers`, table.name, ["readers_index.*"], "permission fan-out");
    for (const field of table.fields.values()) {
      if (field.recordType && !field.recordType.isArray) {
        add(`idx_${table.name}_${field.name}`, table.name, [field.name], "record reference");
      }
    }
  }
  for (const view of viewIndexes) {
    add(`idx_${view.table}_${view.fields.join("_")}`, view.table, view.fields, "computed view lookup");
  }
  return { sql: output, indexes };
}

module.exports = { generateIndexes };
