function identifier(value, label = "identifier") {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || ""))
    throw new Error(`Invalid ${label}: ${value}`);
  return value;
}

function result(responses) {
  const value = Array.isArray(responses) ? responses.at(-1) : responses;
  return value && typeof value === "object" && "result" in value
    ? value.result
    : value;
}

async function dbInfo(db) {
  if (!db?.query) throw new Error("A SurrealDB client is required");
  return result(await db.query("INFO FOR DB;")) || {};
}

function names(section) {
  return Object.keys(section || {});
}

async function tables({ db }) {
  const info = await dbInfo(db);
  return info.tb || info.tables || {};
}

async function accessMethods({ db }) {
  const info = await dbInfo(db);
  return info.ac || info.accesses || {};
}

async function computedFields({ db, table }) {
  const selected = table
    ? [identifier(table, "table")]
    : names((await dbInfo(db)).tb || (await dbInfo(db)).tables);
  const found = [];
  for (const name of selected) {
    const value = result(await db.query(`INFO FOR TABLE ${name};`)) || {};
    const fields = value.fd || value.fields || {};
    for (const [field, definition] of Object.entries(fields)) {
      if (/\b(VALUE|DEFAULT|ASSERT)\b/i.test(String(definition)))
        found.push({ table: name, field, definition });
    }
  }
  return found;
}

async function indexes({ db, table }) {
  const selected = table
    ? [identifier(table, "table")]
    : names((await dbInfo(db)).tb || (await dbInfo(db)).tables);
  const found = [];
  for (const name of selected) {
    const value = result(await db.query(`INFO FOR TABLE ${name};`)) || {};
    for (const [index, definition] of Object.entries(
      value.ix || value.indexes || {},
    ))
      found.push({ table: name, index, definition });
  }
  return found;
}

async function recordState({ db, ids }) {
  if (!Array.isArray(ids) || !ids.length)
    throw new Error("recordState requires ids");
  return result(await db.query("SELECT * FROM type::record($ids);", { ids }));
}

module.exports = {
  tables,
  accessMethods,
  computedFields,
  indexes,
  recordState,
};
