function identifier(value, label) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) throw new Error(`Invalid ${label}: ${value}`);
  return value;
}

function result(responses) {
  const value = Array.isArray(responses) ? responses.at(-1) : responses;
  return value && typeof value === "object" && "result" in value ? value.result : value;
}

function client(db) {
  if (!db?.query) throw new Error("A SurrealDB client is required");
  return db;
}

async function resetDatabase({ db, namespace, database, confirm = false }) {
  if (!confirm) throw new Error("resetDatabase requires confirm: true");
  identifier(namespace, "namespace");
  identifier(database, "database");
  client(db);
  await db.query(`DEFINE NAMESPACE IF NOT EXISTS ${namespace}; USE NS ${namespace}; REMOVE DATABASE IF EXISTS ${database}; DEFINE DATABASE ${database}; USE DB ${database};`);
  return { operation: "resetDatabase", namespace, database };
}

async function clearTable({ db, table }) {
  client(db);
  identifier(table, "table");
  const response = await db.query(`DELETE FROM ${table};`);
  return { operation: "clearTable", table, response };
}

async function clearData({ db, tables }) {
  if (!Array.isArray(tables) || !tables.length) throw new Error("clearData requires an explicit tables array");
  const results = [];
  for (const table of tables) results.push(await clearTable({ db, table }));
  return { operation: "clearData", tables, results };
}

async function databaseInfo({ db }) {
  return result(await client(db).query("INFO FOR DB;"));
}

async function tableInfo({ db, table }) {
  identifier(table, "table");
  return result(await client(db).query(`INFO FOR TABLE ${table};`));
}

module.exports = { resetDatabase, clearData, clearTable, databaseInfo, tableInfo };
