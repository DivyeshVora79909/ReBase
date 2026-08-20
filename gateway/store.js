const { clean, queryResult, recordIdString } = require("./utils");

function identifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) throw new Error(`Invalid table identifier: ${value}`);
  return value;
}

function createTableStore(database) {
  const db = database.db || database;

  async function load(id) {
    return clean(queryResult(await db.query(
      "RETURN (SELECT * FROM type::record($id))[0];",
      { id: String(id) },
    )));
  }

  async function patch(id, patchValue) {
    if (!patchValue || typeof patchValue !== "object" || Array.isArray(patchValue)) {
      throw new Error("Handler patch must be an object");
    }
    return clean(queryResult(await db.query(
      "RETURN (UPDATE type::record($id) MERGE $patch RETURN AFTER)[0];",
      { id: String(id), patch: patchValue },
    )));
  }

  async function claim(id) {
    return clean(queryResult(await db.query(
      "RETURN (UPDATE type::record($id) SET effect_state = 'processing' WHERE effect_state IN ['pending', 'waiting'] RETURN AFTER)[0];",
      { id: String(id) },
    )));
  }

  async function pending(tables) {
    const names = [...new Set(tables)].map(identifier);
    if (!names.length) return [];
    const parts = names.map((table) => `SELECT VALUE <string>id FROM ${table} WHERE effect_state IN ['pending', 'waiting'] AND (scheduled_for = NONE OR scheduled_for <= time::now())`);
    const value = queryResult(await db.query(`RETURN array::flatten([${parts.join(", ")}]);`));
    return (Array.isArray(value) ? value : []).map(recordIdString);
  }

  return { claim, load, patch, pending };
}

module.exports = { createTableStore };
