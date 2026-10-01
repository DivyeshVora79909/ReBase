"use strict";

// The caller supplies a consistent snapshot of the old profile and an explicit
// book -> economic entity map. No migration write may precede this preflight.
const accountDimensions = {
  treasury_account: ["treasury", "currency"],
  claim_account: ["opponent", "currency"],
  stock_account: ["operating_unit", "resource"],
  sales_invoice: ["number"],
  purchase_invoice: ["number"],
};

function preflightH1(snapshot, assignments) {
  const books = new Set(snapshot.books.map((book) => String(book.id)));
  const map = new Map();
  for (const assignment of assignments) {
    const book = String(assignment.book);
    const entity = String(assignment.economic_entity);
    if (!books.has(book)) throw new Error(`H1_UNKNOWN_BOOK: ${book}`);
    if (!/^(rebase_user|organization):[^\s]+$/.test(entity)) {
      throw new Error(`H1_INVALID_ENTITY: ${entity}`);
    }
    if (map.has(book)) throw new Error(`H1_AMBIGUOUS_MAPPING: ${book}`);
    map.set(book, entity);
  }
  for (const book of books) {
    if (!map.has(book)) throw new Error(`H1_MISSING_MAPPING: ${book}`);
  }

  const output = {};
  for (const [table, fields] of Object.entries(accountDimensions)) {
    const seen = new Map();
    const existingIds = new Set((snapshot.existing?.[table] || []).map((row) => String(row.id)));
    output[table] = [];
    for (const row of [...(snapshot.existing?.[table] || []), ...(snapshot.legacy?.[table] || [])]) {
      const mapped = row.book ? map.get(String(row.book)) : undefined;
      if (row.economic_entity && mapped && String(row.economic_entity) !== mapped) {
        throw new Error(`H1_ENTITY_MAPPING_CONFLICT: ${String(row.id)}`);
      }
      const entity = row.economic_entity ? String(row.economic_entity) : mapped;
      if (!entity) throw new Error(`H1_MISSING_MAPPING: ${String(row.book)}`);
      const key = JSON.stringify([entity, ...fields.map((field) => String(row[field]))]);
      const other = seen.get(key);
      if (other && other !== String(row.id)) {
        throw new Error(`H1_DESTINATION_COLLISION: ${table} ${other} ${String(row.id)}`);
      }
      seen.set(key, String(row.id));
      if (row.book && !existingIds.has(String(row.id))) {
        output[table].push({ id: String(row.id), economic_entity: entity });
      }
    }
  }

  const unitEntities = new Map();
  for (const row of snapshot.legacy?.stock_account || []) {
    const unit = String(row.operating_unit);
    const entity = map.get(String(row.book));
    if (unitEntities.has(unit) && unitEntities.get(unit) !== entity) {
      throw new Error(`H1_AMBIGUOUS_OPERATING_UNIT: ${unit}`);
    }
    unitEntities.set(unit, entity);
  }
  for (const row of snapshot.legacy?.operating_unit || []) {
    const entity = unitEntities.get(String(row.id));
    if (!entity) throw new Error(`H1_UNMAPPED_OPERATING_UNIT: ${String(row.id)}`);
    output.operating_unit ||= [];
    output.operating_unit.push({ id: String(row.id), economic_entity: entity });
  }
  return output;
}

module.exports = { preflightH1 };
