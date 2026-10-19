"use strict";

const { Surreal } = require("surrealdb");
const { validateAccess } = require("./graph");

async function query(db, sql, bindings) {
  const responses = await db.query(sql, bindings).json().responses();
  const failure = responses.find(response => !response.success);
  if (failure) throw failure.error || new Error("The database rejected the query.");
  if (!responses.length) throw new Error("The database returned no response.");
  return responses.at(-1).result;
}

async function readAccess(db, tenant, limit = 1000) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10000) throw new Error("Use a limit from 1 to 10,000 per table.");
  const result = await query(db, [
    "LET $scope = type::record($tenant);",
    "IF record::tb($scope) != 'rebase_tenant' { THROW 'Choose a rebase_tenant record'; };",
    "RETURN {",
    "  root: (SELECT id, tenant, name, role, [] AS parents, 'rebase_tenant' AS table FROM $scope TIMEOUT 15s),",
    "  groups: (SELECT id, tenant, name, parents, role, authorization_depth, 'rebase_group' AS table",
    "    FROM rebase_group WHERE tenant = $scope ORDER BY id LIMIT $limit TIMEOUT 15s),",
    "  users: (SELECT id, tenant, name, parents, permissions, login_access, authorization_depth, 'rebase_user' AS table",
    "    FROM rebase_user WHERE tenant = $scope ORDER BY id LIMIT $limit TIMEOUT 15s)",
    "};",
  ].join("\n"), { tenant, limit: limit + 1 });
  if (result.root.length !== 1) throw new Error("Tenant not found or not readable by this login.");
  return validateAccess({
    format: "rebase-access", version: 1, tenant: result.root[0].id, limit,
    truncated: result.groups.length > limit || result.users.length > limit,
    records: [...result.root, ...result.groups.slice(0, limit), ...result.users.slice(0, limit)],
  });
}

async function connectAccess({ endpoint, namespace, database, username, password, token, tenant, limit }) {
  const url = new URL(endpoint);
  if (!["ws:", "wss:"].includes(url.protocol) || url.username || url.password) throw new Error("Use a ws:// or wss:// endpoint without credentials in its URL.");
  if (!namespace?.trim() || !database?.trim() || !tenant?.trim()) throw new Error("Namespace, database and tenant are required.");
  const db = new Surreal();
  try {
    await db.connect(url.href, { reconnect: false });
    await db.use({ namespace, database });
    if (token) await db.authenticate(token);
    else await db.signin({ username, password });
    return { db, snapshot: await readAccess(db, tenant, limit) };
  } catch (error) {
    await db.close();
    throw error;
  }
}

async function readRecordState(db, table, id, tenant) {
  const fields = ["id", "tenant", "owned_by", "read_by", ...table.fields
    .filter(field => ["root", "member", "query", "derived"].includes(field.kind))
    .map(field => field.name)];
  const rows = await query(db, [
    "LET $record = type::record($id);",
    "IF record::tb($record) != $table { THROW 'Record belongs to a different table'; };",
    "SELECT type::fields($fields) FROM $record WHERE tenant = type::record($tenant) TIMEOUT 15s;",
  ].join("\n"), { id, table: table.name, fields: [...new Set(fields)], tenant });
  if (rows.length !== 1) throw new Error("Record not found, outside this tenant, or not readable.");
  return rows[0];
}

module.exports = { connectAccess, readAccess, readRecordState };
