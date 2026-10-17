"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { prepare } = require("../prepare");

function session(context = { namespace: "test", database: "books" }) {
  const writes = [];
  let committed = false, cancelled = false;
  const db = {
    query: async () => [context],
    beginTransaction: async () => ({
      query: async (sql, bindings) => { writes.push({ sql, bindings }); return []; },
      commit: async () => { committed = true; },
      cancel: async () => { cancelled = true; },
    }),
  };
  return { db, writes, get committed() { return committed; }, get cancelled() { return cancelled; } };
}

test("prepare rejects invalid requests before opening a transaction", async () => {
  const client = session();
  for (const options of [{}, { clear: "yes" }, { schema: "x", typo: true }, { clear: true, batchBytes: 0 },
    { schema: "x", onProgress: true }]) {
    await assert.rejects(prepare(client.db, options));
  }
  assert.equal(client.committed, false);
  assert.equal(client.cancelled, false);
  assert.deepEqual(client.writes, []);
});

test("schema preparation retains the selected context and rejects foreign USE/transaction control", async () => {
  const client = session();
  const report = await prepare(client.db, { schema: "-- context\nUSE NS test DB books; DEFINE TABLE x SCHEMALESS;" });
  assert.equal(report.statements, 1);
  assert.equal(client.committed, true);
  assert(!client.writes[0].sql.includes("USE NS"));
  assert.deepEqual(client.writes[0].bindings, { prepare_namespace: "test", prepare_database: "books" });
  for (const source of ["USE NS other DB books; DEFINE TABLE x;", "BEGIN; DEFINE TABLE x; COMMIT;", "OPTION IMPORT; DEFINE TABLE x;"]) {
    const unchanged = session();
    await assert.rejects(prepare(unchanged.db, { schema: source }));
    assert.deepEqual(unchanged.writes, []);
  }
  await assert.rejects(prepare(session({}).db, { schema: "DEFINE TABLE x;" }), /Select a namespace/);
});

test("batching counts UTF-8 bytes and keeps function bodies intact", async () => {
  const client = session();
  const functionSql = "DEFINE FUNCTION fn::example() { RETURN '€;value'; };";
  const tableSql = "DEFINE TABLE x SCHEMALESS;";
  const report = await prepare(client.db, { schema: `${functionSql}\n${tableSql}`, batchBytes: 60 });
  assert.equal(client.writes.length, 2);
  assert(client.writes[0].sql.includes(functionSql));
  assert(client.writes[1].sql.includes(tableSql));
  assert.equal(report.statements, 2);
  const unchanged = session();
  await assert.rejects(prepare(unchanged.db, { schema: functionSql, batchBytes: 20 }), /exceeds batchBytes/);
  assert.deepEqual(unchanged.writes, []);
});

test("progress failure cancels all earlier batches and never commits", async () => {
  const client = session();
  await assert.rejects(prepare(client.db, {
    schema: "DEFINE TABLE a SCHEMALESS; DEFINE TABLE b SCHEMALESS;", batchBytes: 30,
    onProgress: progress => { if (progress.completed === 1) throw new Error("stop trial"); },
  }), /stop trial/);
  assert.equal(client.writes.length, 1);
  assert.equal(client.cancelled, true);
  assert.equal(client.committed, false);
});

test("query response failures and cancellation failures remain visible", async () => {
  const client = session();
  client.db.beginTransaction = async () => ({
    query: () => ({ responses: async () => [
      { success: false, error: new Error("cancelled statement") },
      { success: false, error: new Error("actual failure") },
    ] }),
    cancel: async () => { throw new Error("cancellation failed"); },
  });
  await assert.rejects(prepare(client.db, { schema: "DEFINE TABLE x;" }), error => {
    assert(error instanceof AggregateError);
    assert.match(error.errors[0].message, /actual failure/);
    assert.match(error.errors[1].message, /cancellation failed/);
    return true;
  });
});
