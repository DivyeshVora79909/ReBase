"use strict";

const { performance } = require("node:perf_hooks");
const { escapeIdent } = require("surrealdb");
const { mapSqlCode, splitStatementsWithLocations } = require("./compiler/surql");

// Clearing needs OPTION IMPORT, which 3.3 cannot execute in an SDK interactive
// transaction. Its entire mutation is one ordinary, explicitly atomic query.
const DEFAULT_BATCH_BYTES = 256000;

async function query(target, source, bindings) {
  const pending = target.query(source, bindings);
  if (typeof pending.responses !== "function") return pending;
  const responses = await pending.responses();
  const errors = responses.filter(response => !response.success).map(response => response.error);
  if (errors.length) {
    throw new AggregateError(errors, [...new Set(errors.map(error => error.message))].join("\n"));
  }
  return responses.map(response => response.result);
}

function chunks(statements, limit) {
  const result = [];
  let source = "", bytes = 0, start = 0;
  statements.forEach((statement, index) => {
    const size = Buffer.byteLength(statement.source) + 1;
    if (size > limit) throw new Error(`Statement at line ${statement.line} exceeds batchBytes (${limit})`);
    if (bytes + size > limit && source) {
      result.push({ source, start, end: index });
      source = ""; bytes = 0; start = index;
    }
    source += `${statement.source}\n`;
    bytes += size;
  });
  if (source) result.push({ source, start, end: statements.length });
  return result;
}

function schemaStatements(schema, context) {
  if (schema === undefined) return [];
  if (typeof schema !== "string" || !schema.trim()) throw new Error("schema must be non-empty SurrealQL text");
  return splitStatementsWithLocations(schema).filter(statement => {
    const code = mapSqlCode(statement.source, value => value, value =>
      /^(?:--|\/\*)/.test(value) ? " " : value).trim();
    if (!code) return false;
    if (/^(?:BEGIN|COMMIT|CANCEL|OPTION)\b/i.test(code)) {
      throw new Error(`prepare owns transactions and options; unsupported statement at line ${statement.line}`);
    }
    if (/^USE\b/i.test(code)) {
      const match = /^USE\s+(?:NS|NAMESPACE)\s+(.+?)\s+(?:DB|DATABASE)\s+(.+?)\s*;?$/i.exec(code);
      if (!match || match[1] !== escapeIdent(context.namespace) || match[2] !== escapeIdent(context.database)) {
        throw new Error(`Schema USE at line ${statement.line} must match the connected namespace and database`);
      }
      return false; // Keep the caller's SDK session as the only target selector.
    }
    return true;
  }).map(statement => ({ ...statement,
    source: statement.source.endsWith(";") ? statement.source : `${statement.source}\n;`,
  }));
}

async function inspect(db, context, batchBytes, run) {
  const catalog = (await run(db, `LET $info = INFO FOR DB;
    RETURN { tables: object::keys($info.tables), signature: crypto::sha256(<string>$info) };`)).at(-1);
  if (!Array.isArray(catalog?.tables) || typeof catalog.signature !== "string") {
    throw new Error("Unable to inspect the complete database catalog");
  }
  const tables = [...catalog.tables].sort();
  const descriptions = tables.map((table, index) => ({ line: index + 1, source: `
    LET $prepare_info_${index} = INFO FOR TABLE ${escapeIdent(table)} STRUCTURE;
    RETURN {
      signature: crypto::sha256(<string>$prepare_info_${index}),
      references: $prepare_info_${index}.fields.filter(|$field| $field.reference != NONE)
        .map(|$field| { name: $field.name, onDelete: $field.reference.on_delete }),
      asyncEvents: $prepare_info_${index}.events.filter(|$event| $event.async = true).name
    };` }));
  const metadata = [];
  for (const batch of chunks(descriptions, batchBytes)) {
    const results = await run(db, batch.source);
    metadata.push(...results.filter(value => value && typeof value.signature === "string"));
  }
  if (metadata.length !== tables.length) throw new Error("Incomplete table metadata; database was not cleared");
  const guards = [], disable = [], restore = [];
  let referenceCount = 0;
  metadata.forEach((info, index) => {
    const table = escapeIdent(tables[index]);
    if (!Array.isArray(info.references) || !Array.isArray(info.asyncEvents)) throw new Error("Unsupported table metadata");
    if (info.asyncEvents.length) {
      throw new Error(`Cannot clear ${tables[index]}: native ASYNC events may have queued work; use an isolated database without native ASYNC events`);
    }
    guards.push(`IF crypto::sha256(<string>(INFO FOR TABLE ${table} STRUCTURE)) != $prepare_signatures[${index}] { THROW 'PREPARE_SCHEMA_CHANGED'; };`);
    for (const field of info.references) {
      if (typeof field.name !== "string" || typeof field.onDelete !== "string" || !field.onDelete) {
        throw new Error(`Unsupported reference metadata on ${tables[index]}`);
      }
      referenceCount++;
      if (field.onDelete === "IGNORE") continue;
      // STRUCTURE renders field names as native SQL idioms, including quoting
      // and array paths. Escaping the whole idiom would change its meaning.
      const prefix = `ALTER FIELD ${field.name} ON ${table} REFERENCE ON DELETE`;
      disable.push(`${prefix} IGNORE;`);
      restore.push(`${prefix} ${field.onDelete};`);
    }
  });
  const source = [
    "OPTION IMPORT;", "BEGIN TRANSACTION;",
    "IF session::ns() != $prepare_namespace OR session::db() != $prepare_database { THROW 'PREPARE_CONTEXT_CHANGED'; };",
    "IF crypto::sha256(<string>(INFO FOR DB)) != $prepare_catalog { THROW 'PREPARE_SCHEMA_CHANGED'; };",
    ...guards, ...disable,
    ...tables.map(table => `DELETE ${escapeIdent(table)} RETURN NONE;`),
    ...restore, "OPTION IMPORT = false;",
  ].join("\n");
  return { tables, referenceCount, statementCount: disable.length + restore.length + tables.length, source, bindings: {
    prepare_namespace: context.namespace, prepare_database: context.database,
    prepare_catalog: catalog.signature, prepare_signatures: metadata.map(info => info.signature),
  } };
}

/** Prepare the explicitly selected database; never connects, closes, or infers a profile. */
async function prepare(db, options = {}) {
  const { schema, clear = false, batchBytes = DEFAULT_BATCH_BYTES, onProgress } = options;
  if (!db || typeof db.query !== "function") throw new Error("prepare requires a connected SurrealDB SDK client");
  for (const key of Object.keys(options)) {
    if (!["schema", "clear", "batchBytes", "onProgress"].includes(key)) throw new Error(`Unknown prepare option: ${key}`);
  }
  if (typeof clear !== "boolean") throw new Error("clear must be boolean");
  if (!clear && schema === undefined) throw new Error("Provide schema or clear: true");
  if (!Number.isSafeInteger(batchBytes) || batchBytes < 1) throw new Error("batchBytes must be a positive safe integer");
  if (onProgress !== undefined && typeof onProgress !== "function") throw new Error("onProgress must be a function");
  const started = performance.now();
  const operation = clear ? (schema === undefined ? "clear" : "clear+schema") : "schema";
  const report = { operation, tables: [], references: 0, statements: 0, requests: 0,
    timings: { inspectMs: 0, executeMs: 0, commitMs: 0 }, durationMs: 0 };
  const run = async (target, source, bindings) => {
    report.requests++;
    return query(target, source, bindings);
  };
  const progress = async (phase, completed, total) => {
    if (onProgress) await onProgress({ operation, phase, completed, total,
      requests: report.requests, elapsedMs: performance.now() - started });
  };
  const [context] = await run(db, "RETURN { namespace: session::ns(), database: session::db() };");
  if (!context?.namespace || !context.database) throw new Error("Select a namespace and database before prepare");
  const statements = schemaStatements(schema, context);
  const batches = chunks(statements, batchBytes);
  report.statements = statements.length;
  if (clear) {
    await progress("inspect", 0, 1);
    const plan = await inspect(db, context, batchBytes, run);
    report.tables = plan.tables;
    report.references = plan.referenceCount;
    report.statements += plan.statementCount;
    const source = `${plan.source}\n${statements.map(statement => statement.source).join("\n")}\nCOMMIT TRANSACTION;`;
    if (Buffer.byteLength(source) + Buffer.byteLength(JSON.stringify(plan.bindings)) > batchBytes) {
      throw new Error("Atomic clear request exceeds batchBytes; increase it within server limits. Clearing cannot be split across requests");
    }
    report.timings.inspectMs = performance.now() - started;
    await progress("clear", 0, plan.tables.length);
    const executeStart = performance.now();
    await run(db, source, plan.bindings);
    report.timings.executeMs = performance.now() - executeStart;
    // Clear's commit is included in its one atomic request. Do not invoke a
    // fallible observer after commit: success must never look like a rollback.
  } else {
    if (typeof db.beginTransaction !== "function") throw new Error("Schema installation requires SDK WebSocket transactions");
    report.timings.inspectMs = performance.now() - started;
    await progress("install", 0, statements.length);
    const transaction = await db.beginTransaction();
    const executeStart = performance.now();
    try {
      for (const batch of batches) {
        try { await run(transaction, `IF session::ns() != $prepare_namespace OR session::db() != $prepare_database { THROW 'PREPARE_CONTEXT_CHANGED'; };\n${batch.source}`,
          { prepare_namespace: context.namespace, prepare_database: context.database }); }
        catch (error) {
          throw new Error(`Schema installation failed at lines ${statements[batch.start].line}–${statements[batch.end - 1].line}: ${error.message}`, { cause: error });
        }
        await progress("install", batch.end, statements.length);
      }
      report.timings.executeMs = performance.now() - executeStart;
      await progress("commit", statements.length, statements.length);
      const commitStart = performance.now();
      await transaction.commit();
      report.timings.commitMs = performance.now() - commitStart;
    } catch (error) {
      try { await transaction.cancel(); }
      catch (cancelError) { throw new AggregateError([error, cancelError], "Preparation failed and transaction cancellation also failed", { cause: error }); }
      throw error;
    }
  }
  report.durationMs = performance.now() - started;
  return report;
}

module.exports = { prepare };
