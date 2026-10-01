#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { connectDatabase } = require("../gateway/connection");
const { assertConfiguredContext, assertConnectionConfiguration, resolveConfiguration } = require("../config/environment");

const DEFAULT_MAX_PASSES = 100;

function parseArgs(argv) {
  const args = { profile: "test", context: null, maxPasses: DEFAULT_MAX_PASSES, apply: false, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const next = () => {
      index += 1;
      if (argv[index] === undefined) throw new Error(`Missing value for ${option}`);
      return argv[index];
    };
    if (option === "--profile") args.profile = next();
    else if (option === "--context") args.context = next();
    else if (option === "--max-passes") args.maxPasses = Number(next());
    else if (option === "--apply") args.apply = true;
    else if (option === "--confirm-workers-stopped") args.confirmWorkersStopped = true;
    else if (option === "--confirm-backup-created") args.confirmBackupCreated = true;
    else if (option === "--help" || option === "-h") args.help = true;
    else throw new Error(`Unknown option: ${option}`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(args.profile)) throw new Error("--profile must be a build directory name");
  if (args.context && !/^[A-Za-z_][A-Za-z0-9_]*\/[A-Za-z_][A-Za-z0-9_]*$/.test(args.context)) {
    throw new Error("--context must be namespace/database identifiers");
  }
  if (!Number.isSafeInteger(args.maxPasses) || args.maxPasses < 1 || args.maxPasses > 10000) {
    throw new Error("--max-passes must be an integer between 1 and 10000");
  }
  if (args.apply && !args.confirmWorkersStopped) {
    throw new Error("--apply requires --confirm-workers-stopped");
  }
  if (args.apply && !args.confirmBackupCreated) {
    throw new Error("--apply requires --confirm-backup-created");
  }
  return args;
}

function migrationTables(sql) {
  const tables = [...String(sql).matchAll(/RETURN\s+\{\s*table:\s*'([A-Za-z_][A-Za-z0-9_]*)'\s*,\s*processed:/g)]
    .map((match) => match[1]);
  if (tables.length === 0 || new Set(tables).size !== tables.length) {
    throw new Error("Backfill artifact has no unique per-table processed reports");
  }
  return tables;
}

function queryReports(response, expectedTables) {
  if (!Array.isArray(response)) throw new Error("Backfill query did not return statement results");
  const error = response.find((entry) => entry?.status === "ERR");
  if (error) throw new Error(`Backfill query failed: ${String(error.result?.message || error.result || "SurrealDB error")}`);
  const reports = response.map((entry) => {
    if (entry && typeof entry === "object" && Object.hasOwn(entry, "table") && Object.hasOwn(entry, "processed")) return entry;
    return entry?.result;
  }).filter((result) =>
    result && typeof result === "object" && Object.hasOwn(result, "table") && Object.hasOwn(result, "processed"));
  const byTable = new Map();
  for (const report of reports) {
    if (typeof report.table !== "string" || !Number.isSafeInteger(report.processed) || report.processed < 0 || report.processed > 1000) {
      throw new Error("Backfill returned an invalid processed report");
    }
    if (byTable.has(report.table)) throw new Error(`Backfill returned duplicate report for ${report.table}`);
    byTable.set(report.table, report.processed);
  }
  if (byTable.size !== expectedTables.length || expectedTables.some((table) => !byTable.has(table))) {
    throw new Error(`Backfill did not report every task table; expected ${expectedTables.join(", ")}, received ${[...byTable.keys()].join(", ") || "none"}; refusing to finalize`);
  }
  return expectedTables.map((table) => ({ table, processed: byTable.get(table) }));
}

async function runLifecycleMigration({ db, backfillSql, finalizeSql, maxPasses = DEFAULT_MAX_PASSES, onPass = () => {} }) {
  if (!db || typeof db.query !== "function") throw new Error("A connected SurrealDB client is required");
  if (typeof backfillSql !== "string" || !backfillSql.trim() || typeof finalizeSql !== "string" || !finalizeSql.trim()) {
    throw new Error("Nonempty generated backfill and finalizer artifacts are required");
  }
  if (!Number.isSafeInteger(maxPasses) || maxPasses < 1) throw new Error("maxPasses must be a positive integer");
  const tables = migrationTables(backfillSql);
  for (let pass = 1; pass <= maxPasses; pass += 1) {
    const reports = queryReports(await db.query(backfillSql), tables);
    onPass({ pass, reports });
    if (reports.every((report) => report.processed === 0)) {
      const result = await db.query(finalizeSql);
      if (!Array.isArray(result) || result.some((entry) => entry?.status === "ERR")) {
        throw new Error("Lifecycle migration finalizer failed");
      }
      return { complete: true, passes: pass, reports };
    }
  }
  return { complete: false, passes: maxPasses, tables };
}

function usage() {
  return `Usage: node [--env-file PATH] dev-tools/lifecycle-migration.js --apply [options]

Options:
  --profile <build-dir>       Generated build directory (default: test)
  --context <ns/database>     Select a context already allowed by the process profile
  --max-passes <count>        Bounded backfill executions (default: ${DEFAULT_MAX_PASSES})
  --confirm-workers-stopped   Confirm old gateway workers are drained
  --confirm-backup-created    Confirm a restorable database backup exists
  --apply                     Connect and execute backfill, then guarded finalizer
  --help                      Show this help

Connection and database context come only from the loaded process profile.`;
}

async function main(argv = process.argv.slice(2), environment = process.env) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return { help: true };
  }
  if (!args.apply) throw new Error("No changes made. Pass --apply with the required safety acknowledgements.");
  const configuration = resolveConfiguration(environment);
  assertConnectionConfiguration(configuration);
  const [namespace, database] = args.context?.split("/") || [];
  const context = args.context
    ? assertConfiguredContext(configuration, { namespace, database })
    : configuration.surreal.defaultContext;
  if (!context) throw new Error("Migration requires a configured default namespace/database context");
  const buildDir = path.resolve("build", args.profile);
  const backfillSql = fs.readFileSync(path.join(buildDir, "migrate-one-shot-backfill.surql"), "utf8");
  const finalizeSql = fs.readFileSync(path.join(buildDir, "migrate-one-shot-finalize.surql"), "utf8");
  console.log(`Applying one-shot task migration to ${context.namespace}/${context.database} from ${buildDir}`);
  const connection = await connectDatabase({
    ...configuration.surreal,
    namespace: context.namespace,
    database: context.database,
  });
  try {
    const result = await runLifecycleMigration({
      db: connection.db,
      backfillSql,
      finalizeSql,
      maxPasses: args.maxPasses,
      onPass({ pass, reports }) {
        console.log(JSON.stringify({ pass, reports }));
      },
    });
    if (!result.complete) {
      console.error(`Backfill remains incomplete after ${result.passes} passes; finalizer was not run.`);
      process.exitCode = 2;
      return result;
    }
    console.log(`One-shot task migration completed after ${result.passes} passes.`);
    return result;
  } finally {
    await connection.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`One-shot task migration failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { DEFAULT_MAX_PASSES, main, migrationTables, parseArgs, queryReports, runLifecycleMigration, usage };
