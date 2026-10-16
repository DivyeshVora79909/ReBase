#!/usr/bin/env node

const path = require("node:path");
const { resolveConfiguration } = require("../../config/environment");
const { compileFromArgs } = require("./project");

function parseArgs(argv) {
  const args = {
    check: false,
    printRaw: false,
    projectDir: path.join("designs", "test"),
    frameworkDir: "framework",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const next = () => {
      index += 1;
      if (argv[index] === undefined) throw new Error(`Missing value for ${option}`);
      return argv[index];
    };
    if (option === "--project" || option === "--source") args.projectDir = next();
    else if (option === "--framework") args.frameworkDir = next();
    else if (option === "--output") args.outputDir = next();
    else if (option === "--check") args.check = true;
    else if (option === '--explain') args.explain = next();
    else if (option === "--print-raw") args.printRaw = true;
    else if (option === "--no-root-permissions") args.rootPermissions = false;
    else if (option === "--help" || option === "-h") args.help = true;
    else throw new Error(`Unknown argument: ${option}`);
  }
  return args;
}

function usage() {
  return `Usage: node [--env-file PATH] dev-tools/compiler/cli.js [options]

Material inputs:
  --project <directory>       Project SurrealQL root (default: designs/test)
  --framework <directory>     Framework SurrealQL root (default: framework)
  --output <directory>        Build artifact directory (default: build/<project>)
  Runtime context and event credentials come from the loaded process profile.
  --print-raw                 Print the combined source material before compiling
  --no-root-permissions       Skip generated root permission bootstrap
  --check                     Verify generated artifacts without writing them
  --explain <table[.field]>    Explain calculations and indexes without writing files (* for all)
  --help                      Show this help`;
}

function deploymentNotice(configuration) {
  const context = [configuration.surreal.namespace, configuration.surreal.database];
  const runtime = [configuration.runtime.url, configuration.runtime.secret];
  const messages = [];
  if (!context.some(Boolean)) {
    messages.push("namespace/database context absent; artifacts are context-neutral");
  }
  if (!runtime.some(Boolean)) {
    messages.push("runtime binding absent; effect events are omitted");
  }
  return messages.length ? `ReBase compiler: ${messages.join("; ")}` : null;
}

function main(argv = process.argv.slice(2), environment = process.env) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return null;
  }
  args.configuration = resolveConfiguration(environment);
  const notice = deploymentNotice(args.configuration);
  if (notice) console.error(notice);
  return compileFromArgs(args);
}

if (require.main === module) {
  try {
    const result = main();
    if (!result) process.exit(0);
    if (result.explanation) {
      console.log(JSON.stringify(result.explanation, null, 2));
      process.exit(0);
    }
    const relativeOutput = path.relative(process.cwd(), result.outputDir) || ".";
    console.log(`ReBase compiled ${result.schema.tables.size} tables and ${result.schema.views.length} views.`);
    console.log(`Material files: ${result.materialFileCount}`);
    console.log(`Table handlers: ${result.tableHandlerCount}`);
    console.log(`Webhook handlers: ${result.webhookHandlerCount}`);
    console.log(`Output: ${relativeOutput}`);
    console.log(`Schema: ${path.join(relativeOutput, "schema.surql")}`);
    console.log(`One-shot upgrade batches: ${path.join(relativeOutput, "migrate-one-shot-backfill.surql")}`);
    console.log(`One-shot upgrade finalizer: ${path.join(relativeOutput, "migrate-one-shot-finalize.surql")}`);
  } catch (error) {
    console.error(`ReBase compilation failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { compileFromArgs, deploymentNotice, main, parseArgs, usage };
