#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { loadEnvironment, resolveConfiguration } = require("../../config/environment");
const { loadMaterials } = require("./materials");
const { validateTableHandlers } = require("./table-handlers");
const {
  generateBundle,
  writeArtifacts,
} = require("./pipeline");

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
    else if (option === "--namespace" || option === "--ns") args.namespace = next();
    else if (option === "--database" || option === "--db") args.database = next();
    else if (option === "--runtime-url") args.runtimeUrl = next();
    else if (option === "--runtime-secret") args.runtimeSecret = next();
    else if (option === "--check") args.check = true;
    else if (option === "--print-raw") args.printRaw = true;
    else if (option === "--no-root-permissions") args.rootPermissions = false;
    else if (option === "--help" || option === "-h") args.help = true;
    else throw new Error(`Unknown argument: ${option}`);
  }
  return args;
}

function usage() {
  return `Usage: node dev-tools/compiler/cli.js [options]

Material inputs:
  --project <directory>       Project SurrealQL root (default: designs/test)
  --framework <directory>     Framework SurrealQL root (default: framework)
  --output <directory>        Build artifact directory (default: build/<project>)

  Compilation context:
  --env-file <path>           Load deployment values from an environment profile
  --namespace <name>          Optional target namespace
  --database <name>           Optional target database
  --runtime-url <url>         Generate effect events for this runtime
  --runtime-secret <secret>   Internal wake credential embedded in generated events
  --print-raw                 Print the combined source material before compiling
  --no-root-permissions       Skip generated root permission bootstrap
  --check                     Verify generated artifacts without writing them
  --help                      Show this help`;
}

function deploymentNotice(configuration) {
  const context = [configuration.surreal.namespace, configuration.surreal.database];
  const runtime = [configuration.runtime.url, configuration.runtime.wakeSecret];
  const messages = [];
  if (context.some(Boolean) && !context.every(Boolean)) {
    messages.push("incomplete namespace/database context omitted");
  } else if (!context.some(Boolean)) {
    messages.push("namespace/database context absent; artifacts are context-neutral");
  }
  if (runtime.some(Boolean) && !runtime.every(Boolean)) {
    messages.push("incomplete runtime binding omitted");
  } else if (!runtime.some(Boolean)) {
    messages.push("runtime binding absent; effect events are omitted");
  }
  return messages.length ? `ReBase compiler: ${messages.join("; ")}` : null;
}

function resolveDirectory(root, value) {
  return path.resolve(root, value);
}

function removeLegacyArtifacts(outputDir, check) {
  for (const name of ["edge", "optimizer.json", "manifest.json", "operations.json", "schemas"]) {
    const target = path.join(outputDir, name);
    if (!fs.existsSync(target)) continue;
    if (check) throw new Error(`Generated output contains legacy artifact: ${target}`);
    fs.rmSync(target, { recursive: true, force: true });
  }
}

function compileFromArgs(rawArgs, root = process.cwd()) {
  const projectDir = resolveDirectory(root, rawArgs.projectDir);
  const frameworkDir = resolveDirectory(root, rawArgs.frameworkDir);
  const outputDir = resolveDirectory(
    root,
    rawArgs.outputDir || path.join("build", path.basename(projectDir)),
  );
  const materials = loadMaterials({
    groups: [
      { name: "framework", roots: [frameworkDir] },
      { name: "project", roots: [projectDir] },
    ],
    print: rawArgs.printRaw,
  });
  const configuration = rawArgs.configuration || resolveConfiguration({}, rawArgs);
  const context = {
    namespace: rawArgs.namespace || configuration.surreal.defaultContext?.namespace,
    database: rawArgs.database || configuration.surreal.defaultContext?.database,
    runtimeUrl: rawArgs.runtimeUrl || configuration.runtime.url,
    runtimeSecret: rawArgs.runtimeSecret || configuration.runtime.wakeSecret,
  };
  if ((context.namespace && !context.database) || (!context.namespace && context.database)) {
    context.namespace = undefined;
    context.database = undefined;
  }
  if ((context.runtimeUrl && !context.runtimeSecret) || (!context.runtimeUrl && context.runtimeSecret)) {
    context.runtimeUrl = undefined;
    context.runtimeSecret = undefined;
  }
  const result = generateBundle(materials, { context, rootPermissions: rawArgs.rootPermissions !== false });
  const tableHandlers = validateTableHandlers(projectDir, result.schema, result.contracts);
  const artifacts = writeArtifacts({
    outputDir,
    bundle: result.bundle,
    contracts: result.contracts,
    copies: fs.existsSync(path.join(projectDir, "table-handlers"))
      ? [{ sourceDir: path.join(projectDir, "table-handlers"), outputDir: path.join(outputDir, "table-handlers") }]
      : [],
  }, { check: rawArgs.check });
  removeLegacyArtifacts(outputDir, rawArgs.check);
  return {
    ...result,
    artifacts,
    outputDir,
    projectDir,
    tableHandlerCount: tableHandlers.tables.length,
    materialFileCount: materials.files.length,
    configuration,
  };
}

function main(argv = process.argv.slice(2)) {
  const loaded = loadEnvironment(argv);
  const args = parseArgs(loaded.args);
  args.configuration = resolveConfiguration(loaded.values, args);
  if (args.help) {
    console.log(usage());
    return null;
  }
  const notice = deploymentNotice(args.configuration);
  if (notice) console.error(notice);
  return compileFromArgs(args);
}

if (require.main === module) {
  try {
    const result = main();
    if (!result) process.exit(0);
    const relativeOutput = path.relative(process.cwd(), result.outputDir) || ".";
    console.log(`ReBase compiled ${result.schema.tables.size} tables and ${result.schema.views.length} views.`);
    console.log(`Material files: ${result.materialFileCount}`);
    console.log(`Table handlers: ${result.tableHandlerCount}`);
    console.log(`Output: ${relativeOutput}`);
    console.log(`Schema: ${path.join(relativeOutput, "schema.surql")}`);
  } catch (error) {
    console.error(`ReBase compilation failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { compileFromArgs, deploymentNotice, main, parseArgs, usage };
