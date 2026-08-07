const fs = require("node:fs");
const path = require("node:path");

function parseCliArgs(argv) {
  const args = { check: false, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const next = () => {
      index += 1;
      if (!argv[index]) throw new Error(`Missing value for ${option}`);
      return argv[index];
    };
    if (option === "--project") args.projectDir = next();
    else if (option === "--output") args.outputDir = next();
    else if (option === "--include-array-readers") args.includeArrayReaders = true;
    else if (option === "--check") args.check = true;
    else if (option === "--help" || option === "-h") args.help = true;
    else throw new Error(`Unknown argument: ${option}`);
  }
  if (!args.help && !args.projectDir) throw new Error("--project is required");
  return args;
}

function printUsage() {
  console.log(`Usage: node compile.js --project <dir> [options]

Project files:
  rebase.config.js             Optional compiler/schema settings only
  schema.surql                 Tables, fields, rules, and explicit business indexes
  views.surql                  Reactive grouped views
  seed.surql                   Optional configuration and seed records

Options:
  --output <dir>               Build directory (default: build/<project-name>)
  --include-array-readers      Inherit readers through array record references
  --check                      Fail when generated output is stale
  --help                       Show this help`);
}

function readRequired(filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`Required file not found: ${filePath}`);
  return fs.readFileSync(filePath, "utf8");
}

function loadProject(rawOptions) {
  const rootDir = process.cwd();
  const projectDir = path.resolve(rootDir, rawOptions.projectDir);
  const configPath = path.join(projectDir, "rebase.config.js");
  if (!fs.existsSync(configPath)) throw new Error(`Required file not found: ${configPath}`);
  const config = require(configPath);
  const namespace = process.env.SURREAL_NAMESPACE;
  const database = process.env.SURREAL_DATABASE;
  if (!namespace || !database) throw new Error("Missing SURREAL_NAMESPACE or SURREAL_DATABASE");
  const selectMode = config.authorization?.selectMode ?? "readers";
  if (!["readers", "owner"].includes(selectMode)) {
    throw new Error(`Invalid authorization.selectMode: ${selectMode}`);
  }
  const outputDir = path.resolve(
    rootDir,
    rawOptions.outputDir || path.join("build", path.basename(projectDir)),
  );
  const frameworkDir = path.resolve(__dirname, "../framework");
  const framework = {
    auth: path.resolve(projectDir, config.framework?.auth || path.join(frameworkDir, "auth.surql")),
    access: path.resolve(projectDir, config.framework?.access || path.join(frameworkDir, "access.surql")),
  };

  const seedPath = path.join(projectDir, "seed.surql");
  return {
    rootDir,
    projectDir,
    outputDir,
    namespace,
    database,
    selectMode,
    includeArrayReaders: rawOptions.includeArrayReaders ?? config.ownership?.inheritArrayReaders ?? false,
    check: rawOptions.check,
    sources: {
      schema: readRequired(path.join(projectDir, "schema.surql")),
      views: readRequired(path.join(projectDir, "views.surql")),
      seed: fs.existsSync(seedPath) ? fs.readFileSync(seedPath, "utf8") : "",
      auth: readRequired(framework.auth),
      access: readRequired(framework.access),
    },
  };
}

module.exports = { loadProject, parseCliArgs, printUsage };
