const fs = require("node:fs");
const path = require("node:path");

function parseCliArgs(argv) {
  const args = { check: false, help: false, projectDir: path.join("designs", process.env.REBASE_PROJECT || "test") };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const next = () => {
      index += 1;
      if (!argv[index]) throw new Error(`Missing value for ${option}`);
      return argv[index];
    };
    if (option === "--project") args.projectDir = next();
    else if (option === "--output") args.outputDir = next();
    else if (option === "--check") args.check = true;
    else if (option === "--help" || option === "-h") args.help = true;
    else throw new Error(`Unknown argument: ${option}`);
  }
  return args;
}

function printUsage() {
  console.log(`Usage: node compile.js --project <dir> [options]

Project files:
  schema.surql                 Tables, fields, rules, and explicit business indexes
  views.surql                  Reactive grouped views
  seed.surql                   Optional configuration and seed records
  data/*.schema.json           Development-only fake-data schemas
  edge/**/*.js                 Self-describing handlers and webhooks

Options:
  --output <dir>               Build directory (default: build/<project-name>)
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
  const namespace = process.env.SURREAL_NAMESPACE;
  const database = process.env.SURREAL_DATABASE;
  if (!namespace || !database) throw new Error("Missing SURREAL_NAMESPACE or SURREAL_DATABASE");
  const outputDir = path.resolve(
    rootDir,
    rawOptions.outputDir || path.join("build", path.basename(projectDir)),
  );
  const frameworkDir = path.resolve(__dirname, "../framework");
  const framework = {
    auth: path.join(frameworkDir, "auth.surql"),
    access: path.join(frameworkDir, "access.surql"),
    audit: path.join(frameworkDir, "audit.surql"),
    edge: path.join(frameworkDir, "edge.surql"),
  };

  const seedPath = path.join(projectDir, "seed.surql");
  return {
    rootDir,
    projectDir,
    outputDir,
    namespace,
    database,
    check: rawOptions.check,
    sources: {
      schema: readRequired(path.join(projectDir, "schema.surql")),
      views: readRequired(path.join(projectDir, "views.surql")),
      seed: fs.existsSync(seedPath) ? fs.readFileSync(seedPath, "utf8") : "",
      auth: readRequired(framework.auth),
      access: readRequired(framework.access),
      audit: readRequired(framework.audit),
      edge: readRequired(framework.edge),
    },
  };
}

module.exports = { loadProject, parseCliArgs, printUsage };
