#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const { Surreal } = require("surrealdb");
const { populate } = require("./populate");
const { connectDatabase, sessionEndpoint } = require("../gateway/connection");
const {
  assertConfiguredContext,
  assertConnectionConfiguration,
  resolveConfiguration,
} = require("../config/environment");

const root = path.resolve(__dirname, "..");

function parseArgs(argv) {
  const options = {
    project: "test",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const next = () => {
      index += 1;
      if (argv[index] === undefined)
        throw new Error(`Missing value for ${option}`);
      return argv[index];
    };
    if (option === "--project") options.project = next();
    else if (option === "--help" || option === "-h") options.help = true;
    else throw new Error(`Unknown option: ${option}`);
  }
  return options;
}

function sourceDir(options) {
  return options.project.includes(path.sep)
    ? options.project
    : path.join("designs", options.project);
}

function buildDir(options) {
  return path.join(root, "build", path.basename(options.project));
}

async function connectAdmin({ configuration, context }) {
  assertConnectionConfiguration(configuration);
  const selected = assertConfiguredContext(configuration, context);
  return (await connectDatabase({
    ...configuration.surreal,
    namespace: selected.namespace,
    database: selected.database,
  })).db;
}

async function switchContext({ admin, actor, options, connect = connectAdmin }, namespace, database) {
  if (!namespace || !database) throw new Error(".use requires namespace and database");
  const context = assertConfiguredContext(options.configuration, { namespace, database });
  await actor?.close().catch(() => {});
  await admin?.close().catch(() => {});
  options.context = context;
  return {
    admin: await connect({ configuration: options.configuration, context }),
    actor: null,
  };
}

function json(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function runBuild(options) {
  const args = [path.join("dev-tools", "compiler", "cli.js"), "--project", sourceDir(options)];
  const result = spawnSync(process.execPath, args,
    {
      cwd: root,
      env: options.environment,
      encoding: "utf8",
    },
  );
  process.stdout.write(result.stdout || "");
  process.stderr.write(result.stderr || "");
  if (result.status !== 0) throw new Error("Build failed");
}

async function main(argv = process.argv.slice(2), environment = process.env) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(
      "Usage: node [--env-file PATH] dev-tools/workbench.js [--project NAME|DIR]",
    );
    return;
  }
  const configuration = resolveConfiguration(environment);
  options.configuration = configuration;
  options.environment = { ...environment };
  assertConnectionConfiguration(configuration);
  const prompt = readline.createInterface({
    input: stdin,
    output: stdout,
    prompt: "rebase> ",
  });
  options.context = configuration.surreal.defaultContext || (
    configuration.surreal.contexts.length === 1
      ? configuration.surreal.contexts[0]
      : undefined
  );
  if (!options.context) {
    const namespace = (await prompt.question("Configured namespace: ")).trim();
    const database = (await prompt.question("Configured database: ")).trim();
    try {
      options.context = assertConfiguredContext(configuration, { namespace, database });
    } catch (error) {
      prompt.close();
      throw error;
    }
  }
  let admin = await connectAdmin({ configuration, context: options.context });
  let actor = null;
  console.log("ReBase workbench. Type .help for commands.");
  prompt.prompt();
  try {
    for await (const line of prompt) {
      const input = line.trim();
      if (!input) {
        prompt.prompt();
        continue;
      }
      try {
        if (input === ".help") {
          console.log(`Commands:
  .build                         Compile the current project
  .deploy                        Apply build/<project>/schema.surql
  .populate [table] [count]      Generate valid random data from data/*.schema.json
  .use <namespace> <database>    Switch to a context in the process profile
  .as <identifier> <password>    Authenticate a working actor
  .query <surql>                 Run a query as the current actor or admin
  .sample <table> [limit]        Inspect a bounded sample
  .probe [security|data|all]      Run disposable live probes
  .quit                          Exit`);
        } else if (input === ".quit" || input === ".exit") break;
        else if (input.startsWith(".use ")) {
          const [, namespace, database] = input.split(/\s+/);
          ({ admin, actor } = await switchContext({ admin, actor, options }, namespace, database));
          console.log(`Using ${namespace}/${database}`);
        }
        else if (input === ".build") runBuild(options);
        else if (input === ".deploy") {
          const file = path.join(buildDir(options), "schema.surql");
          if (!fs.existsSync(file)) throw new Error("Build first");
          await admin.query(fs.readFileSync(file, "utf8"));
          console.log(`Deployed ${file}`);
        } else if (input.startsWith(".populate")) {
          const [, table = "all", count = "25"] = input.split(/\s+/);
          const result = await populate({
            project: options.project,
            table,
            count: Number(count),
            batchSize: 100,
            namespace: options.context.namespace,
            database: options.context.database,
            configuration,
          });
          console.log(json(result));
        } else if (input.startsWith(".as ")) {
          const [, identifier, password] = input.split(/\s+/);
          if (!identifier || !password)
            throw new Error(".as requires an identifier and password");
          const session = new Surreal();
          await session.connect(sessionEndpoint(configuration.surreal.endpoint));
          const auth = await session.signin({
            namespace: options.context.namespace,
            database: options.context.database,
            access: "account_password",
            variables: { identifier, password },
          });
          await actor?.close().catch(() => {});
          actor = session;
          console.log(`Authenticated ${identifier}`);
        } else if (input.startsWith(".query ")) {
          const result = await (actor || admin).query(input.slice(7));
          console.log(json(result));
        } else if (input.startsWith(".sample ")) {
          const [, table, limit = "10"] = input.split(/\s+/);
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table || ""))
            throw new Error("Invalid table");
          console.log(
            json(
              await (actor || admin).query(
                `SELECT * FROM ${table} LIMIT ${Math.min(100, Math.max(1, Number(limit)))};`,
              ),
            ),
          );
        } else if (input.startsWith(".probe")) {
          const command = input.split(/\s+/)[1] || "all";
          const result = spawnSync(
            process.execPath,
            [path.join("dev-tools", "probe.js"), command],
            { cwd: root, env: options.environment, encoding: "utf8" },
          );
          process.stdout.write(result.stdout || "");
          process.stderr.write(result.stderr || "");
        } else console.log("Unknown command. Type .help.");
      } catch (error) {
        console.error(`Error: ${error.message}`);
      }
      prompt.prompt();
    }
  } finally {
    await actor?.close().catch(() => {});
    await admin.close().catch(() => {});
    prompt.close();
  }
}

if (require.main === module)
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });

module.exports = { main, parseArgs, switchContext };
