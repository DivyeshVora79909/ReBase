#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const { Surreal } = require("surrealdb");
const { populate } = require("./populate");

const root = path.resolve(__dirname, "..");

function parseArgs(argv) {
  const options = {
    endpoint: process.env.SURREAL_ENDPOINT || "ws://127.0.0.1:8000/rpc",
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
    if (option === "--endpoint") options.endpoint = next();
    else if (option === "--namespace" || option === "--ns")
      options.namespace = next();
    else if (option === "--database" || option === "--db")
      options.database = next();
    else if (option === "--project") options.project = next();
    else if (option === "--help" || option === "-h") options.help = true;
    else throw new Error(`Unknown option: ${option}`);
  }
  if (
    (options.namespace && !options.database) ||
    (!options.namespace && options.database)
  ) {
    throw new Error("--namespace and --database must be supplied together");
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

async function connectAdmin(options) {
  const db = new Surreal();
  await db.connect(options.endpoint);
  await db.signin({
    username: process.env.SURREAL_USER,
    password: process.env.SURREAL_PASS,
  });
  await db.use({ namespace: options.namespace, database: options.database });
  return db;
}

function json(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function runBuild(options) {
  const result = spawnSync(
    process.execPath,
    [
      path.join("dev-tools", "compiler", "cli.js"),
      "--project",
      sourceDir(options),
      "--namespace",
      options.namespace,
      "--database",
      options.database,
    ],
    {
      cwd: root,
      env: process.env,
      encoding: "utf8",
    },
  );
  process.stdout.write(result.stdout || "");
  process.stderr.write(result.stderr || "");
  if (result.status !== 0) throw new Error("Build failed");
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(
      "Usage: node dev-tools/workbench.js [--endpoint URL] [--namespace NS --database DB] [--project NAME|DIR]",
    );
    return;
  }
  const prompt = readline.createInterface({
    input: stdin,
    output: stdout,
    prompt: "rebase> ",
  });
  options.namespace ||= (await prompt.question("Namespace: ")).trim();
  options.database ||= (await prompt.question("Database: ")).trim();
  if (!options.namespace || !options.database) {
    prompt.close();
    throw new Error("Namespace and database are required");
  }
  const admin = await connectAdmin(options);
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
  .as <email> <password>         Authenticate a working actor
  .query <surql>                 Run a query as the current actor or admin
  .sample <table> [limit]        Inspect a bounded sample
  .probe [security|data|all]      Run disposable live probes
  .quit                          Exit`);
        } else if (input === ".quit" || input === ".exit") break;
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
            endpoint: options.endpoint,
            username: process.env.SURREAL_USER,
            password: process.env.SURREAL_PASS,
            namespace: options.namespace,
            database: options.database,
          });
          console.log(json(result));
        } else if (input.startsWith(".as ")) {
          const [, email, password] = input.split(/\s+/);
          if (!email || !password)
            throw new Error(".as requires email and password");
          const session = new Surreal();
          await session.connect(options.endpoint);
          const auth = await session.signin({
            namespace: options.namespace,
            database: options.database,
            access: "account",
            variables: { email, password },
          });
          await actor?.close().catch(() => {});
          actor = session;
          console.log(`Authenticated ${email}`);
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
            { cwd: root, env: process.env, encoding: "utf8" },
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

module.exports = { main, parseArgs };
