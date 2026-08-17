#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const { Surreal } = require("surrealdb");
const { populate } = require("./populate");

const root = path.resolve(__dirname, "..");

function endpoint() {
  return process.env.SURREAL_ENDPOINT || "ws://127.0.0.1:8000/rpc";
}

function projectDir() {
  return process.env.REBASE_PROJECT || "test";
}

function sourceDir() {
  return projectDir().includes(path.sep) ? projectDir() : path.join("designs", projectDir());
}

function buildDir() {
  return path.join(root, "build", path.basename(projectDir()));
}

async function connectAdmin() {
  const db = new Surreal();
  await db.connect(endpoint());
  await db.signin({ username: process.env.SURREAL_USER, password: process.env.SURREAL_PASS });
  await db.use({ namespace: process.env.SURREAL_NAMESPACE, database: process.env.SURREAL_DATABASE });
  return db;
}

function json(value) {
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

function runBuild() {
  const result = spawnSync(process.execPath, ["compile.js", "--project", sourceDir()], {
    cwd: root,
    env: process.env,
    encoding: "utf8",
  });
  process.stdout.write(result.stdout || "");
  process.stderr.write(result.stderr || "");
  if (result.status !== 0) throw new Error("Build failed");
}

async function main() {
  const admin = await connectAdmin();
  let actor = null;
  let token = null;
  const prompt = readline.createInterface({ input: stdin, output: stdout, prompt: "rebase> " });
  console.log("ReBase workbench. Type .help for commands.");
  prompt.prompt();
  try {
    for await (const line of prompt) {
      const input = line.trim();
      if (!input) { prompt.prompt(); continue; }
      try {
        if (input === ".help") {
          console.log(`Commands:
  .build                         Compile the current project
  .deploy                        Apply build/<project>/schema.surql
  .populate [table] [count]      Generate valid random data from data/*.schema.json
  .as <email> <password>         Authenticate a working actor
  .query <surql>                 Run a query as the current actor or admin
  .sample <table> [limit]        Inspect a bounded sample
  .edge <capability> <json>       Call a running gateway
  .probe [security|gateway|data|all]  Run disposable live probes
  .quit                          Exit`);
        } else if (input === ".quit" || input === ".exit") break;
        else if (input === ".build") runBuild();
        else if (input === ".deploy") {
          const file = path.join(buildDir(), "schema.surql");
          if (!fs.existsSync(file)) throw new Error("Build first");
          await admin.query(fs.readFileSync(file, "utf8"));
          console.log(`Deployed ${file}`);
        } else if (input.startsWith(".populate")) {
          const [, table = "all", count = "25"] = input.split(/\s+/);
          const result = await populate({ project: projectDir(), table, count: Number(count), batchSize: 100 });
          console.log(json(result));
        } else if (input.startsWith(".as ")) {
          const [, email, password] = input.split(/\s+/);
          if (!email || !password) throw new Error(".as requires email and password");
          const session = new Surreal();
          await session.connect(endpoint());
          const auth = await session.signin({ namespace: process.env.SURREAL_NAMESPACE, database: process.env.SURREAL_DATABASE, access: "account", variables: { email, password } });
          await actor?.close().catch(() => {});
          actor = session;
          token = auth.access;
          console.log(`Authenticated ${email}`);
        } else if (input.startsWith(".query ")) {
          const result = await (actor || admin).query(input.slice(7));
          console.log(json(result));
        } else if (input.startsWith(".sample ")) {
          const [, table, limit = "10"] = input.split(/\s+/);
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table || "")) throw new Error("Invalid table");
          console.log(json(await (actor || admin).query(`SELECT * FROM ${table} LIMIT ${Math.min(100, Math.max(1, Number(limit)))};`)));
        } else if (input.startsWith(".edge ")) {
          if (!token) throw new Error("Authenticate with .as first");
          const match = /^\.edge\s+(\S+)\s+([\s\S]+)$/.exec(input);
          if (!match) throw new Error(".edge requires capability and JSON body");
          const response = await fetch(`${process.env.REBASE_GATEWAY_URL || "http://127.0.0.1:8787"}/v1/edge/${match[1]}`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: match[2] });
          console.log(`${response.status} ${await response.text()}`);
        } else if (input.startsWith(".probe")) {
          const command = input.split(/\s+/)[1] || "all";
          const result = spawnSync(process.execPath, [path.join("dev-tools", "probe.js"), command], { cwd: root, env: process.env, encoding: "utf8" });
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

if (require.main === module) main().catch((error) => { console.error(error); process.exitCode = 1; });
