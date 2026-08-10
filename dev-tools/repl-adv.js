#!/usr/bin/env node

const repl = require("node:repl");
const { performance } = require("node:perf_hooks");
const { Surreal } = require("surrealdb");
const { splitStatements } = require("../src/surql");
const tools = {
  database: require("../scripts/database"),
  schema: require("../scripts/schema"),
  data: require("../scripts/data"),
  materialize: require("../scripts/materialize"),
  inspect: require("../scripts/inspect"),
  benchmark: require("../scripts/benchmark"),
};

// --- CONFIGURATION ---
const endpoint = process.env.SURREAL_ENDPOINT || "http://127.0.0.1:8000";
const namespace = process.env.SURREAL_NAMESPACE || "main";
const database = process.env.SURREAL_DATABASE || "main";
const adminUser = process.env.SURREAL_USER || "root";
const adminPass = process.env.SURREAL_PASS || "root";
const accessName = "personifier";

const sqlKeywords =
  /^(SELECT|CREATE|UPDATE|UPSERT|DELETE|INSERT|DEFINE|REMOVE|RETURN|LET|BEGIN|COMMIT|CANCEL|INFO|SHOW|RELATE|USE|FOR|THROW|SLEEP)\b/i;
const rpc = (url) =>
  `${String(url).replace(/\/$/, "")}${String(url).replace(/\/$/, "").endsWith("/rpc") ? "" : "/rpc"}`;

// --- AESTHETICS ---
const c = {
  dim: "\x1b[90m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
};

const getPrompt = (id) => {
  const hash =
    Math.abs(
      [...String(id)].reduce((a, char) => a * 31 + char.charCodeAt(0), 0),
    ) % 6;
  const colorCode = id === "admin" ? 31 : 31 + hash;
  return `\x1b[1;${colorCode}m[${id}]>\x1b[0m `;
};

// --- UTILITIES ---
function clean(value, seen = new WeakSet()) {
  if (value == null || typeof value !== "object")
    return typeof value === "bigint" ? `${value}n` : value;
  if (value instanceof Date) return value.toISOString();
  if (
    ["RecordId", "DateTime", "Decimal", "Uuid"].some((name) =>
      value.constructor?.name?.startsWith(name),
    )
  )
    return String(value);
  if (seen.has(value)) return "[Circular]";
  if (Array.isArray(value)) return value.map((item) => clean(item, seen));
  seen.add(value);
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, clean(item, seen)]),
  );
}

function rows(responses) {
  const result = responses.at(-1);
  return result && typeof result === "object" && "result" in result
    ? result.result
    : result;
}

function printResult(result, elapsedMs) {
  console.log(`${c.dim}[${elapsedMs}ms]${c.reset}`);
  if (Array.isArray(result)) {
    if (result.length === 0) console.log(`${c.dim}(0 rows)${c.reset}`);
    else if (result.length <= 50 && typeof result[0] === "object")
      console.table(result);
    else
      console.dir(result, { depth: null, colors: true, maxArrayLength: 100 });
  } else if (result !== undefined) {
    console.dir(result, { depth: null, colors: true });
  }
}

// --- MAIN APPLICATION ---
async function main() {
  const admin = new Surreal();
  await admin.connect(rpc(endpoint));
  await admin.signin({ username: adminUser, password: adminPass });
  await admin.use({ namespace, database });

  await admin.query(
    `DEFINE ACCESS OVERWRITE ${accessName} ON DATABASE TYPE RECORD SIGNIN ( SELECT * FROM type::record($record_id) );`,
  );

  let db = admin;
  let activeId = "admin";
  let sqlBuffer = "";

  const sessions = new Map([["admin", admin]]);
  const vars = {};

  async function sql(query, bindings = vars) {
    const response = await db.query(query, bindings);
    return clean(rows(response));
  }

  console.clear();
  console.log(`${c.cyan}${c.bold}ReBase REPL${c.reset} ${c.dim}v2.0${c.reset}`);
  console.log(`${c.dim}Target : ${c.reset}${endpoint}`);
  console.log(
    `${c.dim}Scope  : ${c.reset}NS [${c.yellow}${namespace}${c.reset}] DB [${c.yellow}${database}${c.reset}]\n`,
  );
  console.log(
    `Type ${c.green}SQL${c.reset} directly, or use ${c.green}JavaScript${c.reset}.`,
  );
  console.log(`Context globals: ${c.bold}db, sql(), vars, tools${c.reset}`);
  console.log(`Type ${c.cyan}.help${c.reset} for commands.\n`);

  const server = repl.start({
    prompt: getPrompt(activeId),
    terminal: true,
    useGlobal: false,
  });
  const nativeEval = server.eval;
  server.eval = evaluate;
  Object.assign(server.context, { db, sql, vars, tools });

  const setSession = (id, client) => {
    activeId = id;
    db = client;
    server.context.db = client;
    server.setPrompt(getPrompt(id));
  };

  const command = (name, help, action) =>
    server.defineCommand(name, {
      help,
      async action(arg) {
        try {
          await action(String(arg || "").trim());
        } catch (error) {
          console.error(`${c.red}✗ ${error.message}${c.reset}`);
        }
        this.displayPrompt();
      },
    });

  command(
    "as",
    "Switch to a record session (e.g. .as user:alice)",
    async (id) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*:.+$/.test(id))
        throw new Error("Usage: .as user:alice");
      const client = new Surreal();
      await client.connect(rpc(endpoint));
      await client.signin({
        namespace,
        database,
        access: accessName,
        variables: { record_id: id },
      });
      await client.use({ namespace, database });
      sessions.set(id, client);
      setSession(id, client);
      console.log(`${c.green}✓ Switched to ${id}${c.reset}`);
    },
  );

  command("admin", "Switch to the root administrator session", async () => {
    setSession("admin", admin);
    console.log(`${c.green}✓ Switched to admin${c.reset}`);
  });

  command("help", "Show ReBase tools and commands", async () => {
    console.log(`\n${c.bold}ReBase Commands:${c.reset}`);
    console.log(
      `  ${c.cyan}.admin${c.reset}            Return to admin session`,
    );
    console.log(
      `  ${c.cyan}.as <record>${c.reset}      Authenticate as a specific record`,
    );
    console.log(`\n${c.bold}Global Context:${c.reset}`);
    console.log(`  ${c.green}db${c.reset}                SurrealDB SDK Client`);
    console.log(`  ${c.green}sql(query)${c.reset}        Awaitable SQL runner`);
    console.log(
      `  ${c.green}vars${c.reset}              Object for bindings (e.g. vars.limit = 10)`,
    );
    console.log(
      `  ${c.dim}vars._${c.reset}            Auto-saves the last query result`,
    );
    console.log(
      `  ${c.green}tools${c.reset}             { database, schema, data, materialize, inspect, benchmark }\n`,
    );
  });

  async function evaluate(input, context, filename, callback) {
    const text = String(input).trim();
    if (!text) return callback(null);

    if (!sqlBuffer && sqlKeywords.test(text)) sqlBuffer = text;
    else if (sqlBuffer) sqlBuffer += `\n${text}`;

    if (sqlBuffer) {
      const complete = splitStatements(sqlBuffer);
      if (!complete.length || !/[;}]\s*$/.test(sqlBuffer)) {
        server.setPrompt(`${c.dim}... ${c.reset}`);
        server.prompt();
        return callback(null);
      }

      const query = sqlBuffer;
      sqlBuffer = "";
      server.setPrompt(getPrompt(activeId));

      try {
        const started = performance.now();
        const result = await sql(query);
        const elapsed = Number((performance.now() - started).toFixed(3));
        vars._ = result;
        printResult(result, elapsed);
      } catch (error) {
        console.error(`${c.red}✗ SQL Error: ${error.message}${c.reset}`);
      }
      return callback(null);
    }

    if (repl.Recoverable(input)) return callback(null);
    nativeEval.call(server, input, context, filename, callback);
  }

  server.on("exit", async () => {
    console.log(`${c.dim}\nCleaning up temporary access...${c.reset}`);
    await admin
      .query(`REMOVE ACCESS ${accessName} ON DATABASE;`)
      .catch(() => {});
    for (const [id, client] of sessions)
      if (id !== "admin") await client.close().catch(() => {});
    await admin.close().catch(() => {});
    process.exit(0);
  });
}

process.on("unhandledRejection", (reason) => {
  console.error(
    `\x1b[31m\n✗ Unhandled Promise Rejection: ${reason.message || reason}\x1b[0m`,
  );
});

main().catch((error) => {
  console.error(`\x1b[31mREPL startup failed: ${error.message}\x1b[0m`);
  process.exitCode = 1;
});
