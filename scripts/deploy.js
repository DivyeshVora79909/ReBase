#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const required = ["SURREAL_ENDPOINT", "SURREAL_USER", "SURREAL_PASS", "SURREAL_NAMESPACE", "SURREAL_DATABASE", "REBASE_BUILD_DIR"];
for (const name of required) if (!process.env[name]) throw new Error(`Missing ${name}`);

const schema = path.resolve(process.env.REBASE_BUILD_DIR, "schema.surql");
if (!fs.existsSync(schema)) throw new Error(`Build artifact not found: ${schema}`);

function surreal(command, args, input) {
  const result = spawnSync("surreal", [command, ...args], { encoding: "utf8", input });
  if (result.status !== 0) throw new Error((result.stderr || result.stdout || `${command} failed`).trim());
}

const connection = [
  "--endpoint", process.env.SURREAL_ENDPOINT,
  "--user", process.env.SURREAL_USER,
  "--pass", process.env.SURREAL_PASS,
  "--ns", process.env.SURREAL_NAMESPACE,
  "--db", process.env.SURREAL_DATABASE,
];

surreal("validate", [schema]);
surreal("sql", [...connection, "--hide-welcome"], fs.readFileSync(schema, "utf8"));
console.log(`Deployed ${schema} to ${process.env.SURREAL_NAMESPACE}/${process.env.SURREAL_DATABASE}.`);
