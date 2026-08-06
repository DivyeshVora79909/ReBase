#!/usr/bin/env node

const { spawnSync } = require("node:child_process");

const required = ["SURREAL_ENDPOINT", "SURREAL_USER", "SURREAL_PASS", "SURREAL_NAMESPACE", "SURREAL_DATABASE", "REBASE_ADMIN_EMAIL", "REBASE_ADMIN_PASSWORD"];
for (const name of required) if (!process.env[name]) throw new Error(`Missing ${name}`);
if (process.env.REBASE_ADMIN_PASSWORD.length < 8) throw new Error("REBASE_ADMIN_PASSWORD must contain at least 8 characters");

const sql = `UPSERT user:root SET
  name = ${JSON.stringify(process.env.REBASE_ADMIN_NAME || "System Administrator")},
  email = ${JSON.stringify(process.env.REBASE_ADMIN_EMAIL)},
  parents = [groups:root],
  login_access = true,
  password = crypto::argon2::generate(${JSON.stringify(process.env.REBASE_ADMIN_PASSWORD)});`;

const result = spawnSync("surreal", [
  "sql",
  "--endpoint", process.env.SURREAL_ENDPOINT,
  "--user", process.env.SURREAL_USER,
  "--pass", process.env.SURREAL_PASS,
  "--ns", process.env.SURREAL_NAMESPACE,
  "--db", process.env.SURREAL_DATABASE,
  "--hide-welcome",
], { input: sql, encoding: "utf8" });

if (result.status !== 0) throw new Error((result.stderr || result.stdout || "Admin bootstrap failed").trim());
console.log(`Bootstrapped user:root in ${process.env.SURREAL_NAMESPACE}/${process.env.SURREAL_DATABASE}.`);
