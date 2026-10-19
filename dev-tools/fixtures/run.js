#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { parseArgs } = require("node:util");
const { connect } = require("..");
const fixtures = require("./index");

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    config: { type: "string" }, preview: { type: "boolean" }, help: { type: "boolean", short: "h" },
  } });
  if (values.help) {
    console.log("Usage: node [--env-file=PROFILE] dev-tools/fixtures/run.js build/DESIGN/fixtures/RECIPE.js [--config JSON_FILE] [--preview]\nPreview is offline. Population uses the configured, already-deployed database; it never installs or clears a schema.");
    return;
  }
  if (positionals.length !== 1) throw new Error("Supply one built recipe: build/DESIGN/fixtures/RECIPE.js (see --help)");
  const file = path.resolve(positionals[0]);
  if (path.basename(path.dirname(file)) !== "fixtures") throw new Error("Choose a recipe directly inside a build's fixtures directory");
  const model = fixtures.loadModel(path.dirname(path.dirname(file)));
  const recipe = require(file);
  const config = values.config ? JSON.parse(fs.readFileSync(values.config, "utf8")) : {};
  if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("Fixture config must be a JSON object");
  const configure = values.preview ? recipe.options : recipe.populationOptions || recipe.options;
  if (typeof configure !== "function") throw new Error("Recipe must export an options function");
  const options = await configure({ ...config, model });
  let connection;
  try {
    const result = values.preview ? await fixtures.plan(options)
      : await fixtures.populate((connection = await connect()).db, options);
    console.log(JSON.stringify({ scenario: options.scenario, tenant: options.tenant,
      ...(values.preview ? { planned: result.rows.length } : { inserted: result.created.length, reused: options.reused }),
      counts: options.expectedCounts, ids: options.ids,
    }, null, 2));
  } finally { if (connection) await connection.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };
