const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { splitStatements } = require("../src/surql");

function schemaStatements({ file }) {
  return splitStatements(fs.readFileSync(file, "utf8"));
}

async function loadSchema({ db, file }) {
  const source = fs.readFileSync(file, "utf8");
  const responses = await db.query(source);
  return { file, bytes: Buffer.byteLength(source), responses };
}

function validateSchema({ file }) {
  const statements = schemaStatements({ file });
  if (!statements.length) throw new Error(`Schema is empty: ${file}`);
  const checked = spawnSync("surreal", ["validate", file], { encoding: "utf8" });
  if (checked.error) throw checked.error;
  if (checked.status !== 0) throw new Error((checked.stderr || checked.stdout || "Schema validation failed").trim());
  return { file, statements: statements.length, output: checked.stdout.trim() };
}

module.exports = { loadSchema, validateSchema, schemaStatements };
