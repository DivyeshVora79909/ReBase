const fs = require("node:fs");
const path = require("node:path");
const { discoverHandlers } = require("../../src/handlers");
const { parseSchema } = require("../../src/schema");

function loadHandlers(projectDir) {
  const root = path.resolve(projectDir);
  const schemaPath = path.join(root, "schema.surql");
  if (!fs.existsSync(schemaPath)) throw new Error(`Compiled schema is missing: ${schemaPath}`);
  const schema = parseSchema(fs.readFileSync(schemaPath, "utf8"), "");
  return discoverHandlers(path.join(root, "edge"), new Set(schema.tables.keys()));
}

module.exports = { loadHandlers };
