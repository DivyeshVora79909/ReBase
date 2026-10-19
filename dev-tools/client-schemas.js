"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { assertDisjointPaths, checkCopiedTree, copyTree } = require("./compiler/pipeline");

const SCHEMA_SUFFIX = ".schema.json";
const SCHEMA_NAME = /^[A-Za-z_][A-Za-z0-9_-]*\.schema\.json$/;

function schemaFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).map((entry) => {
    if (!entry.isFile() || !SCHEMA_NAME.test(entry.name)) {
      throw new Error(
        `Client schema directory must be flat and contain only *.schema.json files: ${path.join(directory, entry.name)}`,
      );
    }
    return entry.name;
  }).sort();
}

function readSchemas(sourceDir) {
  const directory = path.resolve(sourceDir);
  const files = schemaFiles(directory);
  return files.map((file) => {
    const source = fs.readFileSync(path.join(directory, file), "utf8");
    let schema;
    try {
      schema = JSON.parse(source);
    } catch (error) {
      throw new Error(`Invalid JSON in ${path.join(directory, file)}: ${error.message}`, { cause: error });
    }
    if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
      throw new Error(`Client schema must be a JSON object: ${path.join(directory, file)}`);
    }
    return {
      name: file.slice(0, -SCHEMA_SUFFIX.length),
      file,
      source,
      schema,
    };
  });
}

function loadClientSchemas(sourceDir) {
  const schemas = readSchemas(sourceDir);
  const ajv = new Ajv({ allErrors: true, strict: true, validateSchema: true });
  addFormats(ajv);

  for (const entry of schemas) {
    const schemaId = entry.schema.$id || `urn:rebase:client-schema:${entry.name}`;
    entry.schemaId = schemaId;
    ajv.addSchema(entry.schema, schemaId);
  }

  const byName = new Map();
  for (const entry of schemas) {
    entry.validate = ajv.getSchema(entry.schemaId);
    byName.set(entry.name, entry);
  }
  return { ajv, directory: path.resolve(sourceDir), schemas: byName };
}

function assertClientInput(catalog, schemaName, value) {
  const entry = catalog?.schemas?.get(schemaName);
  if (!entry) throw new Error(`Client schema not found: ${schemaName}`);
  if (!entry.validate(value)) {
    throw new Error(
      `Invalid ${schemaName} input: ${catalog.ajv.errorsText(entry.validate.errors)}`,
    );
  }
  return value;
}

function writeClientSchemas({ sourceDir, outputDir, check = false }) {
  const source = path.resolve(sourceDir);
  const destination = path.resolve(outputDir);
  assertDisjointPaths(source, destination, "Client schema source and output");
  const validationCatalog = loadClientSchemas(source);
  const entries = [...validationCatalog.schemas.values()];
  const expectedFiles = entries.map((entry) => entry.file);

  if (check) {
    checkCopiedTree(source, destination);
    return { outputDir: destination, copied: [], schemas: expectedFiles };
  }

  fs.rmSync(destination, { recursive: true, force: true });
  const copied = copyTree(source, destination);
  return {
    outputDir: destination,
    copied,
    schemas: expectedFiles,
  };
}

module.exports = {
  assertClientInput,
  loadClientSchemas,
  readSchemas,
  writeClientSchemas,
};
