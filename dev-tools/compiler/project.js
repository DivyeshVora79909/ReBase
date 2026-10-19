const fs = require("node:fs");
const path = require("node:path");
const { resolveConfiguration, validateConfiguration } = require("../../config/environment");
const { loadMaterials } = require("./materials");
const { validateTableHandlers, validateWebhookHandlers } = require("./table-handlers");
const { loadClientSchemas, writeClientSchemas } = require("../client-schemas");
const { developerCatalog } = require("./catalog");
const { buildInspector } = require("../inspector/build");
const { explainDependency } = require('./dependency-plan');
const {
  assertDisjointPaths,
  generateBundle,
  preflightArtifacts,
  writeArtifacts,
} = require("./pipeline");

function resolveDirectory(root, value) {
  return path.resolve(root, value);
}

function buildProject(rawArgs, root = process.cwd()) {
  for (const key of [
    "endpoint",
    "username",
    "password",
    "namespace",
    "database",
    "runtimeUrl",
    "runtimeSecret",
    "environment",
  ]) {
    if (Object.hasOwn(rawArgs, key)) {
      throw new Error(`${key} is process-profile configuration and cannot be overridden`);
    }
  }
  const projectDir = resolveDirectory(root, rawArgs.projectDir);
  const frameworkDir = resolveDirectory(root, rawArgs.frameworkDir);
  const outputDir = resolveDirectory(
    root,
    rawArgs.outputDir || path.join("build", path.basename(projectDir)),
  );
  assertDisjointPaths(projectDir, outputDir, "Project input and output");
  assertDisjointPaths(frameworkDir, outputDir, "Framework input and output");
  const materials = loadMaterials({
    groups: [
      { name: "framework", roots: [frameworkDir] },
      { name: "project", roots: [projectDir] },
    ],
    print: rawArgs.printRaw,
  });
  const configuration = validateConfiguration(
    rawArgs.configuration || resolveConfiguration(process.env),
  );
  const context = {
    namespace: configuration.surreal.defaultContext?.namespace,
    database: configuration.surreal.defaultContext?.database,
    runtimeUrl: configuration.runtime.url,
    runtimeSecret: configuration.runtime.secret,
  };
  const result = generateBundle(materials, { context, rootPermissions: rawArgs.rootPermissions !== false });
  result.catalog = developerCatalog(result, {
    project: path.basename(projectDir),
    schemas: loadClientSchemas(path.join(projectDir, "schemas")).schemas,
  });
  if (rawArgs.explain) return { ...result, outputDir,
    explanation: explainDependency(result.dependencyPlan, rawArgs.explain) };
  const tableHandlers = validateTableHandlers(projectDir, result.schema, result.contracts);
  const webhookHandlers = validateWebhookHandlers(projectDir);
  result.contracts.webhooks = webhookHandlers.contract();
  const copies = [];
  for (const directory of ["table-handlers", "webhook-handlers"]) {
    if (fs.existsSync(path.join(projectDir, directory))) {
      copies.push({ sourceDir: path.join(projectDir, directory), outputDir: path.join(outputDir, directory) });
    }
  }
  // Include the empty source case so removing fixtures also prunes old copies.
  copies.push({ sourceDir: path.join(projectDir, "fixtures"), outputDir: path.join(outputDir, "fixtures") });
  preflightArtifacts(outputDir, copies);
  const clientSchemas = writeClientSchemas({
    sourceDir: path.join(projectDir, "schemas"),
    outputDir: path.join(outputDir, "client", "schemas"),
    check: rawArgs.check,
  });
  const artifacts = writeArtifacts({
    outputDir,
    bundle: result.bundle,
    contracts: result.contracts,
    dependencyPlan: result.dependencyPlan,
    catalog: result.catalog,
    inspector: buildInspector(result.catalog),
    lifecycleMigration: result.lifecycleMigration,
    copies,
  }, { check: rawArgs.check });
  return {
    ...result,
    artifacts,
    clientSchemas,
    outputDir,
    projectDir,
    tableHandlerCount: tableHandlers.tables.length,
    webhookHandlerCount: webhookHandlers.list().length,
    materialFileCount: materials.files.length,
    configuration,
  };
}

const compileFromArgs = buildProject;

module.exports = { buildProject, compileFromArgs };
