const fs = require("node:fs");
const path = require("node:path");
const { analyzeSchema } = require("../../src/analyze");
const { generateAuditEvents } = require("../../src/generators/audit");
const { generateOAuthAccess } = require("../../src/generators/access");
const { generateIndexes } = require("../../src/generators/indexes");
const { generateReferenceAssertions } = require("../../src/generators/references");
const { generateCascades, generateReaderCycleGuards, generateViews } = require("../../src/generators/reactivity");
const { generateRootPermissions, generateSecurity } = require("../../src/generators/security");
const {
  generateEffectEvents,
  generateLifecycleMigration,
  generateLifecycleFields,
  generateOperationEvents,
  generateRuntimeContracts,
} = require("../../src/generators/effects");
const { generateTemporal, resolveTemporalModel } = require("../../src/generators/temporal");
const { parseSchema } = require("../../src/schema");
const { PRINCIPAL_TABLES, detectSelectPolicy, validatePrincipalTables } = require("./principals");
const { composeProfiles, contextStatement } = require("./materials");

function section(name, sql) {
  const body = String(sql || "").trim();
  return body ? `-- REBASE: ${name}\n${body}\n` : "";
}

function contextOptions(context = {}) {
  return {
    namespace: context.namespace,
    database: context.database,
    principalTables: PRINCIPAL_NAMES_FOR_CONTEXT,
    rootGroupId: context.rootGroupId || "rebase_group:root",
    runtimeUrl: context.runtimeUrl,
    runtimeSecret: context.runtimeSecret,
  };
}

const PRINCIPAL_NAMES_FOR_CONTEXT = [PRINCIPAL_TABLES.user, PRINCIPAL_TABLES.group];

function discoverFrameworkTables(frameworkSource) {
  return new Set(parseSchema(frameworkSource, "").tables.keys());
}

function resolveModel(materials, options = {}) {
  const context = contextOptions(options.context);
  const profiles = composeProfiles(materials, options.profiles);
  const framework = profiles.framework;
  const project = profiles.project;
  const rawFrameworkSource = [framework.schema, framework.raw, framework.events].filter(Boolean).join("\n\n");
  const projectSelectPolicy = detectSelectPolicy([project.schema, project.raw].filter(Boolean).join("\n\n"));
  const principals = PRINCIPAL_TABLES;
  const frameworkSource = rawFrameworkSource;
  const frameworkStatements = framework.frameworkStatements;
  const projectEventsSource = project.events;
  const projectSchema = [project.schema, project.raw].filter(Boolean).join("\n\n");
  const projectOnlySchema = parseSchema(project.schemaStatements, "");
  const viewsSource = project.views;
  const seedSource = project.seed;
  const frameworkSeedSource = framework.seed;
  const schema = parseSchema([...project.schemaStatements, ...frameworkStatements], viewsSource);
  if (!schema.tables.size) throw new Error("No DEFINE TABLE statements found in material");
  validatePrincipalTables(schema);
  const frameworkTables = options.frameworkTables || discoverFrameworkTables(frameworkSource);
  let analysis;
  let temporalModel;
  try {
    analysis = analyzeSchema(schema, frameworkTables);
    temporalModel = resolveTemporalModel(schema, analysis.systemTables);
  } catch (error) {
    throw withSourceLocation(error, schema);
  }
  const generatedOptions = {
    ...context,
    principalTables: PRINCIPAL_NAMES_FOR_CONTEXT,
    rootGroupId: `${principals.group}:root`,
    selectPolicy: options.selectPolicy || projectSelectPolicy,
  };
  return {
    materials,
    profiles,
    context,
    generatedOptions,
    principals,
    selectPolicy: generatedOptions.selectPolicy,
    schema,
    analysis,
    temporalModel,
    projectSchema,
    projectEventsSource,
    frameworkSource,
    frameworkSeedSource,
    seedSource,
    viewsSource,
    projectOnlySchema,
    rootPermissions: options.rootPermissions !== false,
  };
}

function withSourceLocation(error, schema) {
  if (error?.location || !error?.message) return error;
  const pathMatch = error.message.match(/\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\b/);
  const field = pathMatch && schema.tables.get(pathMatch[1])?.fields.get(pathMatch[2]);
  const location = field?.location || (pathMatch && schema.tables.get(pathMatch[1])?.location);
  if (!location?.relative || !location.line || !location.column) return error;
  const at = `${location.group ? `${location.group}:` : ""}${location.relative}:${location.line}:${location.column}`;
  const diagnosed = new Error(`${error.message} at ${at}`, { cause: error });
  diagnosed.location = location;
  return diagnosed;
}

function emitResolvedModel(model) {
  const {
    context, generatedOptions, principals, schema, analysis, projectSchema,
    projectEventsSource, frameworkSource, frameworkSeedSource, seedSource,
    viewsSource, projectOnlySchema, rootPermissions,
  } = model;
  const views = generateViews(schema, generatedOptions, analysis.systemTables);
  const indexes = generateIndexes(schema, views.viewIndexes, context, analysis.systemTables);
  const temporal = generateTemporal(schema, generatedOptions, analysis.systemTables, model.temporalModel);
  const operationEvents = generateOperationEvents(schema, generatedOptions);
  const lifecycleMigration = generateLifecycleMigration(schema, generatedOptions);
  const sections = [
    ["context", contextStatement(context)],
    ["raw schema", projectSchema],
    ["project events", projectEventsSource],
    ["raw framework", frameworkSource],
    ["oauth access", generateOAuthAccess(principals, generatedOptions)],
    ["record reference assertions", generateReferenceAssertions(projectOnlySchema, context)],
    ["raw views", viewsSource],
    ["ownership, RLS, and flags", generateSecurity(schema, generatedOptions, analysis.systemTables)],
    ["audit log", generateAuditEvents(schema, generatedOptions, analysis.systemTables)],
    ["reactive views", views.definitions],
    ["upward view events", views.events],
    ["reader cycle guards", generateReaderCycleGuards(schema, generatedOptions, analysis.systemTables)],
    ["downward propagation", generateCascades(analysis, generatedOptions)],
    ["indexes", indexes.sql],
    ["computed view fields", views.computed],
    ["temporal trees and field dependencies", temporal.sql],
    ["effect lifecycle fields", generateLifecycleFields(schema)],
    ["table effect events", generateEffectEvents(schema, generatedOptions)],
  ];
  if (operationEvents) sections.push(["operation events", operationEvents]);
  if (frameworkSeedSource) sections.push(["framework bootstrap", frameworkSeedSource]);
  if (seedSource) sections.push(["seed", seedSource]);
  if (rootPermissions) {
    sections.push(["root permissions", generateRootPermissions(schema, generatedOptions, analysis.systemTables)]);
  }
  return {
    ...model,
    bundle: `${sections.map(([name, sql]) => section(name, sql)).join("\n")}\n`,
    context: generatedOptions,
    principals,
    selectPolicy: generatedOptions.selectPolicy,
    schema,
    analysis,
    views,
    indexes,
    temporal,
    seedSource,
    lifecycleMigration,
    contracts: generateRuntimeContracts(schema, principals),
  };
}

function emitModel(model) {
  try {
    return emitResolvedModel(model);
  } catch (error) {
    throw withSourceLocation(error, model.schema);
  }
}

function generateBundle(materials, options = {}) {
  return emitModel(resolveModel(materials, options));
}

function copyTree(sourceDir, outputDir) {
  if (!sourceDir || !fs.existsSync(sourceDir)) return [];
  const copied = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const source = path.join(directory, entry.name);
      const relative = path.relative(sourceDir, source);
      const target = path.join(outputDir, relative);
      if (entry.isDirectory()) visit(source);
      else {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.copyFileSync(source, target);
        copied.push(relative);
      }
    }
  }
  visit(sourceDir);
  return copied.sort();
}

function treeFiles(directory) {
  if (!directory || !fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    return entry.isDirectory() ? treeFiles(resolved) : [resolved];
  });
}

function checkCopiedTree(sourceDir, outputDir) {
  const expected = treeFiles(sourceDir).map((file) => path.relative(sourceDir, file)).sort();
  const actual = treeFiles(outputDir).map((file) => path.relative(outputDir, file)).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Generated artifact tree is stale: ${outputDir}`);
  }
  for (const relative of expected) {
    const source = fs.readFileSync(path.join(sourceDir, relative));
    const target = fs.readFileSync(path.join(outputDir, relative));
    if (!source.equals(target)) throw new Error(`Generated artifact is stale: ${path.join(outputDir, relative)}`);
  }
}

function writeArtifacts({ outputDir, bundle, contracts, lifecycleMigration, copies = [] }, { check = false } = {}) {
  const trees = copies.filter((value) => value?.sourceDir && value?.outputDir);
  const schemaPath = path.join(outputDir, "schema.surql");
  const contractPath = path.join(outputDir, "runtime-contracts.json");
  const backfillPath = path.join(outputDir, "migrate-one-shot-backfill.surql");
  const finalizeMigrationPath = path.join(outputDir, "migrate-one-shot-finalize.surql");
  const contractSource = `${JSON.stringify(contracts || { tables: {} }, null, 2)}\n`;
  const backfillSource = `${lifecycleMigration?.backfill || ""}\n`;
  const finalizeMigrationSource = `${lifecycleMigration?.finalize || ""}\n`;
  if (check) {
    if (!fs.existsSync(schemaPath) || fs.readFileSync(schemaPath, "utf8") !== bundle) {
      throw new Error(`Generated output is stale: ${schemaPath}`);
    }
    if (!fs.existsSync(contractPath) || fs.readFileSync(contractPath, "utf8") !== contractSource) {
      throw new Error(`Generated output is stale: ${contractPath}`);
    }
    if (!fs.existsSync(backfillPath) || fs.readFileSync(backfillPath, "utf8") !== backfillSource) {
      throw new Error(`Generated output is stale: ${backfillPath}`);
    }
    if (!fs.existsSync(finalizeMigrationPath) || fs.readFileSync(finalizeMigrationPath, "utf8") !== finalizeMigrationSource) {
      throw new Error(`Generated output is stale: ${finalizeMigrationPath}`);
    }
    for (const tree of trees) checkCopiedTree(tree.sourceDir, tree.outputDir);
    return { schemaPath, contractPath, backfillPath, finalizeMigrationPath, copied: [] };
  }
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(schemaPath, bundle);
  fs.writeFileSync(contractPath, contractSource);
  fs.writeFileSync(backfillPath, backfillSource);
  fs.writeFileSync(finalizeMigrationPath, finalizeMigrationSource);
  const copied = trees.flatMap((tree) => {
    fs.rmSync(tree.outputDir, { recursive: true, force: true });
    return copyTree(tree.sourceDir, tree.outputDir).map((file) => path.join(path.basename(tree.outputDir), file));
  });
  return { schemaPath, contractPath, backfillPath, finalizeMigrationPath, copied };
}

module.exports = {
  contextOptions,
  checkCopiedTree,
  copyTree,
  emitModel,
  generateBundle,
  resolveModel,
  section,
  writeArtifacts,
};
