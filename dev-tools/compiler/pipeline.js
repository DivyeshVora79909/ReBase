const fs = require("node:fs");
const path = require("node:path");
const { analyzeSchema } = require("./analyze");
const { generateAuditEvents } = require("./generators/audit");
const { generateOAuthAccess } = require("./generators/access");
const { generateIndexes } = require("./generators/indexes");
const { generateReferenceAssertions, generateTenantReferenceGuards } = require("./generators/references");
const { generateCascades, generateViews } = require("./generators/reactivity");
const { generateRootPermissions, generateSecurity } = require("./generators/security");
const {
  generateEffectEvents,
  generateLifecycleMigration,
  generateLifecycleFields,
  generateOperationEvents,
  generateRuntimeContracts,
} = require("./generators/effects");
const { generateTemporal, resolveTemporalModel } = require("./generators/temporal");
const { dependencyPlan } = require('./dependency-plan');
const { parseSchema } = require("./schema");
const { PRINCIPAL_TABLES, detectSelectPolicy, validatePrincipalTables } = require("./principals");
const { composeProfiles, contextStatement } = require("./materials");
const { splitStatements, sqlCode } = require("./surql");

function section(name, sql) {
  const body = String(sql || "").trim();
  return body ? `-- REBASE: ${name}\n${body}\n` : "";
}

function contextOptions(context = {}) {
  return {
    namespace: context.namespace,
    database: context.database,
    principalTables: PRINCIPAL_NAMES_FOR_CONTEXT,
    runtimeUrl: context.runtimeUrl,
    runtimeSecret: context.runtimeSecret,
  };
}

const PRINCIPAL_NAMES_FOR_CONTEXT = [PRINCIPAL_TABLES.user, PRINCIPAL_TABLES.group, PRINCIPAL_TABLES.tenant];

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
  const projectStatements = splitStatements([project.schema, project.raw].filter(Boolean).join("\n\n"));
  // Tenant is a generated field. Native indexes referring to it must be
  // defined after common fields exist (SurrealDB 3.3 validates index fields).
  const isIndex = statement => /^\s*DEFINE\s+INDEX\b/i.test(sqlCode(statement));
  const projectSchema = projectStatements.filter(statement => !isIndex(statement)).join("\n\n");
  const projectIndexes = projectStatements.filter(isIndex).join("\n\n");
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
    temporalModel = resolveTemporalModel(schema, analysis.systemTables, projectSchema + '\n' + frameworkSource);
  } catch (error) {
    throw withSourceLocation(error, schema);
  }
  const generatedOptions = {
    ...context,
    principalTables: PRINCIPAL_NAMES_FOR_CONTEXT,
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
    projectIndexes,
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
    projectEventsSource, projectIndexes, frameworkSource, frameworkSeedSource, seedSource,
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
    ["tenant reference boundaries", generateTenantReferenceGuards(schema, generatedOptions, analysis.systemTables)],
    ["audit log", generateAuditEvents(schema, generatedOptions, analysis.systemTables)],
    ["reactive views", views.definitions],
    ["upward view events", views.events],
    ["reader ownership propagation", generateCascades(analysis, generatedOptions, model.temporalModel.trees)],
    ["indexes", indexes.sql],
    ["authored indexes", projectIndexes],
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
    dependencyPlan: dependencyPlan(schema, model.temporalModel, projectSchema + '\n' + frameworkSource),
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

function pathWithin(parent, child) {
  const relative = path.relative(parent, child);
  return relative === "" || (
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function canonicalPath(value) {
  let current = path.resolve(value);
  const missing = [];
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    missing.unshift(path.basename(current));
    current = parent;
  }
  return path.join(fs.realpathSync.native(current), ...missing);
}

function assertDisjointPaths(leftPath, rightPath, label = "Source and output") {
  const left = path.resolve(leftPath);
  const right = path.resolve(rightPath);
  const paths = [[left, right], [canonicalPath(left), canonicalPath(right)]];
  if (paths.some(([first, second]) => pathWithin(first, second) || pathWithin(second, first))) {
    throw new Error(`${label} paths must not overlap: ${left} and ${right}`);
  }
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

function preflightArtifacts(outputDir, copies = []) {
  for (const name of [
    "schema.surql",
    "runtime-contracts.json",
    "dependency-plan.json",
    "devtools.json",
    "migrate-one-shot-backfill.surql",
    "migrate-one-shot-finalize.surql",
  ]) {
    const target = path.join(outputDir, name);
    if (fs.lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink()) {
      throw new Error(`Generated artifact must not be a symbolic link: ${target}`);
    }
  }
  const trees = copies.filter((value) => value?.sourceDir && value?.outputDir);
  for (const tree of trees) {
    assertDisjointPaths(outputDir, tree.sourceDir, "Artifact output and copy source");
    for (const source of trees) {
      assertDisjointPaths(source.sourceDir, tree.outputDir, "Copied artifact source and destination");
    }
  }
  for (let index = 0; index < trees.length; index += 1) {
    for (let next = index + 1; next < trees.length; next += 1) {
      assertDisjointPaths(trees[index].outputDir, trees[next].outputDir, "Copied artifact output");
    }
  }
  return trees;
}

function writeGeneratedFile(target, contents) {
  const existing = fs.lstatSync(target, { throwIfNoEntry: false });
  const temporaryDirectory = fs.mkdtempSync(
    path.join(path.dirname(target), ".rebase-artifact-"),
  );
  const temporary = path.join(temporaryDirectory, path.basename(target));
  try {
    fs.writeFileSync(
      temporary,
      contents,
      existing ? { mode: existing.mode & 0o7777 } : undefined,
    );
    if (existing) fs.chmodSync(temporary, existing.mode & 0o7777);
    fs.renameSync(temporary, target);
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
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

function writeArtifacts({ outputDir, bundle, contracts, dependencyPlan, catalog, lifecycleMigration, copies = [] }, { check = false } = {}) {
  const trees = preflightArtifacts(outputDir, copies);
  const schemaPath = path.join(outputDir, "schema.surql");
  const contractPath = path.join(outputDir, "runtime-contracts.json");
  const dependencyPath = path.join(outputDir, 'dependency-plan.json');
  const dependencySource = `${JSON.stringify(dependencyPlan || { version: 1, tables: {} }, null, 2)}\n`;
  const catalogPath = path.join(outputDir, "devtools.json");
  const catalogSource = JSON.stringify(catalog || null, null, 2) + "\n";
  const backfillPath = path.join(outputDir, "migrate-one-shot-backfill.surql");
  const finalizeMigrationPath = path.join(outputDir, "migrate-one-shot-finalize.surql");
  const contractSource = `${JSON.stringify(contracts || { tables: {} }, null, 2)}\n`;
  const backfillSource = `${lifecycleMigration?.backfill || ""}\n`;
  const finalizeMigrationSource = `${lifecycleMigration?.finalize || ""}\n`;
  if (check) {
    if (!fs.existsSync(catalogPath) || fs.readFileSync(catalogPath, "utf8") !== catalogSource) {
      throw new Error("Generated output is stale: " + catalogPath);
    }
    if (!fs.existsSync(dependencyPath) || fs.readFileSync(dependencyPath, 'utf8') !== dependencySource) {
      throw new Error(`Generated output is stale: ${dependencyPath}`);
    }
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
    return { schemaPath, contractPath, dependencyPath, catalogPath, backfillPath, finalizeMigrationPath, copied: [] };
  }
  fs.mkdirSync(outputDir, { recursive: true });
  writeGeneratedFile(schemaPath, bundle);
  writeGeneratedFile(contractPath, contractSource);
  writeGeneratedFile(dependencyPath, dependencySource);
  writeGeneratedFile(catalogPath, catalogSource);
  writeGeneratedFile(backfillPath, backfillSource);
  writeGeneratedFile(finalizeMigrationPath, finalizeMigrationSource);
  const copied = trees.flatMap((tree) => {
    fs.rmSync(tree.outputDir, { recursive: true, force: true });
    return copyTree(tree.sourceDir, tree.outputDir).map((file) => path.join(path.basename(tree.outputDir), file));
  });
  return { schemaPath, contractPath, dependencyPath, catalogPath, backfillPath, finalizeMigrationPath, copied };
}

module.exports = {
  assertDisjointPaths,
  contextOptions,
  checkCopiedTree,
  copyTree,
  emitModel,
  generateBundle,
  preflightArtifacts,
  resolveModel,
  section,
  writeArtifacts,
};
