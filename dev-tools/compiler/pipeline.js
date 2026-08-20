const fs = require("node:fs");
const path = require("node:path");
const { analyzeSchema } = require("../../src/analyze");
const { generateAuditEvents, generateChangeLogEvents } = require("../../src/generators/audit");
const { generateIndexes } = require("../../src/generators/indexes");
const { generateReferenceAssertions } = require("../../src/generators/references");
const { generateCascades, generateReaderCycleGuards, generateViews } = require("../../src/generators/reactivity");
const { generateRootPermissions, generateSecurity } = require("../../src/generators/security");
const { generateEffectEvents } = require("../../src/generators/effects");
const { parseSchema } = require("../../src/schema");
const { bindFrameworkPrincipals, detectSelectPolicy, discoverPrincipalTables } = require("./principals");
const { contextStatement, materialSources, partitionSource } = require("./materials");

function section(name, sql) {
  const body = String(sql || "").trim();
  return body ? `-- REBASE: ${name}\n${body}\n` : "";
}

function contextOptions(context = {}) {
  return {
    namespace: context.namespace,
    database: context.database,
    principalTables: context.principalTables || ["user", "groups"],
    rootGroupId: context.rootGroupId || "groups:root",
    runtimeUrl: context.runtimeUrl,
    runtimeSecret: context.runtimeSecret,
  };
}

function discoverFrameworkTables(frameworkSource) {
  return new Set(parseSchema(frameworkSource, "").tables.keys());
}

function generateBundle(materials, options = {}) {
  const context = contextOptions(options.context);
  const rawFrameworkSource = [
    materialSources(materials, "framework", "schema"),
    materialSources(materials, "framework", "raw"),
  ].filter(Boolean).join("\n\n");
  const projectSelectPolicy = detectSelectPolicy(materials.combined);
  const principalSource = materialSources(materials, "project", "schema");
  const provisionalSchema = parseSchema(principalSource, "");
  const principals = options.principalTables || discoverPrincipalTables(provisionalSchema);
  const frameworkSource = bindFrameworkPrincipals(rawFrameworkSource, principals);
  const schemaSource = materialSources(materials, "project", "schema");
  const projectRawSource = materialSources(materials, "project", "raw");
  const projectSchema = [schemaSource, projectRawSource].filter(Boolean).join("\n\n");
  const projectOnlySchema = parseSchema(projectSchema, "");
  const viewsSource = partitionSource(materials, "views");
  const seedSource = materialSources(materials, "project", "seed");
  const frameworkSeedSource = bindFrameworkPrincipals(
    materialSources(materials, "framework", "seed"),
    principals,
  );
  const schema = parseSchema(`${projectSchema}\n${frameworkSource}`, viewsSource);
  if (!schema.tables.size) throw new Error("No DEFINE TABLE statements found in material");
  const frameworkTables = options.frameworkTables || discoverFrameworkTables(frameworkSource);
  const analysis = analyzeSchema(schema, frameworkTables);
  const generatedOptions = {
    ...context,
    principalTables: [principals.user, principals.group],
    rootGroupId: `${principals.group}:root`,
    selectPolicy: options.selectPolicy || projectSelectPolicy,
  };
  const views = generateViews(schema, generatedOptions, analysis.systemTables);
  const indexes = generateIndexes(schema, views.viewIndexes, context, analysis.systemTables);
  const sections = [
    ["context", contextStatement(context)],
    ["raw schema", projectSchema],
    ["raw framework", frameworkSource],
    ["record reference assertions", generateReferenceAssertions(projectOnlySchema, context)],
    ["raw views", viewsSource],
    ["ownership, RLS, and flags", generateSecurity(schema, generatedOptions, analysis.systemTables)],
    ["audit log", generateAuditEvents(schema, generatedOptions, analysis.systemTables)],
    ["change log", generateChangeLogEvents(schema, generatedOptions)],
    ["reactive views", views.definitions],
    ["upward view events", views.events],
    ["reader cycle guards", generateReaderCycleGuards(schema, generatedOptions, analysis.systemTables)],
    ["downward propagation", generateCascades(analysis, generatedOptions)],
    ["indexes", indexes.sql],
    ["computed view fields", views.computed],
    ["table effect events", generateEffectEvents(schema, generatedOptions)],
  ];
  if (frameworkSeedSource) sections.push(["framework bootstrap", frameworkSeedSource]);
  if (seedSource) sections.push(["seed", seedSource]);
  if (options.rootPermissions !== false) {
    sections.push(["root permissions", generateRootPermissions(schema, generatedOptions, analysis.systemTables)]);
  }
  return {
    bundle: `${sections.map(([name, sql]) => section(name, sql)).join("\n")}\n`,
    context: generatedOptions,
    principals,
    selectPolicy: generatedOptions.selectPolicy,
    schema,
    analysis,
    views,
    indexes,
    seedSource,
  };
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

function writeArtifacts({ outputDir, bundle, copies = [] }, { check = false } = {}) {
  const trees = copies.filter((value) => value?.sourceDir && value?.outputDir);
  const schemaPath = path.join(outputDir, "schema.surql");
  if (check) {
    if (!fs.existsSync(schemaPath) || fs.readFileSync(schemaPath, "utf8") !== bundle) {
      throw new Error(`Generated output is stale: ${schemaPath}`);
    }
    for (const tree of trees) checkCopiedTree(tree.sourceDir, tree.outputDir);
    return { schemaPath, copied: [] };
  }
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(schemaPath, bundle);
  const copied = trees.flatMap((tree) => {
    fs.rmSync(tree.outputDir, { recursive: true, force: true });
    return copyTree(tree.sourceDir, tree.outputDir).map((file) => path.join(path.basename(tree.outputDir), file));
  });
  return { schemaPath, copied };
}

module.exports = {
  contextOptions,
  checkCopiedTree,
  copyTree,
  generateBundle,
  section,
  writeArtifacts,
};
