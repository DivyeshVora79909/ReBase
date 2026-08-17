const fs = require("node:fs");
const path = require("node:path");
const { analyzeSchema } = require("./analyze");
const { generateAuditEvents } = require("./generators/audit");
const { generateIndexes } = require("./generators/indexes");
const { generateCascades, generateReaderCycleGuards, generateViews } = require("./generators/reactivity");
const { generateRootPermissions, generateSecurity } = require("./generators/security");
const { discoverHandlers } = require("./handlers");
const { loadProject } = require("./project");
const { parseSchema } = require("./schema");
const { scopeSource } = require("./surql");

function section(name, sql) {
  return `-- REBASE: ${name}\n${sql.trim()}\n`;
}

function writeOrCheck(filePath, content, check) {
  if (check) {
    if (!fs.existsSync(filePath) || fs.readFileSync(filePath, "utf8") !== content) {
      throw new Error(`Generated output is stale: ${filePath}`);
    }
    return;
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function treeFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    return entry.isDirectory() ? treeFiles(resolved) : [resolved];
  });
}

function syncGeneratedTree(sourceDir, outputDir, check) {
  const sourceFiles = treeFiles(sourceDir);
  const sourceRoot = path.resolve(sourceDir);
  const expected = new Set(sourceFiles.map((file) => path.relative(sourceRoot, file)));
  const existing = treeFiles(outputDir).map((file) => path.relative(outputDir, file));
  for (const sourceFile of sourceFiles) {
    const relative = path.relative(sourceRoot, sourceFile);
    const outputFile = path.join(outputDir, relative);
    const content = fs.readFileSync(sourceFile);
    if (check) {
      if (!fs.existsSync(outputFile) || !fs.readFileSync(outputFile).equals(content)) {
        throw new Error(`Generated artifact is stale: ${outputFile}`);
      }
    } else {
      fs.mkdirSync(path.dirname(outputFile), { recursive: true });
      fs.writeFileSync(outputFile, content);
    }
  }
  if (check) {
    for (const file of existing) if (!expected.has(file)) throw new Error(`Generated artifact contains stale file: ${path.join(outputDir, file)}`);
  } else {
    for (const file of existing) if (!expected.has(file)) fs.unlinkSync(path.join(outputDir, file));
  }
  return sourceFiles;
}

function removeLegacyArtifacts(outputDir, check) {
  for (const name of ["optimizer.json", "manifest.json", "operations.json", "schemas"]) {
    const filePath = path.join(outputDir, name);
    if (!fs.existsSync(filePath)) continue;
    if (check) throw new Error(`Generated output contains legacy artifact: ${filePath}`);
    fs.rmSync(filePath, { recursive: true, force: true });
  }
}

function compileProject(rawOptions) {
  const project = loadProject(rawOptions);
  const scoped = Object.fromEntries(
    Object.entries(project.sources).map(([name, source]) => [
      name,
      source ? scopeSource(source, project.namespace, project.database) : "",
    ]),
  );
  const frameworkSource = [scoped.auth, scoped.access, scoped.audit, scoped.edge].join("\n\n");
  const frameworkTables = new Set(parseSchema(frameworkSource, "").tables.keys());
  const schema = parseSchema([scoped.schema, frameworkSource].join("\n\n"), scoped.views);
  if (!schema.tables.size) throw new Error(`No tables found in ${project.projectDir}`);
  const analysis = analyzeSchema(schema, frameworkTables);
  const businessTables = new Set([...schema.tables.keys()].filter((table) => !analysis.systemTables.has(table)));
  const handlers = discoverHandlers(path.join(project.projectDir, "edge"), businessTables);
  const views = generateViews(schema, project, analysis.systemTables);
  const indexes = generateIndexes(schema, views.viewIndexes, project, analysis.systemTables);
  const sections = [
    ["business schema", scoped.schema],
    ["DAG RBAC", scoped.auth],
    ["record access", scoped.access],
    ["audit storage", scoped.audit],
    ["edge jobs, outbox, and logs", scoped.edge],
    ["ownership, RLS, and flags", generateSecurity(schema, project, analysis.systemTables)],
    ["fire-and-forget mutation audit", generateAuditEvents(schema, project, analysis.systemTables)],
    ["reactive views", views.definitions],
    ["upward view events", views.events],
    ["reader cycle guards", generateReaderCycleGuards(schema, project, analysis.systemTables)],
    ["downward cascade events", generateCascades(analysis, project)],
    ["indexes", indexes.sql],
    ["computed view fields", views.computed],
    ["root permissions", generateRootPermissions(
      schema,
      project,
      analysis.systemTables,
      handlers.capabilities,
    )],
  ];
  if (scoped.seed) sections.push(["project seed", scoped.seed]);
  const bundle = `${sections.map(([name, sql]) => section(name, sql)).join("\n")}\n`;
  removeLegacyArtifacts(project.outputDir, project.check);
  writeOrCheck(path.join(project.outputDir, "schema.surql"), bundle, project.check);
  syncGeneratedTree(path.join(project.projectDir, "edge"), path.join(project.outputDir, "edge"), project.check);
  return {
    outputDir: project.outputDir,
    tableCount: schema.tables.size,
    viewCount: schema.views.length,
    handlerCount: handlers.capabilities.length,
    schema,
    handlers,
  };
}

module.exports = { compileProject };
