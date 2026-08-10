const fs = require("node:fs");
const path = require("node:path");
const { analyzeSchema } = require("./analyze");
const { generateIndexes } = require("./generators/indexes");
const { generateCascades, generateViews } = require("./generators/reactivity");
const { generateRootPermissions, generateSecurity } = require("./generators/security");
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

function removeLegacyArtifacts(outputDir, check) {
  for (const name of ["optimizer.json", "manifest.json"]) {
    const filePath = path.join(outputDir, name);
    if (!fs.existsSync(filePath)) continue;
    if (check) throw new Error(`Generated output contains legacy artifact: ${filePath}`);
    fs.unlinkSync(filePath);
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
  const schema = parseSchema([scoped.schema, scoped.edge].filter(Boolean).join("\n\n"), scoped.views);
  if (!schema.tables.size) throw new Error(`No tables found in ${project.projectDir}`);
  const analysis = analyzeSchema(schema);
  const views = generateViews(schema, project);
  const indexes = generateIndexes(schema, views.viewIndexes, project, analysis.systemTables);
  const sections = [
    ["business schema", scoped.schema],
    ["edge integrations", scoped.edge],
    ["DAG RBAC", scoped.auth],
    ["record access", scoped.access],
    ["ownership, RLS, audit, and flags", generateSecurity(schema, project, analysis.systemTables)],
    ["reactive views", views.definitions],
    ["upward view events", views.events],
    ["downward cascade events", generateCascades(analysis, project)],
    ["indexes", indexes.sql],
    ["computed view fields", views.computed],
    ["root permissions", generateRootPermissions(schema, project, analysis.systemTables)],
  ];
  if (scoped.seed) sections.push(["project seed", scoped.seed]);
  const bundle = `${sections.map(([name, sql]) => section(name, sql)).join("\n")}\n`;
  removeLegacyArtifacts(project.outputDir, project.check);
  writeOrCheck(path.join(project.outputDir, "schema.surql"), bundle, project.check);
  return { outputDir: project.outputDir, tableCount: schema.tables.size, viewCount: schema.views.length, schema };
}

module.exports = { compileProject };
