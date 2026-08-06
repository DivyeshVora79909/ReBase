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

function optimizerManifest(tables, indexes) {
  return {
    version: 1,
    securityBoundary: {
      predicate: "readers_index CONTAINSANY $auth.z_access_index",
      behavior: "RLS remains authoritative even when the query planner uses another index.",
    },
    findings: [
      {
        queryShape: "permission-only with dynamic auth array",
        observedPlan: "TableScan",
        reason: "SurrealDB 3.2 does not index dynamic CONTAINSANY arrays.",
      },
      {
        queryShape: "permission-only with scalar OR/fan-out branches",
        observedPlan: "IndexScan on readers_index.*",
        complexity: "approximately O(m log n + candidates)",
      },
      {
        queryShape: "selective business filter and sort",
        observedPlan: "business IndexScan with RLS as a residual filter",
        guidance: "Prefer this when the business index sharply reduces candidates.",
      },
    ],
    policy: [
      "Use scalar reader fan-out for narrow ACLs and permission-dominated queries.",
      "Use business filters and sort indexes first when they are selective.",
      "Use EXPLAIN FULL in benchmarks; response time alone does not prove index usage.",
      "Do not index array<record> ACL fields directly; index the materialized array<string> field with field.*.",
    ],
    tables: tables.map((table) => ({
      table,
      readersField: "readers_index",
      readersIndex: `idx_${table}_readers`,
      ownershipIndex: `idx_${table}_owned_by`,
    })),
    generatedIndexes: indexes,
  };
}

function compileProject(rawOptions) {
  const project = loadProject(rawOptions);
  const scoped = Object.fromEntries(
    Object.entries(project.sources).map(([name, source]) => [
      name,
      source ? scopeSource(source, project.namespace, project.database) : "",
    ]),
  );
  const schema = parseSchema(`${scoped.settings}\n${scoped.schema}`, scoped.views);
  if (!schema.tables.size) throw new Error(`No tables found in ${project.projectDir}`);
  const analysis = analyzeSchema(schema);
  const views = generateViews(schema, project);
  const indexes = generateIndexes(schema, views.viewIndexes, project, analysis.systemTables);
  const businessTables = [...schema.tables.keys()].filter((table) => !analysis.systemTables.has(table));
  const sections = [
    ["scoped settings", scoped.settings],
    ["business schema", scoped.schema],
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
  const optimizer = optimizerManifest(businessTables.sort(), indexes.indexes);
  writeOrCheck(path.join(project.outputDir, "schema.surql"), bundle, project.check);
  writeOrCheck(path.join(project.outputDir, "optimizer.json"), `${JSON.stringify(optimizer, null, 2)}\n`, project.check);
  return { outputDir: project.outputDir, tableCount: schema.tables.size, viewCount: schema.views.length, schema };
}

module.exports = { compileProject, optimizerManifest };
