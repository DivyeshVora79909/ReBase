"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { build } = require("../index");
const { resolveConfiguration } = require("../../config/environment");
const { compileType } = require("../compiler/fields");
const { developerCatalog, referenceType } = require("../compiler/catalog");
const { generateBundle } = require("../compiler/pipeline");
const { loadMaterials } = require("../compiler/materials");

const root = path.resolve(__dirname, "../..");
const configuration = resolveConfiguration({ NODE_ENV: "test" });
let accounting;
const accountingBuild = () => accounting ||= build({ project: "all-in-accounting", explain: "*", configuration });

test("developer catalog includes nonreactive, private, relation and generated tables/fields", () => {
  const catalog = accountingBuild().catalog;
  assert.equal(catalog.tables.length, 65);
  assert.equal(catalog.tables.filter(table => table.schema).length, 48);
  for (const name of ["rebase_group", "rebase_access", "audit_mutation", "authentication_challenge",
    "rebase_reconciliation_cursor", "rebase_webhook_receipt", "currency", "sales_issue"]) {
    assert(catalog.tables.some(table => table.name === name), name);
  }
  const access = catalog.tables.find(table => table.name === "rebase_access");
  assert.equal(access.kind, "relation");
  assert.deepEqual(access.fields.find(field => field.name === "in").reference.targets,
    ["rebase_group", "rebase_tenant", "rebase_user"]);
  const issue = catalog.tables.find(table => table.name === "sales_issue");
  assert.deepEqual(issue.fields.find(field => field.name === "stock_account").reference.targets,
    ["misc_stock_account", "stock_account"]);
  assert.equal(issue.fields.find(field => field.name === "amount").publicInput, false);
  assert.equal(issue.fields.find(field => field.name === "quantity").publicInput, true);
  assert.equal(issue.fields.find(field => field.name === "tenant").generated, true);
  assert.equal(issue.fields.find(field => field.name === "q_stock_reporting").kind, "query");
  assert.equal(issue.fields.find(field => field.name === "__rebase_dependency_q_stock_reporting").kind, "member");
  assert.equal(issue.fields.find(field => field.name === "invoice").source.file, "postings/issues.surql");
  assert.equal(issue.fields.find(field => field.name === "invoice").source.group, "project");
});

test("root membership, scalar routes, query operations and helper source remain distinct facts", () => {
  const catalog = accountingBuild().catalog;
  const issue = catalog.tables.find(table => table.name === "sales_issue");
  const query = issue.dependencies.queries.find(query => query.field === "q_stock_reporting");
  assert.equal(query.operation, "latest");
  assert.equal(query.phase, "refresh");
  assert.deepEqual(query.sources.map(source => source.table + "." + source.root), ["exchange_pair.z_rates"]);
  const amount = issue.dependencies.calculations.find(field => field.field === "amount");
  assert.deepEqual(new Set(amount.inputs), new Set(["quantity", "price", "precision"]));
  assert(issue.dependencies.references.some(route => route.reference === "invoice"
    && route.table === "sales_invoice" && route.consumers.includes("invoice_date")));
  const membership = catalog.memberships.find(member => member.id === "sales_issue.z_invoice");
  assert.deepEqual(membership.roots, ["purchase_invoice.z_history", "sales_invoice.z_history"]);
  assert.equal(membership.provider, "fn::accounting::issue_members");
  assert.equal(membership.generated, false);
  assert(catalog.roots.find(root => root.id === "sales_invoice.z_history").members.includes(membership.id));
  assert.equal(catalog.roots.find(root => root.id === "sales_invoice.z_history").unique, false);
  assert.equal(catalog.memberships.find(member => member.id === "currency.z_identity").reader, false);
  const helper = catalog.functions.find(fn => fn.name === membership.provider);
  assert.match(helper.body, /fn::accounting::commercial/);
  assert(helper.calls.includes("fn::accounting::post"));
  assert.equal(helper.source.file, "postings/issues.surql");
  assert.equal(catalog.functions.find(fn => fn.name === catalog.monoid.combine).source.group, "compiler");
  assert.match(catalog.functions.find(fn => fn.name === catalog.monoid.identity).body, /count: 0/);
});

test("views and effect tables are inventoried without public input schemas", () => {
  const { catalog } = build({ project: "test", explain: "*", configuration });
  assert.equal(catalog.tables.filter(table => table.kind === "view").length, 8);
  assert.equal(catalog.tables.filter(table => table.schema).length, 0);
  for (const view of catalog.tables.filter(table => table.kind === "view")) {
    assert(view.view.source);
    assert(catalog.tables.some(table => table.name === view.view.source));
    assert(view.view.projections.length);
  }
  assert(catalog.tables.some(table => table.effect));
});

test("native reference inspection handles unions, arrays, nested containers and untyped records", () => {
  assert.deepEqual(referenceType(compileType("option<array<record<alpha> | record<beta>, 2>>")), {
    targets: ["alpha", "beta"], many: true, optional: true, unrestricted: false,
  });
  assert.deepEqual(referenceType(compileType("record")), {
    targets: [], many: false, optional: false, unrestricted: true,
  });
  assert.equal(referenceType(compileType("string")), null);
});

test("catalog excludes deployment credentials and remains reproducible across output locations", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-catalog-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const materials = loadMaterials({ groups: [
    { name: "framework", roots: [path.join(root, "framework")] },
    { name: "project", roots: [path.join(root, "designs/test")] },
  ] });
  const compiled = generateBundle(materials, { context: {
    namespace: "private_namespace_sentinel", database: "private_database_sentinel",
    runtimeUrl: "https://runtime-sentinel.example", runtimeSecret: "credential-sentinel-xyz",
  } });
  const serialized = JSON.stringify(developerCatalog(compiled, { project: "test" }));
  for (const secret of ["private_namespace_sentinel", "private_database_sentinel",
    "runtime-sentinel.example", "credential-sentinel-xyz", root]) assert(!serialized.includes(secret), secret);

  const outputs = ["a", "b"].map(name => path.join(temporary, name));
  for (const outputDir of outputs) build({ project: "index-analytics", outputDir, configuration });
  const first = fs.readFileSync(path.join(outputs[0], "devtools.json"), "utf8");
  assert.equal(first, fs.readFileSync(path.join(outputs[1], "devtools.json"), "utf8"));
  build({ project: "index-analytics", outputDir: outputs[0], configuration, check: true });
  fs.writeFileSync(path.join(outputs[0], "devtools.json"), "stale");
  assert.throws(() => build({ project: "index-analytics", outputDir: outputs[0], configuration, check: true }), /stale/);
  assert.equal(fs.readFileSync(path.join(outputs[0], "devtools.json"), "utf8"), "stale");
});
