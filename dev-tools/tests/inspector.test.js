"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { palette, schemaElements, accessElements, validateCatalog, validateAccess } = require("../inspector/graph");
const { buildInspector } = require("../inspector/build");
const { connectAccess, readAccess } = require("../inspector/access");

function catalog() {
  const field = (name, targets, extra = {}) => ({
    name, type: "record", kind: "input", generated: false,
    reference: { targets, many: false, optional: false, unrestricted: false }, ...extra,
  });
  return {
    format: "rebase-devtools", version: 1, project: "example", functions: [], monoid: {},
    tables: [
      { name: "root", kind: "table", group: "project", fields: [], indexes: [] },
      { name: "alternate", kind: "table", group: "project", fields: [], indexes: [] },
      { name: "isolated", kind: "table", group: "project", fields: [], indexes: [] },
      { name: "child", kind: "table", group: "project", fields: [
        field("parent", ["root", "alternate"]), field("self", ["child"]),
        field("private_parent", ["root"], { generated: true }), field("owned_by", ["root"], { generated: true }),
      ], indexes: [], dependencies: {
        calculations: [], references: [{ table: "root", reference: "parent", fields: ["rate"], consumers: ["amount"] }],
        queries: [{ field: "q_price", operation: "latest", phase: "refresh", sources: [{ table: "root", root: "prices" }] }],
      } },
    ],
    roots: [{ id: "root.prices", table: "root", field: "prices", key: ["datetime"], unique: false, members: ["child.point"] }],
    memberships: [{ id: "child.point", table: "child", field: "point", roots: ["root.prices"], key: ["datetime"], reader: false }],
  };
}

test("colors are reproducible, independent of input order and spaced around the full hue circle", () => {
  const names = ["alpha", "beta", "gamma", "delta", "epsilon"];
  const first = palette(names, "seed");
  assert.deepEqual(first, palette([...names].reverse(), "seed"));
  const hues = [...first.values()].map(color => color.hue).sort((a, b) => a - b);
  for (let index = 0; index < hues.length; index++) {
    const gap = (hues[(index + 1) % hues.length] - hues[index] + 360) % 360;
    assert(Math.abs(gap - 72) < .002);
  }
  assert.notDeepEqual(first, palette(names, "another-seed"));
  const source = catalog();
  for (const layer of ["references", "calculations", "memberships", "access"]) {
    const nodes = schemaElements(source, { layer }).nodes;
    assert.equal(nodes.find(node => node.data.id === "child").data.color,
      schemaElements(source).nodes.find(node => node.data.id === "child").data.color);
  }
});

test("graph preserves polymorphic alternatives, self references and disconnected tables", () => {
  const source = validateCatalog(catalog());
  const graph = schemaElements(source);
  assert.equal(graph.nodes.length, 4);
  assert(graph.nodes.some(node => node.data.id === "isolated"));
  assert.deepEqual(graph.edges.map(edge => [edge.data.source, edge.data.target, edge.data.field]), [
    ["root", "child", "parent"], ["alternate", "child", "parent"], ["child", "child", "self"],
  ]);
  assert(schemaElements(source, { technical: true }).edges.some(edge => edge.data.field === "private_parent"));
  assert.deepEqual(schemaElements(source, { layer: "access" }).edges.map(edge => edge.data.field), ["owned_by"]);
  source.tables[3].fields.push({ name: "anything", type: "record", kind: "input", reference: { targets: [], unrestricted: true } });
  assert(schemaElements(source).nodes.some(node => node.data.id === "*"));
});

test("calculations and memberships preserve their distinct directions and field identities", () => {
  const source = catalog();
  const calculations = schemaElements(source, { layer: "calculations" });
  assert.deepEqual(calculations.edges.map(edge => [edge.data.kind, edge.data.source, edge.data.target, edge.data.field]), [
    ["scalar", "root", "child", "amount"], ["query", "root", "child", "q_price"],
  ]);
  assert.deepEqual(calculations.edges[0].data.sourceFields, ["rate"]);
  const membership = schemaElements(source, { layer: "memberships" }).edges[0].data;
  assert.equal(membership.source, "child");
  assert.equal(membership.target, "root");
  assert.equal(membership.sourceField, "point");
  assert.equal(membership.field, "prices");
});

test("access snapshots show direct edges, multiple parents and unloaded boundaries without inventing closure", () => {
  const tenant = "rebase_tenant:one";
  const source = validateAccess({ format: "rebase-access", version: 1, tenant, truncated: true, records: [
    { id: tenant, table: "rebase_tenant", tenant, parents: [] },
    { id: "rebase_group:a", table: "rebase_group", tenant, parents: [tenant] },
    { id: "rebase_user:b", table: "rebase_user", tenant, parents: ["rebase_group:a", "rebase_group:unloaded"] },
  ] });
  const graph = accessElements(source);
  assert.equal(graph.nodes.length, 4);
  assert.equal(graph.edges.length, 3);
  assert.equal(graph.nodes.find(node => node.data.id === "rebase_group:unloaded").data.kind, "external");
  assert(!graph.edges.some(edge => edge.data.source === tenant && edge.data.target === "rebase_user:b"));
  assert.throws(() => validateAccess({ ...source, records: [...source.records, { ...source.records[1], tenant: "rebase_tenant:other" }] }), /cross-tenant/);
});

test("unsupported and malformed files fail instead of becoming empty graphs", () => {
  assert.throws(() => validateCatalog({ tables: [] }), /devtools.json/);
  const source = catalog();
  source.tables.push(source.tables[0]);
  assert.throws(() => validateCatalog(source), /repeated table/);
  const nested = catalog();
  nested.tables[3].dependencies.queries[0].sources = null;
  assert.throws(() => validateCatalog(nested), /dependency metadata/);
  const tree = catalog();
  tree.memberships[0].roots = ["missing.root"];
  assert.throws(() => validateCatalog(tree), /Unknown tree root/);
  assert.throws(() => validateAccess({ format: "rebase-access", version: 1, records: [] }), /snapshot/);
});

test("standalone HTML embeds inert JSON without script termination or replacement-string expansion", () => {
  const source = catalog();
  const text = "</script><script>globalThis.untrusted = 1</script> $& $' $";
  source.functions.push({ name: "fn::example", body: text });
  const html = buildInspector(source);
  const embedded = html.match(/<script id="rebase-catalog" type="application\/json">([\s\S]*?)<\/script>/)[1];
  assert.deepEqual(JSON.parse(embedded), source);
  assert(!embedded.includes("<script>"));
  assert(!/<script[^>]+src=/.test(html));
  assert(!/<link[^>]+href=/.test(html));
});

test("access reads validate limits and propagate every native statement error", async () => {
  await assert.rejects(connectAccess({ endpoint: "https://example.test" }), /ws:\/\//);
  await assert.rejects(readAccess(null, "rebase_tenant:one", 0), /limit/);
  const db = { query: () => ({ json: () => ({ responses: async () => [
    { success: false, error: new Error("first statement rejected") },
    { success: true, result: [] },
  ] }) }) };
  await assert.rejects(readAccess(db, "rebase_tenant:one"), /first statement rejected/);
});
