"use strict";

// Authorization fixtures for a disposable database compiled by fixture.js.
// This module never reads application profiles or opens a privileged connection.
const assert = require("node:assert/strict");
const { performance } = require("node:perf_hooks");
const { Surreal, RecordId } = require("surrealdb");

const principal = name => new RecordId("rebase_user", name);
const group = name => new RecordId("rebase_group", name);
const text = value => String(value);
const sorted = values => values.map(text).sort();

// Independent source-graph oracle: no closure relation or DB permission helpers.
function dominates(graph, actor, target) {
  actor = text(actor); target = text(target);
  if (actor === target) return false;
  const pending = [...(graph.parents.get(target) || [])], seen = new Set();
  while (pending.length) {
    const parent = pending.pop();
    if (parent === actor) return true;
    if (seen.has(parent)) continue;
    seen.add(parent);
    pending.push(...(graph.parents.get(parent) || []));
  }
  return false;
}

function canAccess(graph, actor, target) {
  actor = text(actor); target = text(target);
  return actor === target
    || (graph.parents.get(actor) || []).some(parent => parent === target
      && /^(rebase_group|rebase_tenant):/.test(parent))
    || dominates(graph, actor, target);
}

function permissions(graph, actor) {
  return new Set((graph.parents.get(text(actor)) || [])
    .filter(parent => /^(rebase_group|rebase_tenant):/.test(parent))
    .flatMap(parent => graph.roles.get(parent) || []));
}

function chooseReader(graph, candidates, fallback) {
  return candidates.filter(candidate => candidate != null).reduce((chosen, candidate) =>
    chosen == null || dominates(graph, chosen, candidate) ? text(candidate) : chosen, null) ?? text(fallback);
}

function expectedVisible(graph, actor, rows, { table, selectPolicy = "readers" } = {}) {
  const actorId = text(actor), tenant = graph.tenants.get(actorId);
  const allowed = permissions(graph, actorId);
  return rows.filter(row => allowed.has(`${table || row.table}_select`)
    && text(row.tenant ?? graph.tenants.get(text(row.owned_by))) === tenant
    && canAccess(graph, actorId, selectPolicy === "owner" ? row.owned_by : row.read_by ?? row.owned_by));
}

async function seedGraph(db, { width = 32 } = {}) {
  if (!Number.isSafeInteger(width) || width < 2 || width > 256) throw new Error("width must be from 2 to 256");
  const tenant = new RecordId("rebase_tenant", "bench_a");
  const foreignTenant = new RecordId("rebase_tenant", "bench_b");
  const [allPermissions] = await db.query("RETURN fn::rebase::tenant_permissions();");
  assert(Array.isArray(allPermissions) && allPermissions.includes("auth_report_select"),
    "Compile auth_anchor and auth_report before seeding authorization fixtures");
  const graph = { tenant, foreignTenant, parents: new Map(), tenants: new Map(), roles: new Map(),
    actors: {}, owners: [], shapes: {}, ids: {}, width };
  for (const [id, name] of [[tenant, "Authorization stress A"], [foreignTenant, "Authorization stress B"]]) {
    await db.query("CREATE $id CONTENT $content;", { id, content: { name } });
    graph.parents.set(text(id), []); graph.tenants.set(text(id), text(id));
    graph.roles.set(text(id), [...allPermissions]);
  }
  async function create(id, parents, tenantId, role) {
    await db.query("CREATE $id CONTENT $content;", {
      id, content: { name: text(id), parents, ...(role === undefined ? {} : { role }) },
    });
    graph.parents.set(text(id), parents.map(text)); graph.tenants.set(text(id), text(tenantId));
    if (role !== undefined) graph.roles.set(text(id), [...role]);
    return id;
  }
  const role = await create(group("bench_role"), [tenant], tenant, allPermissions);
  const foreignRole = await create(group("bench_role_b"), [foreignTenant], foreignTenant, allPermissions);
  const limitedRole = await create(group("bench_role_limited"), [tenant], tenant, ["node_select"]);
  const hiddenRole = await create(group("bench_hidden_role"), [tenant], tenant,
    ["auth_report_select", "auth_report_create", "auth_report_update", "auth_report_delete"]);
  Object.assign(graph.ids, { role, foreignRole, limitedRole, hiddenRole });
  const manager = await create(principal("bench_manager"), [role], tenant);
  const stranger = await create(principal("bench_stranger"), [role], tenant);
  graph.actors.wide = manager;
  graph.actors.outsider = await create(principal("bench_outsider"), [role], tenant);
  graph.actors.crossTenant = await create(principal("bench_other"), [foreignRole], foreignTenant);
  graph.actors.missingPermission = await create(principal("bench_limited"), [limitedRole], tenant);
  graph.actors.groupOnly = await create(principal("bench_group_only"), [hiddenRole], tenant);
  graph.ids.stranger = stranger;
  for (let index = 0; index < width; index++) {
    graph.owners.push(await create(principal(`bench_o${index}`),
      [index < Math.ceil(width / 2) ? manager : stranger, role], tenant));
  }
  graph.actors.sparse = graph.owners[0];

  // Small control-plane graphs are separate from bulk owners. Reparenting these
  // never fans out through a million-row stress dataset.
  const admin = await create(principal("bench_case_admin"), [role], tenant);
  graph.actors.caseAdmin = admin;
  graph.actors.alpha = await create(principal("bench_alpha"), [admin, role], tenant);
  graph.actors.beta = await create(principal("bench_beta"), [admin, role], tenant);
  graph.ids.shared = await create(group("bench_shared"), [admin], tenant, []);
  const chain = [];
  for (let index = 0; index < 8; index++) {
    chain.push(await create(principal(`bench_chain_${index}`), [chain.at(-1) || admin, role], tenant));
  }
  graph.shapes.chain = chain; graph.actors.chainRoot = chain[0];
  const balanced = [];
  for (let index = 0; index < 15; index++) {
    balanced.push(await create(principal(`bench_balanced_${index}`),
      [index ? balanced[Math.floor((index - 1) / 2)] : admin, role], tenant));
  }
  graph.shapes.balanced = balanced;
  graph.actors.balancedRoot = balanced[0];
  const starRoot = await create(principal("bench_star"), [admin, role], tenant);
  const star = [];
  for (let index = 0; index < 32; index++) {
    star.push(await create(principal(`bench_star_${index}`), [starRoot, role], tenant));
  }
  graph.shapes.star = { root: starRoot, leaves: star };
  graph.actors.starRoot = starRoot;
  const diamondRoot = await create(principal("bench_diamond"), [admin, role], tenant);
  const diamondPeer = await create(principal("bench_diamond_peer"), [admin, role], tenant);
  const left = await create(principal("bench_left"), [diamondRoot, role], tenant);
  const right = await create(principal("bench_right"), [diamondRoot, role], tenant);
  const leaf = await create(principal("bench_leaf"), [left, right, role], tenant);
  graph.shapes.diamond = { root: diamondRoot, peer: diamondPeer, left, right, leaf };
  graph.actors.diamondRoot = diamondRoot; graph.actors.diamondPeer = diamondPeer;

  // A credential-free access method belongs only in this disposable experiment.
  // No application account/sign-in/provider configuration is used or modified.
  await db.query(`DEFINE ACCESS bench_actor ON DATABASE TYPE RECORD
    SIGNIN {
      IF $id = NONE { RETURN NONE; };
      LET $principal = type::record($id);
      IF record::tb($principal) != 'rebase_user' { RETURN NONE; };
      RETURN $principal;
    }
    AUTHENTICATE { RETURN $auth; }
    DURATION FOR SESSION 1h, FOR TOKEN 1h;`);
  return graph;
}

async function actorConnection(endpoint, id, { namespace = "temporal_probe", database = "fixture" } = {}) {
  const url = new URL(endpoint);
  if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new Error("Authorization stress actor connections require a disposable loopback endpoint");
  }
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  if (!["ws:", "wss:"].includes(url.protocol)) throw new Error("Unsupported disposable endpoint protocol");
  if (url.pathname === "/") url.pathname = "/rpc";
  const db = new Surreal();
  try {
    await db.connect(url.toString());
    await db.signin({ namespace, database, access: "bench_actor", variables: { id: text(id) } });
    return db;
  } catch (error) { await db.close(); throw error; }
}

async function authorizationCases(db, endpoint, graph, context = {}) {
  const clients = {}, facts = new Map(), cases = [], timings = {};
  let assertions = 0;
  const equal = (actual, expected, message) => { assert.deepEqual(actual, expected, message); assertions++; };
  const actors = ["caseAdmin", "alpha", "beta", "chainRoot", "balancedRoot", "starRoot", "diamondRoot", "diamondPeer",
    "wide", "sparse", "outsider", "crossTenant", "missingPermission", "groupOnly"];
  async function run(name, action) {
    const began = performance.now();
    await action();
    timings[name] = performance.now() - began; cases.push(name);
  }
  async function add(table, name, owned_by, anchors = []) {
    const id = new RecordId(table, `bench_${name}`);
    const content = { owned_by, title: name, ...(table === "auth_report" ? { anchors } : {}) };
    await db.query("CREATE $id CONTENT $content;", { id, content });
    facts.set(text(id), { id, table, tenant: graph.tenants.get(text(owned_by)), ...content });
    return id;
  }
  function expected(row) {
    const candidates = row.table === "auth_report" ? row.anchors.map(id => facts.get(text(id)).owned_by) : [];
    return { ...row, read_by: chooseReader(graph, candidates, row.owned_by) };
  }
  async function check() {
    for (const table of ["auth_anchor", "auth_report"]) {
      const rows = [...facts.values()].filter(row => row.table === table).map(expected);
      const [materialized] = await db.query(`SELECT id, read_by FROM ${table} ORDER BY id;`);
      equal(materialized.map(row => [text(row.id), text(row.read_by)]).sort(),
        rows.map(row => [text(row.id), row.read_by]).sort(), `${table}: reader VALUE matches source oracle`);
      for (const name of actors) {
        const [actual] = await clients[name].query(`SELECT VALUE id FROM ${table} ORDER BY id;`);
        equal(sorted(actual), sorted(expectedVisible(graph, graph.actors[name], rows, { table }).map(row => row.id)),
          `${name}: ${table} visible set matches independent graph oracle`);
      }
    }
  }
  async function parents(id, next) {
    await db.query("UPDATE $id SET parents=$parents;", { id, parents: next });
    graph.parents.set(text(id), next.map(text));
  }
  async function snapshot() {
    return db.query(["rebase_tenant", "rebase_user", "rebase_group", "rebase_access", "auth_anchor", "auth_report", "audit_mutation"]
      .map(table => `SELECT * FROM ${table} WITH NOINDEX ORDER BY id;`).join("\n"));
  }
  async function reject(sql, variables, pattern) {
    const before = await snapshot();
    await assert.rejects(db.query(sql, variables), pattern); assertions++;
    equal(await snapshot(), before, "Rejected mutation preserves principals, closure, sources, trees and audit");
  }
  async function closure() {
    const wanted = new Set();
    for (const target of graph.parents.keys()) {
      const pending = [...graph.parents.get(target)], seen = new Set();
      while (pending.length) {
        const ancestor = pending.pop();
        if (seen.has(ancestor)) continue;
        seen.add(ancestor); equal(ancestor === target, false, "Source graph stays acyclic");
        wanted.add(`${ancestor}|${target}`);
        pending.push(...(graph.parents.get(ancestor) || []));
      }
    }
    const [actual] = await db.query("SELECT in, out FROM rebase_access WHERE tenant IN $tenants;",
      { tenants: [graph.tenant, graph.foreignTenant] });
    equal(new Set(actual.map(row => `${row.in}|${row.out}`)), wanted, "Native closure equals independent source graph walk");
  }
  try {
    for (const name of actors) clients[name] = await actorConnection(endpoint, graph.actors[name], context);
    const a = graph.actors.alpha, b = graph.actors.beta, admin = graph.actors.caseAdmin;
    const role = graph.ids.role, shared = graph.ids.shared, diamond = graph.shapes.diamond;
    let anchorA, anchorB, report, diamondReport;
    await run("initial_graph_shapes_and_reader_selection", async () => {
      anchorA = await add("auth_anchor", "anchor_a", a);
      anchorB = await add("auth_anchor", "anchor_b", b);
      report = await add("auth_report", "report", admin, [anchorA, anchorB]);
      await add("auth_report", "limited", graph.actors.missingPermission);
      await add("auth_report", "foreign", graph.actors.crossTenant);
      await add("auth_report", "chain", graph.shapes.chain.at(-1));
      await add("auth_report", "balanced", graph.shapes.balanced.at(-1));
      await add("auth_report", "star", graph.shapes.star.leaves.at(-1));
      diamondReport = await add("auth_report", "diamond", diamond.leaf);
      await check(); await closure();
      equal(chooseReader(graph, [a, b], admin), text(a), "First incomparable reader wins");
    });
    await run("reader_grant_does_not_grant_writes", async () => {
      const [updated] = await clients.alpha.query("UPDATE $id SET title='forbidden';", { id: report });
      equal(updated, [], "Inherited SELECT grants no UPDATE");
      const [persisted] = await db.query("SELECT VALUE title FROM $id;", { id: report });
      equal(persisted, ["report"], "Denied write preserves source");
    });
    await run("incomparable_reader_reorder", async () => {
      await db.query("UPDATE $id SET anchors=$anchors;", { id: report, anchors: [anchorB, anchorA] });
      facts.get(text(report)).anchors = [anchorB, anchorA];
      equal(expected(facts.get(text(report))).read_by, text(b), "Authored array order chooses incomparable reader");
      await check();
    });
    await run("underlying_owner_move", async () => {
      await db.query("UPDATE $id SET owned_by=$owner;", { id: anchorB, owner: a });
      facts.get(text(anchorB)).owned_by = a;
      await check();
      await db.query("UPDATE $id SET owned_by=$owner;", { id: anchorB, owner: b });
      facts.get(text(anchorB)).owned_by = b;
      await db.query("UPDATE $id SET anchors=$anchors;", { id: report, anchors: [anchorA, anchorB] });
      facts.get(text(report)).anchors = [anchorA, anchorB];
    });
    await run("reparent_grant_revoke_existing_and_fresh_sessions", async () => {
      await parents(b, [a, role]);
      equal(expected(facts.get(text(report))).read_by, text(b), "Later descendant replaces ancestor reader");
      await check();
      const fresh = await actorConnection(endpoint, b, context);
      try {
        const [freshRows] = await fresh.query("SELECT VALUE id FROM auth_report ORDER BY id;");
        const [oldRows] = await clients.beta.query("SELECT VALUE id FROM auth_report ORDER BY id;");
        equal(sorted(freshRows), sorted(oldRows), "Existing and fresh tokens observe graph grant");
      } finally { await fresh.close(); }
      await parents(b, [admin, role]); await check();
      const freshAfter = await actorConnection(endpoint, b, context);
      try {
        const [freshRows] = await freshAfter.query("SELECT VALUE id FROM auth_report ORDER BY id;");
        const [oldRows] = await clients.beta.query("SELECT VALUE id FROM auth_report ORDER BY id;");
        equal(sorted(freshRows), sorted(oldRows), "Existing and fresh tokens observe graph revocation");
        equal(oldRows.some(id => text(id) === text(report)), false, "Old reader grant is revoked");
      } finally { await freshAfter.close(); }
    });
    await run("direct_parent_group_access_and_delete_boundary", async () => {
      await parents(a, [admin, role, shared]); await parents(b, [admin, role, shared]);
      const groupReport = await add("auth_report", "shared", shared);
      await check();
      const [updated] = await clients.alpha.query("UPDATE $id SET title='group update';", { id: groupReport });
      equal(updated.length, 1, "Direct parent-group access grants ownership UPDATE");
      facts.get(text(groupReport)).title = "group update";
      const [deleted] = await clients.alpha.query("DELETE $id RETURN BEFORE;", { id: groupReport });
      equal(deleted, [], "Direct parent-group access alone grants no DELETE");
      const [exists] = await db.query("RETURN record::exists($id);", { id: groupReport });
      equal(exists, true, "Group-owned row survives denied DELETE");
    });
    await run("hidden_parent_group_without_node_select", async () => {
      const hiddenRole = graph.ids.hiddenRole, id = new RecordId("auth_report", "bench_hidden_parent");
      const content = { owned_by: hiddenRole, title: "Hidden parent", anchors: [] };
      equal((await clients.groupOnly.query("SELECT * FROM $id;", { id: hiddenRole }))[0], [],
        "No node_select means the parent group itself is hidden");
      const [created] = await clients.groupOnly.query("CREATE $id CONTENT $content;", { id, content });
      equal(created.length, 1, "Business CREATE derives tenant through accessible but hidden parent group");
      facts.set(text(id), { id, table: "auth_report", tenant: text(graph.tenant), ...content });
      equal((await clients.groupOnly.query("UPDATE $id SET title='Hidden parent updated';", { id }))[0].length,
        1, "Parent-group business UPDATE does not require node_select");
      facts.get(text(id)).title = "Hidden parent updated";
      equal((await clients.groupOnly.query("DELETE $id RETURN BEFORE;", { id }))[0], [],
        "Hidden direct parent group still grants no DELETE");
      await check();
    });
    await run("diamond_alternate_path_and_last_path_revocation", async () => {
      await parents(diamond.left, [diamond.peer, role]);
      equal(canAccess(graph, diamond.root, diamond.leaf), true, "Alternate diamond path survives");
      await check(); await closure();
      await parents(diamond.right, [diamond.peer, role]);
      equal(canAccess(graph, diamond.root, diamond.leaf), false, "Removing final path revokes access");
      await check(); await closure();
      const [rows] = await clients.diamondRoot.query("SELECT VALUE id FROM $id;", { id: diamondReport });
      equal(rows, [], "Existing diamond root token loses the leaf row");
    });
    await run("role_revocation_same_token", async () => {
      // Use a private role for a dedicated user so no bulk actor loses grants.
      const privateRole = group("bench_revocable_role"), revocable = principal("bench_revocable");
      const grants = ["node_select", "auth_report_select"];
      await db.query("CREATE $id CONTENT $content;", { id: privateRole,
        content: { name: "Revocable role", parents: [graph.tenant], role: grants } });
      graph.parents.set(text(privateRole), [text(graph.tenant)]); graph.tenants.set(text(privateRole), text(graph.tenant));
      graph.roles.set(text(privateRole), grants);
      await db.query("CREATE $id CONTENT $content;", { id: revocable,
        content: { name: "Revocable actor", parents: [privateRole] } });
      graph.parents.set(text(revocable), [text(privateRole)]); graph.tenants.set(text(revocable), text(graph.tenant));
      const own = await add("auth_report", "revocable", revocable);
      const session = await actorConnection(endpoint, revocable, context);
      try {
        equal((await session.query("SELECT VALUE id FROM $id;", { id: own }))[0].length, 1, "Role initially grants SELECT");
        await db.query("UPDATE $id SET role=[];", { id: privateRole }); graph.roles.set(text(privateRole), []);
        equal((await session.query("SELECT VALUE id FROM $id;", { id: own }))[0], [], "Existing token observes role revocation");
      } finally { await session.close(); }
    });
    await run("rejected_cycle_cross_tenant_and_forged_closure_rollback", async () => {
      await reject("UPDATE $id SET parents=$parents;", { id: graph.shapes.chain[0],
        parents: [graph.shapes.chain.at(-1), role] }, /ERR_CYCLE/);
      await reject("UPDATE $id SET parents=$parents;", { id: b, parents: [graph.ids.foreignRole] }, /TENANT|assert/i);
      const foreignAnchor = await add("auth_anchor", "foreign_anchor", graph.actors.crossTenant);
      await reject("UPDATE $id SET anchors=$anchors;", { id: report, anchors: [foreignAnchor] }, /TENANT|assert/i);
      const before = await snapshot();
      const edge = new RecordId("rebase_access", [graph.actors.outsider, a]);
      await clients.outsider.query("RELATE $actor->$edge->$target;", { actor: graph.actors.outsider, edge, target: a });
      equal(await snapshot(), before, "Record clients cannot forge closure pairs");
      await assert.rejects(clients.outsider.query("RETURN fn::rebase::refresh_access($id,$tenant);",
        { id: a, tenant: graph.tenant }), /permission|not allowed/i); assertions++;
      await check(); await closure();
    });
    await run("concurrent_cycle_changes_serialize", async () => {
      const left = principal("bench_race_left"), right = principal("bench_race_right");
      for (const id of [left, right]) {
        await db.query("CREATE $id CONTENT $content;", { id,
          content: { name: text(id), parents: [admin, role] } });
        graph.parents.set(text(id), [text(admin), text(role)]);
        graph.tenants.set(text(id), text(graph.tenant));
      }
      const [before] = await db.query("RETURN $tenant.authorization_revision;", { tenant: graph.tenant });
      const changes = [{ id: left, parents: [right, role] }, { id: right, parents: [left, role] }];
      const outcomes = await Promise.allSettled(changes.map(change =>
        db.query("UPDATE $id SET parents=$parents;", change)));
      equal(outcomes.some(outcome => outcome.status === "rejected"), true,
        "Conflicting opposite parent edits cannot both commit");
      for (let index = 0; index < outcomes.length; index++) {
        if (outcomes[index].status === "fulfilled") {
          graph.parents.set(text(changes[index].id), changes[index].parents.map(text));
        }
      }
      const [after] = await db.query("RETURN $tenant.authorization_revision;", { tenant: graph.tenant });
      equal(Number(after) - Number(before), outcomes.filter(outcome => outcome.status === "fulfilled").length,
        "Only committed graph edits advance the tenant fence");
      for (const id of [left, right]) {
        const [stored] = await db.query("SELECT VALUE parents FROM $id;", { id });
        equal(sorted(stored[0]), sorted(graph.parents.get(text(id))), "Rejected concurrent edit leaves its source unchanged");
      }
      equal(dominates(graph, left, right) && dominates(graph, right, left), false,
        "Independent source graph remains acyclic after the race");
      await check(); await closure();
    });
    return { assertions, cases, timings, graphShapes: { chainDepth: 8, balancedNodes: 15,
      starWidth: 32, diamond: true, bulkOwnerWidth: graph.width },
    scope: "Native record sessions and independent source-graph oracle in the caller's disposable database" };
  } finally { await Promise.all(Object.values(clients).map(client => client.close())); }
}

module.exports = { seedGraph, actorConnection, authorizationCases, dominates, canAccess, permissions, chooseReader, expectedVisible };
