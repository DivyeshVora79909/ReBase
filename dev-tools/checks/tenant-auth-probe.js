#!/usr/bin/env node
"use strict";

// Real record-token checks against a disposable database. No app profiles,
// production data, provider calls, or browser authenticator are involved.
const assert = require("node:assert/strict");
const { loadMaterials } = require("../compiler/materials");
const { generateBundle } = require("../compiler/pipeline");
const path = require("node:path");
const { start, client, applySchema } = require("../temporal-tree/harness");

async function signIn(url, tenant, identifier, password = "tenant-probe-password") {
  const response = await fetch(`${url}/signin`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ ns: "temporal_probe", db: "fixture", ac: "account_password", tenant, identifier, password }),
  });
  const body = await response.json();
  return body.token || null;
}

async function main() {
  const server = await start();
  const q = client(server.url);
  const failures = [];
  const reject = async (sql, pattern = /ERR_|TREE_DUPLICATE_VALUE|assert|readonly|unique|already|exist|permission/i) => {
    let error;
    try { await q(sql); } catch (caught) { error = caught; }
    assert(error, `Mutation must fail: ${sql}`);
    assert.match(error.message, pattern);
    failures.push(sql.split(" ").slice(0, 3).join(" "));
  };
  try {
    await q("DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;");
    const materials = loadMaterials({ groups: [{ name: 'framework', roots: [path.join(__dirname, '../../framework')] }] });
    await applySchema(q, generateBundle(materials).bundle);
    await q(`
      CREATE rebase_tenant:a SET name = 'Tenant A';
      CREATE rebase_tenant:b SET name = 'Tenant B';
      CREATE rebase_user:admin SET name = 'Admin A', username = 'admin_user', parents = [rebase_tenant:a],
        password = crypto::argon2::generate('tenant-probe-password');
      CREATE rebase_user:peer SET name = 'Peer A', parents = [rebase_tenant:a];
      CREATE rebase_user:other SET name = 'Admin B', username = 'admin_user', parents = [rebase_tenant:b],
        password = crypto::argon2::generate('tenant-probe-password');
      CREATE authentication_email:a SET owned_by = rebase_user:admin, address = 'same@example.com';
      CREATE authentication_email:b SET owned_by = rebase_user:other, address = 'same@example.com';
      UPDATE [authentication_email:a, authentication_email:b] SET verified_revision = revision;
      CREATE rebase_group:left SET name = 'Left', parents = [rebase_user:admin];
      CREATE rebase_group:right SET name = 'Right', parents = [rebase_user:admin];
      CREATE rebase_user:leaf SET name = 'Leaf', parents = [rebase_group:left, rebase_group:right];
      CREATE rebase_group:tail SET name = 'Tail', parents = [rebase_user:leaf];
    `);

    const admin = await q("RETURN (SELECT * FROM rebase_user:admin)[0];");
    assert.equal(admin.tenant, "rebase_tenant:a");
    assert.deepEqual(admin.parent_groups, ["rebase_tenant:a"]);
    assert.equal(admin.permissions.includes("node_delete"), true);
    assert.equal("dominates" in admin, false);
    assert.equal("z_access_index" in admin, false);
    const token = await signIn(server.url, "rebase_tenant:a", "same@example.com");
    const otherToken = await signIn(server.url, "rebase_tenant:b", "same@example.com");
    assert(token && otherToken);
    assert.equal(await signIn(server.url, "rebase_tenant:missing", "same@example.com"), null);
    assert.equal(await signIn(server.url, undefined, "same@example.com"), null);
    const actor = client(server.url, "fixture", token);
    const other = client(server.url, "fixture", otherToken);
    assert.equal(await actor("RETURN <string>$auth;"), "rebase_user:admin");
    assert.equal(await other("RETURN <string>$auth;"), "rebase_user:other");
    assert.equal((await actor("SELECT * FROM rebase_user:leaf;")).length, 1);
    assert.equal((await actor("SELECT * FROM rebase_user:other;")).length, 0);
    assert.equal((await actor("SELECT * FROM authentication_email:b;")).length, 0);
    assert.equal((await actor("SELECT * FROM rebase_access;")).every(row => row.in === "rebase_user:admin"), true);
    await actor("CREATE rebase_group:native SET name='Native group',parents=[rebase_user:admin];");
    await actor("CREATE rebase_user:native SET name='Native user',parents=[rebase_group:native];");
    assert.equal(await q("RETURN rebase_user:native.tenant;"), "rebase_tenant:a");
    await actor("CREATE authentication_phone:native SET owned_by=rebase_user:admin,number='+12345678901';");
    assert.equal(await q("RETURN authentication_phone:native.tenant;"), "rebase_tenant:a");
    const generatedTenant = (await q("CREATE rebase_tenant SET name='Generated ID';"))[0];
    assert.match(generatedTenant.id, /^rebase_tenant:u'[0-9a-f-]{14}7[0-9a-f-]+'$/);

    await q(`CREATE rebase_group:limited SET name='Limited',parents=[rebase_tenant:a],role=['node_create'];
      CREATE rebase_user:limited SET name='Limited',parents=[rebase_group:limited],password=crypto::argon2::generate('tenant-probe-password');
      CREATE authentication_email:limited SET owned_by=rebase_user:limited,address='limited@example.test';
      UPDATE authentication_email:limited SET verified_revision=revision;
      CREATE rebase_group:strong SET name='Strong',parents=[rebase_user:limited],role=['node_delete'];`);
    const limitedToken = await signIn(server.url, "rebase_tenant:a", "limited@example.test");
    const limited = client(server.url, "fixture", limitedToken);
    assert.deepEqual(await limited("SELECT * FROM rebase_group:limited;"), []);
    await limited("CREATE rebase_user:without_node_select SET name='Inherited',parents=[rebase_group:limited];");
    assert.equal(await q("RETURN rebase_user:without_node_select.tenant;"), "rebase_tenant:a");
    await assert.rejects(limited("CREATE rebase_user:escalated SET name='Escalated',parents=[rebase_group:strong];"), /ERR_PRIVILEGE_ESCALATION/);
    await limited("CREATE rebase_user:tenant_admin SET name='Escalated',parents=[rebase_tenant:a];").catch(() => {});
    assert.equal(await q("RETURN record::exists(rebase_user:tenant_admin);"), false);
    await q("UPDATE rebase_group:limited SET role=[];");
    await limited("CREATE rebase_user:after_revocation SET name='Revoked',parents=[rebase_user:limited];").catch(() => {});
    assert.equal(await q("RETURN record::exists(rebase_user:after_revocation);"), false);

    await reject("CREATE rebase_group:empty SET name='Empty', parents=[];");
    await reject("CREATE rebase_user:empty SET name='Empty', parents=[];");
    await reject("CREATE rebase_group:mixed SET name='Mixed', parents=[rebase_user:admin,rebase_user:other];");
    await reject("UPDATE rebase_group:left SET parents=[rebase_user:other];");
    await reject("UPDATE rebase_user:admin SET tenant=rebase_tenant:b;");
    await reject("UPDATE rebase_group:left SET parents=[rebase_user:leaf];", /ERR_CYCLE/);
    await reject("CREATE authentication_email:duplicate SET owned_by=rebase_user:peer,address='same@example.com';");
    await reject("UPDATE authentication_email:a SET owned_by=rebase_user:other;");
    assert.deepEqual(await actor("UPDATE rebase_user:other SET name='Intruder';"), []);
    assert.deepEqual(await actor("RELATE rebase_user:admin->rebase_access:forged->rebase_user:other;"), []);
    assert.equal(await q("RETURN record::exists(rebase_access:forged);"), false);
    await assert.rejects(actor("RETURN fn::rebase::refresh_access(rebase_user:other,rebase_tenant:b);"), /permission|not allowed/i);

    // Alternate ancestry through right survives removal through left.
    await q("UPDATE rebase_group:left SET parents=[rebase_user:peer];");
    assert.equal(await actor("RETURN fn::rebase::dominates($auth,rebase_user:leaf);"), true);
    await q("UPDATE rebase_group:right SET parents=[rebase_user:peer];");
    assert.equal(await actor("RETURN fn::rebase::dominates($auth,rebase_user:leaf);"), false);
    assert.deepEqual(await actor("SELECT * FROM rebase_user:leaf;"), []);
    assert.deepEqual(await actor("SELECT * FROM rebase_group:tail;"), []);
    assert.equal(await q("RETURN fn::rebase::dominates(rebase_user:peer,rebase_group:tail);"), true);

    // Two mutually cyclic changes race from one snapshot. The tenant fence
    // must force a conflict or make the later cycle check reject the mutation.
    await q(`CREATE rebase_group:x SET name='X',parents=[rebase_user:admin];
      CREATE rebase_group:y SET name='Y',parents=[rebase_user:admin];`);
    const raced = await Promise.allSettled([
      q("UPDATE rebase_group:x SET parents=[rebase_group:y];"),
      q("UPDATE rebase_group:y SET parents=[rebase_group:x];"),
    ]);
    assert(raced.some(result => result.status === "rejected"));
    const cycle = await q("RETURN fn::rebase::dominates(rebase_group:x,rebase_group:y) AND fn::rebase::dominates(rebase_group:y,rebase_group:x);");
    assert.equal(cycle, false);

    await q("DELETE rebase_group:tail;");
    assert.deepEqual(await q("SELECT * FROM rebase_access WHERE out=rebase_group:tail;"), []);

    // Compare stored closure against an independent in-memory graph walk.
    const rows = await q("RETURN array::concat((SELECT * FROM rebase_user),(SELECT * FROM rebase_group));");
    const parents = new Map(rows.map(row => [row.id, row.parents]));
    const expected = new Set();
    for (const row of rows) {
      const pending = [...row.parents];
      const visited = new Set();
      while (pending.length) {
        const ancestor = pending.pop();
        if (visited.has(ancestor)) continue;
        visited.add(ancestor);
        assert.notEqual(ancestor, row.id);
        expected.add(`${ancestor}|${row.id}`);
        pending.push(...(parents.get(ancestor) || []));
      }
    }
    const edges = await q("SELECT * FROM rebase_access;");
    assert.deepEqual(new Set(edges.map(edge => `${edge.in}|${edge.out}`)), expected);
    const plan = await q("SELECT * FROM rebase_access:[rebase_user:peer,rebase_user:leaf] EXPLAIN;");
    assert.match(JSON.stringify(plan), /RecordId|RecordStrategy|RecordScan/);
    const report = {
      tenantIsolation: true, scopedIdentityUniqueness: true, diamondRemoval: true,
      existingTokenRevocation: true, concurrentCycleRejected: true, protectedClosure: true,
      nativeCreatesWithoutNodeSelect: true, parentRoleEscalationRejected: true, defaultUuidV7: true,
      closurePairs: edges.length, rejectedInvalidMutations: failures.length, exactMembershipPlan: plan,
    };
    console.log(`tenant-auth: ${JSON.stringify(report)}`);
    return report;
  } finally { await server.close(); }
}

if (require.main === module) main().catch(error => {
  console.error(`tenant-auth: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
module.exports = { main, signIn };
