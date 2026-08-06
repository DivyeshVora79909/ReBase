#!/usr/bin/env node

const assert = require("node:assert/strict");
const required = ["SURREAL_ENDPOINT", "SURREAL_USER", "SURREAL_PASS", "SURREAL_NAMESPACE", "SURREAL_DATABASE"];
for (const name of required) if (!process.env[name]) throw new Error(`Missing ${name}`);

async function sql(query, token, allowErrors = false) {
  const response = await fetch(`${process.env.SURREAL_ENDPOINT.replace(/\/$/, "")}/sql`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: token ? `Bearer ${token}` : `Basic ${Buffer.from(`${process.env.SURREAL_USER}:${process.env.SURREAL_PASS}`).toString("base64")}`,
      "Content-Type": "text/plain",
      "surreal-ns": process.env.SURREAL_NAMESPACE,
      "surreal-db": process.env.SURREAL_DATABASE,
    },
    body: query,
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`SurrealDB HTTP ${response.status}: ${body}`);
  const statements = JSON.parse(body);
  const failures = statements.filter((statement) => statement.status !== "OK");
  if (failures.length && !allowErrors) throw new Error(JSON.stringify(failures.slice(0, 3)));
  return statements;
}

async function signin(email, password) {
  const response = await fetch(`${process.env.SURREAL_ENDPOINT.replace(/\/$/, "")}/signin`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ NS: process.env.SURREAL_NAMESPACE, DB: process.env.SURREAL_DATABASE, AC: "account", email, password }),
  });
  const result = await response.json();
  if (!response.ok || !result.token) throw new Error(`Record signin failed: ${JSON.stringify(result)}`);
  return result.token;
}

function resultOf(statements, index = -1) {
  return statements.at(index).result;
}

async function run() {
  const prefix = "rebase_verify";
  const ids = {
    team: `groups:${prefix}_team`,
    sub: `groups:${prefix}_sub`,
    alice: `user:${prefix}_alice`,
    bob: `user:${prefix}_bob`,
  };

  await sql(`
    DELETE ${ids.bob};
    DELETE ${ids.sub};
    DELETE ${ids.alice};
    DELETE ${ids.team};
    CREATE ${ids.team} SET name = 'Verify Team', role = ['node_select'], parents = [user:root];
    CREATE ${ids.alice} SET name = 'Verify Alice', email = '${prefix}_alice@example.com', parents = [${ids.team}], password = crypto::argon2::generate('verify-password');
    CREATE ${ids.sub} SET name = 'Verify Sub', role = [], parents = [${ids.alice}];
    CREATE ${ids.bob} SET name = 'Verify Bob', email = '${prefix}_bob@example.com', parents = [${ids.sub}], password = crypto::argon2::generate('verify-password');
  `);

  const state = await sql(`
    SELECT id, parents, parent_groups, permissions, dominates FROM [user:root, ${ids.alice}, ${ids.bob}];
    SELECT id, parents, role, dominates FROM [groups:root, ${ids.team}, ${ids.sub}];
  `);
  const users = resultOf(state, 0);
  const groups = resultOf(state, 1);
  const alice = users.find((record) => record.id === ids.alice);
  const bob = users.find((record) => record.id === ids.bob);
  const root = users.find((record) => record.id === "user:root");
  const team = groups.find((record) => record.id === ids.team);

  assert.deepEqual(alice.parent_groups, [ids.team]);
  assert.ok(alice.permissions.includes("node_select"));
  assert.deepEqual(bob.permissions, []);
  assert.ok(alice.dominates.includes(ids.sub));
  assert.ok(alice.dominates.includes(ids.bob));
  assert.ok(team.dominates.includes(ids.bob));
  assert.ok(root.dominates.includes(ids.team));

  await sql(`UPDATE ${ids.team} SET role += ['node_update'];`);
  const propagated = resultOf(await sql(`SELECT id, permissions FROM [${ids.alice}, ${ids.bob}];`));
  assert.ok(propagated.find((record) => record.id === ids.alice).permissions.includes("node_update"));
  assert.ok(!propagated.find((record) => record.id === ids.bob).permissions.includes("node_update"));

  const cycle = await sql(`UPDATE ${ids.team} SET parents = [${ids.bob}];`, undefined, true);
  assert.equal(cycle[0].status, "ERR", "descendant-as-parent cycle must be rejected");
  const teamAfterCycle = resultOf(await sql(`SELECT parents FROM ONLY ${ids.team};`));
  assert.deepEqual(teamAfterCycle.parents, ["user:root"]);

  const aliceToken = await signin(`${prefix}_alice@example.com`, "verify-password");
  const aliceVisible = resultOf(await sql(`SELECT id FROM groups WHERE id = ${ids.team};`, aliceToken));
  assert.equal(aliceVisible.length, 1);

  const bobToken = await signin(`${prefix}_bob@example.com`, "verify-password");
  const bobVisible = resultOf(await sql(`SELECT id FROM groups WHERE id = ${ids.team};`, bobToken));
  assert.equal(bobVisible.length, 0, "permissions must not be inherited from grandparent groups");

  console.log("ReBase runtime verification passed: DAG propagation, immediate permissions, cycle rejection, and record auth.");
}

run().catch((error) => {
  console.error(`ReBase runtime verification failed: ${error.message}`);
  process.exitCode = 1;
});
