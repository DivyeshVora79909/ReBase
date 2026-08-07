#!/usr/bin/env node

const fs = require("node:fs");
const { performance } = require("node:perf_hooks");

let endpoint;
let namespace;
let database;
let scales;
let memberships;
let samples;
let batchSize;
let outputPath;

async function sql(query, token) {
  const response = await fetch(`${endpoint}/sql`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: token ? `Bearer ${token}` : `Basic ${Buffer.from(`${process.env.SURREAL_USER}:${process.env.SURREAL_PASS}`).toString("base64")}`,
      "Content-Type": "text/plain",
      "surreal-ns": namespace,
      "surreal-db": database,
    },
    body: query,
  });
  const body = await response.text();
  if (!response.ok) throw new Error(`SurrealDB HTTP ${response.status}: ${body}`);
  const statements = JSON.parse(body);
  const failures = statements.filter((statement) => statement.status !== "OK");
  if (failures.length) throw new Error(JSON.stringify(failures.slice(0, 3)));
  return statements;
}

async function signin(email, password) {
  const response = await fetch(`${endpoint}/signin`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ NS: namespace, DB: database, AC: "account", email, password }),
  });
  const result = await response.json();
  if (!response.ok || !result.token) throw new Error(`Record signin failed: ${JSON.stringify(result)}`);
  return result.token;
}

const resultOf = (statements, index = -1) => statements.at(index).result;
const percentile = (sorted, value) => sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * value) - 1)];
const summarize = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    minMs: Number(sorted[0].toFixed(3)),
    p50Ms: Number(percentile(sorted, 0.5).toFixed(3)),
    p95Ms: Number(percentile(sorted, 0.95).toFixed(3)),
    maxMs: Number(sorted.at(-1).toFixed(3)),
  };
};

async function timeQuery(query, token) {
  const values = [];
  await sql(query, token);
  for (let index = 0; index < samples; index += 1) {
    const started = performance.now();
    await sql(query, token);
    values.push(performance.now() - started);
  }
  return summarize(values);
}

function buildIndexedPermissionQuery(accessKeyCount, explain = false) {
  const bindings = [];
  const branches = [];
  for (let index = 0; index < accessKeyCount; index += 1) {
    bindings.push(`LET $rebase_access_${index} = $auth.z_access_index[${index}];`);
    branches.push(`readers_index CONTAINS $rebase_access_${index}`);
  }
  return `${bindings.join("\n")}\nSELECT id FROM rebase_bench_resource WHERE (${branches.join(" OR ")}) LIMIT 50${explain ? " EXPLAIN FULL" : ""};`;
}

async function run() {
  const required = ["SURREAL_ENDPOINT", "SURREAL_USER", "SURREAL_PASS", "SURREAL_NAMESPACE", "SURREAL_DATABASE"];
  for (const name of required) if (!process.env[name]) throw new Error(`Missing ${name}`);
  endpoint = process.env.SURREAL_ENDPOINT.replace(/\/$/, "");
  namespace = process.env.SURREAL_NAMESPACE;
  database = process.env.SURREAL_DATABASE;
  scales = (process.env.REBASE_BENCHMARK_SCALES || "10000").split(",").map(Number);
  memberships = (process.env.REBASE_BENCHMARK_MEMBERSHIPS || "1,10,100").split(",").map(Number);
  samples = Number(process.env.REBASE_BENCHMARK_SAMPLES || 10);
  batchSize = Number(process.env.REBASE_BENCHMARK_BATCH_SIZE || 1000);
  outputPath = process.env.REBASE_BENCHMARK_OUTPUT;
  if ([...scales, ...memberships, samples, batchSize].some((value) => !Number.isInteger(value) || value < 1)) throw new Error("Benchmark values must be positive integers");

  const maxMembership = Math.max(...memberships);
  const groupIds = Array.from({ length: maxMembership }, (_, index) => `groups:rebase_bench_${index}`);
  await sql(`
    DELETE user:rebase_bench_user;
    ${[...groupIds].reverse().map((id) => `DELETE ${id};`).join("\n")}
    REMOVE TABLE IF EXISTS rebase_bench_resource;
    DEFINE TABLE rebase_bench_resource SCHEMAFULL PERMISSIONS
      FOR select WHERE 'rebase_bench_select' IN $auth.permissions AND readers_index CONTAINSANY $auth.z_access_index
      FOR create, update, delete NONE;
    DEFINE FIELD category ON rebase_bench_resource TYPE string;
    DEFINE FIELD score ON rebase_bench_resource TYPE int;
    DEFINE FIELD owned_by ON rebase_bench_resource TYPE record<user | groups>;
    DEFINE FIELD readers ON rebase_bench_resource TYPE array<record<user | groups>> VALUE [$this.owned_by];
    DEFINE FIELD readers_index ON rebase_bench_resource TYPE array<string> VALUE $this.readers.map(|$reader| <string>$reader);
    DEFINE INDEX rebase_bench_readers ON rebase_bench_resource FIELDS readers_index.*;
    DEFINE INDEX rebase_bench_owned_by ON rebase_bench_resource FIELDS owned_by;
    DEFINE INDEX rebase_bench_category_score ON rebase_bench_resource FIELDS category, score;
    ${groupIds.map((id) => `CREATE ${id} SET name = 'Benchmark', role = ['rebase_bench_select'], parents = [user:root];`).join("\n")}
    CREATE user:rebase_bench_user SET name = 'Benchmark User', email = 'rebase_benchmark@example.com', parents = [${groupIds.join(", ")}], password = crypto::argon2::generate('benchmark-password');
  `);

  const results = [];
  let inserted = 0;
  for (const scale of [...scales].sort((a, b) => a - b)) {
    while (inserted < scale) {
      const start = inserted;
      const end = Math.min(scale - 1, start + batchSize - 1);
      await sql(`FOR $i IN ${start}..=${end} { CREATE type::record('rebase_bench_resource', <string>$i) SET category = 'category_' + <string>($i % 20), score = $i, owned_by = IF ($i % 2) = 0 THEN user:rebase_bench_user ELSE type::record('groups', 'rebase_bench_' + <string>($i % ${maxMembership})) END; };`);
      inserted = end + 1;
    }
    if (resultOf(await sql("SELECT count() AS total FROM rebase_bench_resource GROUP ALL;"))[0].total !== scale) throw new Error(`Expected ${scale} benchmark rows`);

    for (const membership of memberships) {
      await sql(`UPDATE user:rebase_bench_user SET parents = [${groupIds.slice(0, membership).join(", ")}];`);
      const token = await signin("rebase_benchmark@example.com", "benchmark-password");
      const native = [
        ["permission_native_dynamic", "SELECT id FROM rebase_bench_resource WHERE readers_index CONTAINSANY $auth.z_access_index LIMIT 50;", null],
        ["permission_filter_sort_native", "SELECT id, category, score FROM rebase_bench_resource WHERE readers_index CONTAINSANY $auth.z_access_index AND category = 'category_1' ORDER BY score DESC LIMIT 50;", "rebase_bench_category_score"],
      ];
      for (const [name, query, expectedIndex] of native) {
        const plan = resultOf(await sql(query.replace(/;$/, " EXPLAIN FULL;"), token));
        const text = JSON.stringify(plan);
        results.push({ case: name, rows: scale, memberships: membership, returnedRows: resultOf(await sql(query, token)).length, expectedIndex, usesExpectedIndex: expectedIndex ? text.includes(expectedIndex) : false, usesIndexScan: text.includes("IndexScan"), usesTableScan: text.includes("TableScan"), timing: await timeQuery(query, token), plan });
      }
      const accessKeyCount = membership + 1; // authenticated user + immediate parent groups
      const indexed = buildIndexedPermissionQuery(accessKeyCount);
      const plan = resultOf(await sql(buildIndexedPermissionQuery(accessKeyCount, true), token));
      const text = JSON.stringify(plan);
      results.push({ case: "permission_indexed_or", rows: scale, memberships: membership, returnedRows: resultOf(await sql(indexed, token)).length, expectedIndex: "rebase_bench_readers", usesExpectedIndex: text.includes("rebase_bench_readers"), usesIndexScan: text.includes("IndexScan"), usesTableScan: text.includes("TableScan"), timing: await timeQuery(indexed, token), plan });
    }
  }

  const report = JSON.stringify({ generatedAt: new Date().toISOString(), endpoint, namespace, database, surrealVersion: "3.2.x", maximumRows: Math.max(...scales), samplesPerCase: samples, results }, null, 2) + "\n";
  if (outputPath) fs.writeFileSync(outputPath, report);
  console.log(outputPath ? `Report: ${outputPath}` : report);
  if (results.some((r) => r.case === "permission_indexed_or" && (r.usesTableScan || !r.usesIndexScan || !r.usesExpectedIndex)) || results.some((r) => r.case === "permission_filter_sort_native" && (r.usesTableScan || !r.usesExpectedIndex))) process.exitCode = 1;
}

if (require.main === module) run().catch((error) => { console.error(`Permission benchmark failed: ${error.message}`); process.exitCode = 1; });

module.exports = { buildIndexedPermissionQuery };
