"use strict";
// Disposable on-disk SurrealKV only; never reads application environment profiles.
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { splitStatements } = require("../../src/surql");
const binary = process.env.REBASE_TREE_SURREAL_BIN || "surreal";

async function start({ engine = process.env.REBASE_TREE_STORAGE_ENGINE || "surrealkv" } = {}) {
  if (!/^[a-z]+$/.test(engine)) throw new Error(`Invalid storage engine: ${engine}`);
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, "127.0.0.1", resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-temporal-tree-"));
  const child = spawn(binary, ["start", `${engine}://${directory}`, "--bind", `127.0.0.1:${port}`,
    "--user", "root", "--pass", "root", "--no-banner", "--log", "error"], { stdio: ["ignore", "ignore", "pipe"] });
  let log = "";
  child.stderr.on("data", chunk => { log += chunk; });
  child.on("error", error => { log += error.message; });
  const url = `http://127.0.0.1:${port}`;
  const close = async ({ keepData = false } = {}) => {
    if (child.exitCode === null && !child.killed) {
      const closed = new Promise(resolve => child.once("exit", resolve));
      child.kill("SIGTERM");
      const timer = setTimeout(() => child.kill("SIGKILL"), 2000);
      await closed;
      clearTimeout(timer);
    }
    if (!keepData) fs.rmSync(directory, { recursive: true, force: true });
  };
  try {
    for (let i = 0; i < 150; i++) {
      if (child.exitCode !== null) throw new Error(log);
      try { if ((await fetch(`${url}/health`)).ok) return { url, close, directory, engine }; } catch {}
      await new Promise(resolve => setTimeout(resolve, 30));
    }
    throw new Error(`SurrealDB did not start: ${log}`);
  } catch (error) { await close(); throw error; }
}

function client(url, database = "fixture", token) {
  return async sql => {
    const response = await fetch(`${url}/sql`, {
      method: "POST", headers: {
        Authorization: token ? `Bearer ${token}` : `Basic ${Buffer.from("root:root").toString("base64")}`,
        "surreal-ns": "temporal_probe", "surreal-db": database, Accept: "application/json"
      }, body: sql
    });
    const body = await response.text();
    if (!response.ok) throw new Error(`SurrealDB HTTP ${response.status}: ${body}`);
    const results = JSON.parse(body);
    if (!response.ok || !Array.isArray(results)) throw new Error(JSON.stringify(results));
    const failed = results.filter(result => result.status !== "OK");
    // A transaction may report cancellation before its actual failing statement.
    if (failed.length) throw new Error(failed.map(result => result.result || JSON.stringify(result)).join('\n'));
    return results.at(-1)?.result;
  };
}

// Large typed profiles exceed /sql's default body limit. DDL is already executed
// statement by statement; split only at parser-recognized statement boundaries.
async function applySchema(q, sql) {
  let chunk = '';
  for (const statement of splitStatements(sql)) {
    if (chunk.length + statement.length > 256000 && chunk) { await q(chunk); chunk = ''; }
    chunk += statement + '\n';
  }
  if (chunk) await q(chunk);
}

function instant(value) {
  const fraction = value.match(/\.(\d+)Z$/)?.[1] || "";
  return BigInt(Date.parse(value.replace(/\.\d+Z$/, "Z"))) * 1000000n + BigInt(fraction.padEnd(9, "0"));
}

function compareKey(a, b) {
  const left = [instant(a[0]), ...a.slice(1)];
  const right = [instant(b[0]), ...b.slice(1)];
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] < right[i]) return -1;
    if (left[i] > right[i]) return 1;
  }
  return left.length - right.length;
}

function compareIntKey(a, b) {
  if (!Number.isSafeInteger(a[0]) || !Number.isSafeInteger(b[0])) throw new Error('Expected safe integer keys');
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

const identity = link => `${link.rid}/${link.slot}`;


module.exports = { start, client, applySchema, compareKey, compareIntKey, instant };
