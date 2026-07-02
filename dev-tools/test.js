const DB_URL = "http://127.0.0.1:8000/sql";
const HEADERS = {
  Accept: "application/json",
  "surreal-ns": "test",
  "surreal-db": "test",
  Authorization: "Basic " + btoa("root:root"),
};

async function execHttp(sql) {
  const res = await fetch(DB_URL, {
    method: "POST",
    headers: HEADERS,
    body: sql,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function setup() {
  console.log("Resetting database...");
  await execHttp(`
    REMOVE TABLE IF EXISTS node_a;
    REMOVE TABLE IF EXISTS node_b;
    CREATE node_a:global SET multiplier = 10;
    CREATE node_b:target SET value = 0;
  `);
}

// Worker 1: The Victim (Reads A, writes B)
async function worker1() {
  const sql = `
    BEGIN TRANSACTION;
    -- 1. Read Node A (Adds node_a:global to the Read Set)
    LET $mult = (SELECT VALUE multiplier FROM ONLY node_a:global);
    
    -- 2. Sleep to simulate heavy processing, allowing Worker 2 to attack
    sleep(500ms);
    
    -- 3. Write Node B based on what we read from Node A
    UPDATE node_b:target SET value = 100 * $mult;
    COMMIT TRANSACTION;
  `;
  try {
    const res = await execHttp(sql);
    const commitStatus = res[res.length - 1];
    if (commitStatus.status === "ERR") {
      console.log(`❌ Worker 1 Failed on Commit: ${commitStatus.result}`);
    } else {
      console.log(`✅ Worker 1 Succeeded!`);
    }
  } catch (e) {
    console.log(`❌ Worker 1 Error: ${e.message}`);
  }
}

// Worker 2: The Attacker (Updates A while Worker 1 is sleeping)
async function worker2() {
  const sql = `
    BEGIN TRANSACTION;
    sleep(100ms); -- Wait just long enough for Worker 1 to read the old value
    -- Mutate Node A!
    UPDATE node_a:global SET multiplier = 999;
    COMMIT TRANSACTION;
  `;
  try {
    await execHttp(sql);
    console.log(`😈 Worker 2 Successfully Mutated Node A!`);
  } catch (e) {
    console.log(`❌ Worker 2 Error: ${e.message}`);
  }
}

async function main() {
  await setup();
  console.log("Launching race condition...\n");

  // Run them concurrently
  await Promise.all([worker1(), worker2()]);

  console.log("\nChecking Final State:");
  const stateA = await execHttp(
    "SELECT VALUE multiplier FROM ONLY node_a:global;",
  );
  const stateB = await execHttp("SELECT VALUE value FROM ONLY node_b:target;");

  console.log(`Node A Multiplier: ${stateA[0].result}`);
  console.log(`Node B Value     : ${stateB[0].result}`);
}

main();
