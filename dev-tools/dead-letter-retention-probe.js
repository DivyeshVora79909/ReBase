const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const crypto = require("node:crypto");
const net = require("node:net");
const { createBullMqPort } = require("../gateway/queues/bullmq");

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const envelope = (id) => ({
  version: 1,
  kind: "operation",
  locator: { namespace: "audit", database: "retention", id: `task:${id}` },
  executionId: crypto.randomUUID(),
  revision: crypto.randomUUID(),
});

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForRedis(port) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    const ready = await new Promise((resolve) => {
      const client = net.createConnection({ host: "127.0.0.1", port });
      client.once("connect", () => { client.destroy(); resolve(true); });
      client.once("error", () => { client.destroy(); resolve(false); });
    });
    if (ready) return;
    await sleep(20);
  }
  throw new Error("Disposable Redis did not become ready");
}

async function waitFor(predicate, message, timeoutMs = 4000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await sleep(10);
  }
  throw new Error(message);
}

function options(url, prefix) {
  return {
    url,
    prefix,
    admission: { maxLiveHints: 50, receiptReserve: 5 },
    deadLetterRetentionMs: 80,
    deadLetterPruneIntervalMs: 15,
    deadLetterPruneBatchSize: 2,
  };
}

async function main() {
  const portNumber = await reservePort();
  const redis = spawn("redis-server", [
    "--bind", "127.0.0.1", "--port", String(portNumber), "--save", "", "--appendonly", "no",
  ], { stdio: "ignore" });
  const url = `redis://127.0.0.1:${portNumber}`;
  const prefix = `rebase-dead-letter-retention-${crypto.randomUUID()}`;
  const durableFailures = new Set();
  let primary;
  let peer;
  let restarted;

  try {
    await waitForRedis(portNumber);
    primary = createBullMqPort(options(url, prefix));
    peer = createBullMqPort(options(url, prefix));
    await waitFor(async () => (await primary.health()).ok, "queue did not become ready");
    await primary.start(async ({ envelope: failedEnvelope }) => {
      durableFailures.add(failedEnvelope.locator.id);
      return { action: "dead-letter", reason: "RETENTION_PROBE" };
    });

    const firstBatch = await Promise.all(Array.from({ length: 6 }, (_, index) => {
      const source = envelope(`first-${index}`);
      return (index % 2 ? peer : primary).publish(source, { attempts: 1 });
    }));
    assert(firstBatch.every((result) => result.queued));
    await waitFor(async () => {
      const counts = await primary.deadLetterQueue.getJobCounts("wait");
      return Number(counts.wait || 0) === firstBatch.length;
    }, "multiple producers did not create the expected diagnostic records");
    assert.equal(durableFailures.size, firstBatch.length,
      "the durable failure outcomes are recorded before diagnostic pruning");

    await waitFor(async () => {
      const counts = await primary.deadLetterQueue.getJobCounts("wait");
      return Number(counts.wait || 0) === 0;
    }, "periodic pruning did not remove expired waiting dead letters");
    assert.equal(durableFailures.size, firstBatch.length,
      "pruning Redis diagnostics must preserve the durable failure record");

    const restartSource = envelope("after-prune-restart");
    assert.equal((await peer.publish(restartSource, { attempts: 1 })).queued, true);
    await waitFor(async () => {
      const counts = await primary.deadLetterQueue.getJobCounts("wait");
      return Number(counts.wait || 0) === 1;
    }, "restart fixture was not dead-lettered");
    await Promise.all([primary.close(), peer.close()]);
    primary = null;
    peer = null;

    await sleep(120);
    restarted = createBullMqPort(options(url, prefix));
    await waitFor(async () => {
      const counts = await restarted.deadLetterQueue.getJobCounts("wait");
      return Number(counts.wait || 0) === 0;
    }, "startup pruning did not remove expired diagnostics after restart");
    assert.equal(durableFailures.size, firstBatch.length + 1,
      "restart pruning must leave all durable failure outcomes intact");

    console.log("dead letters: bounded-age cleanup, batched repeated failures, multiple producers, restart pruning, and durable outcomes passed");
  } finally {
    await Promise.all([primary, peer, restarted].filter(Boolean).map((port) => port.close()));
    if (redis.exitCode === null && redis.signalCode === null) {
      const stopped = once(redis, "exit");
      redis.kill("SIGTERM");
      await stopped;
    }
  }
}

main().catch((error) => {
  console.error(`dead letters: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
