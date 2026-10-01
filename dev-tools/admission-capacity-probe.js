const assert = require("node:assert/strict");
const { fork, spawn } = require("node:child_process");
const { once } = require("node:events");
const crypto = require("node:crypto");
const net = require("node:net");
const { createBullMqPort } = require("../gateway/queues/bullmq");
const { workEnvelopeKey } = require("../gateway/queues/port");

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const makeEnvelope = (id) => ({
  version: 1,
  kind: "operation",
  locator: { namespace: "audit", database: "admission", id: `task:${id}` },
  executionId: crypto.randomUUID(),
  revision: crypto.randomUUID(),
});
const portOptions = (url, prefix) => ({
  url,
  prefix,
  admission: { maxLiveHints: 2, receiptReserve: 0 },
});

async function messageWithTimeout(child, timeoutMs = 10000) {
  let timer;
  try {
    return await Promise.race([
      once(child, "message").then(([message]) => message),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Producer process timed out")), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitForExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  let timer;
  try {
    await Promise.race([
      once(child, "exit"),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Producer did not exit after termination")), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

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

async function waitFor(predicate, message, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await sleep(10);
  }
  throw new Error(message);
}

async function producer(url, prefix) {
  const port = createBullMqPort(portOptions(url, prefix));
  process.send({ stage: "producer-started" });
  const add = port.queue.add.bind(port.queue);
  port.queue.add = async (...args) => {
    process.send({ stage: "before-atomic-add" });
    await new Promise((resolve) => process.once("message", resolve));
    return add(...args);
  };
  try {
    const result = await port.publish(makeEnvelope("paused-producer"));
    process.send({ stage: "result", result });
  } catch (error) {
    process.send({ stage: "producer-error", message: error.message, stack: error.stack });
    throw error;
  } finally {
    await port.close();
    process.disconnect();
  }
}

async function main() {
  if (process.argv[2] === "producer") {
    await producer(process.argv[3], process.argv[4]);
    return;
  }

  const portNumber = await reservePort();
  const redis = spawn("redis-server", [
    "--bind", "127.0.0.1", "--port", String(portNumber), "--save", "", "--appendonly", "no",
  ], { stdio: "ignore" });
  const url = `redis://127.0.0.1:${portNumber}`;
  const prefix = `rebase-admission-race-${crypto.randomUUID()}`;
  let port;
  let child;
  let abandoned;

  try {
    await waitForRedis(portNumber);
    port = createBullMqPort(portOptions(url, prefix));
    child = fork(__filename, ["producer", url, prefix], {
      stdio: ["ignore", "inherit", "inherit", "ipc"],
    });
    const started = await messageWithTimeout(child);
    assert.equal(started.stage, "producer-started");
    const paused = await messageWithTimeout(child);
    assert.equal(paused.stage, "before-atomic-add", paused.message || paused.stack);

    const firstEnvelope = makeEnvelope("other-producer-1");
    const first = await port.publish(firstEnvelope);
    const delayedEnvelope = makeEnvelope("other-producer-2");
    const second = await port.publish(delayedEnvelope, { delayMs: 120000 });
    assert.equal(first.queued, true);
    assert.equal(second.queued, true);
    assert.equal((await port.health()).liveHints, 2);

    const pendingResult = messageWithTimeout(child);
    child.send({ resume: true });
    const completed = await pendingResult;
    assert.equal(completed.stage, "result");
    assert.deepEqual(completed.result, {
      jobId: completed.result.jobId,
      queued: false,
      state: "capacity",
      live: 2,
      limit: 2,
    });
    assert.equal((await port.health()).liveHints, 2,
      "an admission paused before Redis insertion must not exceed the shared cap");

    const duplicate = await port.publish(firstEnvelope);
    assert.equal(duplicate.duplicate, true,
      "an existing job ID remains an idempotent duplicate when the queue is full");
    const duplicateAtScript = await port.queue.add("delivery", firstEnvelope, {
      jobId: workEnvelopeKey(firstEnvelope),
      priority: 50,
    });
    assert.equal(duplicateAtScript.id, workEnvelopeKey(firstEnvelope),
      "BullMQ's atomic duplicate path must run before the capacity guard");

    const delayedJob = await port.queue.getJob(workEnvelopeKey(delayedEnvelope));
    await delayedJob.remove();
    const stopWorker = await port.start(async () => ({ action: "ack" }));
    await waitFor(async () => {
      const job = await port.queue.getJob(workEnvelopeKey(firstEnvelope));
      return job && await job.getState() === "completed";
    }, "completion fixture did not finish");
    await stopWorker();
    const readmitted = await port.publish(firstEnvelope);
    assert.equal(readmitted.queued, true,
      "a completed retained job must be removed before the same hint can be admitted again");
    assert.equal((await port.health()).liveHints, 1);

    abandoned = fork(__filename, ["producer", url, prefix, "abandoned"], {
      stdio: ["ignore", "inherit", "inherit", "ipc"],
    });
    assert.equal((await messageWithTimeout(abandoned)).stage, "producer-started");
    assert.equal((await messageWithTimeout(abandoned)).stage, "before-atomic-add");
    abandoned.kill("SIGKILL");
    await waitForExit(abandoned);
    const afterDeath = await port.publish(makeEnvelope("after-abandoned-producer"));
    assert.equal(afterDeath.queued, true,
      "a producer killed before the atomic insert must leave no admission reservation");
    assert.equal((await port.health()).liveHints, 2);

    console.log("admission: atomic cap, delayed/prioritized entries, duplicate, completion/re-add, and producer-death recovery passed");
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      if (child.connected) child.send({ resume: true });
      child.kill("SIGTERM");
    }
    if (abandoned && abandoned.exitCode === null && abandoned.signalCode === null) {
      if (abandoned.connected) abandoned.send({ resume: true });
      abandoned.kill("SIGTERM");
    }
    if (port) await port.close();
    if (redis.exitCode === null && redis.signalCode === null) {
      const stopped = once(redis, "exit");
      redis.kill("SIGTERM");
      await stopped;
    }
  }
}

main().catch((error) => {
  console.error(`admission: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
