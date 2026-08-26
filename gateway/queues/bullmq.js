const IORedis = require("ioredis");
const { Queue, Worker } = require("bullmq");
const {
  LANES,
  assertLane,
  assertLocator,
  locatorKey,
  normalizeDecision,
  scheduleKey,
} = require("./port");

const DEFAULT_POLICIES = Object.freeze({
  task: { attempts: 5, backoffMs: 1000, concurrency: 8 },
  schedule: { attempts: 8, backoffMs: 1000, concurrency: 2 },
  webhook: { attempts: 5, backoffMs: 1000, concurrency: 4 },
});

function redisOptions(options = {}) {
  return {
    enableReadyCheck: true,
    connectTimeout: options.connectTimeoutMs || 5000,
    maxRetriesPerRequest: null,
    ...(options.redisOptions || {}),
  };
}

async function withDeadline(operation, timeoutMs, message) {
  let timer;
  try {
    return await Promise.race([
      operation(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function createConnection(options = {}) {
  if (options.connection) return { connection: options.connection, owned: false };
  const url = options.url;
  if (!url) throw new Error("BullMQ requires a Redis URL");
  const connection = new IORedis(url, redisOptions(options));
  connection.on("error", (error) => options.onError?.(error));
  return { connection, owned: true };
}

function policyFor(options, lane) {
  return {
    ...DEFAULT_POLICIES[lane],
    ...(options.policies?.[lane] || {}),
  };
}

async function replaceFinished(queue, jobId) {
  const existing = await queue.getJob(jobId);
  if (!existing) return null;
  const state = await existing.getState();
  if (["completed", "failed"].includes(state)) {
    await existing.remove().catch(() => {});
    return null;
  }
  return { job: existing, state };
}

function createBullMqPort(options = {}) {
  const prefix = options.prefix || "rebase";
  const { connection, owned } = createConnection(options);
  const queues = new Map(LANES.map((lane) => [
    lane,
    new Queue(lane, { connection, prefix }),
  ]));
  const deadLetters = new Map(LANES.map((lane) => [
    lane,
    new Queue(`${lane}-dead`, { connection, prefix }),
  ]));
  const workers = new Map();
  let closed = false;

  function queueFor(lane) {
    return queues.get(assertLane(lane));
  }

  async function publish(lane, locator, publishOptions = {}) {
    if (closed) throw new Error("BullMQ queue is closed");
    const normalized = assertLocator(locator);
    const queue = queueFor(lane);
    const policy = policyFor(options, lane);
    const jobId = publishOptions.jobId ? `m-${scheduleKey(publishOptions.jobId)}` : locatorKey(normalized);
    const existing = await replaceFinished(queue, jobId);
    if (existing) return { jobId, duplicate: true, state: existing.state };
    const requestedDelay = Number(publishOptions.delayMs || 0);
    if (!Number.isFinite(requestedDelay) || requestedDelay < 0) {
      throw new Error("BullMQ delivery delay must be a finite non-negative number");
    }
    const delay = Math.max(0, Math.floor(requestedDelay));
    const job = await queue.add("delivery", normalized, {
      jobId,
      delay,
      attempts: publishOptions.attempts || policy.attempts,
      backoff: { type: "rebase" },
      priority: publishOptions.priority,
      removeOnComplete: { age: 3600, count: 1000 },
      removeOnFail: { age: 7 * 86400, count: 5000 },
    });
    return { jobId: job.id, duplicate: false };
  }

  async function deadLetter(lane, job, decision) {
    await deadLetters.get(lane).add("dead-letter", {
      locator: assertLocator(job.data),
      sourceJobId: job.id,
      attempts: job.attemptsMade + 1,
      reason: decision.reason,
      failedAt: new Date().toISOString(),
    }, {
      jobId: `${job.id}-${job.attemptsMade + 1}`,
      removeOnComplete: { age: 30 * 86400, count: 10000 },
    });
  }

  async function enqueueDeadLetter(lane, job, decision) {
    try {
      await deadLetter(lane, job, decision);
      return true;
    } catch (error) {
      options.onError?.(error);
      return false;
    }
  }

  const deadLetteredJobs = new Set();

  async function start(lane, consumer) {
    if (closed) throw new Error("BullMQ queue is closed");
    assertLane(lane);
    if (typeof consumer !== "function") throw new Error(`${lane} consumer must be a function`);
    if (workers.has(lane)) throw new Error(`${lane} BullMQ worker already started`);
    const policy = policyFor(options, lane);
    const worker = new Worker(lane, async (job, token) => {
      const decision = normalizeDecision(await consumer({
        attempts: job.attemptsMade + 1,
        maxAttempts: job.opts.attempts || policy.attempts,
        jobId: job.id,
        lane,
        locator: assertLocator(job.data),
        receivedAt: new Date().toISOString(),
      }));
      if (decision.action === "dead-letter") {
        if (!await enqueueDeadLetter(lane, job, decision)) {
          const error = new Error("ReBase dead-letter delivery failed");
          error.code = "REBASE_DLQ_UNAVAILABLE";
          throw error;
        }
        return { deadLettered: true, reason: decision.reason };
      }
      if (decision.action === "retry") {
        const error = new Error("ReBase delivery requested retry");
        error.code = "REBASE_QUEUE_RETRY";
        error.rebaseDelayMs = decision.delayMs;
        throw error;
      }
      return { acknowledged: true };
    }, {
      connection,
      prefix,
      concurrency: policy.concurrency,
      lockDuration: options.lockDurationMs || 30000,
      settings: {
        backoffStrategy(attemptsMade, type, error) {
          if (type !== "rebase") return policy.backoffMs;
          const requested = Number(error?.rebaseDelayMs);
          if (Number.isFinite(requested) && requested >= 0) return Math.floor(requested);
          return Math.min(policy.backoffMs * (2 ** Math.max(0, attemptsMade - 1)), 300000);
        },
      },
    });
    worker.on("error", (error) => options.onError?.(error));
    worker.on("failed", async (job, error) => {
      options.onFailed?.({ lane, job, error });
      if (!job || job.attemptsMade < (job.opts.attempts || policy.attempts)) return;
      const key = `${lane}:${job.id}:${job.attemptsMade}`;
      if (deadLetteredJobs.has(key)) return;
      deadLetteredJobs.add(key);
      if (deadLetteredJobs.size > 10000) deadLetteredJobs.delete(deadLetteredJobs.values().next().value);
      try {
        await enqueueDeadLetter(lane, job, { action: "dead-letter", reason: error?.code || "QUEUE_RETRY_EXHAUSTED" });
      } catch (deadLetterError) {
        options.onError?.(deadLetterError);
      }
    });
    try {
      await withDeadline(
        () => worker.waitUntilReady(),
        options.startupTimeoutMs || 10000,
        `${lane} BullMQ worker startup timed out`,
      );
    } catch (error) {
      await worker.close(true).catch(() => {});
      throw error;
    }
    workers.set(lane, worker);
    return async () => {
      const current = workers.get(lane);
      if (current !== worker) return;
      workers.delete(lane);
      await worker.close();
    };
  }

  async function schedule(key, locator, dueAt, scheduleOptions = {}) {
    if (closed) throw new Error("BullMQ queue is closed");
    const date = new Date(dueAt);
    if (Number.isNaN(date.getTime())) throw new Error("Schedule dueAt must be a valid datetime");
    const requestedAttempts = scheduleOptions.attempts == null ? policyFor(options, "schedule").attempts : Number(scheduleOptions.attempts);
    if (!Number.isSafeInteger(requestedAttempts) || requestedAttempts < 1) {
      throw new Error("Schedule attempts must be a positive integer");
    }
    const jobId = `s-${scheduleKey(key)}-${date.getTime()}`;
    const queue = queueFor("schedule");
    const existing = await replaceFinished(queue, jobId);
    if (existing) return { jobId, duplicate: true, state: existing.state };
    const policy = policyFor(options, "schedule");
    const job = await queue.add("schedule", assertLocator(locator), {
      jobId,
      delay: Math.max(0, date.getTime() - Date.now()),
      attempts: requestedAttempts,
      backoff: { type: "rebase" },
      removeOnComplete: { age: 3600, count: 1000 },
      removeOnFail: { age: 7 * 86400, count: 5000 },
    });
    return { jobId: job.id, duplicate: false };
  }

  async function removeSchedule(key) {
    const prefixId = `s-${scheduleKey(key)}-`;
    const jobs = await queueFor("schedule").getJobs(["wait", "delayed", "prioritized"]);
    const matching = jobs.filter((job) => String(job.id).startsWith(prefixId));
    await Promise.all(matching.map((job) => job.remove().catch(() => {})));
    return matching.length > 0;
  }

  async function health() {
    try {
      const pong = await withDeadline(
        () => connection.ping(),
        options.healthTimeoutMs || 2000,
        "Redis health check timed out",
      );
      const lanes = {};
      for (const [lane, worker] of workers) lanes[lane] = worker.isRunning();
      const deadLetterCounts = {};
      await Promise.all([...deadLetters].map(async ([lane, queue]) => {
        deadLetterCounts[lane] = await withDeadline(
          () => queue.getJobCounts("wait", "active", "delayed", "failed"),
          options.healthTimeoutMs || 2000,
          `${lane} dead-letter health check timed out`,
        );
      }));
      return {
        ok: pong === "PONG" && !closed,
        provider: "bullmq",
        lanes,
        deadLetters: { ok: true, counts: deadLetterCounts },
        prefix,
      };
    } catch (error) {
      return { ok: false, provider: "bullmq", error: error.message, lanes: {}, deadLetters: { ok: false }, prefix };
    }
  }

  async function close() {
    if (closed) return;
    closed = true;
    await Promise.all([...workers.values()].map((worker) => worker.close()));
    workers.clear();
    await Promise.all([...queues.values(), ...deadLetters.values()].map((queue) => queue.close()));
    if (owned) await connection.quit().catch(() => connection.disconnect());
  }

  return {
    provider: "bullmq",
    prefix,
    publish,
    start,
    schedule,
    removeSchedule,
    async reconcile() { return health(); },
    health,
    close,
    queues,
    deadLetters,
    connection,
  };
}

module.exports = { DEFAULT_POLICIES, createBullMqPort, withDeadline };
