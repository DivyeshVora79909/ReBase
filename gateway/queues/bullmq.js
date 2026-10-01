const crypto = require("node:crypto");
const IORedis = require("ioredis");
const { Queue, Worker } = require("bullmq");
const {
  createAtomicAdmissionBackendFactory,
  parseCapacityResult,
} = require("./atomic-admission");
const {
  assertPriority,
  assertWorkEnvelope,
  normalizeDecision,
  workEnvelopeKey,
} = require("./port");

const DEFAULT_POLICY = Object.freeze({ attempts: 5, backoffMs: 1000, concurrency: 8 });
const DEFAULT_ADMISSION = Object.freeze({ maxLiveHints: 1000, receiptReserve: 100 });
const DEFAULT_DEAD_LETTER_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_DEAD_LETTER_PRUNE_INTERVAL_MS = 60 * 1000;
const DEFAULT_DEAD_LETTER_PRUNE_BATCH_SIZE = 1000;

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
  if (!options.url) throw new Error("BullMQ requires a Redis URL");
  const connection = new IORedis(options.url, redisOptions(options));
  connection.on("error", (error) => options.onError?.(error));
  return { connection, owned: true };
}

function createBullMqPort(options = {}) {
  const prefix = options.prefix || "rebase";
  const policy = { ...DEFAULT_POLICY, ...(options.policy || {}) };
  const admission = { ...DEFAULT_ADMISSION, ...(options.admission || {}) };
  if (!Number.isSafeInteger(admission.maxLiveHints) || admission.maxLiveHints < 2) {
    throw new Error("BullMQ maxLiveHints must be an integer of at least two");
  }
  if (!Number.isSafeInteger(admission.receiptReserve) || admission.receiptReserve < 0
    || admission.receiptReserve >= admission.maxLiveHints) {
    throw new Error("BullMQ receiptReserve must be below maxLiveHints");
  }
  const deadLetterRetentionMs = options.deadLetterRetentionMs ?? DEFAULT_DEAD_LETTER_RETENTION_MS;
  const deadLetterPruneIntervalMs = options.deadLetterPruneIntervalMs ?? DEFAULT_DEAD_LETTER_PRUNE_INTERVAL_MS;
  const deadLetterPruneBatchSize = options.deadLetterPruneBatchSize ?? DEFAULT_DEAD_LETTER_PRUNE_BATCH_SIZE;
  if (!Number.isSafeInteger(deadLetterRetentionMs) || deadLetterRetentionMs < 1) {
    throw new Error("BullMQ deadLetterRetentionMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(deadLetterPruneIntervalMs) || deadLetterPruneIntervalMs < 1) {
    throw new Error("BullMQ deadLetterPruneIntervalMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(deadLetterPruneBatchSize) || deadLetterPruneBatchSize < 1) {
    throw new Error("BullMQ deadLetterPruneBatchSize must be a positive safe integer");
  }
  const { connection, owned } = createConnection(options);
  const queue = new Queue("operations", {
    connection,
    prefix,
  }, createAtomicAdmissionBackendFactory(admission));
  const deadLetterQueue = new Queue("operations-dead", { connection, prefix });
  const workers = new Set();
  let closed = false;
  let deadLetterPruneTimer;
  let deadLetterPrunePending = null;

  async function replaceFinished(jobId) {
    const existing = await queue.getJob(jobId);
    if (!existing) return null;
    const state = await existing.getState();
    if (["completed", "failed"].includes(state)) {
      await existing.remove().catch(() => {});
      return null;
    }
    return { job: existing, state };
  }

  async function liveCount() {
    const counts = await queue.getJobCounts("wait", "paused", "prioritized", "delayed", "active");
    return Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0);
  }

  async function publish(envelope, publishOptions = {}) {
    if (closed) throw new Error("BullMQ queue is closed");
    const normalized = assertWorkEnvelope(envelope);
    const jobId = workEnvelopeKey(normalized);
    const requestedDelay = Number(publishOptions.delayMs || 0);
    if (!Number.isFinite(requestedDelay) || requestedDelay < 0) {
      throw new Error("BullMQ delivery delay must be a finite non-negative number");
    }
    const delay = Math.max(0, Math.floor(requestedDelay));
    const priority = assertPriority(publishOptions.priority, normalized.kind);
    if (closed) throw new Error("BullMQ queue is closed");
    const existing = await replaceFinished(jobId);
    if (existing) return { jobId, duplicate: true, state: existing.state };
    const job = await queue.add("delivery", normalized, {
      jobId,
      delay,
      attempts: publishOptions.attempts || policy.attempts,
      backoff: { type: "rebase" },
      priority,
      removeOnComplete: { age: 3600, count: 1000 },
      removeOnFail: { age: 7 * 86400, count: 5000 },
    });
    const capacity = parseCapacityResult(job.id);
    if (capacity) {
      return { jobId, queued: false, state: "capacity", ...capacity };
    }
    return { jobId: job.id, queued: true, duplicate: false };
  }

  async function deadLetter(job, reason) {
    const data = {
      envelope: assertWorkEnvelope(job.data),
      sourceJobId: job.id,
      attempts: job.attemptsMade + 1,
      reason: String(reason || "QUEUE_RETRY_EXHAUSTED"),
      failedAt: new Date().toISOString(),
    };
    const deadId = `d-${crypto.createHash("sha256").update(`${job.id}:${data.attempts}`).digest("base64url")}`;
    await deadLetterQueue.add("dead-letter", data, {
      jobId: deadId,
      removeOnComplete: { age: 30 * 86400, count: 10000 },
    });
  }

  function pruneDeadLetters() {
    if (closed) return Promise.resolve(0);
    if (deadLetterPrunePending) return deadLetterPrunePending;
    deadLetterPrunePending = deadLetterQueue.clean(
      deadLetterRetentionMs,
      deadLetterPruneBatchSize,
      "wait",
    ).then((jobIds) => jobIds.length).catch((error) => {
      try {
        options.onError?.(error);
      } catch {
        // Cleanup reporting must not produce an unhandled rejection.
      }
      return 0;
    }).finally(() => {
      deadLetterPrunePending = null;
    });
    return deadLetterPrunePending;
  }

  function requestDeadLetterPrune() {
    void pruneDeadLetters();
  }

  deadLetterPruneTimer = setInterval(requestDeadLetterPrune, deadLetterPruneIntervalMs);
  deadLetterPruneTimer.unref?.();
  requestDeadLetterPrune();

  const deadLetteredJobs = new Set();

  async function start(consumer) {
    if (closed) throw new Error("BullMQ queue is closed");
    if (typeof consumer !== "function") throw new Error("Operation consumer must be a function");
    if (workers.size) throw new Error("BullMQ operation worker already started");
    const worker = new Worker("operations", async (job) => {
      const envelope = assertWorkEnvelope(job.data);
      const decision = normalizeDecision(await consumer({
        attempts: job.attemptsMade + 1,
        maxAttempts: job.opts.attempts || policy.attempts,
        jobId: job.id,
        envelope,
        kind: envelope.kind,
        locator: envelope.locator,
        receivedAt: new Date().toISOString(),
      }));
      if (decision.action === "dead-letter") {
        await deadLetter(job, decision.reason);
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
      options.onFailed?.({ job, error });
      if (!job || job.attemptsMade < (job.opts.attempts || policy.attempts)) return;
      const key = `${job.id}:${job.attemptsMade}`;
      if (deadLetteredJobs.has(key)) return;
      deadLetteredJobs.add(key);
      if (deadLetteredJobs.size > 10000) deadLetteredJobs.delete(deadLetteredJobs.values().next().value);
      try {
        await deadLetter(job, error?.code || "QUEUE_RETRY_EXHAUSTED");
      } catch (deadLetterError) {
        options.onError?.(deadLetterError);
      }
    });
    try {
      await withDeadline(
        () => worker.waitUntilReady(),
        options.startupTimeoutMs || 10000,
        "BullMQ operation worker startup timed out",
      );
    } catch (error) {
      await worker.close(true).catch(() => {});
      throw error;
    }
    workers.add(worker);
    return async () => {
      if (!workers.delete(worker)) return;
      await worker.close();
    };
  }

  async function health() {
    try {
      const pong = await withDeadline(
        () => connection.ping(),
        options.healthTimeoutMs || 2000,
        "Redis health check timed out",
      );
      const counts = await withDeadline(() => queue.getJobCounts("wait", "paused", "prioritized", "delayed", "active"), options.healthTimeoutMs || 2000, "Queue health check timed out");
      const deadLetterCounts = await withDeadline(() => deadLetterQueue.getJobCounts("wait", "active", "delayed", "failed"), options.healthTimeoutMs || 2000, "Dead-letter health check timed out");
      return {
        ok: pong === "PONG" && !closed,
        driver: "bullmq",
        worker: [...workers].some((worker) => worker.isRunning()),
        liveHints: Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0),
        admission: { ...admission },
        deadLetters: { ok: true, counts: deadLetterCounts },
        prefix,
      };
    } catch (error) {
      return { ok: false, driver: "bullmq", error: error.message, worker: false, deadLetters: { ok: false }, prefix };
    }
  }

  async function close() {
    if (closed) return;
    clearInterval(deadLetterPruneTimer);
    closed = true;
    await Promise.all([...workers].map((worker) => worker.close()));
    workers.clear();
    await Promise.all([queue.close(), deadLetterQueue.close()]);
    // The best-effort pruner may be queued while Redis is offline; do not wait on it during shutdown.
    if (owned) await connection.quit().catch(() => connection.disconnect());
  }

  return {
    driver: "bullmq",
    prefix,
    publish,
    start,
    async reconcile() { return health(); },
    health,
    close,
    queue,
    deadLetterQueue,
    connection,
  };
}

module.exports = {
  DEFAULT_ADMISSION,
  DEFAULT_DEAD_LETTER_PRUNE_BATCH_SIZE,
  DEFAULT_DEAD_LETTER_PRUNE_INTERVAL_MS,
  DEFAULT_DEAD_LETTER_RETENTION_MS,
  DEFAULT_POLICY,
  createBullMqPort,
  withDeadline,
};
