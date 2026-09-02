const {
  LANES,
  assertLane,
  assertLocator,
  locatorKey,
  normalizeDecision,
  scheduleKey,
} = require("./port");

const DEFAULT_POLICY = Object.freeze({ attempts: 5, batchSize: 10, waitTimeSeconds: 20, visibilityTimeout: 300 });

function requireUrls(values, label) {
  const missing = LANES.filter((lane) => !values[lane]);
  if (missing.length) throw new Error(`${label} requires URLs for lanes: ${missing.join(", ")}`);
  return values;
}

function createSqsQueue(options = {}) {
  const {
    SQSClient,
    ChangeMessageVisibilityCommand,
    DeleteMessageCommand,
    GetQueueAttributesCommand,
    ReceiveMessageCommand,
    SendMessageCommand,
  } = require("@aws-sdk/client-sqs");
  const queueUrls = requireUrls({
    ...(options.queueUrls || {}),
  }, "SQS delivery port");
  const deadLetterQueueUrls = requireUrls({
    ...(options.deadLetterQueueUrls || {}),
  }, "SQS dead-letter port");
  const client = options.client || new SQSClient({
    region: options.region,
    endpoint: options.endpoint,
  });
  const workers = new Map();
  let closed = false;

  function policyFor(lane) {
    return { ...DEFAULT_POLICY, ...(options.policies?.[lane] || {}) };
  }

  function fifoOptions(url, lane, locator, jobId) {
    if (!url.endsWith(".fifo")) return {};
    return {
      MessageGroupId: `${lane}:${locator.namespace}:${locator.database}`,
      MessageDeduplicationId: scheduleKey(jobId || locatorKey(locator)),
    };
  }

  async function publish(lane, locator, publishOptions = {}) {
    if (closed) throw new Error("SQS queue is closed");
    assertLane(lane);
    const normalized = assertLocator(locator);
    const queueUrl = queueUrls[lane];
    const delayMs = Number(publishOptions.delayMs || 0);
    if (!Number.isFinite(delayMs) || delayMs < 0) throw new Error("SQS delivery delay must be non-negative");
    const response = await client.send(new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify(normalized),
      DelaySeconds: Math.min(900, Math.max(0, Math.ceil(delayMs / 1000))),
      ...fifoOptions(queueUrl, lane, normalized, publishOptions.jobId),
    }));
    return { jobId: response.MessageId, duplicate: false };
  }

  async function deadLetter(lane, message, locator, reason) {
    const queueUrl = deadLetterQueueUrls[lane];
    const fallback = { namespace: "invalid", database: "invalid", id: "invalid:message" };
    await client.send(new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify({
        locator,
        sourceMessageId: message.MessageId,
        reason: String(reason || "rejected"),
        failedAt: new Date().toISOString(),
      }),
      ...fifoOptions(queueUrl, lane, locator || fallback, `${message.MessageId}:dead`),
    }));
  }

  async function remove(lane, message) {
    await client.send(new DeleteMessageCommand({
      QueueUrl: queueUrls[lane],
      ReceiptHandle: message.ReceiptHandle,
    }));
  }

  async function handle(lane, message, consumer) {
    let locator;
    try {
      locator = assertLocator(JSON.parse(message.Body));
    } catch (error) {
      await deadLetter(lane, message, null, "invalid-locator");
      await remove(lane, message);
      return;
    }
    const policy = policyFor(lane);
    const attempts = Number(message.Attributes?.ApproximateReceiveCount || 1);
    let decision;
    try {
      decision = normalizeDecision(await consumer({
        attempts,
        maxAttempts: policy.attempts,
        jobId: message.MessageId,
        lane,
        locator,
        receivedAt: new Date().toISOString(),
      }));
    } catch (error) {
      decision = { action: "retry", delayMs: options.consumerErrorDelayMs || 5000 };
    }
    if (decision.action === "retry" && attempts >= policy.attempts) {
      decision = { action: "dead-letter", reason: "retry-exhausted" };
    }
    if (decision.action === "dead-letter") await deadLetter(lane, message, locator, decision.reason);
    if (decision.action === "ack" || decision.action === "dead-letter") {
      await remove(lane, message);
      return;
    }
    await client.send(new ChangeMessageVisibilityCommand({
      QueueUrl: queueUrls[lane],
      ReceiptHandle: message.ReceiptHandle,
      VisibilityTimeout: Math.min(43200, Math.max(0, Math.ceil(decision.delayMs / 1000))),
    }));
  }

  async function pollOnce(lane, consumer) {
    assertLane(lane);
    const policy = policyFor(lane);
    const response = await client.send(new ReceiveMessageCommand({
      QueueUrl: queueUrls[lane],
      MaxNumberOfMessages: policy.batchSize,
      WaitTimeSeconds: policy.waitTimeSeconds,
      VisibilityTimeout: policy.visibilityTimeout,
      AttributeNames: ["ApproximateReceiveCount"],
    }));
    await Promise.all((response.Messages || []).map((message) => handle(lane, message, consumer)));
    return (response.Messages || []).length;
  }

  async function start(lane, consumer) {
    if (closed) throw new Error("SQS queue is closed");
    assertLane(lane);
    if (typeof consumer !== "function") throw new Error(`${lane} consumer must be a function`);
    if (workers.has(lane)) throw new Error(`${lane} SQS worker already started`);
    const worker = { stopped: false, loop: null };
    worker.loop = (async () => {
      while (!worker.stopped && !closed) {
        try {
          await pollOnce(lane, consumer);
        } catch (error) {
          if (worker.stopped || closed) break;
          options.onError?.(error);
          await new Promise((resolve) => setTimeout(resolve, options.errorDelayMs || 1000));
        }
      }
    })();
    workers.set(lane, worker);
    return async () => {
      const current = workers.get(lane);
      if (current !== worker) return;
      worker.stopped = true;
      await worker.loop;
      workers.delete(lane);
    };
  }

  async function schedule(key, locator, dueAt, scheduleOptions = {}) {
    if (closed) throw new Error("SQS queue is closed");
    const due = new Date(dueAt);
    if (Number.isNaN(due.getTime())) throw new Error("Schedule dueAt must be a valid datetime");
    return publish("schedule", locator, {
      ...scheduleOptions,
      delayMs: Math.max(0, due.getTime() - Date.now()),
      jobId: `${scheduleKey(key)}:${due.getTime()}`,
    });
  }

  async function health() {
    try {
      await Promise.all([...Object.values(queueUrls), ...Object.values(deadLetterQueueUrls)].map((QueueUrl) => (
        client.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["QueueArn"] }))
      )));
      return {
        ok: !closed,
        driver: "sqs",
        lanes: Object.fromEntries(LANES.map((lane) => [lane, workers.has(lane) && !workers.get(lane).stopped])),
        deadLetters: { ok: true },
      };
    } catch (error) {
      return { ok: false, driver: "sqs", error: error.message, lanes: {}, deadLetters: { ok: false } };
    }
  }

  async function close() {
    if (closed) return;
    closed = true;
    for (const worker of workers.values()) worker.stopped = true;
    await Promise.all([...workers.values()].map((worker) => worker.loop));
    workers.clear();
    client.destroy?.();
  }

  return {
    driver: "sqs",
    publish,
    pollOnce,
    start,
    schedule,
    async removeSchedule() { return false; },
    async reconcile() { return health(); },
    health,
    close,
  };
}

module.exports = { DEFAULT_POLICY, createSqsQueue };
