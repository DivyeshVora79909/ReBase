const crypto = require("node:crypto");
const { createExecutor } = require("./runtime/executor");
const { gatewayError } = require("./runtime/errors");

function createWorker({ database, handlers, providers, executor, workerId = `worker-${crypto.randomUUID()}` }) {
  const edge = executor || createExecutor({ database, handlers, providers });

  async function consume(delivery) {
    const { jobId, capability } = delivery.envelope;
    const handler = handlers.get(capability);
    if (!handler || handler.mode !== "job") {
      return { action: "dead-letter", reason: "unknown-job-capability" };
    }
    const job = await database.claimJob(jobId, workerId);
    if (!job) return { action: "ack" };
    const started = Date.now();
    try {
      if (job.capability !== capability) {
        await database.retryJob(jobId, workerId, job.revision, 0, {
          code: "QUEUE_CAPABILITY_MISMATCH",
          message: "Queue capability does not match durable job state",
        });
        return { action: "dead-letter", reason: "QUEUE_CAPABILITY_MISMATCH" };
      }
      const result = await edge.execute({
        caller: String(job.actor),
        handler,
        args: job.args || {},
        recordIds: job.records || {},
        execution: {
          jobId: String(job.id),
          requestId: String(job.idempotency_key),
          idempotencyKey: String(job.idempotency_key),
          attempt: job.attempts,
        },
      });
      if (Buffer.byteLength(JSON.stringify(result ?? {})) > 256 * 1024) {
        throw Object.assign(new Error("Job result is too large; persist it externally and return a reference"), {
          code: "RESULT_TOO_LARGE",
        });
      }
      await database.finishJob(jobId, workerId, job.revision, "succeeded", result || {}, null);
      await database.log({
        jobId,
        capability,
        actor: String(job.actor),
        phase: "worker",
        outcome: "succeeded",
        durationMs: Date.now() - started,
      });
      return { action: "ack" };
    } catch (error) {
      const normalized = gatewayError(error);
      const terminal = !normalized.retryable || job.attempts >= job.max_attempts;
      const details = { code: normalized.code, message: normalized.message };
      if (terminal) {
        await database.finishJob(jobId, workerId, job.revision, "failed", null, details);
        await database.log({
          jobId,
          capability,
          actor: String(job.actor),
          phase: "worker",
          outcome: "failed",
          errorCode: normalized.code,
          durationMs: Date.now() - started,
        });
        return { action: "dead-letter", reason: normalized.code };
      }
      const delaySeconds = normalized.delaySeconds ?? Math.min(900, 2 ** Math.max(0, job.attempts - 1));
      await database.retryJob(jobId, workerId, job.revision, delaySeconds, details);
      await database.log({
        jobId,
        capability,
        actor: String(job.actor),
        phase: "worker",
        outcome: "retry",
        errorCode: normalized.code,
        data: { delaySeconds },
      });
      return { action: "ack" };
    }
  }

  return { workerId, consume };
}

module.exports = { createWorker };
