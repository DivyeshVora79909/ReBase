const crypto = require("node:crypto");
const { RecordId, Surreal } = require("surrealdb");
const {
  canAccessJob,
} = require("./access");
const { GatewayError } = require("./errors");
const { connectWithTimeout, requireSessionSupport, sessionEndpoint } = require("./connection");
const queries = require("./queries");
const { withTransaction } = require("./transaction");
const { boundedData, clean, queryResult, recordIdString, sanitize } = require("./utils");

function recordId(value, expectedTable) {
  const text = String(value || "");
  const separator = text.indexOf(":");
  if (separator < 1)
    throw new GatewayError(
      "INVALID_RECORD_ID",
      "Invalid record identifier",
      400,
    );
  const table = text.slice(0, separator);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table))
    throw new GatewayError("INVALID_RECORD_ID", "Invalid record identifier", 400);
  if (expectedTable && table !== expectedTable)
    throw new GatewayError(
      "INVALID_RECORD_ID",
      "Invalid record identifier",
      400,
    );
  return new RecordId(table, text.slice(separator + 1));
}

function recordTable(value) {
  const text = String(value || "");
  const separator = text.indexOf(":");
  if (separator < 1) return null;
  return text.slice(0, separator);
}

function first(value) {
  return Array.isArray(value) ? value[0] : value;
}

function objectResult(value) {
  const result = queryResult(value);
  return Array.isArray(result) ? first(result) : result;
}

function requireMutation(value, code, message) {
  const record = clean(objectResult(value));
  if (!record?.id)
    throw new GatewayError(code, message, 409, { retryable: true });
  return record;
}

function idempotencyKey(caller, capability, requestId) {
  return crypto
    .createHash("sha256")
    .update(`${caller}\n${capability}\n${requestId}`)
    .digest("hex");
}

function leaseActive(receipt) {
  if (receipt?.status !== "processing" || !receipt.lease_expires_at)
    return false;
  return new Date(receipt.lease_expires_at).getTime() > Date.now();
}

class DatabaseRuntime {
  constructor(options) {
    this.db = options.db;
    this.namespace = options.namespace;
    this.database = options.database;
  }

  static async connect(options = {}) {
    const db = new Surreal();
    await connectWithTimeout(
      db,
      sessionEndpoint(
        options.endpoint ||
          process.env.SURREAL_ENDPOINT ||
          "ws://127.0.0.1:8000/rpc",
      ),
      options.connectTimeoutMs || Number(process.env.SURREAL_CONNECT_TIMEOUT_MS) || 10000,
    );
    requireSessionSupport(db);
    await db.signin({
      username: options.username || process.env.SURREAL_USER,
      password: options.password || process.env.SURREAL_PASS,
    });
    const namespace = options.namespace || process.env.SURREAL_NAMESPACE;
    const database = options.database || process.env.SURREAL_DATABASE;
    if (!namespace || !database)
      throw new Error("Missing SurrealDB namespace or database");
    await db.use({ namespace, database });
    return new DatabaseRuntime({ db, namespace, database });
  }

  async close() {
    await this.db.close();
  }

  async authenticate(token) {
    if (!token)
      throw new GatewayError("UNAUTHORIZED", "Missing bearer token", 401);
    const session = await this.db.newSession();
    try {
      await session.use({ namespace: this.namespace, database: this.database });
      await session.authenticate(token);
      const actor = await session.auth();
      if (!actor?.id)
        throw new GatewayError("UNAUTHORIZED", "Authentication failed", 401);
      return recordIdString(actor.id);
    } finally {
      await session.closeSession();
    }
  }

  async actor(caller) {
    const actor = clean(
      objectResult(await this.db.query(queries.actor, { caller })),
    );
    if (!actor?.id)
      throw new GatewayError("UNAUTHORIZED", "Caller no longer exists", 401);
    return actor;
  }

  async resolveRecords(caller, ids) {
    const unique = [...new Set(ids.map(String))];
    if (unique.length > 100)
      throw new GatewayError(
        "TOO_MANY_RECORDS",
        "Too many records requested",
        400,
      );
    for (const id of unique) recordId(id);
    if (!unique.length) return { auth: await this.actor(caller), records: new Map() };
    const tables = [...new Set(unique.map(recordTable))].sort();
    const state = clean(
      objectResult(
        await this.db.query(queries.resolveRecords(tables), { caller, ids: unique }),
      ),
    );
    if (!state?.auth?.id)
      throw new GatewayError("UNAUTHORIZED", "Caller no longer exists", 401);
    const records = new Map(
      (state.records || []).map((record) => [recordIdString(record.id), record]),
    );
    return { auth: state.auth, records };
  }

  async createJob({
    caller,
    capability,
    args,
    records,
    requestId,
    maxAttempts,
  }) {
    const key = idempotencyKey(caller, capability, requestId);
    const find = async () =>
      clean(
        objectResult(
          await this.db.query(
            "RETURN (SELECT * FROM edge_job WHERE idempotency_key = $key LIMIT 1)[0];",
            { key },
          ),
        ),
      );
    const existing = await find();
    if (existing?.id) return existing;
    try {
      return await withTransaction(this.db, async (transaction) =>
        clean(
          objectResult(
            await transaction.query(queries.createJob, {
              caller,
              capability,
              records,
              args,
              max_attempts: maxAttempts,
              key,
            }),
          ),
        ),
      );
    } catch (error) {
      const duplicate = await find();
      if (duplicate?.id) return duplicate;
      throw error;
    }
  }

  async job(caller, jobId) {
    recordId(jobId, "edge_job");
    const state = clean(
      objectResult(
        await this.db.query(queries.jobState, { caller, job_id: jobId }),
      ),
    );
    if (!state?.job?.id)
      throw new GatewayError("JOB_NOT_FOUND", "Job not found", 404);
    if (!canAccessJob(state.actor, state.job))
      throw new GatewayError("FORBIDDEN", "Forbidden", 403);
    return state.job;
  }

  async cancelJob(caller, jobId) {
    recordId(jobId, "edge_job");
    return withTransaction(this.db, async (transaction) => {
      const state = clean(
        objectResult(
          await transaction.query(queries.jobState, { caller, job_id: jobId }),
        ),
      );
      if (!state?.job?.id)
        throw new GatewayError("JOB_NOT_FOUND", "Job not found", 404);
      if (!canAccessJob(state.actor, state.job))
        throw new GatewayError("FORBIDDEN", "Forbidden", 403);
      const job = requireMutation(
        await transaction.query(queries.cancelJob, { job_id: jobId }),
        "JOB_NOT_CANCELLABLE",
        "Job can no longer be cancelled",
      );
      await transaction.query(queries.cancelPendingOutbox, { job_id: jobId });
      return job;
    });
  }

  async claimOutbox(workerId, limit) {
    const rows = await withTransaction(this.db, async (transaction) =>
      clean(
        queryResult(
          await transaction.query(queries.claimOutbox, {
            worker: workerId,
            limit,
          }),
        ),
      ),
    );
    return (Array.isArray(rows) ? rows : []).filter(Boolean);
  }

  async markOutboxPublished(id, workerId, leaseRevision) {
    recordId(id, "edge_outbox");
    return requireMutation(
      await this.db.query(queries.markOutboxPublished, {
        id: recordIdString(id),
        worker: workerId,
        revision: String(leaseRevision),
      }),
      "OUTBOX_LEASE_LOST",
      "Outbox lease was lost",
    );
  }

  async markOutboxFailed(id, workerId, leaseRevision, error) {
    recordId(id, "edge_outbox");
    const message = String(error?.message || error).slice(0, 1000);
    return withTransaction(this.db, async (transaction) => {
      const row = clean(
        objectResult(
          await transaction.query(queries.outbox, { id: String(id) }),
        ),
      );
      if (
        !row?.id ||
        row.lease_owner !== workerId ||
        String(row.revision) !== String(leaseRevision) ||
        row.status !== "publishing"
      ) {
        throw new GatewayError(
          "OUTBOX_LEASE_LOST",
          "Outbox lease was lost",
          409,
          { retryable: true },
        );
      }
      const terminal = (row.attempts || 0) >= (row.max_attempts || 10);
      if (terminal)
        await transaction.query(queries.failQueuedJob, {
          job_id: String(row.job_id),
          message,
        });
      return requireMutation(
        await transaction.query(queries.markOutboxFailed, {
        id: recordIdString(id),
          worker: workerId,
          revision: String(leaseRevision),
          message,
          terminal,
        }),
        "OUTBOX_LEASE_LOST",
        "Outbox lease was lost",
      );
    });
  }

  async claimJob(jobId, workerId) {
    recordId(jobId, "edge_job");
    return clean(
      objectResult(
        await this.db.query(queries.claimJob, { id: jobId, worker: workerId }),
      ),
    );
  }

  async finishJob(jobId, workerId, leaseRevision, status, result, error) {
    recordId(jobId, "edge_job");
    return requireMutation(
      await this.db.query(queries.finishJob, {
        id: jobId,
        worker: workerId,
        revision: String(leaseRevision),
        status,
        result: result ?? undefined,
        error: error ?? undefined,
      }),
      "JOB_LEASE_LOST",
      "Job lease was lost before the result was saved",
    );
  }

  async retryJob(jobId, workerId, leaseRevision, delaySeconds, error) {
    recordId(jobId, "edge_job");
    return requireMutation(
      await this.db.query(queries.retryJob, {
        id: jobId,
        worker: workerId,
        revision: String(leaseRevision),
        delay: `${Math.max(0, delaySeconds)}s`,
        error,
      }),
      "JOB_LEASE_LOST",
      "Job lease was lost before retry state was saved",
    );
  }

  async claimWebhook({
    dedupeKey,
    capability,
    provider,
    providerEventId,
    leaseOwner,
  }) {
    const values = {
      dedupe_key: dedupeKey,
      capability,
      provider: provider || undefined,
      provider_event_id: providerEventId,
      lease_owner: leaseOwner,
    };
    try {
      return await withTransaction(this.db, async (transaction) => {
        const existing = clean(
          objectResult(
            await transaction.query(queries.webhook, { key: dedupeKey }),
          ),
        );
        if (existing?.status === "succeeded" || leaseActive(existing))
          return { claimed: false, receipt: existing };
        if (existing?.id) {
          const claimed = clean(
            objectResult(
              await transaction.query(queries.reclaimWebhook, {
                id: String(existing.id),
                revision: String(existing.revision),
                lease_owner: leaseOwner,
              }),
            ),
          );
          return {
            claimed: Boolean(claimed?.id),
            receipt: claimed || existing,
          };
        }
        const created = clean(
          objectResult(await transaction.query(queries.createWebhook, values)),
        );
        return { claimed: true, receipt: created };
      });
    } catch (error) {
      const duplicate = clean(
        objectResult(await this.db.query(queries.webhook, { key: dedupeKey })),
      );
      if (duplicate?.id) return { claimed: false, receipt: duplicate };
      throw error;
    }
  }

  async finishWebhook(dedupeKey, leaseOwner, status, result, error) {
    return requireMutation(
      await this.db.query(queries.finishWebhook, {
        key: dedupeKey,
        lease_owner: leaseOwner,
        status,
        result: result ?? undefined,
        error: error ?? undefined,
      }),
      "WEBHOOK_LEASE_LOST",
      "Webhook processing lease was lost",
    );
  }

  async log(entry) {
    const value = sanitize(entry);
    try {
      return queryResult(
        await this.db.query(queries.appendLog, {
          request_id: value.requestId || undefined,
          job_id: value.jobId || "",
          capability: value.capability || "unknown",
          phase: value.phase || "runtime",
          outcome: value.outcome || "unknown",
          actor: value.actor || "",
          provider: value.provider || undefined,
          duration_ms: value.durationMs ?? undefined,
          error_code: value.errorCode || undefined,
          data: boundedData(value.data || {}),
        }),
      );
    } catch (error) {
      console.error(`edge_log write failed: ${error.message}`);
      return null;
    }
  }
}

module.exports = {
  DatabaseRuntime,
};
