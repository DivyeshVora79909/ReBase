const { clean, queryResult, recordIdString } = require("./utils");

const FINAL_OUTCOMES = new Set(["succeeded", "failed", "ambiguous", "partial"]);
const RECONCILIATION_CURSOR_ID = "rebase_reconciliation_cursor:operation_scan";

function identifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) throw new Error(`Invalid identifier: ${value}`);
  return value;
}

function patchAssignments(patch, allowedFields) {
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
    throw new Error("Handler patch must be an object");
  }
  const allowed = new Set(allowedFields || []);
  const fields = Object.keys(patch);
  const unknown = fields.find((field) => !allowed.has(field));
  if (unknown) throw new Error(`Handler cannot patch ${unknown}`);
  return fields.map((field) => `${identifier(field)} = $patch.${identifier(field)}`);
}

function outcomePredicate(expectedOutcome) {
  if (expectedOutcome === "pending") return "rebase_outcome = NONE";
  if (expectedOutcome === "ambiguous") return "rebase_outcome = 'ambiguous'";
  throw new Error(`Invalid expected effect outcome: ${expectedOutcome}`);
}

function identityPredicate(identity) {
  if (!identity || typeof identity.executionId !== "string" || typeof identity.revision !== "string") {
    throw new Error("Task execution identity and revision are required for lifecycle transitions");
  }
  return "execution_id = type::uuid($execution_id) AND revision = type::uuid($revision)";
}

function identityVariables(identity) {
  identityPredicate(identity);
  return { execution_id: identity.executionId, revision: identity.revision };
}

function createTableStore(database) {
  const db = database.db || database;

  async function load(id) {
    return clean(queryResult(await db.query(
      "RETURN (SELECT * FROM type::record($id))[0];",
      { id: String(id) },
    )));
  }

  async function createWebhookReceipt(id, input) {
    return clean(queryResult(await db.query(`
      CREATE ONLY type::record($id) SET
        provider_account_id = $provider_account_id,
        event_id = $event_id,
        provider = $provider,
        event = $event,
        config_id = $config_id,
        target_id = $target_id,
        payload_hash = $payload_hash,
        normalized_payload = $normalized_payload
      RETURN AFTER;
    `, { id: String(id), ...input })));
  }

  async function execute(statement, variables = {}) {
    if (typeof statement !== "string" || !statement.trim()) throw new Error("Store statement is required");
    return clean(queryResult(await db.query(statement, variables)));
  }

  async function loadReconciliationCursor() {
    const read = async () => clean(queryResult(await db.query(
      `RETURN (SELECT * FROM ${RECONCILIATION_CURSOR_ID})[0];`,
    )));
    let cursor = await read();
    if (cursor) return cursor;
    try {
      await db.query(`CREATE ONLY ${RECONCILIATION_CURSOR_ID} SET
        cursors = {}, high_water = {}, retention_cursors = {}, retention_high_water = {},
        table_offset = 0, version = 0, updated_at = time::now();`);
    } catch (error) {
      cursor = await read();
      if (!cursor) throw error;
      return cursor;
    }
    cursor = await read();
    if (!cursor) throw new Error("Failed to initialize durable reconciliation cursor");
    return cursor;
  }

  async function compareAndSetReconciliationCursor({
    expectedVersion,
    cursors,
    highWater,
    retentionCursors = {},
    retentionHighWater = {},
    tableOffset,
  }) {
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      throw new Error("Reconciliation cursor version must be a non-negative integer");
    }
    if (!Number.isSafeInteger(tableOffset) || tableOffset < 0) {
      throw new Error("Reconciliation table offset must be a non-negative integer");
    }
    if (!cursors || typeof cursors !== "object" || Array.isArray(cursors)
      || !highWater || typeof highWater !== "object" || Array.isArray(highWater)
      || !retentionCursors || typeof retentionCursors !== "object" || Array.isArray(retentionCursors)
      || !retentionHighWater || typeof retentionHighWater !== "object" || Array.isArray(retentionHighWater)) {
      throw new Error("Reconciliation cursors and high-water bounds must be objects");
    }
    return clean(queryResult(await db.query(`
      RETURN (UPDATE ${RECONCILIATION_CURSOR_ID}
        SET cursors = $cursors,
            high_water = $high_water,
            retention_cursors = $retention_cursors,
            retention_high_water = $retention_high_water,
            table_offset = $table_offset,
            version = version + 1,
            updated_at = time::now()
        WHERE version = $expected_version
        RETURN AFTER)[0];
    `, {
      cursors,
      high_water: highWater,
      retention_cursors: retentionCursors,
      retention_high_water: retentionHighWater,
      table_offset: tableOffset,
      expected_version: expectedVersion,
    })));
  }

  async function expiredTerminalPage(tables, { cursors = {}, highWater = {}, cutoff, pageSize = 100 } = {}) {
    const names = [...new Set(tables)].map(identifier);
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 1000) {
      throw new Error("Terminal retention page size must be between 1 and 1000");
    }
    if (!Number.isFinite(new Date(cutoff).getTime())) throw new Error("Terminal retention cutoff must be a valid date");
    const nextCursors = { ...cursors };
    const nextHighWater = { ...highWater };
    const rows = [];
    for (const table of names) {
      const key = `terminal:${table}`;
      const remaining = pageSize - rows.length;
      if (remaining <= 0) break;
      let upperBound = nextHighWater[key] || null;
      if (!upperBound) {
        const latest = queryResult(await db.query(`
          SELECT VALUE <string>id FROM ${table} ORDER BY id DESC LIMIT 1;
        `));
        upperBound = Array.isArray(latest) && latest.length ? recordIdString(latest[0]) : null;
        nextHighWater[key] = upperBound;
      }
      if (!upperBound) {
        nextCursors[key] = null;
        continue;
      }
      const after = nextCursors[key] || null;
      const afterCondition = after ? "AND id > type::record($after)" : "";
      const found = queryResult(await db.query(`
        SELECT VALUE <string>id FROM ${table}
        WHERE (
          (rebase_outcome IN ['succeeded', 'failed', 'partial']
            AND rebase_finished_at != NONE
            AND rebase_finished_at <= type::datetime($cutoff))
          OR (rebase_outcome = NONE
            AND rebase_cancel_requested = true
            AND rebase_cancelled_at != NONE
            AND rebase_cancelled_at <= type::datetime($cutoff))
        )
          AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())
          AND rebase_provider_started_at = NONE
          AND id <= type::record($upper_bound)
          ${afterCondition}
        ORDER BY id LIMIT $limit;
      `, {
        after,
        upper_bound: upperBound,
        cutoff: new Date(cutoff).toISOString(),
        limit: remaining,
      }));
      const page = (Array.isArray(found) ? found : []).map(recordIdString);
      rows.push(...page.map((id) => ({ id, table })));
      if (page.length && page.length === remaining && page.at(-1) !== upperBound) {
        nextCursors[key] = page.at(-1);
      } else {
        nextCursors[key] = null;
        nextHighWater[key] = null;
      }
    }
    return { rows, cursors: nextCursors, highWater: nextHighWater };
  }

  async function deleteExpiredTerminalRows(rows, cutoff) {
    if (!Array.isArray(rows) || rows.length > 1000) {
      throw new Error("Terminal retention deletes must be a bounded row array");
    }
    const deleted = [];
    for (const entry of rows) {
      const table = identifier(entry.table);
      if (String(entry.id).split(":", 1)[0] !== table) {
        throw new Error("Terminal retention row does not belong to its declared table");
      }
      const result = queryResult(await db.query(`
        RETURN (DELETE type::record($id)
          WHERE (
            (rebase_outcome IN ['succeeded', 'failed', 'partial']
              AND rebase_finished_at != NONE
              AND rebase_finished_at <= type::datetime($cutoff))
            OR (rebase_outcome = NONE
              AND rebase_cancel_requested = true
              AND rebase_cancelled_at != NONE
              AND rebase_cancelled_at <= type::datetime($cutoff))
          )
            AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())
            AND rebase_provider_started_at = NONE
          RETURN BEFORE)[0];
      `, { id: String(entry.id), table, cutoff: new Date(cutoff).toISOString() }));
      if (result) deleted.push(String(entry.id));
    }
    return deleted;
  }

  async function claim(id, { token, leaseUntil, outcome = "pending", executionId, revision }) {
    const identity = { executionId, revision };
    const identityCondition = identityPredicate(identity);
    const outcomeCondition = outcomePredicate(outcome);
    const providerRecovery = outcome === "pending" ? "rebase_provider_started_at != NONE" : "false";
    const attemptAssignment = outcome === "pending"
      ? `rebase_attempt = IF ${providerRecovery} THEN rebase_attempt ELSE (rebase_attempt ?? 0) + 1 END`
      : "rebase_attempt = (rebase_attempt ?? 0) + 1";
    const executionEligibility = outcome === "pending" ? "AND execute_at <= time::now()" : "";
    const cancellationCondition = outcome === "pending"
      ? `AND ((rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
          OR (${providerRecovery} AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())))`
      : "";
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET ${attemptAssignment},
            revision = IF ${providerRecovery} THEN rand::uuid::v7() ELSE revision END,
            rebase_outcome = IF ${providerRecovery} THEN 'ambiguous' ELSE rebase_outcome END,
            rebase_finished_at = IF ${providerRecovery} THEN NONE ELSE rebase_finished_at END,
            rebase_error = IF ${providerRecovery} THEN {
              code: 'WORKER_LOST_AFTER_PROVIDER_START',
              message: 'The provider result is unknown because the worker lease expired.'
            } ELSE rebase_error END,
            rebase_lease_token = IF ${providerRecovery} THEN NONE ELSE type::uuid($lease_token) END,
            rebase_lease_until = IF ${providerRecovery} THEN NONE ELSE type::datetime($lease_until) END,
            rebase_provider_started_at = NONE,
            rebase_wake_at = IF ${providerRecovery} THEN time::now() ELSE NONE END
        WHERE ${identityCondition}
          AND ${outcomeCondition}
          ${cancellationCondition}
          ${executionEligibility}
          AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())
          AND (rebase_wake_at = NONE OR rebase_wake_at <= time::now())
        RETURN AFTER)[0];
    `, {
      id: String(id),
      lease_token: String(token),
      lease_until: new Date(leaseUntil).toISOString(),
      ...identityVariables(identity),
    })));
  }

  async function markProviderStarted(id, token, identity, expectedOutcome = "pending") {
    const identityCondition = identityPredicate(identity);
    const expectedOutcomeCondition = outcomePredicate(expectedOutcome);
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET rebase_provider_started_at = IF rebase_provider_started_at = NONE
          THEN time::now() ELSE rebase_provider_started_at END
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND rebase_lease_until > time::now()
          AND ${identityCondition}
          AND ${expectedOutcomeCondition}
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
    `, {
      id: String(id),
      lease_token: String(token),
      ...identityVariables(identity),
    })));
  }

  async function finalize(id, token, patchValue, allowedFields, outcome, error = null, expectedOutcome = "pending", identity) {
    if (!FINAL_OUTCOMES.has(outcome)) throw new Error(`Invalid effect outcome: ${outcome}`);
    const identityCondition = identityPredicate(identity);
    const outcomeCondition = outcomePredicate(expectedOutcome);
    const assignments = patchAssignments(patchValue || {}, allowedFields);
    assignments.push(
      "revision = rand::uuid::v7()",
      "rebase_outcome = $outcome",
      "rebase_finished_at = time::now()",
      "rebase_lease_token = NONE",
      "rebase_lease_until = NONE",
      "rebase_provider_started_at = NONE",
      "rebase_wake_at = NONE",
      error ? "rebase_error = $error" : "rebase_error = NONE",
    );
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET ${assignments.join(", ")}
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND rebase_lease_until > time::now()
          AND ${identityCondition}
          AND ${outcomeCondition}
        RETURN AFTER)[0];
    `, {
      id: String(id), lease_token: String(token), patch: patchValue || {}, outcome, error,
      ...identityVariables(identity),
    })));
  }

  async function ambiguous(id, token, patchValue, allowedFields, wakeAt, error = null, identity) {
    const identityCondition = identityPredicate(identity);
    const assignments = patchAssignments(patchValue || {}, allowedFields);
    assignments.push(
      "revision = rand::uuid::v7()",
      "rebase_outcome = 'ambiguous'",
      "rebase_finished_at = NONE",
      "rebase_lease_token = NONE",
      "rebase_lease_until = NONE",
      "rebase_provider_started_at = NONE",
      "rebase_wake_at = type::datetime($wake_at)",
      error ? "rebase_error = $error" : "rebase_error = NONE",
    );
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET ${assignments.join(", ")}
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND rebase_lease_until > time::now()
          AND ${identityCondition}
          AND rebase_outcome = NONE
        RETURN AFTER)[0];
    `, {
      id: String(id), lease_token: String(token), patch: patchValue || {}, wake_at: new Date(wakeAt).toISOString(), error,
      ...identityVariables(identity),
    })));
  }

  async function retry(id, token, wakeAt, error, expectedOutcome = "pending", identity) {
    const identityCondition = identityPredicate(identity);
    const outcomeCondition = outcomePredicate(expectedOutcome);
    const cancellationAwarePending = expectedOutcome === "pending";
    const revisionAssignment = cancellationAwarePending
      ? "revision = IF rebase_cancel_requested = true THEN revision ELSE rand::uuid::v7() END"
      : "revision = rand::uuid::v7()";
    const wakeAssignment = cancellationAwarePending
      ? "rebase_wake_at = IF rebase_cancel_requested = true THEN NONE ELSE type::datetime($wake_at) END"
      : "rebase_wake_at = type::datetime($wake_at)";
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
      SET rebase_lease_token = NONE,
            rebase_lease_until = NONE,
            rebase_provider_started_at = NONE,
            ${revisionAssignment},
            ${wakeAssignment},
            rebase_error = $error
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND rebase_lease_until > time::now()
          AND ${identityCondition}
          AND ${outcomeCondition}
        RETURN AFTER)[0];
    `, {
      id: String(id), lease_token: String(token), wake_at: new Date(wakeAt).toISOString(), error,
      ...identityVariables(identity),
    })));
  }

  async function pendingPage(tables, {
    cursors = {},
    highWater = {},
    ambiguousTables = [],
    pageSize = 100,
    horizon = "5m",
  } = {}) {
    const names = [...new Set(tables)].map(identifier);
    const ambiguous = new Set(ambiguousTables.map(identifier));
    if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 1000) {
      throw new Error("Pending page size must be between 1 and 1000");
    }
    if (!/^(?:[1-9]\d*)(?:ms|s|m|h|d)$/.test(String(horizon))) {
      throw new Error("Pending horizon must be a positive duration");
    }
    const nextCursors = { ...cursors };
    const nextHighWater = { ...highWater };
    const ids = [];
    for (const table of names) {
      const remaining = pageSize - ids.length;
      if (remaining <= 0) break;
      const after = nextCursors[table] || null;
      let upperBound = nextHighWater[table] || null;
      if (!upperBound) {
        const latest = queryResult(await db.query(`
          SELECT VALUE <string>id FROM ${table} ORDER BY id DESC LIMIT 1;
        `));
        upperBound = Array.isArray(latest) && latest.length ? recordIdString(latest[0]) : null;
        nextHighWater[table] = upperBound;
      }
      if (!upperBound) {
        nextCursors[table] = null;
        continue;
      }
      const afterCondition = after ? "AND id > type::record($after)" : "";
      const outcomeCondition = ambiguous.has(table)
        ? "(rebase_outcome = NONE OR rebase_outcome = 'ambiguous')"
        : "rebase_outcome = NONE";
      const cancellationCondition = `(rebase_cancel_requested = NONE OR rebase_cancel_requested = false
        OR rebase_outcome = 'ambiguous'
        OR (rebase_provider_started_at != NONE
          AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())))`;
      const rows = queryResult(await db.query(`
        SELECT VALUE <string>id FROM ${table}
        WHERE ${outcomeCondition}
          AND ${cancellationCondition}
          AND (rebase_wake_at = NONE OR rebase_wake_at <= time::now() + type::duration($horizon))
          AND (rebase_outcome = 'ambiguous' OR execute_at <= time::now() + type::duration($horizon))
          AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())
          AND id <= type::record($upper_bound)
          ${afterCondition}
        ORDER BY id LIMIT $limit;
      `, { after, upper_bound: upperBound, horizon, limit: remaining }));
      const page = (Array.isArray(rows) ? rows : []).map(recordIdString);
      ids.push(...page);
      if (page.length) {
        const last = page[page.length - 1];
        if (page.length < remaining || last === upperBound) {
          nextCursors[table] = null;
          nextHighWater[table] = null;
        } else {
          nextCursors[table] = last;
        }
      } else {
        nextCursors[table] = null;
        nextHighWater[table] = null;
      }
    }
    return { ids, cursors: nextCursors, highWater: nextHighWater };
  }

  async function health() {
    return queryResult(await db.query("RETURN true;")) === true;
  }

  return {
    ambiguous,
    claim,
    compareAndSetReconciliationCursor,
    createWebhookReceipt,
    deleteExpiredTerminalRows,
    expiredTerminalPage,
    execute,
    finalize,
    health,
    load,
    loadReconciliationCursor,
    markProviderStarted,
    pendingPage,
    retry,
  };
}

module.exports = { createTableStore, identifier, identityPredicate, patchAssignments };
