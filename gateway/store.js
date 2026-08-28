const { clean, queryResult, recordIdString } = require("./utils");

const FINAL_OUTCOMES = new Set(["succeeded", "failed", "ambiguous", "partial"]);

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

function createTableStore(database) {
  const db = database.db || database;

  async function load(id) {
    return clean(queryResult(await db.query(
      "RETURN (SELECT * FROM type::record($id))[0];",
      { id: String(id) },
    )));
  }

  async function execute(statement, variables = {}) {
    if (typeof statement !== "string" || !statement.trim()) throw new Error("Store statement is required");
    return clean(queryResult(await db.query(statement, variables)));
  }

  async function claim(id, { token, leaseUntil, outcome = "pending" }) {
    const outcomeCondition = outcomePredicate(outcome);
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET rebase_lease_token = type::uuid($lease_token),
            rebase_lease_until = type::datetime($lease_until),
            rebase_wake_at = NONE
        WHERE (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
          AND ${outcomeCondition}
          AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())
          AND (rebase_wake_at = NONE OR rebase_wake_at <= time::now())
        RETURN AFTER)[0];
    `, {
      id: String(id),
      lease_token: String(token),
      lease_until: new Date(leaseUntil).toISOString(),
    })));
  }

  async function finalize(id, token, patchValue, allowedFields, outcome, error = null, expectedOutcome = "pending") {
    if (!FINAL_OUTCOMES.has(outcome)) throw new Error(`Invalid effect outcome: ${outcome}`);
    const outcomeCondition = outcomePredicate(expectedOutcome);
    const assignments = patchAssignments(patchValue || {}, allowedFields);
    assignments.push(
      "rebase_outcome = $outcome",
      "rebase_finished_at = time::now()",
      "rebase_lease_token = NONE",
      "rebase_lease_until = NONE",
      "rebase_wake_at = NONE",
      error ? "rebase_error = $error" : "rebase_error = NONE",
    );
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET ${assignments.join(", ")}
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND ${outcomeCondition}
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
    `, {
      id: String(id), lease_token: String(token), patch: patchValue || {}, outcome, error,
    })));
  }

  async function ambiguous(id, token, patchValue, allowedFields, wakeAt, error = null) {
    const assignments = patchAssignments(patchValue || {}, allowedFields);
    assignments.push(
      "rebase_outcome = 'ambiguous'",
      "rebase_finished_at = NONE",
      "rebase_lease_token = NONE",
      "rebase_lease_until = NONE",
      "rebase_wake_at = type::datetime($wake_at)",
      error ? "rebase_error = $error" : "rebase_error = NONE",
    );
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET ${assignments.join(", ")}
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND rebase_outcome = NONE
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
    `, {
      id: String(id), lease_token: String(token), patch: patchValue || {}, wake_at: new Date(wakeAt).toISOString(), error,
    })));
  }

  async function retry(id, token, wakeAt, error, expectedOutcome = "pending") {
    const outcomeCondition = outcomePredicate(expectedOutcome);
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET rebase_lease_token = NONE,
            rebase_lease_until = NONE,
            rebase_wake_at = type::datetime($wake_at),
            rebase_error = $error
        WHERE rebase_lease_token = type::uuid($lease_token)
          AND ${outcomeCondition}
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
    `, {
      id: String(id), lease_token: String(token), wake_at: new Date(wakeAt).toISOString(), error,
    })));
  }

  async function pending(tables, lane = "task", { deep = false } = {}) {
    const names = [...new Set(tables)].map(identifier);
    if (!names.length) return [];
    let predicate;
    if (lane === "schedule") {
      const due = deep ? "" : " AND (rebase_schedule_next_at = NONE OR rebase_schedule_next_at <= time::now())";
      predicate = `schedule != NONE AND rebase_outcome = NONE AND rebase_schedule_finished_at = NONE${due} AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)`;
    } else if (lane === "webhook") {
      predicate = "rebase_outcome = 'ambiguous' AND (rebase_wake_at = NONE OR rebase_wake_at <= time::now()) AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())";
    } else {
      predicate = "schedule = NONE AND rebase_outcome = NONE AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false) AND (rebase_wake_at = NONE OR rebase_wake_at <= time::now()) AND (rebase_lease_until = NONE OR rebase_lease_until <= time::now())";
    }
    const parts = names.map((table) => `SELECT VALUE <string>id FROM ${table} WHERE ${predicate}`);
    const value = queryResult(await db.query(`RETURN array::flatten([${parts.join(", ")}]);`));
    return (Array.isArray(value) ? value : []).map(recordIdString);
  }

  async function initializeSchedule(id, nextAt) {
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET rebase_schedule_next_at = type::datetime($next_at), rebase_schedule_index = 0
        WHERE schedule != NONE
          AND rebase_schedule_next_at = NONE
          AND rebase_schedule_finished_at = NONE
          AND rebase_outcome = NONE
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
    `, { id: String(id), next_at: new Date(nextAt).toISOString() })));
  }

  async function finishSchedule(id, { cancelled = false } = {}) {
    const outcome = cancelled ? "" : ", rebase_outcome = 'succeeded', rebase_finished_at = time::now()";
    const cancellation = cancelled
      ? "rebase_cancel_requested = true"
      : "(rebase_cancel_requested = NONE OR rebase_cancel_requested = false) AND rebase_outcome = NONE";
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET rebase_schedule_finished_at = time::now(), rebase_schedule_next_at = NONE${outcome}
        WHERE rebase_schedule_finished_at = NONE
          AND ${cancellation}
        RETURN AFTER)[0];
    `, { id: String(id) })));
  }

  async function failSchedule(id, error) {
    return clean(queryResult(await db.query(`
      RETURN (UPDATE type::record($id)
        SET rebase_schedule_finished_at = time::now(),
            rebase_schedule_next_at = NONE,
            rebase_outcome = 'failed',
            rebase_finished_at = time::now(),
            rebase_error = $error
        WHERE schedule != NONE
          AND rebase_schedule_finished_at = NONE
          AND rebase_outcome = NONE
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
    `, { id: String(id), error })));
  }

  async function advanceSchedule(id, {
    expectedAt,
    nextAt,
    nextIndex,
    content,
    recordFields = [],
    emit = true,
    finish = false,
  }) {
    const table = identifier(String(id).split(":", 1)[0]);
    const nextAssignment = finish
      ? "rebase_schedule_next_at = NONE, rebase_schedule_finished_at = time::now(), rebase_outcome = 'succeeded', rebase_finished_at = time::now()"
      : "rebase_schedule_next_at = type::datetime($next_at)";
    const references = new Map(recordFields.map((field) => [field.field, field]));
    const contentAssignments = Object.keys(content || {}).map((field) => {
      const name = identifier(field);
      const reference = references.get(field) || (field === "owned_by" ? { array: false } : null);
      if (!reference) return `${name} = $content.${name}`;
      if (reference.array) return `${name} = ($content.${name} ?? []).map(|$reference| type::record($reference))`;
      return `${name} = IF $content.${name} = NONE THEN NONE ELSE type::record($content.${name}) END`;
    });
    if (emit && !contentAssignments.length) throw new Error("Scheduled occurrence content cannot be empty");
    const occurrence = emit
      ? `LET $occurrence = IF $source != NONE THEN CREATE ONLY ${table} SET ${contentAssignments.join(", ")} RETURN AFTER ELSE NONE END;`
      : "LET $occurrence = NONE;";
    return clean(queryResult(await db.query(`
      BEGIN TRANSACTION;
      LET $source = (UPDATE type::record($id)
        SET rebase_schedule_index = $next_index, ${nextAssignment}
        WHERE rebase_schedule_next_at = type::datetime($expected_at)
          AND rebase_schedule_next_at <= time::now()
          AND rebase_schedule_finished_at = NONE
          AND rebase_outcome = NONE
          AND (rebase_cancel_requested = NONE OR rebase_cancel_requested = false)
        RETURN AFTER)[0];
      ${occurrence}
      COMMIT TRANSACTION;
      RETURN { source: $source, occurrence: $occurrence };
    `, {
      id: String(id),
      expected_at: String(expectedAt),
      next_at: nextAt ? new Date(nextAt).toISOString() : new Date(expectedAt).toISOString(),
      next_index: Number(nextIndex),
      content,
    })));
  }

  async function health() {
    return queryResult(await db.query("RETURN true;")) === true;
  }

  return {
    advanceSchedule,
    ambiguous,
    claim,
    execute,
    finalize,
    finishSchedule,
    failSchedule,
    health,
    initializeSchedule,
    load,
    pending,
    retry,
  };
}

module.exports = { createTableStore, identifier, patchAssignments };
