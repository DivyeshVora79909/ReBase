const crypto = require("node:crypto");
const { RuntimeError } = require("../errors");

const ACTIONS = new Set(["ack", "retry", "dead-letter"]);
const WORK_KINDS = new Set(["operation", "receipt"]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function assertLocator(locator) {
  const valid = locator && typeof locator === "object" && !Array.isArray(locator)
    && typeof locator.namespace === "string" && locator.namespace.length > 0
    && typeof locator.database === "string" && locator.database.length > 0
    && typeof locator.id === "string" && /^[A-Za-z_][A-Za-z0-9_]*:.+/.test(locator.id);
  if (!valid || Object.keys(locator).some((key) => !["namespace", "database", "id"].includes(key))) {
    throw new RuntimeError("INVALID_QUEUE_LOCATOR", "Queue locator must contain only namespace, database, and id", 400);
  }
  return {
    namespace: locator.namespace,
    database: locator.database,
    id: locator.id,
  };
}

function locatorKey(locator) {
  const value = assertLocator(locator);
  return Buffer.from(JSON.stringify([value.namespace, value.database, value.id])).toString("base64url");
}

function assertWorkEnvelope(envelope) {
  const commonValid = envelope && typeof envelope === "object" && !Array.isArray(envelope)
    && envelope.version === 1
    && WORK_KINDS.has(envelope.kind)
    && typeof envelope.revision === "string" && UUID_PATTERN.test(envelope.revision);
  const expectedKeys = envelope?.kind === "receipt"
    ? ["version", "kind", "locator", "revision"]
    : ["version", "kind", "locator", "executionId", "revision"];
  const valid = commonValid
    && Object.keys(envelope).length === expectedKeys.length
    && expectedKeys.every((key) => Object.hasOwn(envelope, key))
    && (envelope.kind === "receipt"
      || (typeof envelope.executionId === "string" && UUID_PATTERN.test(envelope.executionId)));
  if (!valid) {
    throw new RuntimeError("INVALID_WORK_ENVELOPE", "Work envelope must be a versioned operation or receipt identity", 400);
  }
  return {
    version: 1,
    kind: envelope.kind,
    locator: assertLocator(envelope.locator),
    ...(envelope.kind === "operation" ? { executionId: envelope.executionId.toLowerCase() } : {}),
    revision: envelope.revision.toLowerCase(),
  };
}

function assertOperationEnvelope(envelope) {
  const value = assertWorkEnvelope(envelope);
  if (value.kind !== "operation") {
    throw new RuntimeError("INVALID_WORK_KIND", "This worker accepts operation hints only", 400);
  }
  return value;
}

function operationEnvelope(locator, record) {
  if (!record || typeof record !== "object") {
    throw new RuntimeError("WORK_RECORD_REQUIRED", "A current task record is required to create a work envelope", 409);
  }
  return assertWorkEnvelope({
    version: 1,
    kind: "operation",
    locator: assertLocator(locator),
    executionId: String(record.execution_id || ""),
    revision: String(record.revision || ""),
  });
}

function receiptEnvelope(locator, revision) {
  return assertWorkEnvelope({
    version: 1,
    kind: "receipt",
    locator: assertLocator(locator),
    revision: String(revision || ""),
  });
}

function workEnvelopeKey(envelope) {
  const value = assertWorkEnvelope(envelope);
  const canonical = JSON.stringify([
    value.version,
    value.kind,
    value.locator.namespace,
    value.locator.database,
    value.locator.id,
    value.executionId || null,
    value.revision,
  ]);
  return `w-${crypto.createHash("sha256").update(canonical).digest("base64url")}`;
}

function assertPriority(priority, kind = "operation") {
  const value = Number(priority ?? (kind === "receipt" ? 1 : 50));
  const minimum = kind === "receipt" ? 1 : 10;
  const maximum = kind === "receipt" ? 1 : 100;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RuntimeError("INVALID_WORK_PRIORITY", `Priority for ${kind} must be an integer from ${minimum} to ${maximum}`, 400);
  }
  return value;
}

function normalizeDecision(value) {
  const decision = value || { action: "ack" };
  if (!ACTIONS.has(decision.action)) {
    throw new RuntimeError("INVALID_QUEUE_DECISION", "Invalid queue consumer decision", 500);
  }
  if (decision.action === "retry") {
    const delayMs = Number(decision.delayMs ?? Number(decision.delaySeconds || 0) * 1000);
    if (!Number.isFinite(delayMs) || delayMs < 0) {
      throw new RuntimeError("INVALID_QUEUE_DELAY", "Invalid retry delay", 500);
    }
    return { action: "retry", delayMs: Math.floor(delayMs) };
  }
  if (decision.action === "dead-letter") {
    return { action: "dead-letter", reason: String(decision.reason || "rejected") };
  }
  return { action: "ack" };
}

module.exports = {
  WORK_KINDS,
  assertLocator,
  assertOperationEnvelope,
  assertPriority,
  assertWorkEnvelope,
  locatorKey,
  normalizeDecision,
  operationEnvelope,
  receiptEnvelope,
  workEnvelopeKey,
};
