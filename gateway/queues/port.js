const crypto = require("node:crypto");
const { RuntimeError } = require("../errors");

const LANES = Object.freeze(["task", "schedule", "webhook"]);
const LANE_SET = new Set(LANES);
const ACTIONS = new Set(["ack", "retry", "dead-letter"]);

function assertLane(lane) {
  if (!LANE_SET.has(lane)) throw new RuntimeError("INVALID_QUEUE_LANE", `Invalid queue lane: ${lane}`, 400);
  return lane;
}

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

function scheduleKey(key) {
  const normalized = String(key || "");
  if (!normalized) throw new RuntimeError("INVALID_SCHEDULE_KEY", "Schedule key is required", 400);
  return crypto.createHash("sha256").update(normalized).digest("base64url");
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
  LANES,
  assertLane,
  assertLocator,
  locatorKey,
  normalizeDecision,
  scheduleKey,
};
