const { RuntimeError } = require("../errors");

const ACTIONS = new Set(["ack", "retry", "dead-letter"]);

function normalizeDecision(value) {
  const decision = value || { action: "ack" };
  if (!ACTIONS.has(decision.action)) throw new RuntimeError("INVALID_QUEUE_DECISION", "Invalid queue consumer decision", 500);
  if (decision.action === "retry") {
    const delaySeconds = Number(decision.delaySeconds || 0);
    if (!Number.isFinite(delaySeconds) || delaySeconds < 0) throw new RuntimeError("INVALID_QUEUE_DELAY", "Invalid retry delay", 500);
    return { action: "retry", delaySeconds: Math.floor(delaySeconds) };
  }
  if (decision.action === "dead-letter") return { action: "dead-letter", reason: String(decision.reason || "rejected") };
  return { action: "ack" };
}

function assertEnvelope(envelope) {
  const tableEffect = envelope && typeof envelope === "object"
    && typeof envelope.namespace === "string"
    && envelope.namespace.length > 0
    && typeof envelope.database === "string"
    && envelope.database.length > 0
    && typeof envelope.id === "string"
    && /^[A-Za-z_][A-Za-z0-9_]*:.+/.test(envelope.id);
  if (!tableEffect || Object.keys(envelope).some((key) => !["namespace", "database", "id"].includes(key))) {
    throw new RuntimeError("INVALID_QUEUE_ENVELOPE", "Invalid queue envelope", 500);
  }
  return envelope;
}

module.exports = { assertEnvelope, normalizeDecision };
