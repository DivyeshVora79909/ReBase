const { GatewayError } = require("../runtime/errors");

const ACTIONS = new Set(["ack", "retry", "dead-letter"]);

function normalizeDecision(value) {
  const decision = value || { action: "ack" };
  if (!ACTIONS.has(decision.action)) throw new GatewayError("INVALID_QUEUE_DECISION", "Invalid queue consumer decision", 500);
  if (decision.action === "retry") {
    const delaySeconds = Number(decision.delaySeconds || 0);
    if (!Number.isFinite(delaySeconds) || delaySeconds < 0) throw new GatewayError("INVALID_QUEUE_DELAY", "Invalid retry delay", 500);
    return { action: "retry", delaySeconds: Math.floor(delaySeconds) };
  }
  if (decision.action === "dead-letter") return { action: "dead-letter", reason: String(decision.reason || "rejected") };
  return { action: "ack" };
}

function assertEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object" || typeof envelope.jobId !== "string" || typeof envelope.capability !== "string") {
    throw new GatewayError("INVALID_QUEUE_ENVELOPE", "Invalid queue envelope", 500);
  }
  return envelope;
}

module.exports = { assertEnvelope, normalizeDecision };
