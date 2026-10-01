#!/usr/bin/env node

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { DEFAULT_ADMISSION, DEFAULT_POLICY } = require("../gateway/queues/bullmq");
const {
  assertOperationEnvelope,
  assertPriority,
  assertWorkEnvelope,
  normalizeDecision,
  operationEnvelope,
  receiptEnvelope,
  workEnvelopeKey,
} = require("../gateway/queues/port");

function main() {
  const locator = { namespace: "tenant", database: "app", id: "send_brevo_email:one" };
  const record = { execution_id: crypto.randomUUID(), revision: crypto.randomUUID() };
  const envelope = operationEnvelope(locator, record);
  assert.deepEqual(assertWorkEnvelope(envelope), envelope);
  assert.deepEqual(assertOperationEnvelope(envelope), envelope);
  assert.match(workEnvelopeKey(envelope), /^w-[A-Za-z0-9_-]+$/);
  assert.notEqual(workEnvelopeKey(envelope), workEnvelopeKey({ ...envelope, revision: crypto.randomUUID() }));
  assert.equal(assertPriority(undefined), 50);
  assert.equal(assertPriority(10), 10);
  assert.equal(assertPriority(100), 100);
  assert.equal(assertPriority(undefined, "receipt"), 1);
  const receipt = receiptEnvelope({ namespace: "tenant", database: "app", id: "provider_receipt:one" }, crypto.randomUUID());
  assert.deepEqual(Object.keys(receipt).sort(), ["kind", "locator", "revision", "version"]);
  assert.equal(assertPriority(undefined, receipt.kind), 1);
  assert.throws(() => assertPriority(0), /Priority/);
  assert.throws(() => assertPriority(101), /Priority/);
  assert.throws(() => assertWorkEnvelope({ ...envelope, priority: 10 }), /envelope/);
  assert.deepEqual(normalizeDecision({ action: "retry", delayMs: 25 }), { action: "retry", delayMs: 25 });
  assert.equal(normalizeDecision({ action: "dead-letter", reason: "x" }).reason, "x");
  assert.deepEqual(DEFAULT_ADMISSION, { maxLiveHints: 1000, receiptReserve: 100 });
  assert.equal(DEFAULT_POLICY.concurrency, 8);
  assert.equal(DEFAULT_POLICY.attempts, 5);
  console.log("queues: versioned work identity, positive priority, shared admission defaults, and decisions passed");
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`queues: FAIL: ${error.stack || error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { main };
