const { createSqsQueue } = require("./sqs");
const { createBullMqPort } = require("./bullmq");

function createQueue(options = {}) {
  const driver = options.driver || "bullmq";
  if (driver === "bullmq") return createBullMqPort(options.bullmq || {});
  if (driver === "sqs") return createSqsQueue(options.sqs || {});
  throw new Error(`Unsupported queue driver: ${driver}`);
}

module.exports = { createBullMqPort, createQueue, createSqsQueue };
