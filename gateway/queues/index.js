const { createSqsQueue } = require("./sqs");
const { createBullMqPort } = require("./bullmq");

function createQueue(options = {}) {
  const provider = options.provider || "bullmq";
  if (provider === "bullmq" || provider === "redis") return createBullMqPort(options.bullmq || options.redis || options);
  if (provider === "sqs") return createSqsQueue(options.sqs || {});
  throw new Error(`Unsupported queue provider: ${provider}`);
}

module.exports = { createBullMqPort, createQueue, createSqsQueue };
