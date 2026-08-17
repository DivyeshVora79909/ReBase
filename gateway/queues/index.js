const { createMemoryQueue } = require("./memory");
const { createSqsQueue } = require("./sqs");

function createQueue(options = {}) {
  const provider = options.provider || process.env.REBASE_QUEUE_PROVIDER || "memory";
  if (provider === "memory") {
    if ((options.environment || process.env.NODE_ENV) === "production") {
      throw new Error("The memory queue adapter is not allowed in production");
    }
    return createMemoryQueue(options.memory);
  }
  if (provider === "sqs") return createSqsQueue(options.sqs);
  throw new Error(`Unsupported queue provider: ${provider}`);
}

module.exports = { createQueue, createMemoryQueue, createSqsQueue };
