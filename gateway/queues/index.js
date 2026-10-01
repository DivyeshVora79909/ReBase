const { createBullMqPort } = require("./bullmq");

function createQueue(options = {}) {
  return createBullMqPort(options.bullmq || options);
}

module.exports = { createBullMqPort, createQueue };
