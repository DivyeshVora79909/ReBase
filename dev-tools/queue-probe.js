#!/usr/bin/env node

const assert = require("node:assert/strict");
const { createSqsQueue } = require("../gateway/queues/sqs");

function fakeSqs() {
  const commands = [];
  const receives = new Map();
  let message = 0;
  return {
    commands,
    enqueue(queueUrl, messages) {
      const batches = receives.get(queueUrl) || [];
      batches.push(messages);
      receives.set(queueUrl, batches);
    },
    async send(command) {
      const name = command.constructor.name;
      commands.push({ name, input: command.input });
      if (name === "SendMessageCommand") return { MessageId: `message-${++message}` };
      if (name === "ReceiveMessageCommand") {
        const batches = receives.get(command.input.QueueUrl) || [];
        return { Messages: batches.shift() || [] };
      }
      if (name === "GetQueueAttributesCommand") return { Attributes: { QueueArn: "arn:probe" } };
      return {};
    },
    destroy() {},
  };
}

function message(body, receiveCount = 1, id = "source") {
  return {
    MessageId: id,
    ReceiptHandle: `receipt-${id}`,
    Body: body,
    Attributes: { ApproximateReceiveCount: String(receiveCount) },
  };
}

async function main() {
  const client = fakeSqs();
  const queueUrls = { task: "task-url", schedule: "schedule-url", webhook: "webhook-url" };
  const deadLetterQueueUrls = { task: "task-dead", schedule: "schedule-dead", webhook: "webhook-dead" };
  const port = createSqsQueue({
    client,
    queueUrls,
    deadLetterQueueUrls,
    policies: { task: { attempts: 3, waitTimeSeconds: 0 } },
  });
  const locator = { namespace: "tenant", database: "app", id: "send_brevo_email:one" };

  await port.publish("task", locator, { delayMs: 2_000_000, jobId: "domain:event:1" });
  const published = client.commands.find((command) => command.name === "SendMessageCommand");
  assert.equal(published.input.DelaySeconds, 900);
  assert.deepEqual(JSON.parse(published.input.MessageBody), locator);

  client.enqueue("task-url", [message(JSON.stringify(locator), 1, "ack")]);
  assert.equal(await port.pollOnce("task", async (delivery) => {
    assert.deepEqual(delivery.locator, locator);
    assert.equal(delivery.attempts, 1);
    return { action: "ack" };
  }), 1);
  assert(client.commands.some((command) => command.name === "DeleteMessageCommand" && command.input.ReceiptHandle === "receipt-ack"));

  client.enqueue("task-url", [message(JSON.stringify(locator), 1, "retry")]);
  await port.pollOnce("task", async () => ({ action: "retry", delayMs: 2500 }));
  assert(client.commands.some((command) => command.name === "ChangeMessageVisibilityCommand"
    && command.input.ReceiptHandle === "receipt-retry" && command.input.VisibilityTimeout === 3));

  client.enqueue("task-url", [message(JSON.stringify(locator), 3, "exhausted")]);
  await port.pollOnce("task", async () => ({ action: "retry", delayMs: 1000 }));
  assert(client.commands.some((command) => command.name === "SendMessageCommand"
    && command.input.QueueUrl === "task-dead" && command.input.MessageBody.includes("retry-exhausted")));

  client.enqueue("task-url", [message("not-json", 1, "invalid")]);
  await port.pollOnce("task", async () => ({ action: "ack" }));
  assert(client.commands.some((command) => command.name === "SendMessageCommand"
    && command.input.QueueUrl === "task-dead" && command.input.MessageBody.includes("invalid-locator")));

  await port.schedule("tenant/app/schedule", locator, new Date(Date.now() + 60_000));
  assert(client.commands.some((command) => command.name === "SendMessageCommand"
    && command.input.QueueUrl === "schedule-url" && command.input.DelaySeconds > 0));
  assert.equal((await port.health()).ok, true);
  await port.close();
  console.log("queues: SQS lane port, delay, retry, dead-letter, invalid locator, schedule, and health passed");
}

if (require.main === module) main().catch((error) => {
  console.error(`queues: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
