const { assertEnvelope, normalizeDecision } = require("./port");

function createSqsQueue(options = {}) {
  const {
    SQSClient,
    ChangeMessageVisibilityCommand,
    DeleteMessageCommand,
    ReceiveMessageCommand,
    SendMessageCommand,
  } = require("@aws-sdk/client-sqs");
  const queueUrl = options.queueUrl || process.env.SQS_QUEUE_URL;
  if (!queueUrl) throw new Error("Missing SQS_QUEUE_URL");
  const client = options.client || new SQSClient({
    region: options.region || process.env.AWS_REGION,
    endpoint: options.endpoint || process.env.SQS_ENDPOINT,
  });
  const waitTimeSeconds = options.waitTimeSeconds ?? 20;
  const visibilityTimeout = options.visibilityTimeout ?? 300;
  const deadLetterQueueUrl = options.deadLetterQueueUrl || process.env.SQS_DEAD_LETTER_QUEUE_URL;
  let stopped = false;
  let loop = null;

  async function publish(envelope, publishOptions = {}) {
    assertEnvelope(envelope);
    const response = await client.send(new SendMessageCommand({
      QueueUrl: queueUrl,
      MessageBody: JSON.stringify(envelope),
      DelaySeconds: Math.min(900, Math.max(0, Math.floor(publishOptions.delaySeconds || 0))),
    }));
    return { messageId: response.MessageId };
  }

  async function handle(message, consumer) {
    let envelope;
    try {
      envelope = assertEnvelope(JSON.parse(message.Body));
    } catch (error) {
      if (deadLetterQueueUrl) {
        await client.send(new SendMessageCommand({
          QueueUrl: deadLetterQueueUrl,
          MessageBody: JSON.stringify({ invalidMessageId: message.MessageId, deadLetterReason: "invalid-envelope" }),
        }));
      }
      await client.send(new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: message.ReceiptHandle }));
      return;
    }
    let decision;
    try {
      decision = normalizeDecision(await consumer({
        id: message.MessageId,
        envelope,
        attempts: Number(message.Attributes?.ApproximateReceiveCount || 1),
        receivedAt: new Date().toISOString(),
      }));
    } catch (error) {
      decision = { action: "retry", delaySeconds: options.consumerErrorDelaySeconds ?? 5 };
    }
    if (decision.action === "dead-letter" && deadLetterQueueUrl) {
      await client.send(new SendMessageCommand({
        QueueUrl: deadLetterQueueUrl,
        MessageBody: JSON.stringify({ ...envelope, deadLetterReason: decision.reason }),
      }));
    }
    if (decision.action === "ack" || decision.action === "dead-letter") {
      await client.send(new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: message.ReceiptHandle }));
      return;
    }
    await client.send(new ChangeMessageVisibilityCommand({
      QueueUrl: queueUrl,
      ReceiptHandle: message.ReceiptHandle,
      VisibilityTimeout: Math.min(43200, decision.delaySeconds),
    }));
  }

  async function pollOnce(consumer) {
    const response = await client.send(new ReceiveMessageCommand({
      QueueUrl: queueUrl,
      MaxNumberOfMessages: options.batchSize || 10,
      WaitTimeSeconds: waitTimeSeconds,
      VisibilityTimeout: visibilityTimeout,
      AttributeNames: ["ApproximateReceiveCount"],
    }));
    await Promise.all((response.Messages || []).map((message) => handle(message, consumer)));
    return (response.Messages || []).length;
  }

  async function start(consumer) {
    if (loop) throw new Error("SQS consumer already started");
    stopped = false;
    loop = (async () => {
      while (!stopped) {
        try {
          await pollOnce(consumer);
        } catch (error) {
          if (stopped) break;
          options.onError?.(error);
          await new Promise((resolve) => setTimeout(resolve, options.errorDelayMs || 1000));
        }
      }
    })();
    return async () => {
      stopped = true;
      await loop;
      loop = null;
    };
  }

  return {
    provider: "sqs",
    publish,
    pollOnce,
    start,
    async close() {
      stopped = true;
      if (loop) await loop;
      client.destroy?.();
    },
  };
}

module.exports = { createSqsQueue };
