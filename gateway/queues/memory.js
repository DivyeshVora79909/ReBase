const { assertEnvelope, normalizeDecision } = require("./port");

function createMemoryQueue(options = {}) {
  const pending = [];
  const deadLetters = [];
  let consumer = null;
  let closed = false;
  let timer = null;
  let draining = null;
  let sequence = 0;

  function schedule() {
    if (timer || closed || !consumer) return;
    timer = setTimeout(async () => {
      timer = null;
      await drain();
    }, 0);
  }

  async function deliver(message) {
    let decision;
    try {
      decision = normalizeDecision(await consumer({
        id: message.id,
        envelope: message.envelope,
        attempts: message.attempts,
        receivedAt: new Date().toISOString(),
      }));
    } catch {
      decision = { action: "retry", delaySeconds: Math.max(0, Number(options.errorDelaySeconds || 0)) };
    }
    if (decision.action === "retry") {
      pending.push({ ...message, attempts: message.attempts + 1, availableAt: Date.now() + decision.delaySeconds * 1000 });
    } else if (decision.action === "dead-letter") {
      deadLetters.push({ ...message, reason: decision.reason });
    }
  }

  async function drain() {
    if (draining) return draining;
    if (!consumer || closed) return undefined;
    draining = (async () => {
      const now = Date.now();
      const due = pending.filter((message) => message.availableAt <= now);
      for (const message of due) pending.splice(pending.indexOf(message), 1);
      for (const message of due) await deliver(message);
      if (pending.length && !timer) {
        const delay = Math.max(0, Math.min(...pending.map((message) => message.availableAt)) - Date.now());
        timer = setTimeout(async () => { timer = null; await drain(); }, delay);
      }
    })();
    try {
      return await draining;
    } finally {
      draining = null;
    }
  }

  return {
    provider: "memory",
    async publish(envelope, options = {}) {
      assertEnvelope(envelope);
      const message = {
        id: `memory-${++sequence}`,
        envelope: structuredClone(envelope),
        attempts: 1,
        availableAt: Date.now() + Math.max(0, Number(options.delaySeconds || 0)) * 1000,
      };
      pending.push(message);
      schedule();
      return { messageId: message.id };
    },
    async start(handler) {
      if (consumer) throw new Error("Memory queue consumer already started");
      consumer = handler;
      schedule();
      return async () => { consumer = null; };
    },
    async flush() {
      do {
        await drain();
      } while (draining || pending.some((message) => message.availableAt <= Date.now()));
    },
    async close() {
      closed = true;
      if (timer) clearTimeout(timer);
    },
    inspect() {
      return { pending: structuredClone(pending), deadLetters: structuredClone(deadLetters) };
    },
    autoStart: options.autoStart !== false,
  };
}

module.exports = { createMemoryQueue };
