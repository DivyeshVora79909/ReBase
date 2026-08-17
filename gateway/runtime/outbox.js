const crypto = require("node:crypto");

function createOutboxRelay({ database, queue, workerId = `outbox-${crypto.randomUUID()}`, batchSize = 50 }) {
  let running = null;
  return {
    workerId,
    async close() {
      await running;
    },
    runOnce() {
      if (running) return running;
      running = (async () => {
        const rows = (await database.claimOutbox(workerId, batchSize) || []).filter(Boolean);
        let published = 0;
        let failed = 0;
        for (const row of rows) {
          try {
            await queue.publish(row.envelope);
            await database.markOutboxPublished(row.id, workerId, row.revision);
            published += 1;
          } catch (error) {
            await database.markOutboxFailed(row.id, workerId, row.revision, error);
            failed += 1;
          }
        }
        return { claimed: rows.length, published, failed };
      })().finally(() => { running = null; });
      return running;
    },
  };
}

module.exports = { createOutboxRelay };
