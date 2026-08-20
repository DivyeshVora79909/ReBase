const { connectDatabase } = require("./connection");
const { createTableStore } = require("./store");

function contextKey(namespace, database) {
  if (typeof namespace !== "string" || !namespace || typeof database !== "string" || !database) {
    throw new Error("Namespace and database are required");
  }
  return `${namespace}\u0000${database}`;
}

function fixedStoreDirectory(store, context = {}) {
  return {
    async forContext(namespace, database) {
      if (context.namespace && namespace !== context.namespace) throw new Error("Namespace context mismatch");
      if (context.database && database !== context.database) throw new Error("Database context mismatch");
      return store;
    },
    async close() {},
  };
}

function createStoreDirectory({ connect, idleMs = 15 * 60 * 1000, maxContexts = 1000 }) {
  const contexts = new Map();

  async function closeEntry(key, entry) {
    contexts.delete(key);
    const resolved = await entry.promise.catch(() => null);
    await resolved?.close?.();
  }

  async function sweep() {
    const now = Date.now();
    const idle = [...contexts].filter(([, entry]) => now - entry.usedAt > idleMs);
    for (const [key, entry] of idle) await closeEntry(key, entry);
  }

  return {
    async forContext(namespace, database) {
      const key = contextKey(namespace, database);
      let entry = contexts.get(key);
      if (!entry) {
        await sweep();
        if (contexts.size >= maxContexts) {
          throw new Error(`SurrealDB context limit reached: ${maxContexts}`);
        }
        entry = {
          usedAt: Date.now(),
          promise: Promise.resolve(connect({ namespace, database })).catch((error) => {
            contexts.delete(key);
            throw error;
          }),
        };
        contexts.set(key, entry);
      }
      entry.usedAt = Date.now();
      return entry.promise;
    },
    async close() {
      for (const [key, entry] of [...contexts]) await closeEntry(key, entry);
    },
    size() { return contexts.size; },
  };
}

function createSurrealStoreDirectory(options = {}) {
  return createStoreDirectory({
    idleMs: options.idleMs,
    maxContexts: options.maxContexts,
    async connect({ namespace, database }) {
      const connection = await connectDatabase({
        ...(options.databaseOptions || {}),
        namespace,
        database,
      });
      return { ...createTableStore(connection), close: () => connection.close() };
    },
  });
}

module.exports = { contextKey, createStoreDirectory, createSurrealStoreDirectory, fixedStoreDirectory };
