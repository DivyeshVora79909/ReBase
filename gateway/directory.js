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
    size() { return 1; },
  };
}

function wrapStore(entry, store) {
  return new Proxy(store, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== "function" || property === "close") return value;
      return async (...args) => {
        entry.active += 1;
        entry.usedAt = Date.now();
        try {
          return await value.apply(target, args);
        } finally {
          entry.active -= 1;
          entry.usedAt = Date.now();
        }
      };
    },
  });
}

function createStoreDirectory({ connect, idleMs = 15 * 60 * 1000, maxContexts = 1000 }) {
  const contexts = new Map();

  async function closeEntry(key, entry) {
    if (entry.active > 0 || contexts.get(key) !== entry) return false;
    contexts.delete(key);
    const resolved = await entry.promise.catch(() => null);
    await resolved?.close?.();
    return true;
  }

  async function sweep(exceptKey) {
    const now = Date.now();
    const idle = [...contexts].filter(([key, entry]) => key !== exceptKey && entry.active === 0 && now - entry.usedAt > idleMs);
    for (const [key, entry] of idle) await closeEntry(key, entry);
  }

  return {
    async forContext(namespace, database) {
      const key = contextKey(namespace, database);
      let entry = contexts.get(key);
      if (entry) {
        entry.usedAt = Date.now();
        return entry.promise;
      }
      await sweep();
      entry = contexts.get(key);
      if (entry) {
        entry.usedAt = Date.now();
        return entry.promise;
      }
      if (contexts.size >= maxContexts) throw new Error(`SurrealDB context limit reached: ${maxContexts}`);
      entry = { active: 0, usedAt: Date.now(), promise: null };
      contexts.set(key, entry);
      entry.promise = (async () => {
        const store = await connect({ namespace, database });
        return wrapStore(entry, store);
      })().catch((error) => {
        if (contexts.get(key) === entry) contexts.delete(key);
        throw error;
      });
      return entry.promise;
    },
    async close() {
      for (const [key, entry] of [...contexts]) {
        await entry.promise.catch(() => null);
        await closeEntry(key, entry);
      }
    },
    async sweep() { return sweep(); },
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
