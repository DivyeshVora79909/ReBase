const { connectDatabase } = require('./connection');
const { createTableStore } = require('./store');

function contextKey(namespace, database) {
  if (typeof namespace !== 'string' || !namespace || typeof database !== 'string' || !database) {
    throw new Error('Namespace and database are required');
  }
  return `${namespace}\u0000${database}`;
}

function assertDesign(design, namespace, database) {
  if ((namespace !== undefined && namespace !== design.namespace)
    || (database !== undefined && database !== design.database)) {
    throw new Error('Database design context mismatch');
  }
}

function fixedStoreDirectory(store, context = {}) {
  return {
    async forContext(namespace, database) {
      assertDesign(context, namespace, database);
      return store;
    },
    async close() {},
    size() { return 1; },
  };
}

// One lazy shared connection per process design. Tenants do not allocate
// connections, caches or reconciliation loops. A failed connect can retry.
function createStoreDirectory({ connect, context } = {}) {
  let design = context;
  let pending;
  let closed = false;
  return {
    async forContext(namespace = design?.namespace, database = design?.database) {
      if (closed) throw new Error('Database connection is closed');
      if (!design) {
        contextKey(namespace, database);
        design = { namespace, database };
      }
      assertDesign(design, namespace, database);
      if (!pending) {
        pending = Promise.resolve().then(() => connect(design)).catch(error => {
          pending = undefined;
          throw error;
        });
      }
      return pending;
    },
    async close() {
      if (closed) return;
      closed = true;
      const store = await pending?.catch(() => null);
      await store?.close?.();
      pending = undefined;
    },
    size() { return pending ? 1 : 0; },
  };
}

function createSurrealStoreDirectory(options = {}) {
  const databaseOptions = options.databaseOptions || {};
  const context = databaseOptions.defaultContext || databaseOptions;
  contextKey(context.namespace, context.database);
  return createStoreDirectory({
    context: { namespace: context.namespace, database: context.database },
    async connect(design) {
      const connection = await connectDatabase({ ...databaseOptions, ...design });
      return { ...createTableStore(connection), close: () => connection.close() };
    },
  });
}

module.exports = { contextKey, createStoreDirectory, createSurrealStoreDirectory, fixedStoreDirectory };
