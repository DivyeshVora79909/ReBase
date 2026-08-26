const { Surreal } = require("surrealdb");

function sessionEndpoint(endpoint) {
  if (!endpoint) throw new Error("SURREAL_ENDPOINT is required");
  const url = new URL(String(endpoint));
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  else if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error(`Unsupported SurrealDB endpoint protocol: ${url.protocol}`);
  }
  const pathname = url.pathname.replace(/\/$/, "");
  url.pathname = pathname.endsWith("/rpc") ? pathname : `${pathname}/rpc`;
  return url.toString();
}

async function connectWithTimeout(db, endpoint, timeoutMs, connectOptions = {}) {
  let timer;
  try {
    await Promise.race([
      db.connect(endpoint, connectOptions),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const error = new Error(`SurrealDB connection timed out after ${timeoutMs}ms`);
          error.code = "SURREAL_CONNECT_TIMEOUT";
          reject(error);
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    await db.close().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function connectDatabase(options = {}) {
  const { namespace, database } = options;
  if (!namespace || !database) throw new Error("Namespace and database are required");
  const timeoutMs = options.connectTimeoutMs || 10000;
  const db = new Surreal();
  await connectWithTimeout(
    db,
    sessionEndpoint(options.endpoint),
    timeoutMs,
    {
      namespace,
      database,
      authentication: {
        username: options.username,
        password: options.password,
      },
      ...(options.reconnect === undefined ? {} : { reconnect: options.reconnect }),
      ...(options.expiryMargin === undefined ? {} : { expiryMargin: options.expiryMargin }),
      ...(options.invalidateOnExpiry === undefined ? {} : { invalidateOnExpiry: options.invalidateOnExpiry }),
    },
  );
  return { db, namespace, database, close: () => db.close() };
}

module.exports = { connectDatabase, sessionEndpoint };
