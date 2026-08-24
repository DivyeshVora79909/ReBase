const { Surreal } = require("surrealdb");

function sessionEndpoint(endpoint) {
  const url = new URL(String(endpoint || "ws://127.0.0.1:8000/rpc"));
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  else if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new Error(`Unsupported SurrealDB endpoint protocol: ${url.protocol}`);
  }
  const pathname = url.pathname.replace(/\/$/, "");
  url.pathname = pathname.endsWith("/rpc") ? pathname : `${pathname}/rpc`;
  return url.toString();
}

async function connectWithTimeout(db, endpoint, timeoutMs) {
  let timer;
  try {
    await Promise.race([
      db.connect(endpoint),
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
  const timeoutMs = options.connectTimeoutMs || Number(process.env.SURREAL_CONNECT_TIMEOUT_MS) || 10000;
  const db = new Surreal();
  await connectWithTimeout(
    db,
    sessionEndpoint(options.endpoint || process.env.SURREAL_ENDPOINT),
    timeoutMs,
  );
  const operation = async () => {
    await db.signin({
      username: options.username || process.env.SURREAL_USER,
      password: options.password || process.env.SURREAL_PASS,
    });
    await db.use({ namespace, database });
  };
  let timer;
  try {
    await Promise.race([
      operation(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const error = new Error(`SurrealDB authentication/context setup timed out after ${timeoutMs}ms`);
          error.code = "SURREAL_SETUP_TIMEOUT";
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
  return { db, namespace, database, close: () => db.close() };
}

module.exports = { connectDatabase, sessionEndpoint };
