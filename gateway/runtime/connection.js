const { Features } = require("surrealdb");

async function connectWithTimeout(db, endpoint, timeoutMs = 10000) {
  if (!db || typeof db.connect !== "function") {
    throw new Error("A SurrealDB client is required");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
    throw new Error("SurrealDB connect timeout must be a positive number");
  }
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
    await db.close?.().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
  return db;
}

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

function requireSessionSupport(db) {
  if (
    typeof db?.isFeatureSupported === "function" &&
    !db.isFeatureSupported(Features.Sessions)
  ) {
    throw new Error(
      "The SurrealDB connection must use the WebSocket engine because ReBase requires isolated sessions",
    );
  }
}

module.exports = { connectWithTimeout, requireSessionSupport, sessionEndpoint };
