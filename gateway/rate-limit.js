const Redis = require("ioredis");

const CONSUME_SCRIPT = `
  local count = redis.call('INCR', KEYS[1])
  if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
  local ttl = redis.call('PTTL', KEYS[1])
  return { count, ttl }
`;

function decision(count, ttl, limit) {
  return {
    allowed: count <= limit,
    remaining: Math.max(0, limit - count),
    retryAfterMs: Math.max(0, Number(ttl) || 0),
  };
}

function assertPolicy(policy = {}) {
  const limit = Number(policy.limit);
  const windowMs = Number(policy.windowMs);
  if (!Number.isInteger(limit) || limit < 1) throw new Error("Rate limit must be a positive integer");
  if (!Number.isInteger(windowMs) || windowMs < 1000) throw new Error("Rate-limit window must be at least 1000ms");
  return { limit, windowMs };
}

function createMemoryRateLimiter(options = {}) {
  const entries = new Map();
  const now = options.now || Date.now;
  return {
    async consume(key, policy) {
      const { limit, windowMs } = assertPolicy(policy);
      const currentTime = now();
      let entry = entries.get(key);
      if (!entry || entry.expiresAt <= currentTime) {
        entry = { count: 0, expiresAt: currentTime + windowMs };
        entries.set(key, entry);
      }
      entry.count += 1;
      return decision(entry.count, entry.expiresAt - currentTime, limit);
    },
    async health() { return { ok: true, provider: "memory" }; },
    async close() { entries.clear(); },
  };
}

function createRedisRateLimiter(options = {}) {
  if (!options.url) throw new Error("REBASE_QUEUE_REDIS_URL is required for Redis rate limiting");
  const redis = options.redis || new Redis(options.url, {
    lazyConnect: true,
    enableReadyCheck: true,
    maxRetriesPerRequest: 1,
    connectTimeout: options.connectTimeoutMs || 5000,
  });
  const prefix = String(options.prefix || "rebase:rate-limit").replace(/:+$/, "");
  async function connected() {
    if (redis.status === "wait") await redis.connect();
  }
  return {
    async consume(key, policy) {
      const { limit, windowMs } = assertPolicy(policy);
      await connected();
      const result = await redis.eval(CONSUME_SCRIPT, 1, `${prefix}:${key}`, windowMs);
      return decision(Number(result[0]), Number(result[1]), limit);
    },
    async health() {
      try {
        await connected();
        return { ok: await redis.ping() === "PONG", provider: "redis" };
      } catch {
        return { ok: false, provider: "redis" };
      }
    },
    async close() {
      if (["end", "close"].includes(redis.status)) return;
      if (redis.status === "wait") {
        redis.disconnect();
        return;
      }
      await redis.quit().catch(() => redis.disconnect());
    },
  };
}

module.exports = {
  assertPolicy,
  createMemoryRateLimiter,
  createRedisRateLimiter,
};
