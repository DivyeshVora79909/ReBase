const path = require("node:path");
const { createRedisBackend } = require("bullmq");

const BULLMQ_INTERNALS = path.dirname(require.resolve("bullmq"));
const BULLMQ_VERSION = require(path.join(BULLMQ_INTERNALS, "version.js")).version;
const EXPECTED_BULLMQ_VERSION = "6.2.0";
const CAPACITY_RESULT_PREFIX = "REBASE_ADMISSION_FULL:";

const INSERT_SCRIPTS = Object.freeze({
  addDelayedJob: {
    file: "addDelayedJob-6.js",
    keys: 6,
    marker: "local delay, priority = storeJob(",
  },
  addPrioritizedJob: {
    file: "addPrioritizedJob-9.js",
    keys: 9,
    marker: "local delay, priority = storeJob(",
  },
  addStandardJob: {
    file: "addStandardJob-9.js",
    keys: 9,
    marker: "-- Store the job.\nstoreJob(",
  },
});

if (BULLMQ_VERSION !== EXPECTED_BULLMQ_VERSION) {
  throw new Error(`Atomic BullMQ admission requires ${EXPECTED_BULLMQ_VERSION}; found ${BULLMQ_VERSION}`);
}

function bullMqInsertScript(commandName) {
  const spec = INSERT_SCRIPTS[commandName];
  if (!spec) throw new Error(`Unsupported BullMQ insert command: ${commandName}`);
  const modulePath = path.join(BULLMQ_INTERNALS, "scripts", spec.file);
  const exported = require(modulePath);
  const script = exported[Object.keys(exported)[0]];
  if (!script || script.keys !== spec.keys || typeof script.content !== "string") {
    throw new Error(`BullMQ ${commandName} script shape changed; review atomic capacity admission`);
  }
  const position = script.content.indexOf(spec.marker);
  if (position < 0 || script.content.indexOf(spec.marker, position + 1) >= 0) {
    throw new Error(`BullMQ ${commandName} insertion marker changed; review atomic capacity admission`);
  }
  return { spec, content: script.content };
}

function makeCapacityGuard(keyIndexes) {
  return `-- ReBase: serialize the capacity decision with BullMQ's insertion.\n` +
    `local liveHints = redis.call("LLEN", KEYS[${keyIndexes.wait}]) +\n` +
    `  redis.call("LLEN", KEYS[${keyIndexes.paused}]) +\n` +
    `  redis.call("ZCARD", KEYS[${keyIndexes.prioritized}]) +\n` +
    `  redis.call("ZCARD", KEYS[${keyIndexes.delayed}]) +\n` +
    `  redis.call("LLEN", KEYS[${keyIndexes.active}])\n` +
    `local envelope = cjson.decode(ARGV[2])\n` +
    `local liveLimit = tonumber(ARGV[4])\n` +
    `if envelope.kind ~= "receipt" then\n` +
    `  liveLimit = liveLimit - tonumber(ARGV[5])\n` +
    `end\n` +
    `if liveHints >= liveLimit then\n` +
    `  return "${CAPACITY_RESULT_PREFIX}" .. tostring(liveHints) .. ":" .. tostring(liveLimit)\n` +
    `end\n`;
}

function parseCapacityResult(value) {
  if (typeof value !== "string" || !value.startsWith(CAPACITY_RESULT_PREFIX)) return null;
  const [liveText, limitText] = value.slice(CAPACITY_RESULT_PREFIX.length).split(":");
  const live = Number(liveText);
  const limit = Number(limitText);
  if (!Number.isSafeInteger(live) || !Number.isSafeInteger(limit)) {
    throw new Error("BullMQ returned a malformed atomic admission result");
  }
  return { live, limit };
}

function createAtomicAdmissionBackendFactory(admission) {
  const compiled = new Map();
  for (const commandName of Object.keys(INSERT_SCRIPTS)) {
    compiled.set(commandName, bullMqInsertScript(commandName));
  }

  return (name, options, context) => {
    const backend = createRedisBackend(name, options, context);
    if (name !== "operations") return backend;

    const originalExecCommand = backend.execCommand.bind(backend);
    backend.execCommand = function execCommandWithAtomicAdmission(client, commandName, args) {
      const scriptInfo = compiled.get(commandName);
      if (!scriptInfo) return originalExecCommand(client, commandName, args);

      const { spec, content } = scriptInfo;
      const originalKeys = args.slice(0, spec.keys);
      const argv = args.slice(spec.keys);
      const queueKeys = backend.queue.keys;
      const stateKeys = ["wait", "paused", "prioritized", "delayed", "active"]
        .map((state) => queueKeys[state]);
      const allKeys = [...originalKeys];
      for (const key of stateKeys) {
        if (!allKeys.includes(key)) allKeys.push(key);
      }
      const indexes = Object.fromEntries(stateKeys.map((key, index) => {
        const keyName = ["wait", "paused", "prioritized", "delayed", "active"][index];
        return [keyName, allKeys.indexOf(key) + 1];
      }));
      const marker = spec.marker;
      const script = content.replace(marker, `${makeCapacityGuard(indexes)}${marker}`);
      return client.eval(
        script,
        allKeys.length,
        ...allKeys,
        ...argv,
        admission.maxLiveHints,
        admission.receiptReserve,
      );
    };
    return backend;
  };
}

module.exports = {
  CAPACITY_RESULT_PREFIX,
  createAtomicAdmissionBackendFactory,
  parseCapacityResult,
};
