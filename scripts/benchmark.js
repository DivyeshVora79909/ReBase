const { performance } = require("node:perf_hooks");
const ss = require("simple-statistics");

const isNumber = (value) => typeof value === "number" && Number.isFinite(value);

function round(value, digits = 3) {
  if (value == null) return null;

  const numeric = Number(value);
  return Number.isFinite(numeric) ? Number(numeric.toFixed(digits)) : null;
}

function percentileSorted(sorted, ratio) {
  if (!sorted.length) return null;
  if (ratio <= 0) return sorted[0];
  if (ratio >= 1) return sorted.at(-1);

  const index = (sorted.length - 1) * ratio;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);

  if (lower === upper) return sorted[lower];

  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

function mode(values) {
  const counts = new Map();
  let best = null;
  let bestCount = 0;

  for (const value of values) {
    const count = (counts.get(value) ?? 0) + 1;
    counts.set(value, count);

    if (count > bestCount) {
      best = value;
      bestCount = count;
    }
  }

  return bestCount > 1 ? best : null;
}

function numericStats(values) {
  const numbers = Array.isArray(values) ? values.filter(isNumber) : [];

  if (!numbers.length) {
    return { count: 0 };
  }

  const sorted = [...numbers].sort((left, right) => left - right);
  const variance = numbers.length > 1 ? ss.sampleVariance(numbers) : 0;

  return {
    count: numbers.length,
    min: round(sorted[0]),
    max: round(sorted.at(-1)),
    mean: round(ss.mean(numbers)),
    median: round(percentileSorted(sorted, 0.5)),
    mode: round(mode(numbers)),
    variance: round(variance, 6),
    stdDev: round(Math.sqrt(variance), 6),
    p5: round(percentileSorted(sorted, 0.05)),
    p25: round(percentileSorted(sorted, 0.25)),
    p50: round(percentileSorted(sorted, 0.5)),
    p75: round(percentileSorted(sorted, 0.75)),
    p95: round(percentileSorted(sorted, 0.95)),
    p99: round(percentileSorted(sorted, 0.99)),
  };
}

function statsDeep(value) {
  if (Array.isArray(value)) {
    if (value.every(isNumber)) return numericStats(value);
    return value.map(statsDeep);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, statsDeep(item)]),
    );
  }

  return value;
}

function defaultSerialize(value) {
  try {
    const text = JSON.stringify(value);
    return typeof text === "string" ? text : "";
  } catch {
    return String(value);
  }
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function countKeys(value, key) {
  let count = 0;
  const seen = new WeakSet();

  const walk = (node) => {
    if (!node || typeof node !== "object") return;
    if (seen.has(node)) return;

    seen.add(node);

    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }

    for (const [childKey, childValue] of Object.entries(node)) {
      if (childKey === key) count += 1;
      walk(childValue);
    }
  };

  walk(value);
  return count;
}

function size(value) {
  if (value == null) return 0;

  if (Array.isArray(value)) return value.length;
  if (typeof value === "string") return value.length;
  if (value instanceof Map || value instanceof Set) return value.size;
  if (typeof value === "object") return Object.keys(value).length;

  return 1;
}

function runProbe(probe, output, serialize) {
  if (!probe?.name) {
    throw new Error("Each probe requires a name");
  }

  if (probe.type === "regex") {
    if (!probe.pattern) {
      throw new Error(`Probe ${probe.name} requires a pattern`);
    }

    const text = serialize(output);
    const matches = text.match(new RegExp(probe.pattern, probe.flags ?? "gi"));
    return matches ? matches.length : 0;
  }

  if (probe.type === "value") {
    if (probe.value == null) {
      throw new Error(`Probe ${probe.name} requires a value`);
    }

    const text = serialize(output);
    const matches = text.match(
      new RegExp(escapeRegex(probe.value), probe.flags ?? "g"),
    );

    return matches ? matches.length : 0;
  }

  if (probe.type === "key") {
    return countKeys(output, probe.key ?? probe.name);
  }

  if (probe.type === "size") {
    return size(output);
  }

  throw new Error(`Unknown probe type: ${probe.type}`);
}

function normalizeTask(task, index) {
  if (typeof task === "string") {
    task = { query: task };
  }

  if (!task || typeof task !== "object") {
    throw new Error(`queries[${index}] must be a string or object`);
  }

  if (!task.query || typeof task.query !== "string") {
    throw new Error(`queries[${index}] requires a query string`);
  }

  return {
    name: task.name || `query_${index + 1}`,
    query: task.query,
    vars: task.vars || {},
    probes: Array.isArray(task.probes) ? task.probes : [],
  };
}

async function benchmark(options = {}) {
  const {
    run,
    db,
    queries,
    vars = {},
    samples = 10,
    warmups = 1,
    probes = [],
    serialize = defaultSerialize,
  } = options;

  if (!Array.isArray(queries) || !queries.length) {
    throw new Error("benchmark requires a non-empty queries array");
  }

  if (!Number.isInteger(samples) || samples < 1) {
    throw new Error("samples must be a positive integer");
  }

  if (!Number.isInteger(warmups) || warmups < 0) {
    throw new Error("warmups must be a non-negative integer");
  }

  let execute;

  if (typeof run === "function") {
    execute = run;
  } else if (db?.query) {
    execute = (task) => db.query(task.query, task.vars);
  } else {
    throw new Error("benchmark requires either run() or db.query");
  }

  const tasks = queries.map(normalizeTask);

  const raw = {
    benchmarks: [],
    comparisons: {
      timings: [],
      metrics: {},
    },
  };

  for (const task of tasks) {
    const taskVars = {
      ...vars,
      ...task.vars,
    };

    const taskProbes = [...probes, ...task.probes];

    const probeNames = new Set();

    for (const probe of taskProbes) {
      if (!probe?.name) {
        throw new Error("Each probe requires a name");
      }

      if (probeNames.has(probe.name)) {
        throw new Error(`Duplicate probe name: ${probe.name}`);
      }

      probeNames.add(probe.name);
    }

    for (let index = 0; index < warmups; index += 1) {
      await execute({
        query: task.query,
        vars: taskVars,
      });
    }

    const timings = [];
    const metrics = {};

    for (const probe of taskProbes) {
      metrics[probe.name] = [];
    }

    for (let index = 0; index < samples; index += 1) {
      const started = performance.now();

      const output = await execute({
        query: task.query,
        vars: taskVars,
      });

      timings.push(performance.now() - started);

      for (const probe of taskProbes) {
        metrics[probe.name].push(runProbe(probe, output, serialize));
      }
    }

    raw.benchmarks.push({
      name: task.name,
      query: task.query,
      timings,
      metrics,
    });

    raw.comparisons.timings.push(...timings);

    for (const [name, values] of Object.entries(metrics)) {
      if (!raw.comparisons.metrics[name]) {
        raw.comparisons.metrics[name] = [];
      }

      raw.comparisons.metrics[name].push(...values);
    }
  }

  return statsDeep(raw);
}

function toTable(report) {
  const benchmarks = report?.benchmarks || [];

  return benchmarks.map((item) => {
    const timing = item.timings || {};

    const row = {
      name: item.name,
      samples: timing.count ?? 0,
      meanMs: timing.mean ?? null,
      medianMs: timing.median ?? null,
      modeMs: timing.mode ?? null,
      p5Ms: timing.p5 ?? null,
      p95Ms: timing.p95 ?? null,
      varianceMs2: timing.variance ?? null,
      stdDevMs: timing.stdDev ?? null,
    };

    const metrics = item.metrics || {};

    for (const [metric, metricStats] of Object.entries(metrics)) {
      row[metric] = metricStats?.mean ?? null;
    }

    return row;
  });
}

module.exports = {
  benchmark,
  toTable,
  stats: numericStats,
  statsDeep,
};
