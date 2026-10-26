import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

/** Resource limits are caller supplied; these defaults are a small local trial profile. */
export const DEFAULT_RESOURCE_BUDGETS = Object.freeze({
  rssBytes: 512 * 1024 * 1024,
  openFiles: 256,
  threads: 96,
  physicalBytes: 512 * 1024 * 1024,
  observerMs: 250,
  maxFiles: 65_536,
});

/**
 * Sample explicitly named process IDs and physical paths. Linux /proc metrics
 * are reported as unavailable on other platforms; the returned record always
 * identifies the platform and the caller supplied native binary metadata.
 */
export async function observeResources({ processes, native, paths = [], maxFiles = DEFAULT_RESOURCE_BUDGETS.maxFiles } = {}) {
  if (!Array.isArray(processes) || processes.length < 1) throw new TypeError('processes must explicitly name at least one { role, pid }');
  if (!native || typeof native.binary !== 'string' || !/^[0-9a-f]{64}$/.test(native.sha256 ?? '')
    || typeof native.model !== 'string' || typeof native.backend !== 'string') {
    throw new TypeError('native metadata must include binary, sha256, model, and backend');
  }
  if (!Array.isArray(paths)) throw new TypeError('paths must be an explicit array');
  positiveInteger(maxFiles, 'maxFiles');
  if (maxFiles > DEFAULT_RESOURCE_BUDGETS.maxFiles) throw new RangeError('maxFiles exceeds the hard physical observation bound');
  const roles = new Set();
  for (const item of processes) {
    if (!item || typeof item.role !== 'string' || !item.role || roles.has(item.role)) throw new TypeError('process roles must be unique non-empty strings');
    positiveInteger(item.pid, `PID for ${item.role}`);
    roles.add(item.role);
  }
  const started = performance.now();
  const linux = process.platform === 'linux';
  const processRows = {};
  for (const item of processes) processRows[item.role] = linux ? await linuxProcess(item.pid) : unavailable(item.pid, 'Linux /proc metrics unavailable');
  const physical = await physicalFiles(paths, maxFiles);
  return Object.freeze({
    at: new Date().toISOString(), platform: process.platform,
    linuxMetricsAvailable: linux,
    metricDisclosure: linux ? 'PID-scoped /proc RSS, descriptors, threads and CPU; explicit paths deduplicated by device/inode'
      : 'Linux /proc metrics unavailable; no substitute process metrics inferred',
    processes: Object.freeze(processRows), physical,
    native: Object.freeze({ binary: path.resolve(native.binary), sha256: native.sha256, model: native.model,
      backend: native.backend, ...(native.store === undefined ? {} : { store: native.store }),
      ...(native.pid === undefined ? {} : { pid: native.pid }) }),
    observerMs: performance.now() - started,
  });
}

/** Check retained raw samples against finite caller budgets. Missing Linux metrics stay incomplete. */
export function checkResources(samples, budgets = {}, { requiredRoles = [] } = {}) {
  if (!Array.isArray(samples) || samples.length === 0) throw new TypeError('at least one raw resource sample is required');
  const limits = { ...DEFAULT_RESOURCE_BUDGETS, ...budgets };
  for (const key of Object.keys(DEFAULT_RESOURCE_BUDGETS)) positiveFinite(limits[key], key);
  if (!Array.isArray(requiredRoles) || requiredRoles.some(role => typeof role !== 'string')) throw new TypeError('requiredRoles must be strings');
  const obligations = [];
  const latest = new Map();
  for (const [index, sample] of samples.entries()) {
    if (!sample || typeof sample.platform !== 'string' || !sample.processes || !sample.native) {
      obligations.push(result(`sample-${index}-shape`, 'failed', 'sample lacks platform, process, or native identity')); continue;
    }
    if (typeof sample.native.binary !== 'string' || !sample.native.binary
      || !/^[0-9a-f]{64}$/.test(sample.native.sha256 ?? '')
      || typeof sample.native.model !== 'string' || !sample.native.model
      || typeof sample.native.backend !== 'string' || !sample.native.backend) {
      obligations.push(result(`sample-${index}-native-identity`, 'failed', 'sample has no complete binary, hash, model, and backend identity'));
    }
    if (typeof sample.observerMs !== 'number' || !Number.isFinite(sample.observerMs) || sample.observerMs < 0) obligations.push(result(`sample-${index}-observer-time`, 'incomplete', 'observer duration is missing or malformed'));
    else if (sample.observerMs > limits.observerMs) obligations.push(result(`sample-${index}-observer-time`, 'failed', 'observation exceeded its time budget'));
    for (const role of requiredRoles) {
      const proc = sample.processes[role];
      if (!proc) { obligations.push(result(`sample-${index}-${role}`, 'incomplete', 'required process role was not sampled')); continue; }
      if (!proc.available) { obligations.push(result(`sample-${index}-${role}`, 'incomplete', 'process metrics unavailable')); continue; }
      if (!Number.isSafeInteger(proc.pid) || proc.pid <= 0) obligations.push(result(`sample-${index}-${role}-pid`, 'failed', 'process identity has an invalid PID'));
      for (const [field, ceiling] of [['rssBytes', limits.rssBytes], ['openFiles', limits.openFiles], ['threads', limits.threads]]) {
        if (typeof proc[field] !== 'number' || !Number.isFinite(proc[field])) obligations.push(result(`sample-${index}-${role}-${field}`, 'incomplete', 'metric unavailable or malformed'));
        else if (proc[field] < 0) obligations.push(result(`sample-${index}-${role}-${field}`, 'failed', 'metric cannot be negative'));
        else if (proc[field] > ceiling) obligations.push(result(`sample-${index}-${role}-${field}`, 'failed', `${field} exceeded its declared budget`));
      }
      latest.set(role, proc);
    }
    if (!sample.physical?.available) obligations.push(result(`sample-${index}-physical`, 'incomplete', 'physical path measurement unavailable'));
    else if (!Number.isSafeInteger(sample.physical.bytes) || !Number.isSafeInteger(sample.physical.files)) obligations.push(result(`sample-${index}-physical`, 'incomplete', 'physical byte or file count is missing or malformed'));
    else if (sample.physical.bytes < 0 || sample.physical.files < 0) obligations.push(result(`sample-${index}-physical`, 'failed', 'physical bytes and file count cannot be negative'));
    else if (sample.physical.bytes > limits.physicalBytes || sample.physical.files > limits.maxFiles) obligations.push(result(`sample-${index}-physical`, 'failed', 'physical bytes or file count exceeded their declared budget'));
  }
  if (obligations.length === 0) obligations.push(result('resource-bounds', 'passed'));
  const status = obligations.some(row => row.status === 'failed') ? 'failed'
    : obligations.some(row => row.status === 'incomplete') ? 'incomplete' : 'passed';
  return Object.freeze({ status, obligations: Object.freeze(obligations), samples: samples.length });
}

async function linuxProcess(pid) {
  try {
    const [statText, statusText, fds, tasks] = await Promise.all([
      readFile(`/proc/${pid}/stat`, 'utf8'), readFile(`/proc/${pid}/status`, 'utf8'),
      readdir(`/proc/${pid}/fd`), readdir(`/proc/${pid}/task`),
    ]);
    const close = statText.lastIndexOf(')');
    const stat = statText.slice(close + 2).trim().split(/\s+/);
    const status = Object.fromEntries(statusText.split('\n').map(line => {
      const [key, value] = line.split(':'); return [key, value?.trim()];
    }).filter(([key, value]) => key && value));
    const rssKb = Number(status.VmRSS?.split(/\s+/)[0]);
    return { available: Number.isFinite(rssKb), pid, rssBytes: Number.isFinite(rssKb) ? rssKb * 1024 : null,
      openFiles: fds.length, threads: tasks.length, cpuTicks: Number(stat[11]) + Number(stat[12]),
      startTicks: Number(stat[19]) };
  } catch { return unavailable(pid, 'PID exited or /proc access failed during observation'); }
}

async function physicalFiles(paths, maxFiles) {
  if (!paths.length) return { available: false, bytes: null, files: 0, paths: [], reason: 'no physical paths supplied' };
  const selected = paths.map(value => path.resolve(value));
  const seen = new Set(); let bytes = 0; let files = 0; let visited = 0;
  try {
    const visit = async value => {
      visited += 1;
      if (visited > maxFiles) throw new Error('physical path file bound exhausted');
      const st = await lstat(value);
      if (st.isSymbolicLink()) return;
      if (st.isDirectory()) {
        for (const name of await readdir(value)) await visit(path.join(value, name));
      } else if (st.isFile()) {
        const id = `${st.dev}:${st.ino}`;
        if (!seen.has(id)) { seen.add(id); bytes += st.size; files += 1; }
      }
    };
    for (const root of selected) await visit(root);
    return { available: true, bytes, files, paths: selected };
  } catch (error) { return { available: false, bytes: null, files, paths: selected, reason: error.message.slice(0, 200) }; }
}

function unavailable(pid, reason) { return { available: false, pid, reason }; }
function result(name, status, reason) { return { name, status, ...(reason ? { reason } : {}) }; }
function positiveInteger(value, name) { if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`); }
function positiveFinite(value, name) { if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) throw new TypeError(`${name} must be finite and positive`); }
