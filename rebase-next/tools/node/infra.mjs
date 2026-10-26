import { randomUUID } from 'node:crypto';
import { access, open, mkdir, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import net from 'node:net';
import { spawn } from 'node:child_process';
import path from 'node:path';

const MAX_OUTPUT_BYTES = 1_048_576;
const DEFAULT_SERVER_ARGS = Object.freeze(['-m', '512', '--cache-memory', '128', '--storage-memory', '128']);

/**
 * Own one local FoundationDB test server process. It never attaches to or kills
 * a PID from disk; only the ChildProcess created by this handle can be stopped.
 */
export async function openFdbEnvironment({ fdbserver, fdbcli, clusterFile, dataDirectory,
  logDirectory, serverLog, host = '127.0.0.1', port, environment, startTimeoutMs = 10_000,
  stopTimeoutMs = 10_000, commandTimeoutMs = 20_000 } = {}) {
  for (const [name, value] of Object.entries({ fdbserver, fdbcli, clusterFile, dataDirectory, logDirectory, serverLog })) {
    absolutePath(value, name);
  }
  if (host !== '127.0.0.1') throw new TypeError('managed FoundationDB must bind to 127.0.0.1');
  boundedInteger(port, 1, 65_535, 'port');
  for (const [name, value] of Object.entries({ startTimeoutMs, stopTimeoutMs, commandTimeoutMs })) {
    boundedInteger(value, 1, 120_000, name);
  }
  if (!plain(environment) || Object.values(environment).some(value => typeof value !== 'string' || value.includes('\0'))) {
    throw new TypeError('environment must be an explicit object of strings without NUL');
  }
  for (const [name, target] of Object.entries({ fdbserver, fdbcli, clusterFile })) {
    const info = await stat(target);
    if (!info.isFile()) throw new TypeError(`${name} must be a regular file`);
  }
  await Promise.all([access(fdbserver, constants.X_OK), access(fdbcli, constants.X_OK)]);

  const address = `${host}:${port}`;
  const cluster = { host, port, address, fdbserver: path.resolve(fdbserver), fdbcli: path.resolve(fdbcli),
    clusterFile: path.resolve(clusterFile), dataDirectory: path.resolve(dataDirectory),
    logDirectory: path.resolve(logDirectory), serverLog: path.resolve(serverLog) };
  let child = null;
  let output = null;
  let startPromise = null;
  let closePromise = null;

  const api = Object.freeze({
    cluster: Object.freeze(cluster),
    get pid() { return child?.pid ?? null; },
    start() {
      startPromise ??= startOwned().finally(() => { startPromise = null; });
      return startPromise;
    },
    async status() {
      return runCli(fdbcli, ['-C', clusterFile, '--exec', 'status'], commandTimeoutMs, environment);
    },
    async bootstrap() {
      return runCli(fdbcli, ['-C', clusterFile, '--no-status', '--exec', 'configure new single ssd'], commandTimeoutMs, environment);
    },
    async check() {
      const key = `rebase_n5_environment_probe_${randomUUID().replaceAll('-', '')}`;
      const command = `writemode on; begin; set ${key} verified; commit; get ${key}; begin; clear ${key}; commit`;
      const result = await runCli(fdbcli, ['-C', clusterFile, '--exec', command], commandTimeoutMs, environment);
      if (!result.stdout.includes(key) || !result.stdout.includes('verified')) {
        throw codedError('check_failed', 'FoundationDB read/write probe did not return the written value');
      }
      return Object.freeze({ status: 'passed', key, output: result.stdout });
    },
    async stop() {
      closePromise ??= (async () => {
        await startPromise?.catch(() => {});
        const owned = child;
        if (!owned) return Object.freeze({ status: 'stopped', pid: null });
        await stopOwned(owned, stopTimeoutMs);
        child = null;
        await closeLog();
        return Object.freeze({ status: 'stopped', pid: owned.pid });
      })().finally(() => { closePromise = null; });
      return closePromise;
    },
    async close() { return api.stop(); },
  });
  return api;

  async function startOwned() {
      await closePromise;
      if (child && child.exitCode === null && child.signalCode === null) throw new Error('managed FoundationDB is already running');
      if (child) child = null;
      await closeLog();
      if (await isListening(host, port)) throw codedError('port_in_use', `FoundationDB port ${address} is already owned`);
      await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
      await mkdir(logDirectory, { recursive: true, mode: 0o700 });
      await mkdir(path.dirname(serverLog), { recursive: true, mode: 0o700 });
      output = await open(serverLog, 'a', 0o600);
      const args = ['-p', address, '-C', clusterFile, '-d', dataDirectory, '-L', logDirectory, ...DEFAULT_SERVER_ARGS];
      child = spawn(fdbserver, args, { shell: false, detached: false,
        stdio: ['ignore', output.fd, output.fd], env: { ...environment }, windowsHide: true });
      const owned = child;
      let spawnError = null;
      owned.on('error', error => { spawnError = error; });
      try {
        await waitFor(async () => {
          if (spawnError) throw spawnError;
          if (owned.exitCode !== null || owned.signalCode !== null) {
            throw codedError('server_exited', `FoundationDB server exited (${owned.exitCode ?? owned.signalCode})`);
          }
          return await isListening(host, port);
        }, startTimeoutMs, `FoundationDB listener ${address}`);
        return Object.freeze({ status: 'started', pid: owned.pid, address });
      } catch (error) {
        try {
          await stopOwned(owned, stopTimeoutMs);
          if (child === owned) child = null;
          await closeLog();
        } catch {
          // Keep the still-owned process and log handle reachable for a later close().
        }
        throw error;
      }
  }

  async function closeLog() {
    const handle = output;
    output = null;
    await handle?.close().catch(() => {});
  }
}

async function runCli(executable, args, timeoutMs, environment) {
  const child = spawn(executable, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], env: { ...environment }, windowsHide: true });
  return await collectCommand(child, timeoutMs);
}

function collectCommand(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    const stdout = [];
    const stderr = [];
    let byteCount = 0;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve(result);
    };
    const rejectAfterTermination = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void terminateCommand(child).finally(() => reject(error));
    };
    const collect = destination => chunk => {
      byteCount += chunk.length;
      if (byteCount > MAX_OUTPUT_BYTES) {
        rejectAfterTermination(codedError('output_limit', 'FoundationDB command output exceeds its byte limit'));
        return;
      }
      destination.push(chunk);
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    child.on('error', error => finish(error));
    child.on('close', (code, signal) => {
      const output = Buffer.concat(stdout).toString('utf8');
      const diagnostics = Buffer.concat(stderr).toString('utf8');
      if (code !== 0) finish(codedError('command_failed', `FoundationDB command failed (${code ?? signal}): ${diagnostics.slice(-2048)}`));
      else finish(null, Object.freeze({ status: 'completed', stdout: output, stderr: diagnostics }));
    });
    const timer = setTimeout(() => {
      rejectAfterTermination(codedError('command_timeout', 'FoundationDB command exceeded its time limit'));
    }, timeoutMs);
    timer.unref?.();
  });
}

async function terminateCommand(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  try { await waitChild(child, 1_000); }
  catch {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await waitChild(child, 1_000).catch(() => {});
  }
}

async function stopOwned(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    await waitChild(child, Math.min(timeoutMs, 1_000));
    return;
  }
  child.kill('SIGTERM');
  await waitChild(child, timeoutMs);
}

function waitChild(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.off('close', onClose);
      reject(codedError('stop_timeout', 'Owned FoundationDB server did not stop after SIGTERM; no further signal was sent'));
    }, timeoutMs);
    timer.unref?.();
    const onClose = () => { clearTimeout(timer); resolve(); };
    child.once('close', onClose);
  });
}

async function isListening(host, port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host, port });
    socket.setTimeout(250);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => { socket.destroy(); resolve(false); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
}

async function waitFor(check, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw codedError('start_timeout', `Timed out waiting for ${label}`);
}

function absolutePath(value, name) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) throw new TypeError(`${name} must be an absolute path`);
}
function boundedInteger(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new RangeError(`${name} must be ${minimum}..${maximum}`);
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function codedError(code, message) { return Object.assign(new Error(message), { code }); }
