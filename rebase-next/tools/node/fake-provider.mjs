import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';
import { parseFrame } from './private/json-codec.mjs';

const FORMAT = 'rebase-fake-provider-journal-2';
const MAX_BODY_BYTES = 4_096;
const MAX_JOURNAL_BYTES = 8 * 1024 * 1024;
const MAX_EXECUTIONS = 2_048;
const MAX_CALLS = 4_096;
const MAX_ACTIVE_HOLDS = 64;
const MAX_PAUSE_WAITERS = 64;
const MAX_UNITS = 1_000_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MODES = new Set(['success', 'waiting', 'not_accepted', 'reject_once', 'failed', 'lost_response', 'pause_response', 'empty']);

/**
 * Start an explicitly owned, independent local fake provider. Its bounded JSON
 * journal is durable across backend process loss and provider handle restart.
 * This fixture has one writer per directory and is not a production provider.
 */
export async function startFakeProvider({ directory, host = '127.0.0.1' } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) throw new TypeError('directory must be an absolute path');
  if (host !== '127.0.0.1') throw new TypeError('fake provider must bind to loopback');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const root = path.resolve(directory);
  const journalPath = path.join(root, 'journal.json');
  let state = await loadState(journalPath);
  let queue = Promise.resolve();
  let closed = false;
  let persistenceFailure = null;
  const holds = new Map();
  const paused = new Map();
  const assertOpen = () => { if (closed) throw new Error('fake provider is closed'); };

  const transaction = operation => {
    const pending = queue.then(async () => {
      if (closed) throw new Error('fake provider is closed');
      if (persistenceFailure) throw codedError('journal_durability_unknown', 'Provider state must be reopened after uncertain journal durability');
      const next = structuredClone(state);
      const value = operation(next);
      validateJournal(next);
      try { await publishJournal(journalPath, next); }
      catch (error) {
        if (error.published === true) persistenceFailure = error;
        throw error;
      }
      state = next;
      return value;
    });
    queue = pending.catch(() => {});
    return pending;
  };

  const server = createServer((request, response) => {
    void handle(request, response).catch(error => {
      if (!response.headersSent) reply(response, 500, { error: 'provider journal unavailable' });
      else response.destroy(error);
    });
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.maxHeadersCount = 32;
  await new Promise((resolve, reject) => {
    const onError = error => { server.off('listening', onListening); reject(error); };
    const onListening = () => { server.off('error', onError); resolve(); };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(0, host);
  });

  const address = server.address();
  const endpoint = `http://${host}:${address.port}`;
  let closePromise;

  async function handle(request, response) {
    const route = /^\/executions\/([^/]+)\/1$/.exec(new URL(request.url, endpoint).pathname);
    if (!route || !canonicalUuid(route[1])) return reply(response, 404, { error: 'unknown action' });
    const execution = route[1];
    if (request.method !== 'GET' && request.method !== 'POST') {
      response.setHeader('Allow', 'GET, POST');
      return reply(response, 405, { error: 'method not allowed' });
    }

    let body;
    if (request.method === 'POST') {
      try { body = await readBody(request); }
      catch (error) { return reply(response, error.code === 'body_limit' ? 413 : 400, { error: error.message }); }
      try { body = parseFrame(body); }
      catch { return reply(response, 400, { error: 'invalid fake request JSON' }); }
      try { validateSubmission(execution, body); }
      catch (error) { return reply(response, 400, { error: error.message }); }
    }

    let outcome;
    try {
      outcome = await transaction(next => recordCall(next, request.method, execution, body));
    } catch (error) {
      return reply(response, error.code === 'journal_full' ? 503 : 500, { error: error.code === 'journal_full' ? 'journal capacity' : 'provider journal unavailable' });
    }

    if (outcome.status !== 200) return reply(response, outcome.status, { error: outcome.phase });
    if (request.method === 'POST' && outcome.mode === 'pause_response') {
      await waitForRelease(execution);
    }
    if (request.method === 'POST' && outcome.mode === 'lost_response') {
      response.destroy();
      return;
    }
    return reply(response, 200, outcome.value);
  }

  function waitForRelease(execution) {
    const current = holds.get(execution);
    if (!current) return Promise.resolve();
    current.paused = true;
    const pause = paused.get(execution);
    if (pause) { pause.resolve(); paused.delete(execution); }
    return current.promise;
  }

  const handleApi = {
    endpoint,
    directory: root,
    async setMode(execution, mode) {
      assertOpen();
      assertUuid(execution, 'execution');
      if (!MODES.has(mode)) throw new TypeError(`unsupported fake-provider mode ${String(mode)}`);
      await transaction(next => { next.modes[execution] = mode; });
    },
    holdResponse(execution) {
      assertOpen();
      assertUuid(execution, 'execution');
      if (holds.has(execution)) throw new Error('response is already held');
      if (holds.size >= MAX_ACTIVE_HOLDS) throw bodyError('hold_capacity', 'too many active fake-provider holds');
      let release;
      const promise = new Promise(resolve => { release = resolve; });
      holds.set(execution, { promise, release, paused: false });
      return Object.freeze({
        waitUntilPaused: ({ timeoutMs = 5_000 } = {}) => waitPaused(execution, timeoutMs),
        release: () => { assertOpen(); return releaseResponse(execution); },
      });
    },
    async releaseResponse(execution) { assertOpen(); return releaseResponse(execution); },
    async counts(execution) {
      assertOpen();
      assertUuid(execution, 'execution');
      await queue;
      const calls = state.calls.filter(row => row.execution === execution);
      return Object.freeze({
        submissions: calls.filter(row => row.method === 'POST').length,
        observations: calls.filter(row => row.method === 'GET').length,
        accepted: state.executions[execution]?.accepted ? 1 : 0,
      });
    },
    async execution(execution) {
      assertOpen();
      assertUuid(execution, 'execution');
      await queue;
      const value = state.executions[execution];
      return value ? structuredClone(value) : null;
    },
    async calls(execution) {
      assertOpen();
      if (execution !== undefined) assertUuid(execution, 'execution');
      await queue;
      return structuredClone(state.calls.filter(row => execution === undefined || row.execution === execution));
    },
    async close() {
      closePromise ??= (async () => {
        closed = true;
        for (const [execution, pause] of paused) {
          paused.delete(execution);
          pause.reject(new Error('fake provider is closed'));
        }
        for (const execution of [...holds.keys()]) releaseResponse(execution);
        await queue;
        await new Promise(resolve => server.close(() => resolve()));
      })();
      return closePromise;
    },
  };
  return Object.freeze(handleApi);

  function releaseResponse(execution) {
    const current = holds.get(execution);
    if (!current) return false;
    holds.delete(execution);
    current.release();
    return true;
  }

  async function waitPaused(execution, timeoutMs) {
    assertOpen();
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new RangeError('timeoutMs must be 1..60000');
    const current = holds.get(execution);
    if (!current) throw new Error('response hold is not active');
    if (current.paused) return;
    if (paused.has(execution)) throw bodyError('waiter_exists', 'only one pause waiter is allowed per execution');
    if (paused.size >= MAX_PAUSE_WAITERS) throw bodyError('waiter_capacity', 'too many fake-provider pause waiters');
    let resolve;
    let reject;
    const arrived = new Promise((yes, no) => { resolve = yes; reject = no; });
    paused.set(execution, { resolve, reject });
    let timer;
    try {
      await Promise.race([arrived, new Promise((_, no) => { timer = setTimeout(() => no(new Error('provider response did not reach its hold')), timeoutMs); })]);
    } finally {
      clearTimeout(timer);
      if (paused.get(execution)?.resolve === resolve) paused.delete(execution);
    }
  }
}

function recordCall(journal, method, execution, payload) {
  if (journal.calls.length >= MAX_CALLS) throw Object.assign(new Error('journal capacity'), { code: 'journal_full' });
  const mode = journal.modes[execution] ?? 'success';
  const requestHash = payload ? sha256(canonical(payload)) : null;
  let phase;
  let status = 200;
  let existing = journal.executions[execution];
  if (method === 'POST') {
    const intent = journal.intents[execution];
    if (intent && intent.requestHash !== requestHash) {
      phase = 'conflict';
      status = 409;
    } else {
      if (!intent) journal.intents[execution] = { requestHash, payload: structuredClone(payload) };
      if (existing && existing.requestHash !== requestHash) {
        phase = 'conflict';
        status = 409;
      } else if (!existing) {
        const attempts = journal.calls.filter(row => row.execution === execution && row.method === 'POST').length;
        if (mode === 'not_accepted' || (mode === 'reject_once' && attempts === 0)) {
          phase = 'not_accepted';
        } else {
          phase = mode === 'waiting' ? 'waiting' : mode === 'failed' ? 'failed' : 'succeeded';
          if (journal.executionsCount >= MAX_EXECUTIONS) throw codedError('journal_full', 'journal capacity');
          existing = journal.executions[execution] = {
            requestHash,
            payload: structuredClone(payload),
            phase,
            receipt: phase === 'failed' ? null : uuid5(execution, 'fake-units-1'),
            accepted: phase !== 'failed',
          };
          journal.executionsCount += 1;
        }
      } else {
        phase = existing.phase;
        if (existing.phase === 'waiting' && mode === 'success') {
          existing.phase = phase = 'succeeded';
          existing.receipt = uuid5(execution, 'fake-units-1');
          existing.accepted = true;
        }
      }
    }
  } else if (!existing && method === 'GET') {
    phase = 'unknown';
    status = 404;
  } else {
    phase = existing.phase;
    if (existing.phase === 'waiting' && mode === 'success') {
      existing.phase = phase = 'succeeded';
      existing.receipt = uuid5(execution, 'fake-units-1');
      existing.accepted = true;
    }
  }
  if (method === 'GET' && mode === 'empty') {
    phase = 'unknown';
    status = 404;
  }
  journal.calls.push({ sequence: journal.nextCall++, method, execution, requestHash, phase, observedMs: Date.now() });
  let value = null;
  if (status === 200) {
    const accepted = existing ?? null;
    const body = payload ?? accepted?.payload;
    value = {
      execution_id: execution,
      account: 'fake-account-1',
      action: 1,
      units: body?.request?.units ?? null,
      phase,
      receipt: accepted?.receipt ?? null,
    };
  }
  return { status, phase, mode, value };
}

async function loadState(file) {
  let info;
  try { info = await lstat(file); }
  catch (error) { if (error.code === 'ENOENT') return emptyJournal(); throw error; }
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || info.size > MAX_JOURNAL_BYTES) throw new Error('fake-provider journal has invalid type, permissions, or byte bound');
  let parsed;
  try { parsed = parseFrame(await readFile(file)); }
  catch { throw new Error('fake-provider journal is invalid JSON'); }
  validateJournal(parsed);
  return parsed;
}

async function publishJournal(file, value) {
  const bytes = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
  if (bytes.length > MAX_JOURNAL_BYTES) throw Object.assign(new Error('journal capacity'), { code: 'journal_full' });
  const temp = path.join(path.dirname(file), `.journal-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temp, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temp, file);
    try { await syncDirectory(path.dirname(file)); }
    catch (error) { throw Object.assign(error, { published: true, code: 'journal_durability_unknown' }); }
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR', 'EPERM', 'ENOSYS'].includes(error.code)) throw error;
  } finally { await handle?.close().catch(() => {}); }
}

async function readBody(request) {
  const declared = Number(request.headers['content-length'] ?? 0);
  if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_BODY_BYTES) throw bodyError('body_limit', 'request body exceeds byte limit');
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) throw bodyError('body_limit', 'request body exceeds byte limit');
    chunks.push(chunk);
  }
  if (!length || (declared !== 0 && declared !== length)) throw bodyError('invalid_body', 'request body is incomplete');
  return Buffer.concat(chunks, length);
}

function validateSubmission(execution, body) {
  if (!plain(body) || !exactKeys(body, ['execution_id', 'account', 'action', 'request'])
      || body.execution_id !== execution || body.account !== 'fake-account-1' || body.action !== 1
      || !plain(body.request) || !exactKeys(body.request, ['account', 'units', 'execute_at', 'not_after'])
      || !canonicalUuid(body.request.account) || typeof body.request.units !== 'string'
      || !/^[1-9][0-9]*$/.test(body.request.units) || BigInt(body.request.units) > BigInt(MAX_UNITS)
      || !(body.request.execute_at === null || typeof body.request.execute_at === 'string' && /^(0|-?[1-9][0-9]*)$/.test(body.request.execute_at))
      || !(body.request.not_after === null || typeof body.request.not_after === 'string' && /^(0|-?[1-9][0-9]*)$/.test(body.request.not_after))) {
    throw new TypeError('invalid fake request');
  }
}

function validateJournal(value) {
  if (!plain(value) || !exactKeys(value, ['format', 'nextCall', 'executionsCount', 'modes', 'intents', 'executions', 'calls'])
      || value.format !== FORMAT || !Number.isSafeInteger(value.nextCall) || value.nextCall < 1
      || !Number.isSafeInteger(value.executionsCount) || value.executionsCount < 0
      || !plain(value.modes) || !plain(value.intents) || !plain(value.executions) || !Array.isArray(value.calls)
      || value.calls.length > MAX_CALLS || value.executionsCount > MAX_EXECUTIONS) {
    throw new Error('fake-provider journal shape differs');
  }
  for (const [id, mode] of Object.entries(value.modes)) if (!canonicalUuid(id) || !MODES.has(mode)) throw new Error('fake-provider journal mode differs');
  const intents = Object.keys(value.intents);
  if (intents.length > MAX_CALLS) throw new Error('fake-provider intent inventory differs');
  for (const [id, row] of Object.entries(value.intents)) {
    if (!canonicalUuid(id) || !plain(row) || !exactKeys(row, ['requestHash', 'payload'])
        || !/^[0-9a-f]{64}$/.test(row.requestHash)) throw new Error('fake-provider intent row differs');
    validateSubmission(id, row.payload);
    if (sha256(canonical(row.payload)) !== row.requestHash) throw new Error('fake-provider intent hash differs');
  }
  const ids = Object.keys(value.executions);
  if (ids.length !== value.executionsCount) throw new Error('fake-provider execution inventory differs');
  for (const [id, row] of Object.entries(value.executions)) {
    if (!canonicalUuid(id) || !plain(row) || !exactKeys(row, ['requestHash', 'payload', 'phase', 'receipt', 'accepted'])
        || !/^[0-9a-f]{64}$/.test(row.requestHash) || !['waiting', 'succeeded', 'failed'].includes(row.phase)
        || typeof row.accepted !== 'boolean' || !(row.receipt === null || canonicalUuid(row.receipt))) throw new Error('fake-provider execution row differs');
    validateSubmission(id, row.payload);
    const intent = value.intents[id];
    if (!intent || intent.requestHash !== row.requestHash || canonical(intent.payload) !== canonical(row.payload)) throw new Error('fake-provider execution intent differs');
    if (row.phase === 'failed') {
      if (row.accepted || row.receipt !== null) throw new Error('fake-provider rejected execution facts differ');
    } else if (!row.accepted || row.receipt !== uuid5(id, 'fake-units-1')) throw new Error('fake-provider accepted execution facts differ');
  }
  for (let i = 0; i < value.calls.length; i += 1) {
    const row = value.calls[i];
    if (!plain(row) || !exactKeys(row, ['sequence', 'method', 'execution', 'requestHash', 'phase', 'observedMs'])
        || row.sequence !== i + 1 || !['GET', 'POST'].includes(row.method) || !canonicalUuid(row.execution)
        || !(row.requestHash === null || /^[0-9a-f]{64}$/.test(row.requestHash))
        || !['unknown', 'conflict', 'not_accepted', 'waiting', 'succeeded', 'failed'].includes(row.phase)
        || !Number.isSafeInteger(row.observedMs) || row.observedMs < 0) throw new Error('fake-provider call row differs');
    if (row.method === 'POST') {
      if (!row.requestHash || !value.intents[row.execution]) throw new Error('fake-provider call intent is missing');
      if (row.requestHash !== value.intents[row.execution].requestHash && row.phase !== 'conflict') throw new Error('fake-provider changed request was not rejected');
    } else if (row.requestHash !== null) throw new Error('fake-provider lookup has a request hash');
  }
  if (value.nextCall !== value.calls.length + 1) throw new Error('fake-provider call sequence differs');
}

function emptyJournal() {
  return { format: FORMAT, nextCall: 1, executionsCount: 0, modes: {}, intents: {}, executions: {}, calls: [] };
}

function reply(response, status, value) {
  if (response.destroyed) return;
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  response.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, 'cache-control': 'no-store' });
  response.end(body);
}

function uuid5(namespace, name) {
  const namespaceBytes = Buffer.from(namespace.replaceAll('-', ''), 'hex');
  const hash = createHash('sha1').update(namespaceBytes).update(name, 'utf8').digest().subarray(0, 16);
  hash[6] = (hash[6] & 0x0f) | 0x50;
  hash[8] = (hash[8] & 0x3f) | 0x80;
  const hex = hash.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function sha256(text) { return createHash('sha256').update(text, 'utf8').digest('hex'); }
function canonicalUuid(value) { return typeof value === 'string' && UUID.test(value) && value !== '00000000-0000-0000-0000-000000000000'; }
function assertUuid(value, name) { if (!canonicalUuid(value)) throw new TypeError(`${name} must be a canonical nonnil UUID`); }
function exactKeys(value, keys) { return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function bodyError(code, message) { return Object.assign(new Error(message), { code }); }
