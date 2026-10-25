import { spawn } from 'node:child_process';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { validateNativeConfigurationSchema, validateNativeDescription, validatePublicConfig } from './private/config-validation.mjs';
import { encodeFrame, parseFrame } from './private/json-codec.mjs';
import { LineFrameDecoder, PROTOCOL, REQUEST_MAX_BYTES, RESPONSE_MAX_BYTES } from './private/framing.mjs';

const ALLOWED_METHODS = new Set(['host.describe', 'host.configure', 'model.catalog', 'store.check', 'store.inspect', 'host.close']);
const RESPONSE_KEYS = new Set(['protocol', 'id', 'result', 'error']);
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function openNative(config, { signal } = {}) {
  validateLaunchConfig(config);
  if (typeof config.native.binary !== 'string' || !path.isAbsolute(config.native.binary)) {
    throw new TypeError('native.binary must be an explicit absolute executable path');
  }
  const childEnvironment = config.native.environment;
  const processHandle = spawn(config.native.binary, ['host'], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...childEnvironment },
    windowsHide: true,
  });
  const host = new NativeHost(processHandle, config);
  try {
    const description = await host.describe({ signal, timeoutMs: config.runner.startTimeoutMs });
    assertHostCanConfigure(description, config.native.configuration);
    validateNativeConfigurationSchema(description.configuration.schema, config.native.configuration);
    const configured = await host.configure(config.native.configuration, { signal, timeoutMs: config.runner.startTimeoutMs });
    host.finishConfiguration(description, configured, config.native.configuration);
    return host.publicHandle();
  } catch (error) {
    await host.dispose().catch(() => {});
    throw error;
  }
}

class NativeHost {
  #child;
  #config;
  #decoder = new LineFrameDecoder(RESPONSE_MAX_BYTES);
  #pending = null;
  #sequence = 0;
  #queue = Promise.resolve();
  #failed = null;
  #closed = false;
  #closing = null;
  #admissionClosed = false;
  #closeAcknowledged = false;
  #stderrDecoder = new StringDecoder('utf8');
  #stderrLine = '';
  #stderrLineBytes = 0;
  #discardingStderrLine = false;
  #suppressStderr = false;
  #insidePrivateKey = false;
  #diagnosticTail = Buffer.alloc(0);
  #description = null;
  #configured = null;
  #grants = new Set();

  constructor(child, config) {
    this.#child = child;
    this.#config = config;
    child.stdout.on('data', chunk => this.#onStdout(chunk));
    child.stdout.on('end', () => {
      try { this.#decoder.finish(); }
      catch (error) { this.#fail(error); }
    });
    child.stdout.on('error', error => this.#fail(transportError('Native host stdout failed', error)));
    child.stderr.on('data', chunk => this.#onStderr(chunk));
    child.stderr.on('end', () => this.#finishStderr());
    child.stderr.on('error', error => this.#fail(transportError('Native host diagnostics failed', error)));
    child.stdin.on('error', error => this.#fail(transportError('Native host input failed', error)));
    child.on('error', error => this.#fail(transportError('Native host could not start', error)));
    child.on('close', (code, signal) => {
      if (!this.#closed && !this.#closeAcknowledged && !this.#failed) this.#fail(transportError(`Native host exited (${code ?? signal ?? 'unknown'})`));
      if (this.#pending) this.#rejectPending(this.#requestFailure(this.#pending, 'Native host exited before a complete response'));
    });
  }

  describe(options = {}) {
    return this.#request('host.describe', {}, options, false).then(result => {
      this.#description = validateNativeDescription(result, PROTOCOL);
      return result;
    });
  }

  configure(configuration, options = {}) {
    const normalized = normalizeConfiguration(configuration);
    return this.#request('host.configure', normalized, options, true).then(result => {
      validateConfiguredResult(result, normalized);
      return result;
    });
  }

  finishConfiguration(description, result, configuration) {
    const expectedModelSelector = configuration.model;
    if (!description.engine.compiled_models.includes(expectedModelSelector)) throw new Error('Native host does not compile the requested model');
    const backendName = configuration.backend.kind;
    if (!description.capabilities.host_backends.includes(backendName)) throw new Error('Native host does not support the requested backend');
    this.#description = description;
    this.#configured = Object.freeze({ model: result.model, target: result.target });
    this.#grants = new Set(result.operator_methods);
  }

  publicHandle() {
    const host = this;
    let closePromise = null;
    return Object.freeze({
      describe(options) { return host.describe(options); },
      catalog({ scope = 'public', signal } = {}) {
        if (!['public', 'developer'].includes(scope)) return Promise.reject(new TypeError('scope must be public or developer'));
        return host.#request('model.catalog', { scope }, { signal }, false);
      },
      check({ signal } = {}) { return host.#operatorRequest('store.check', signal); },
      inspect({ signal } = {}) { return host.#operatorRequest('store.inspect', signal); },
      diagnostics() { return host.#diagnostics(); },
      close() { closePromise ??= host.close(); return closePromise; },
    });
  }

  #operatorRequest(method, signal) {
    if (!this.#configured?.target || !this.#grants.has(method)) {
      return Promise.reject(hostError('forbidden', 'Host operation is not granted'));
    }
    return this.#request(method, { scope: { model: this.#configured.model, store: this.#configured.target.store } }, { signal }, false);
  }

  #request(method, params, { signal, timeoutMs } = {}, sideEffecting) {
    if (!ALLOWED_METHODS.has(method)) return Promise.reject(new TypeError('Unsupported native host method'));
    if (this.#admissionClosed) return Promise.reject(transportError('Native host is closing'));
    let resolveCaller;
    let rejectCaller;
    const caller = new Promise((resolve, reject) => { resolveCaller = resolve; rejectCaller = reject; });
    const scheduled = this.#queue.then(() => {
      if (this.#failed) { rejectCaller(this.#failed); return; }
      if (this.#closed) { rejectCaller(transportError('Native host is closed')); return; }
      if (signal?.aborted) { rejectCaller(abortError()); return; }
      return this.#startExchange(method, params, { signal, timeoutMs, sideEffecting }, resolveCaller, rejectCaller);
    });
    this.#queue = scheduled.catch(() => {});
    return caller;
  }

  #startExchange(method, params, { signal, timeoutMs, sideEffecting }, resolveCaller, rejectCaller) {
    const id = `node:${++this.#sequence}`;
    const request = Object.freeze({ protocol: PROTOCOL, id, method, params });
    let frame;
    try { frame = encodeFrame(request, REQUEST_MAX_BYTES); }
    catch (error) { rejectCaller(error); return Promise.resolve(); }

    return new Promise((resolveDrain, rejectDrain) => {
      const pending = { id, method, params, sideEffecting, resolveCaller, rejectCaller, resolveDrain, rejectDrain, timer: null, abort: null, aborted: false };
      pending.signal = signal;
      this.#pending = pending;
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        pending.timer = setTimeout(() => {
          this.#abortPending(pending, this.#requestFailure(pending, 'Native host response timed out'));
        }, timeoutMs);
        pending.timer.unref?.();
      }
      if (signal) {
        pending.abort = () => this.#abortPending(pending, pending.sideEffecting
          ? outcomeUnknown(pending, 'Native host request was interrupted')
          : abortError());
        signal.addEventListener('abort', pending.abort, { once: true });
      }
      try {
        const writable = this.#child.stdin.write(frame, error => {
          if (error) this.#fail(this.#requestFailure(pending, 'Native host request could not be written', error));
        });
        if (!writable) this.#child.stdin.once('drain', () => {});
      } catch (error) {
        this.#fail(this.#requestFailure(pending, 'Native host request could not be written', error));
      }
    });
  }

  #abortPending(pending, error) {
    if (pending.aborted || this.#pending !== pending) return;
    pending.aborted = true;
    if (pending.timer) clearTimeout(pending.timer);
    pending.timer = null;
    if (pending.abort) pending.signal?.removeEventListener('abort', pending.abort);
    pending.abort = null;
    pending.rejectCaller(error);
  }

  #onStdout(chunk) {
    if (this.#failed) return;
    let frames;
    try { frames = this.#decoder.push(chunk); }
    catch (error) { this.#fail(transportError('Native host sent an oversized response', error)); return; }
    if (frames.length === 0) {
      if (!this.#pending) this.#fail(transportError('Native host wrote unsolicited stdout bytes'));
      return;
    }
    if (frames.length !== 1 || this.#decoder.hasPartialFrame) {
      this.#fail(transportError('Native host sent extra or incomplete response frames'));
      return;
    }
    const pending = this.#pending;
    if (!pending) { this.#fail(transportError('Native host sent an unsolicited response')); return; }
    let response;
    try { response = validateResponse(parseFrame(frames[0]), pending.id); }
    catch (error) {
      this.#fail(transportError('Native host response failed protocol validation', error));
      return;
    }
    this.#clearPending(pending);
    if (response.error) pending.rejectCaller(hostError(response.error.kind, response.error.message));
    else {
      if (pending.method === 'host.close' && isRecord(response.result) && response.result.status === 'closed') this.#closeAcknowledged = true;
      pending.resolveCaller(response.result);
    }
    pending.resolveDrain();
  }

  #onStderr(chunk) {
    if (!this.#config.runner.diagnosticBytes || this.#suppressStderr) return;
    this.#consumeStderr(this.#stderrDecoder.write(chunk));
  }

  #diagnostics() {
    return this.#diagnosticTail.toString('utf8');
  }

  #consumeStderr(text) {
    let start = 0;
    for (let index = 0; index < text.length; index += 1) {
      if (text.charCodeAt(index) !== 0x0a) continue;
      this.#appendStderrFragment(text.slice(start, index));
      if (!this.#discardingStderrLine) this.#appendSanitizedLine(this.#stderrLine);
      this.#stderrLine = '';
      this.#stderrLineBytes = 0;
      this.#discardingStderrLine = false;
      start = index + 1;
      if (this.#suppressStderr) return;
    }
    this.#appendStderrFragment(text.slice(start));
  }

  #appendStderrFragment(fragment) {
    if (this.#discardingStderrLine || !fragment) return;
    const bytes = Buffer.byteLength(fragment, 'utf8');
    if (this.#stderrLineBytes + bytes > 8192) {
      this.#stderrLine = '';
      this.#stderrLineBytes = 0;
      this.#discardingStderrLine = true;
      this.#suppressStderr = true;
      this.#appendSanitizedLine('[REDACTED OVERSIZED DIAGNOSTIC LINE]');
      return;
    }
    this.#stderrLine += fragment;
    this.#stderrLineBytes += bytes;
  }

  #appendSanitizedLine(line) {
    let safe;
    const endPattern = /-----END [A-Z ]*PRIVATE KEY-----/;
    const startPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
    if (this.#insidePrivateKey) {
      const end = endPattern.exec(line);
      if (!end) return;
      this.#insidePrivateKey = false;
      safe = line.slice(end.index + end[0].length);
    } else {
      const begin = startPattern.exec(line);
      if (begin) {
        const end = endPattern.exec(line.slice(begin.index + begin[0].length));
        safe = `${line.slice(0, begin.index)}[REDACTED PRIVATE KEY]`;
        if (end) safe += line.slice(begin.index + begin[0].length + end.index + end[0].length);
        else this.#insidePrivateKey = true;
      } else safe = line;
    }
    const redacted = redactDiagnosticLine(safe);
    const data = Buffer.from(`${redacted}\n`, 'utf8');
    const maximum = this.#config.runner.diagnosticBytes;
    const combined = Buffer.concat([this.#diagnosticTail, data]);
    this.#diagnosticTail = utf8Tail(combined, maximum);
  }

  #finishStderr() {
    if (this.#config.runner.diagnosticBytes && !this.#suppressStderr) {
      const remainder = this.#stderrDecoder.end();
      if (remainder) this.#consumeStderr(remainder);
      if (this.#stderrLine && !this.#discardingStderrLine) this.#appendSanitizedLine(this.#stderrLine);
    }
    this.#stderrLine = '';
    this.#stderrLineBytes = 0;
  }

  #requestFailure(pending, message, cause) {
    if (pending.sideEffecting) return outcomeUnknown(pending, message, cause);
    return transportError(message, cause);
  }

  #fail(error) {
    if (this.#failed || this.#closed) return;
    this.#failed = error;
    if (this.#pending) this.#rejectPending(this.#requestFailure(this.#pending, error.message, error));
    this.#child.stdin.destroy();
    if (this.#child.exitCode === null && this.#child.signalCode === null) this.#child.kill('SIGTERM');
  }

  #clearPending(pending) {
    if (pending.timer) clearTimeout(pending.timer);
    if (pending.abort) pending.signal?.removeEventListener('abort', pending.abort);
    if (this.#pending === pending) this.#pending = null;
  }

  #rejectPending(error) {
    const pending = this.#pending;
    if (!pending) return;
    this.#clearPending(pending);
    pending.rejectCaller(error);
    pending.rejectDrain(error);
  }

  async close() {
    if (this.#closing) return this.#closing;
    this.#admissionClosed = true;
    const admittedRequests = this.#queue;
    this.#closing = (async () => {
      if (this.#closed) return;
      const closeTimeout = this.#config.runner.closeTimeoutMs;
      const watchdog = setTimeout(() => {
        if (!this.#closed && this.#child.exitCode === null && this.#child.signalCode === null) {
          this.#fail(transportError('Native host cleanup deadline expired'));
        }
      }, closeTimeout);
      watchdog.unref?.();
      try {
        await admittedRequests;
        if (!this.#failed && this.#child.exitCode === null && this.#child.signalCode === null) {
          let resolveCaller;
          let rejectCaller;
          const caller = new Promise((resolve, reject) => { resolveCaller = resolve; rejectCaller = reject; });
          const drain = this.#startExchange('host.close', {}, { timeoutMs: closeTimeout, sideEffecting: false }, resolveCaller, rejectCaller);
          this.#queue = drain.catch(() => {});
          try {
            const result = await caller;
            assertExactObject(result, ['status']);
            if (result.status !== 'closed') throw transportError('Native host close acknowledgement was invalid');
          } catch (error) {
            if (!this.#failed) this.#fail(error);
            else this.#child.stdin.destroy();
          }
          await drain.catch(() => {});
        } else {
          this.#child.stdin.end();
        }
        await this.#waitForExit(closeTimeout).catch(() => {});
        if (this.#child.exitCode === null && this.#child.signalCode === null) {
          this.#child.kill('SIGTERM');
          await this.#waitForExit(Math.min(closeTimeout, 1000)).catch(() => {});
        }
        if (this.#child.exitCode === null && this.#child.signalCode === null) {
          this.#child.kill('SIGKILL');
          await this.#waitForExit(1000).catch(() => {});
        }
        this.#closed = true;
        if (this.#failed) throw this.#failed;
        if (this.#child.exitCode !== 0) throw transportError(`Native host exited with status ${this.#child.exitCode ?? this.#child.signalCode}`);
      } finally {
        clearTimeout(watchdog);
      }
    })();
    return this.#closing;
  }

  async dispose() {
    if (this.#closed) return;
    this.#child.stdin.end();
    await this.#waitForExit(this.#config.runner.closeTimeoutMs).catch(() => {});
    if (this.#child.exitCode === null && this.#child.signalCode === null) {
      this.#child.kill('SIGTERM');
      await this.#waitForExit(Math.min(this.#config.runner.closeTimeoutMs, 1000)).catch(() => {});
    }
    if (this.#child.exitCode === null && this.#child.signalCode === null) this.#child.kill('SIGKILL');
    await this.#waitForExit(1000).catch(() => {});
    this.#closed = true;
  }

  #waitForExit(timeoutMs) {
    if (this.#child.exitCode !== null || this.#child.signalCode !== null) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#child.off('close', onClose);
        reject(transportError('Native host did not stop within its cleanup deadline'));
      }, timeoutMs);
      timer.unref?.();
      const onClose = () => { clearTimeout(timer); resolve(); };
      this.#child.once('close', onClose);
    });
  }
}

function assertHostCanConfigure(description, configuration) {
  if (description.state !== 'unconfigured') throw new Error('Native host must start unconfigured');
  if (!description.engine.compiled_models.includes(configuration.model)) throw new Error('Native host does not compile the requested model');
  if (configuration.backend.kind !== 'redb' || !description.capabilities.host_backends.includes('redb')) {
    throw new Error('Native host does not support the requested backend');
  }
  if (!description.capabilities.host_methods.includes('host.configure')) throw new Error('Native host does not advertise host.configure');
  for (const method of configuration.operator_methods) {
    if (!description.capabilities.host_methods.includes(method)) throw new Error(`Native host does not advertise ${method}`);
  }
}

function validateLaunchConfig(config) {
  const fail = message => { throw new TypeError(`invalid resolved native configuration: ${message}`); };
  const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  if (!isRecord(config) || Object.keys(config).some(key => !['runner', 'native', 'provenance'].includes(key))) fail('unknown top-level key');
  if (!isRecord(config.runner) || Object.keys(config.runner).length !== 3
    || !['startTimeoutMs', 'diagnosticBytes', 'closeTimeoutMs'].every(key => Object.hasOwn(config.runner, key))) fail('runner settings are incomplete');
  for (const [key, value] of Object.entries(config.runner)) {
    const range = key === 'diagnosticBytes' ? [0, 1_048_576] : [1, 120_000];
    if (!Number.isSafeInteger(value) || value < range[0] || value > range[1]) fail(`runner.${key} is out of range`);
  }
  if (!isRecord(config.native) || Object.keys(config.native).some(key => !['binary', 'environment', 'configuration'].includes(key))) fail('unknown native key');
  if (typeof config.native.binary !== 'string' || !path.isAbsolute(config.native.binary) || config.native.binary.includes('\0')) fail('native.binary must be an absolute path');
  if (!isRecord(config.native.environment)) fail('native.environment must be an explicit object');
  const allowedEnvironment = new Set(['PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'FDB_CLIENT_LIB_PATH', 'TMPDIR', 'TMP', 'TEMP']);
  for (const [key, value] of Object.entries(config.native.environment)) {
    if (!allowedEnvironment.has(key) || typeof value !== 'string' || value.includes('\0')) fail(`native.environment.${key} is not allowed`);
  }
  try { validatePublicConfig(config.native.configuration); }
  catch (error) { fail(error.message); }
  if (Object.hasOwn(config, 'provenance')) {
    if (!isRecord(config.provenance) || Object.values(config.provenance).some(value => !['default', 'environment', 'override'].includes(value))) fail('provenance is invalid');
  }
}

function normalizeConfiguration(configuration) {
  validatePublicConfig(configuration);
  return {
    model: configuration.model,
    backend: { kind: configuration.backend.kind, cluster_file: null },
    target: configuration.target === null ? null : { ...configuration.target },
    operator_methods: [...configuration.operator_methods].sort(),
  };
}

function validateConfiguredResult(result, configuration) {
  assertExactObject(result, ['status', 'model', 'target', 'operator_methods']);
  if (result.status !== 'configured' || typeof result.model !== 'string' || !HASH.test(result.model)) {
    throw transportError('Native host configuration acknowledgement was invalid');
  }
  const expected = [...configuration.operator_methods].sort();
  if (!Array.isArray(result.operator_methods) || result.operator_methods.length !== expected.length
    || result.operator_methods.some((method, index) => method !== expected[index])) {
    throw transportError('Native host grant acknowledgement did not match configuration');
  }
  if (configuration.target === null) {
    if (result.target !== null) throw transportError('Native host returned unexpected store ownership');
  } else {
    assertExactObject(result.target, ['path', 'store']);
    if (typeof result.target.path !== 'string' || !path.isAbsolute(result.target.path) || !UUID.test(result.target.store)) {
      throw transportError('Native host target acknowledgement was invalid');
    }
    if (configuration.target.mode === 'open' && result.target.store !== configuration.target.expect_store) {
      throw transportError('Native host opened a different store than requested');
    }
  }
}

function validateResponse(response, requestId) {
  if (!isRecord(response)) throw transportError('Native response must be an object');
  const hasResult = Object.hasOwn(response, 'result');
  const hasError = Object.hasOwn(response, 'error');
  if (Object.keys(response).some(key => !RESPONSE_KEYS.has(key)) || hasResult === hasError) {
    throw transportError('Native response envelope has unknown or ambiguous fields');
  }
  if (response.protocol !== PROTOCOL || response.id !== requestId) throw transportError('Native response protocol or correlation ID did not match');
  if (hasError) {
    assertExactObject(response.error, ['kind', 'message']);
    if (typeof response.error.kind !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(response.error.kind)
      || typeof response.error.message !== 'string' || Buffer.byteLength(response.error.message, 'utf8') > 1024) {
      throw transportError('Native error envelope was invalid');
    }
    return response;
  }
  return response;
}

function assertExactObject(value, keys) {
  if (!isRecord(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    throw transportError('Native result shape was invalid');
  }
}

function isRecord(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }

function hostError(code, message) {
  const error = new Error(message);
  error.name = 'NativeHostError';
  error.code = code;
  return error;
}

function transportError(message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.name = 'NativeTransportError';
  error.code = 'native_transport';
  return error;
}

function outcomeUnknown(pending, message, cause) {
  const error = new Error(`${message}; host outcome is unknown`, cause ? { cause } : undefined);
  error.name = 'NativeOutcomeUnknownError';
  error.code = 'outcome_unknown';
  error.operation = Object.freeze({ protocol: PROTOCOL, id: pending.id, method: pending.method, params: pending.params });
  return error;
}

function abortError() {
  const error = new Error('The operation was aborted before dispatch');
  error.name = 'AbortError';
  error.code = 'ABORT_ERR';
  return error;
}

function redactDiagnosticLine(value) {
  return value
    .replace(/\bBearer\s+.*$/i, 'Bearer [REDACTED]')
    .replace(/\b(token|secret|password|authorization|credential|private[_-]?key|api[_-]?key|access[_-]?key)\s*([:=]).*$/i, '$1$2[REDACTED]');
}

function utf8Tail(buffer, maximumBytes) {
  let start = Math.max(0, buffer.byteLength - maximumBytes);
  while (start < buffer.byteLength && (buffer[start] & 0xc0) === 0x80) start += 1;
  return Buffer.from(buffer.subarray(start));
}
