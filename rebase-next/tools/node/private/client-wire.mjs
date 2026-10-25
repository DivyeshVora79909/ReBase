import { randomUUID } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { encodeFrame, parseFrame } from './json-codec.mjs';

export const MAX_REQUEST_BYTES = 65_536;
export const MAX_PLAN_BYTES = 131_072;
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
export const PLAN_FORMAT = 'rebase-operation-plan-1';

export function encodeJson(value, maximum = MAX_REQUEST_BYTES) {
  const frame = encodeFrame(value, maximum);
  return frame.subarray(0, frame.byteLength - 1);
}

export function parseJson(bytes) {
  return parseFrame(Buffer.from(bytes));
}

export function rpcError(code, message, extra = {}) {
  const error = new Error(message);
  error.name = 'ClientError';
  error.code = code;
  Object.assign(error, extra);
  return error;
}

export function requestOnce(url, token, method, params, { timeoutMs, signal } = {}) {
  const id = randomUUID();
  const payload = encodeJson({ jsonrpc: '2.0', id, method, params });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      fn(value);
    };
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        accept: 'application/json',
        'content-length': payload.byteLength,
      },
      agent: false,
      signal,
    }, response => {
      const chunks = [];
      let received = 0;
      const declared = response.headers['content-length'];
      response.on('data', chunk => {
        received += chunk.byteLength;
        if (received > MAX_RESPONSE_BYTES) {
          response.destroy();
          finish(reject, rpcError('outcome_unknown', 'Response exceeds the client limit; retain the saved plan', { httpStatus: response.statusCode }));
        } else chunks.push(chunk);
      });
      response.on('error', error => finish(reject, rpcError('outcome_unknown', 'No complete response; retain the saved plan', { cause: error, httpStatus: response.statusCode })));
      response.on('end', () => {
        if (settled) return;
        if (declared !== undefined && (!/^\d+$/.test(declared) || Number(declared) !== received)) {
          finish(reject, rpcError('outcome_unknown', 'Incomplete response; retain the saved plan', { httpStatus: response.statusCode }));
          return;
        }
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          finish(reject, rpcError('redirect_rejected', 'RPC redirects are not followed', { httpStatus: status }));
          return;
        }
        if (status === 401) {
          finish(reject, rpcError('unauthenticated', 'Credential rejected', { httpStatus: status }));
          return;
        }
        if (status === 429) {
          finish(reject, rpcError('busy', 'Server admission is full; no automatic retry', { httpStatus: status }));
          return;
        }
        let envelope;
        try { envelope = parseJson(Buffer.concat(chunks, received)); }
        catch (cause) {
          finish(reject, rpcError('outcome_unknown', 'Response was not valid JSON; retain the saved plan', { cause, httpStatus: status }));
          return;
        }
        if (!isObject(envelope) || envelope.jsonrpc !== '2.0' || envelope.id !== id ||
            (Object.hasOwn(envelope, 'result') === Object.hasOwn(envelope, 'error'))) {
          finish(reject, rpcError('outcome_unknown', 'Invalid RPC response; retain the saved plan', { httpStatus: status }));
          return;
        }
        if (Object.hasOwn(envelope, 'error')) {
          const detail = envelope.error;
          if (!isObject(detail) || !isObject(detail.data) || typeof detail.data.kind !== 'string' || typeof detail.message !== 'string') {
            finish(reject, rpcError('outcome_unknown', 'Invalid RPC error response', { httpStatus: status }));
          } else if (status !== 200) {
            finish(reject, rpcError('outcome_unknown', `Unexpected HTTP status ${status} with an error response; retain the saved plan`, { httpStatus: status }));
          } else {
            finish(reject, rpcError(detail.data.kind, detail.message, { name: 'RpcError', httpStatus: status, rpcCode: detail.code }));
          }
          return;
        }
        if (status !== 200) {
          finish(reject, rpcError('outcome_unknown', `Unexpected HTTP status ${status}; retain the saved plan`, { httpStatus: status }));
          return;
        }
        finish(resolve, envelope.result);
      });
    });
    req.on('error', error => finish(reject, rpcError(signal?.aborted ? 'outcome_unknown' : 'outcome_unknown', 'No complete response; reconcile or replay the original saved plan', { cause: error })));
    const timer = setTimeout(() => {
      req.destroy();
      finish(reject, rpcError('outcome_unknown', 'Request timed out without a complete response; retain the saved plan'));
    }, timeoutMs);
    timer.unref?.();
    const abort = () => {
      req.destroy();
      finish(reject, rpcError('outcome_unknown', 'Request was interrupted without a complete response; retain the saved plan'));
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
    req.end(payload);
  });
}

export function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
