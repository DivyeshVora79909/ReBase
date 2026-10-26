#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const protocol = 'rebase-native-host-1';
const mode = path.basename(process.argv[1]).replace(/^fake-host-/, '').replace(/\.mjs$/, '');
if (mode === 'close-ack-stuck') process.on('SIGTERM', () => {});
const schema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  additionalProperties: false,
  required: ['model', 'backend', 'target', 'operator_methods'],
  properties: {
    model: { type: 'string', enum: ['calculation', 'equipment', 'invoicing', 'measurement', 'effect-demo', 'quantity', ...(mode === 'future-binding' ? ['future-binding'] : [])] },
    backend: {
      type: 'object', additionalProperties: false, required: ['kind', 'cluster_file'],
      properties: { kind: { const: 'redb' }, cluster_file: { type: 'null' } },
    },
    target: {
      anyOf: [
        { type: 'null' },
        { type: 'object', additionalProperties: false, required: ['mode', 'path', 'tenant', 'actor'], properties: {
          mode: { const: 'create' }, path: { type: 'string', minLength: 1 }, tenant: { type: 'string', format: 'uuid' }, actor: { type: 'string', format: 'uuid' },
        } },
        { type: 'object', additionalProperties: false, required: ['mode', 'path', 'expect_store'], properties: {
          mode: { const: 'open' }, path: { type: 'string', minLength: 1 }, expect_store: { type: 'string', format: 'uuid' },
        } },
      ],
    },
    operator_methods: { type: 'array', uniqueItems: true, items: { enum: ['store.check', 'store.inspect', 'effects.retry'] } },
  },
};
const modeSchema = mode === 'remote-ref' ? {
  $schema: schema.$schema, type: 'object', properties: { x: { $ref: 'https://example.invalid/schema.json' } },
} : schema;
const compiledModels = ['calculation', 'equipment', 'invoicing', 'measurement', 'effect-demo', 'quantity', ...(mode === 'future-binding' ? ['future-binding'] : [])];
let configured = false;
let modelIdentity = '2522613c12f6de684d5c983b814ca9bb6a262f00d467b2239e96a747a22c9cb2';
let modelSelector = 'calculation';
let target = null;
let grants = [];
let buffer = '';

function frame(value) { return `${JSON.stringify(value)}\n`; }
function respond(request, result, error) {
  const response = { protocol, id: request.id };
  if (error) response.error = error;
  else response.result = result;
  process.stdout.write(frame(response));
}
function description() {
  return {
    protocol,
    state: configured ? 'configured' : 'unconfigured',
    engine: {
      version: '0.16.0', api: '4', store_format: '10', native_codec: '7', effect_codec: '4',
      compiled_models: compiledModels, compiled_backends: ['redb'],
    },
    configuration: { schema: modeSchema, defaults: {}, sources: {} },
    capabilities: {
      framing: { request_bytes: mode === 'wrong-framing' ? 100 : 65536, response_bytes: 8388608, max_outstanding: 1, bytes_exclude_lf: true },
      host_methods: ['host.describe', 'host.configure', 'model.catalog', 'store.check', 'store.inspect', 'effects.retry', 'host.close'],
      host_backends: ['redb'], model: null, mutation_work_limit: 200000, backup_bytes: 67108864,
    },
      selection: configured ? { selector: modelSelector, model: modelIdentity, backend: { kind: 'redb', cluster_file: null }, target } : null,
    ownership: configured && target ? { store: target.store, mode: 'exclusive' } : null,
  };
}

function sendFault(request, result) {
  if (mode === 'duplicate-response') {
    process.stdout.write(`{"protocol":"${protocol}","id":"${request.id}","id":"${request.id}","result":{}}\n`);
    return true;
  }
  if (mode === 'wrong-id') {
    process.stdout.write(frame({ protocol, id: 'node:999', result }));
    return true;
  }
  if (mode === 'invalid-version') {
    process.stdout.write(frame({ protocol: 'other', id: request.id, result }));
    return true;
  }
  if (mode === 'surrogate-response') {
    process.stdout.write(`{"protocol":"${protocol}","id":"${request.id}","result":{"x":"\\ud800"}}\n`);
    return true;
  }
  if (mode === 'invalid-utf8') {
    process.stdout.write(Buffer.concat([Buffer.from(`{"protocol":"${protocol}","id":"${request.id}","result":{"x":"`), Buffer.from([0xc3, 0x28]), Buffer.from('"}}\n')]));
    return true;
  }
  if (mode === 'unsafe-number') {
    process.stdout.write(`{"protocol":"${protocol}","id":"${request.id}","result":{"count":9007199254740992}}\n`);
    return true;
  }
  if (mode === 'oversized-response') {
    process.stdout.write(Buffer.concat([Buffer.alloc(8_388_609, 0x61), Buffer.from('\n')]));
    return true;
  }
  if (mode === 'extra-frames') {
    process.stdout.write(frame({ protocol, id: request.id, result }) + frame({ protocol, id: 'node:999', result: {} }));
    return true;
  }
  return false;
}

function handle(request) {
  if (mode === 'stderr-flood') process.stderr.write(('token=topsecret Bearer abcdef\n').repeat(4000));
  if (mode === 'stderr-unicode') process.stderr.write('中\n');
  if (mode === 'stderr-pem') {
    process.stderr.write('-----BEGIN PRIVATE KEY-----\n');
    process.stderr.write('supersecretkeymaterial\n');
    process.stderr.write('-----END PRIVATE KEY-----\n');
  }
  if (request.method === 'host.describe') {
    if (mode === 'hang-describe') return;
    if (mode === 'exit-before-response') process.exit(17);
    const result = description();
    if (sendFault(request, result)) return;
    respond(request, result);
    if (mode === 'late-extra-frame') setTimeout(() => process.stdout.write(frame({ protocol, id: 'node:999', result: {} })), 25);
    return;
  }
  if (request.method === 'host.configure') {
    if (mode === 'configure-error') return respond(request, undefined, { kind: 'invalid_config', message: 'Invalid host configuration' });
    if (mode === 'configure-duplicate') {
      process.stdout.write(`{"protocol":"${protocol}","id":"${request.id}","id":"${request.id}","result":{}}\n`);
      return;
    }
    if (mode === 'configure-hang' || mode === 'exit-on-configure') {
      if (request.params.target?.mode === 'create') {
        fs.mkdirSync(path.dirname(request.params.target.path), { recursive: true });
        fs.writeFileSync(request.params.target.path, 'owned fake side effect');
      }
      if (mode === 'exit-on-configure') process.exit(17);
      return;
    }
    modelSelector = request.params.model;
    configured = true;
    grants = request.params.operator_methods;
    if (request.params.target) target = { path: path.resolve(request.params.target.path), store: request.params.target.expect_store ?? '33333333-3333-4333-8333-333333333333' };
    const result = { status: 'configured', model: modelIdentity, target, operator_methods: grants };
    if (sendFault(request, result)) return;
    respond(request, result);
    return;
  }
  if (request.method === 'model.catalog') {
    if (!configured) return respond(request, undefined, { kind: 'not_configured', message: 'Host is not configured' });
    if (mode === 'delayed-catalog') return setTimeout(() => respond(request, { scope: request.params.scope, contracts: [] }), 120);
    return respond(request, { scope: request.params.scope, contracts: [] });
  }
  if (request.method === 'identity.issue' && mode === 'delayed-catalog') {
    process.stdout.write(`{"protocol":"${protocol}","id":"${request.id}","id":"${request.id}","result":{}}\n`);
    return;
  }
  if (request.method === 'service.start' && mode === 'delayed-catalog') {
    return respond(request, { status: 'started', service: 'malformed-service-id' });
  }
  if (request.method === 'service.stop' && mode === 'delayed-catalog') {
    return respond(request, { status: 'stopped', service: request.params.service });
  }
  if (request.method === 'store.check' || request.method === 'store.inspect') {
    const grant = request.method;
    if (!grants.includes(grant)) return respond(request, undefined, { kind: 'forbidden', message: 'Host operation is not granted' });
    return respond(request, request.method === 'store.check' ? { valid: true } : { records: [] });
  }
  if (request.method === 'effects.retry') {
    if (!grants.includes(request.method)) return respond(request, undefined, { kind: 'forbidden', message: 'Host operation is not granted' });
    if (request.params.scope?.model !== modelIdentity || request.params.scope?.store !== target?.store) {
      return respond(request, undefined, { kind: 'wrong_target', message: 'Retry scope does not match the configured store' });
    }
    if (mode === 'retry-lost-response') process.exit(17);
    return respond(request, { status: 'retried', execution_id: request.params.execution_id, revision: request.params.if_revision });
  }
  if (request.method === 'host.close') {
    if (mode === 'close-hang') return;
    if (mode === 'close-ack-stuck') {
      process.stdout.write(frame({ protocol, id: request.id, result: { status: 'closed' } }));
      setInterval(() => {}, 1000);
      return;
    }
    process.stdout.write(frame({ protocol, id: request.id, result: { status: 'closed' } }), () => process.exit(0));
    return;
  }
  respond(request, undefined, { kind: 'method_not_found', message: 'Unknown host method' });
}

if (process.argv[2] !== 'host') {
  process.stderr.write('expected fixed host argument\n');
  process.exit(2);
}
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buffer += chunk;
  for (;;) {
    const newline = buffer.indexOf('\n');
    if (newline < 0) break;
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    try { handle(JSON.parse(line)); }
    catch { process.exit(3); }
  }
});
process.stdin.on('end', () => process.exit(0));
