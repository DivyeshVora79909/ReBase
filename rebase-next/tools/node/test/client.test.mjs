import assert from 'node:assert/strict';
import { mkdtemp, open, readFile, rm, stat } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { connect, savePlan } from '../client.mjs';
import { persistWriteOnce } from '../private/plan-files.mjs';

const tenant = '11111111-1111-4111-8111-111111111111';
const actor = '22222222-2222-4222-8222-222222222222';
const store = '33333333-3333-4333-8333-333333333333';
const operationId = '44444444-4444-4444-8444-444444444444';
const identity = { tenant, actor, store, model: 'quantity', credential_epoch: 7, operation_context: 'ctx-original-α' };

let server;
let base;
let calls;

test.before(async () => {
  calls = [];
  server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    const envelope = JSON.parse(body);
    calls.push({ path: request.url, authorization: request.headers.authorization, envelope });
    if (request.url === '/delayed-session' && envelope.method === 'session.describe') {
      await new Promise(resolve => setTimeout(resolve, 40));
    }
    if (request.url === '/redirect') {
      response.writeHead(307, { location: '/rpc/destination' });
      response.end();
      return;
    }
    if (request.url === '/lost') { request.socket.destroy(); return; }
    if (request.url === '/duplicate') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(`{"jsonrpc":"2.0","id":"${envelope.id}","result":{},"result":{}}`);
      return;
    }
    if (request.url === '/expired' && envelope.method === 'records.mutate') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: envelope.id, error: { code: -32000, message: 'Original context expired', data: { kind: 'operation_expired' } } }));
      return;
    }
    if (request.url === '/http-error') {
      response.writeHead(400, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: envelope.id, error: { code: -32000, message: 'Rejected', data: { kind: 'invalid_input' } } }));
      return;
    }
    let result = { ok: true };
    if (envelope.method === 'session.describe') result = identity;
    else if (envelope.method === 'operations.status') result = { status: 'unknown' };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ jsonrpc: '2.0', id: envelope.id, result }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise(resolve => server.close(resolve));
});

test('prepare binds original session context and identities; execute and status preserve original request', async () => {
  calls.length = 0;
  const draft = {
    model: 'quantity',
    commands: [{ op: 'delete', id: tenant, if_version: 'version-exact' }],
    returning: [tenant],
  };
  const client = connect({ endpoint: `${base}/rpc`, credential: async () => 'test-token' });
  const plan = await client.prepare(draft, { operationId });
  assert.equal(plan.request.operation_id, operationId);
  assert.equal(plan.request.context, identity.operation_context);
  assert.equal(plan.target.credential_epoch, identity.credential_epoch);
  assert.deepEqual(plan.request.commands, draft.commands);
  assert.ok(Object.isFrozen(plan) && Object.isFrozen(plan.request.commands[0]));
  draft.commands[0].if_version = 'changed-after-prepare';
  assert.equal(plan.request.commands[0].if_version, 'version-exact');

  await client.execute(plan);
  await client.status(plan);
  const mutation = calls.find(call => call.envelope.method === 'records.mutate');
  const status = calls.find(call => call.envelope.method === 'operations.status');
  assert.deepEqual(mutation.envelope.params, plan.request);
  assert.deepEqual(status.envelope.params, { model: 'quantity', context: 'ctx-original-α', operation_id: operationId });
  assert.equal(calls.filter(call => call.envelope.method === 'session.describe').length, 3);
  assert.ok(calls.every(call => call.authorization === 'Bearer test-token'));
});

test('plans are private, complete, and write-once', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'rebase-client-'));
  try {
    const client = connect({ endpoint: base, credential: 'test-token' });
    const plan = await client.prepare({ model: 'quantity', commands: [{ op: 'delete', id: tenant, if_version: 'v1' }], returning: [] }, { operationId });
    const destination = path.join(temp, 'intent.json');
    await savePlan(destination, plan);
    assert.deepEqual(JSON.parse(await readFile(destination, 'utf8')), plan);
    assert.equal((await stat(destination)).mode & 0o777, 0o600);
    await assert.rejects(savePlan(destination, plan), error => error.code === 'EEXIST');
    assert.deepEqual(JSON.parse(await readFile(destination, 'utf8')), plan);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('transport rejects redirects and malformed JSON without retry; explicit server rejection stays known', async () => {
  const client = connect({ endpoint: base, credential: 'test-token' });
  for (const [route, kind] of [['redirect', 'redirect_rejected'], ['duplicate', 'outcome_unknown'], ['lost', 'outcome_unknown']]) {
    const before = calls.length;
    const routeClient = connect({ endpoint: `${base}/${route}`, credential: 'test-token' });
    await assert.rejects(routeClient.call('session.describe'), error => error.code === kind);
    assert.equal(calls.length, before + 1);
  }
  const plan = await client.prepare({ model: 'quantity', commands: [{ op: 'delete', id: tenant, if_version: 'v1' }], returning: [] }, { operationId });
  const expired = connect({ endpoint: `${base}/expired`, credential: 'test-token' });
  const expiredPlan = { ...plan, target: { ...plan.target, url: `${base}/expired` } };
  await assert.rejects(expired.execute(expiredPlan), error => error.name === 'RpcError' && error.code === 'operation_expired');
  const request = calls.at(-1).envelope;
  assert.equal(request.method, 'records.mutate');
  assert.equal(request.params.context, plan.request.context);
  assert.equal(request.params.operation_id, plan.request.operation_id);
});

test('credentials are resolved per call and identity changes fence a saved plan', async () => {
  let count = 0;
  const client = connect({ endpoint: base, credential: async () => `token-${++count}` });
  const plan = await client.prepare({ model: 'quantity', commands: [{ op: 'delete', id: tenant, if_version: 'v1' }], returning: [] }, { operationId });
  await client.execute(plan);
  assert.ok(calls.slice(-3).every(call => call.authorization?.startsWith('Bearer token-')));
  const changed = connect({ endpoint: `${base}/other`, credential: 'test-token' });
  await assert.rejects(changed.execute(plan), error => error.code === 'target_mismatch');
});

test('invalid endpoints, credential values, duplicate IDs, and oversized requests fail before network use', async () => {
  assert.throws(() => connect({ endpoint: 'https://user:pass@example.test/rpc', credential: 'token' }), error => error.code === 'invalid_endpoint');
  assert.throws(() => connect({ endpoint: base, credential: 'bad token' }), error => error.code === 'invalid_token');
  const client = connect({ endpoint: base, credential: 'test-token' });
  await assert.rejects(client.prepare({ model: 'quantity', commands: [{}], returning: [tenant, tenant] }), error => error.code === 'invalid_plan');
  await assert.rejects(client.call('large', { value: 'x'.repeat(66_000) }), error => error.code === 'protocol_error' || error.code === 'request_limit');
});

test('remote plaintext HTTP requires an explicit policy; HTTP error envelopes remain unknown', async () => {
  assert.throws(() => connect({ endpoint: 'http://example.com/rpc', credential: 'test-token' }), error => error.code === 'invalid_endpoint_policy');
  assert.doesNotThrow(() => connect({ endpoint: 'http://example.com/rpc', credential: 'test-token', allowRemoteHttp: true }));
  assert.doesNotThrow(() => connect({ endpoint: 'http://127.0.0.2/rpc', credential: 'test-token' }));
  const client = connect({ endpoint: `${base}/http-error`, credential: 'test-token' });
  await assert.rejects(client.call('records.mutate', { operation_id: operationId }), error => error.code === 'outcome_unknown' && error.httpStatus === 400);
});

test('prepare, execute, status, and call detach caller data before their first await', async () => {
  calls.length = 0;
  const client = connect({ endpoint: `${base}/delayed-session`, credential: async () => 'test-token' });
  const draft = { model: 'quantity', commands: [{ op: 'delete', id: tenant, if_version: 'original-version' }], returning: [] };
  const preparing = client.prepare(draft, { operationId });
  draft.commands[0].if_version = 'mutated-while-session-waited';
  const plan = await preparing;
  assert.equal(plan.request.commands[0].if_version, 'original-version');

  const mutablePlan = structuredClone(plan);
  const executing = client.execute(mutablePlan);
  mutablePlan.request.commands[0].if_version = 'mutated-while-target-waited';
  await executing;
  const sentMutation = calls.findLast(call => call.path === '/delayed-session' && call.envelope.method === 'records.mutate');
  assert.equal(sentMutation.envelope.params.commands[0].if_version, 'original-version');

  const mutableStatusPlan = structuredClone(plan);
  const checking = client.status(mutableStatusPlan);
  mutableStatusPlan.request.operation_id = '55555555-5555-4555-8555-555555555555';
  await checking;
  const sentStatus = calls.findLast(call => call.path === '/delayed-session' && call.envelope.method === 'operations.status');
  assert.equal(sentStatus.envelope.params.operation_id, operationId);

  const params = { value: 'original' };
  const mutatingProvider = connect({ endpoint: base, credential: async () => { params.value = 'changed-during-provider'; return 'test-token'; } });
  await mutatingProvider.call('custom.read', params);
  assert.equal(calls.at(-1).envelope.params.value, 'original');
});

test('directory fsync failure reports a published target that must be retained', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'rebase-plan-fsync-'));
  try {
    const destination = path.join(temp, 'intent.json');
    const openFile = async (filename, ...args) => {
      const handle = await open(filename, ...args);
      if (filename === temp && args[0] === 'r') handle.sync = async () => { throw new Error('simulated directory fsync failure'); };
      return handle;
    };
    await assert.rejects(persistWriteOnce(destination, Buffer.from('{"complete":true}\n'), { openFile }), error => {
      assert.equal(error.code, 'plan_durability_unknown');
      assert.equal(error.path, destination);
      assert.equal(error.published, true);
      assert.match(error.message, /retain the target and reconcile/);
      return true;
    });
    assert.deepEqual(JSON.parse(await readFile(destination, 'utf8')), { complete: true });
    assert.equal((await stat(destination)).mode & 0o777, 0o600);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('temporary cleanup failure reports a published target without masking publication', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'rebase-plan-cleanup-'));
  const destination = path.join(temp, 'intent.json');
  try {
    await assert.rejects(persistWriteOnce(destination, Buffer.from('{"complete":true}\n'), {
      unlinkFile: async () => { const error = new Error('simulated unlink failure'); error.code = 'EACCES'; throw error; },
    }), error => {
      assert.equal(error.code, 'plan_cleanup_failed');
      assert.equal(error.path, destination);
      assert.equal(error.published, true);
      assert.match(error.message, /Plan was published/);
      return true;
    });
    assert.deepEqual(JSON.parse(await readFile(destination, 'utf8')), { complete: true });
    assert.equal((await stat(destination)).mode & 0o777, 0o600);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
