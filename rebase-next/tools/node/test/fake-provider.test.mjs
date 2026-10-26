import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { startFakeProvider } from '../fake-provider.mjs';

async function withProvider(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-fake-provider-'));
  let provider;
  try {
    provider = await startFakeProvider({ directory });
    await run({ directory, provider });
  } finally {
    await provider?.close();
    await rm(directory, { recursive: true, force: true });
  }
}

function submission(execution = randomUUID(), units = '3') {
  return {
    execution_id: execution,
    account: 'fake-account-1',
    action: 1,
    request: { account: randomUUID(), units, execute_at: null, not_after: null },
  };
}

async function call(provider, execution, body) {
  const response = await fetch(`${provider.endpoint}/executions/${execution}/1`, {
    method: body ? 'POST' : 'GET',
    ...(body ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}),
  });
  let value;
  try { value = await response.json(); } catch { value = null; }
  return { status: response.status, value };
}

test('durable provider truth survives handle restart and keeps idempotency and conflict semantics', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-fake-provider-restart-'));
  const first = await startFakeProvider({ directory });
  const intent = submission();
  try {
    const created = await call(first, intent.execution_id, intent);
    assert.equal(created.status, 200);
    assert.equal(created.value.phase, 'succeeded');
    assert.equal(created.value.receipt, await expectedReceipt(intent.execution_id));
    assert.deepEqual(await call(first, intent.execution_id, intent), created);
    assert.deepEqual(await first.counts(intent.execution_id), { submissions: 2, observations: 0, accepted: 1 });
    const journal = JSON.parse(await readFile(path.join(directory, 'journal.json'), 'utf8'));
    assert.equal(journal.format, 'rebase-fake-provider-journal-2');
    assert.equal((await stat(path.join(directory, 'journal.json'))).mode & 0o777, 0o600);
  } finally {
    await first.close();
  }

  const second = await startFakeProvider({ directory });
  try {
    assert.deepEqual(await call(second, intent.execution_id, intent), {
      status: 200,
      value: {
        execution_id: intent.execution_id, account: 'fake-account-1', action: 1,
        units: '3', phase: 'succeeded', receipt: await expectedReceipt(intent.execution_id),
      },
    });
    const changed = { ...intent, request: { ...intent.request, units: '4' } };
    assert.deepEqual(await call(second, intent.execution_id, changed), { status: 409, value: { error: 'conflict' } });
    assert.deepEqual(await call(second, randomUUID()), { status: 404, value: { error: 'unknown' } });
    assert.deepEqual(await second.counts(intent.execution_id), { submissions: 4, observations: 0, accepted: 1 });
  } finally {
    await second.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test('mode controls preserve rejected, waiting, failed, lost-response and paused-response boundaries', async () => {
  await withProvider(async ({ provider }) => {
    const rejected = submission();
    await provider.setMode(rejected.execution_id, 'reject_once');
    assert.deepEqual(await call(provider, rejected.execution_id, rejected), {
      status: 200, value: { execution_id: rejected.execution_id, account: 'fake-account-1', action: 1, units: '3', phase: 'not_accepted', receipt: null },
    });
    const changedAfterRejection = { ...rejected, request: { ...rejected.request, units: '4' } };
    assert.deepEqual(await call(provider, rejected.execution_id, changedAfterRejection), {
      status: 409, value: { error: 'conflict' },
    });
    assert.deepEqual(await call(provider, rejected.execution_id, rejected), {
      status: 200, value: { execution_id: rejected.execution_id, account: 'fake-account-1', action: 1, units: '3', phase: 'succeeded', receipt: await expectedReceipt(rejected.execution_id) },
    });
    assert.deepEqual(await provider.counts(rejected.execution_id), { submissions: 3, observations: 0, accepted: 1 });

    const waiting = submission();
    await provider.setMode(waiting.execution_id, 'waiting');
    assert.equal((await call(provider, waiting.execution_id, waiting)).value.phase, 'waiting');
    assert.equal((await call(provider, waiting.execution_id)).value.phase, 'waiting');
    await provider.setMode(waiting.execution_id, 'success');
    assert.equal((await call(provider, waiting.execution_id)).value.phase, 'succeeded');

    const failed = submission();
    await provider.setMode(failed.execution_id, 'failed');
    assert.equal((await call(provider, failed.execution_id, failed)).value.phase, 'failed');
    assert.deepEqual(await provider.counts(failed.execution_id), { submissions: 1, observations: 0, accepted: 0 });

    const empty = submission();
    await call(provider, empty.execution_id, empty);
    await provider.setMode(empty.execution_id, 'empty');
    assert.deepEqual(await call(provider, empty.execution_id), { status: 404, value: { error: 'unknown' } });
    assert.deepEqual(await provider.counts(empty.execution_id), { submissions: 1, observations: 1, accepted: 1 });

    const lost = submission();
    await provider.setMode(lost.execution_id, 'lost_response');
    await assert.rejects(fetch(`${provider.endpoint}/executions/${lost.execution_id}/1`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(lost),
    }));
    assert.equal((await provider.execution(lost.execution_id)).phase, 'succeeded');
    assert.equal((await call(provider, lost.execution_id)).value.phase, 'succeeded');

    const paused = submission();
    await provider.setMode(paused.execution_id, 'pause_response');
    const hold = provider.holdResponse(paused.execution_id);
    const pending = call(provider, paused.execution_id, paused);
    await hold.waitUntilPaused();
    assert.deepEqual(await provider.counts(paused.execution_id), { submissions: 1, observations: 0, accepted: 1 });
    assert.equal(await hold.release(), true);
    assert.equal((await pending).value.phase, 'succeeded');
    assert.equal(await hold.release(), false);
  });
});

test('single-writer journal serializes concurrent duplicate submissions and bounds request bodies', async () => {
  await withProvider(async ({ provider, directory }) => {
    const intent = submission();
    const results = await Promise.all(Array.from({ length: 12 }, () => call(provider, intent.execution_id, intent)));
    assert.ok(results.every(row => row.status === 200 && row.value.phase === 'succeeded'));
    assert.deepEqual(await provider.counts(intent.execution_id), { submissions: 12, observations: 0, accepted: 1 });
    assert.equal((await provider.calls(intent.execution_id)).length, 12);

    const oversized = await fetch(`${provider.endpoint}/executions/${randomUUID()}/1`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(4_097),
    });
    assert.equal(oversized.status, 413);
    const entries = await readdir(directory);
    assert.equal(entries.some(name => name.endsWith('.tmp')), false);
  });
});

test('input validation rejects unsupported modes, invalid identities and malformed JSON', async () => {
  await withProvider(async ({ provider }) => {
    await assert.rejects(provider.setMode('not-a-uuid', 'success'), /canonical nonnil UUID/);
    const canonicalLegacyUuid = '00000000-0000-0000-0000-000000000001';
    await provider.setMode(canonicalLegacyUuid, 'success');
    assert.equal((await call(provider, canonicalLegacyUuid, submission(canonicalLegacyUuid))).status, 200);
    await assert.rejects(provider.setMode(randomUUID(), 'surprise'), /unsupported fake-provider mode/);
    const execution = randomUUID();
    const invalid = submission(execution, '0003');
    assert.equal((await call(provider, execution, invalid)).status, 400);
    const raw = await fetch(`${provider.endpoint}/executions/${execution}/1`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: `{"execution_id":"${execution}","execution_id":"${execution}"}`,
    });
    assert.equal(raw.status, 400);
    assert.deepEqual(await provider.counts(execution), { submissions: 0, observations: 0, accepted: 0 });
  });
});

test('refuses a journal whose durable intent payload no longer matches its saved digest', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-fake-provider-tamper-'));
  const first = await startFakeProvider({ directory });
  const intent = submission();
  try { assert.equal((await call(first, intent.execution_id, intent)).status, 200); }
  finally { await first.close(); }
  const journalPath = path.join(directory, 'journal.json');
  const journal = JSON.parse(await readFile(journalPath, 'utf8'));
  journal.executions[intent.execution_id].payload.request.units = '4';
  await writeFile(journalPath, JSON.stringify(journal) + '\n');
  try {
    await assert.rejects(startFakeProvider({ directory }), /intent hash|execution intent/i);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('bounds active holds and pause waiters and rejects handle operations after close', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-fake-provider-bounds-'));
  const provider = await startFakeProvider({ directory });
  const ids = Array.from({ length: 65 }, () => randomUUID());
  const holds = [];
  let waiters = [];
  try {
    for (let index = 0; index < 64; index += 1) holds.push(provider.holdResponse(ids[index]));
    assert.throws(() => provider.holdResponse(ids[64]), error => error.code === 'hold_capacity');
    waiters = holds.map(hold => hold.waitUntilPaused({ timeoutMs: 60_000 }));
    assert.throws(() => provider.holdResponse(ids[64]), error => error.code === 'hold_capacity');
    await assert.rejects(holds[0].waitUntilPaused(), error => error.code === 'waiter_exists');
    // The existing hold map is full; all 64 pending wait handles are owned and bounded.
    assert.equal(waiters.length, 64);
  } finally {
    await provider.close();
    await Promise.allSettled(waiters);
    await rm(directory, { recursive: true, force: true });
  }
  await assert.rejects(provider.counts(ids[0]), /closed/);
  await assert.rejects(provider.execution(ids[0]), /closed/);
  await assert.rejects(provider.calls(), /closed/);
  assert.throws(() => provider.holdResponse(ids[0]), /closed/);
  assert.throws(() => holds[0].release(), /closed/);
  await assert.rejects(holds[0].waitUntilPaused(), /closed/);
});

async function expectedReceipt(namespace) {
  const hex = namespace.replaceAll('-', '');
  const namespaceBytes = Buffer.from(hex, 'hex');
  const { createHash } = await import('node:crypto');
  const bytes = createHash('sha1').update(namespaceBytes).update('fake-units-1').digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const value = bytes.toString('hex');
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}
