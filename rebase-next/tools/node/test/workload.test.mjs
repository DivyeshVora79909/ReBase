import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { checkRun, runWorkload } from '../workload.mjs';

const profile = { durationMs: 1_000, ratePerSecond: 10_000, maxActions: 8,
  concurrency: 2, maxPending: 2, maxObservations: 8, maxArtifactBytes: 16_384,
  sampleIntervalMs: 100 };

async function* scenario() {
  for (let i = 0; i < 2; i += 1) yield {
    id: `a${i}`, kind: 'source-change', mutation: true,
    request: { operation: i, source: `s${i}` },
    run: async () => ({ source: `s${i}`, value: i + 1 }),
  };
}

test('two ordinary scenarios use the same bounded runner and source oracle', async () => {
  const first = await runWorkload({ scenario, state: {}, profile, identity: { model: 'quantity' } });
  const second = await runWorkload({ scenario: async function* () {
    yield { id: 'read', kind: 'observation', run: async () => ({ source: 's0', value: 1 }) };
  }, state: {}, profile: { ...profile, maxActions: 2, maxObservations: 2 } });
  const oracle = ({ observations }) => observations.filter(row => row.action).every(observation => observation.status === 'completed' && observation.value?.value > 0);
  assert.equal(first.status, 'complete');
  assert.equal(first.completed, 2);
  assert.equal((await checkRun({ run: first, oracle })).status, 'passed');
  assert.equal(second.status, 'complete');
  assert.equal((await checkRun({ run: second, oracle })).status, 'passed');
  assert.equal(first.costs.nativeMs, null);
});

test('natural exhaustion drains a sampler already in flight before finalizing the report', async () => {
  let signalStarted;
  const sampling = new Promise(resolve => { signalStarted = resolve; });
  const run = await runWorkload({ state: {}, profile: { ...profile, durationMs: 500, maxActions: 2,
    maxObservations: 2, sampleIntervalMs: 20 }, observe: async () => {
      signalStarted();
      await new Promise(resolve => setTimeout(resolve, 30));
      return { status: 'ready' };
    }, scenario: async function* () {
      yield { id: 'finish', kind: 'read', run: async () => { await sampling; return { ok: true }; } };
    } });
  assert.equal(run.status, 'complete');
  assert.equal(run.cancelled, false);
  assert.equal(run.samples.length, 1);
  assert.equal(run.samples[0].status, 'observed');
});

test('natural exhaustion stays incomplete when an in-flight sampler ignores the deadline', async () => {
  let signalStarted;
  const sampling = new Promise(resolve => { signalStarted = resolve; });
  const run = await runWorkload({ state: {}, profile: { ...profile, durationMs: 60, maxActions: 2,
    maxObservations: 2, sampleIntervalMs: 10 }, observe: () => { signalStarted(); return new Promise(() => {}); },
    scenario: async function* () {
      yield { id: 'finish', kind: 'read', run: async () => { await sampling; return { ok: true }; } };
    } });
  assert.equal(run.status, 'incomplete');
  assert.equal(run.timedOut, true);
  assert.equal(run.cancelled, true);
  assert.equal(run.observations[0].status, 'completed');
});

test('checker derives from raw observations and detects corruption and incomplete capture', async () => {
  const run = await runWorkload({ scenario, state: {}, profile });
  const corrupt = structuredClone(run);
  corrupt.observations[0].value.value = -1;
  assert.equal((await checkRun({ run: corrupt, oracle: ({ observations }) => observations.filter(row => row.action).every(row => row.value.value > 0) })).status, 'failed');
  const truncated = { ...run, status: 'incomplete', dropped: 1 };
  assert.equal((await checkRun({ run: truncated, oracle: () => true })).status, 'failed');
  const fakePass = { ...run, passed: true, observations: [] };
  assert.equal((await checkRun({ run: fakePass, oracle: () => true })).status, 'failed');
  const deleted = structuredClone(run);
  deleted.observations.pop();
  assert.equal((await checkRun({ run: deleted, oracle: ({ observations }) => observations.filter(row => row.action).length === 2 })).status, 'failed');
  assert.notEqual((await checkRun({ run: { ...run, status: 'complete', cancelled: true }, oracle: () => true })).status, 'passed');
  assert.notEqual((await checkRun({ run: { ...run, status: 'complete', exhausted: false }, oracle: () => true })).status, 'passed');
});

test('detaches the original request before invoking a callback that can mutate it', async () => {
  const request = { operation_id: 'original', context: 'epoch-1' };
  const run = await runWorkload({ scenario: async function* () {
    yield { id: 'detach', kind: 'mutation', mutation: true, request,
      run: async () => { request.operation_id = 'changed-late'; return { ok: true }; } };
  }, state: {}, profile });
  assert.equal(run.observations[0].request.operation_id, 'original');
  assert.equal(request.operation_id, 'changed-late');
});

test('unresolved write preserves original request and is never reported rolled back', async () => {
  const run = await runWorkload({
    scenario: async function* () {
      yield { id: 'lost-reply', kind: 'mutation', mutation: true,
        request: { operation_id: 'original-op', context: 'original-context' }, run: () => new Promise(() => {}) };
    },
    state: {}, profile: { ...profile, durationMs: 50, sampleIntervalMs: 25, maxActions: 2, maxObservations: 2 },
  });
  assert.equal(run.status, 'incomplete');
  assert.equal(run.observations[0].status, 'unresolved');
  assert.equal(run.observations[0].outcomeUnknown, true);
  assert.deepEqual(run.observations[0].request, { operation_id: 'original-op', context: 'original-context' });
  assert.equal((await checkRun({ run, oracle: () => true })).status, 'incomplete');
});

test('rejects unbounded or internally inconsistent profiles', async () => {
  await assert.rejects(runWorkload({ scenario, state: {}, profile: { ...profile, maxPending: 3 } }), /maxPending/);
  await assert.rejects(runWorkload({ scenario, state: {}, profile: { ...profile, maxArtifactBytes: Infinity } }), /maxArtifactBytes/);
});

test('oversized completed mutation result retains its exact request and marks the report incomplete', async () => {
  const request = { envelope: { operation_id: 'original-op', context: 'original-context' } };
  const run = await runWorkload({ state: {}, profile: { ...profile, maxArtifactBytes: 512, maxObservations: 2 },
    scenario: async function* () { yield { id: 'large', kind: 'mutation', mutation: true, request,
      run: async () => ({ payload: 'x'.repeat(2_000) }) }; } });
  assert.equal(run.status, 'incomplete');
  assert.equal(run.observations[0].status, 'completed');
  assert.deepEqual(run.observations[0].request, request);
  assert.equal(run.observations[0].resultTruncated, true);
  assert.equal(run.droppedResults, 1);
  assert.equal((await checkRun({ run, oracle: () => true })).status, 'incomplete');
});

test('combined request and result pressure preserves the original mutation plan', async () => {
  const request = { operation_id: 'original', context: 'ctx', payload: 'x'.repeat(600) };
  let dispatched = false;
  const run = await runWorkload({ state: {}, profile: { ...profile, maxArtifactBytes: 1_024, maxObservations: 2 },
    scenario: async function* () { yield { id: 'combined', kind: 'mutation', mutation: true, request,
      run: async () => { dispatched = true; return { payload: 'y'.repeat(600) }; } }; } });
  assert.equal(dispatched, true);
  assert.equal(run.offered, 1);
  assert.equal(run.completed, 1);
  assert.deepEqual(run.observations[0].request, request);
  assert.equal(run.observations[0].resultTruncated, true);
  assert.equal(run.status, 'incomplete');
});

test('cancelled pending next and ignored iterator return remain explicitly unresolved', async () => {
  const controller = new AbortController();
  const runPromise = runWorkload({ state: {}, signal: controller.signal,
    profile: { ...profile, durationMs: 500, maxActions: 2, maxObservations: 2 },
    scenario: () => ({ [Symbol.asyncIterator]() { return { next: () => new Promise(() => {}), return: () => new Promise(() => {}) }; } }) });
  setTimeout(() => controller.abort(), 15);
  const run = await runPromise;
  assert.equal(run.status, 'incomplete');
  assert.equal(run.cancelled, true);
  assert.equal(run.iteratorUnresolved, true);
  assert.equal(run.iteratorCleanupUnresolved, true);
  assert.notEqual((await checkRun({ run: { ...run, status: 'complete', cancelled: false, timedOut: false, exhausted: true, unresolved: 0 }, oracle: () => true })).status, 'passed');
});

test('caller cancellation clears a very slow pacing timer so a subprocess exits promptly', async () => {
  const workloadUrl = new URL('../workload.mjs', import.meta.url).href;
  const source = `import { runWorkload } from ${JSON.stringify(workloadUrl)};
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 30);
    await runWorkload({ state: {}, signal: controller.signal,
      profile: { durationMs: 500, ratePerSecond: 0.000001, maxActions: 2, concurrency: 1,
        maxPending: 1, maxObservations: 2, maxArtifactBytes: 4096, sampleIntervalMs: 100 },
      scenario: async function* () { yield { id: 'one', kind: 'read', run: async () => 1 };
        yield { id: 'two', kind: 'read', run: async () => 2 }; } });`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: 'ignore' });
  const exited = once(child, 'exit').then(([code, signal]) => ({ code, signal }));
  let timer;
  const outcome = await Promise.race([exited, new Promise(resolve => { timer = setTimeout(() => resolve(null), 750); })]);
  clearTimeout(timer);
  if (!outcome) child.kill('SIGKILL');
  assert.ok(outcome, 'subprocess stayed alive on a cancelled pacing timer');
  assert.equal(outcome.code, 0);
});

test('identity metadata is detached and deeply frozen', async () => {
  const identity = { native: { model: 'quantity' } };
  const run = await runWorkload({ scenario: async function* () {}, state: {}, profile: { ...profile, maxActions: 1, maxObservations: 1 }, identity });
  assert.ok(Object.isFrozen(run.identity));
  assert.ok(Object.isFrozen(run.identity.native));
  identity.native.model = 'changed';
  assert.equal(run.identity.native.model, 'quantity');
});
