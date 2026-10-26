import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { checkResources, observeResources } from '../observe.mjs';
import { churnProfile, churnScenario, faultProfile, faultScenario, overloadProfile, overloadScenario } from '../scenarios.mjs';

const native = { binary: '/tmp/rebase-next', sha256: 'a'.repeat(64), model: 'b'.repeat(64), backend: 'redb', pid: process.pid };
const read = id => ({ id, kind: 'read', run: async () => ({ id }) });
const mutate = id => ({ id, kind: 'update', mutation: true, request: { operation_id: id, commands: [{ op: 'update', id: 'record-1' }] }, run: async () => ({ status: 'committed' }) });

test('N4 profiles are finite, bounded and reject unknown or conflicting limits', () => {
  assert.equal(churnProfile().maxActions, 1_000);
  assert.equal(churnProfile({ setupMs: 0 }).setupMs, 0);
  assert.equal(overloadProfile().maxPending, 8);
  assert.equal(faultProfile().maxActions, 64);
  assert.throws(() => overloadProfile({ maxActions: 769 }), /no greater than 768/);
  assert.throws(() => churnProfile({ surprise: true }), /unknown fields/);
  assert.throws(() => churnProfile({ setupMs: -1 }), /finite and nonnegative/);
  assert.throws(() => faultProfile({ surprise: true }), /unknown fields/);
  assert.throws(() => overloadProfile({ concurrency: 2 }), /inconsistent/);
});

test('churn and overload sources are lazy, finite and retain exact mutation descriptors', async () => {
  const original = mutate('operation-original');
  const churn = churnScenario({ actions: [read('r1'), original], maxActions: 1 });
  assert.deepEqual((await Array.fromAsync(churn())).map(row => row.id), ['r1']);
  const overload = overloadScenario({ actions: [original] });
  assert.deepEqual(await Array.fromAsync(overload()), [original]);
  const malformed = churnScenario({ actions: [{ ...mutate('bad'), request: undefined }] });
  await assert.rejects(async () => { for await (const _item of malformed()) {} }, /exact original request/);
});

test('fault phases preserve an original write identity through recovery reconciliation', async () => {
  const original = mutate('operation-7');
  const phases = await Array.fromAsync(faultScenario({ before: [read('health')], outage: [original], recovery: [read('recovered')], reconcile: [original] })());
  assert.deepEqual(phases.map(row => row.phase), ['before', 'outage', 'recovery', 'reconcile']);
  assert.equal(phases[1].request, original.request);
  assert.equal(phases[3].request.operation_id, 'operation-7');
  await assert.rejects(async () => {
    for await (const _item of faultScenario({ reconcile: [{ ...original, request: undefined }] })()) {}
  }, /exact original mutation request/);
});

test('resource samples disclose platform and native identity and check raw Linux process metrics', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n4-observe-'));
  try {
    await writeFile(path.join(directory, 'owned.dat'), 'bounded evidence');
    const sample = await observeResources({ processes: [{ role: 'controller', pid: process.pid }], native, paths: [directory] });
    assert.equal(sample.platform, process.platform);
    assert.equal(sample.native.sha256, native.sha256);
    assert.equal(sample.processes.controller.pid, process.pid);
    assert.equal(sample.linuxMetricsAvailable, process.platform === 'linux');
    assert.equal(sample.physical.available, true);
    const checked = checkResources([sample], { rssBytes: 2 ** 40, openFiles: 100_000, threads: 100_000,
      physicalBytes: 2 ** 40, observerMs: 10_000, maxFiles: 100 }, { requiredRoles: ['controller'] });
    assert.equal(checked.status, process.platform === 'linux' ? 'passed' : 'incomplete');
    await assert.rejects(observeResources({ processes: [{ role: 'app', pid: process.pid }], native: { ...native, sha256: 'bad' } }), /metadata/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('resource checker rejects impossible metrics and leaves missing identities or costs incomplete', () => {
  const bad = { platform: 'linux', native: { binary: '/tmp/x', sha256: 'a'.repeat(64) },
    processes: { controller: { available: true, pid: 123, rssBytes: -1, openFiles: -1, threads: -1 } },
    physical: { available: true, bytes: -1, files: -1 } };
  const failed = checkResources([bad], {}, { requiredRoles: ['controller'] });
  assert.equal(failed.status, 'failed');
  const absent = checkResources([{ ...bad, native, observerMs: undefined,
    processes: { controller: { available: true, pid: 123, rssBytes: 1, openFiles: 1, threads: 1 } },
    physical: { available: true, bytes: 1, files: 1 } }], {}, { requiredRoles: ['controller'] });
  assert.equal(absent.status, 'incomplete');
  assert.ok(absent.obligations.some(row => row.name.endsWith('observer-time') && row.status === 'incomplete'));
});
