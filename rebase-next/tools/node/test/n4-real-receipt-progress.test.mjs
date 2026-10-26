import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { connect, savePlan } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { accept, preparePopulation, propose } from '../population.mjs';
import { checkRun, runWorkload } from '../workload.mjs';
import { observeResources } from '../observe.mjs';
import { churnProfile, churnScenario } from '../scenarios.mjs';
import { checkSourceSnapshot, evaluateSources } from '../oracles.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N4_BINARY ?? path.join(root, 'target/n2-native-default/rebase-next');
const frozenHash = '74b816d1f72dff333c76633420da35e5e08daf3c087a06abc6d38a07cd39ae5e';
const available = existsSync(binary);
const methods = ['service.start', 'service.stop', 'identity.issue', 'store.archive', 'store.check', 'store.inspect'];

async function openWorkflow(directory, selector) {
  const tenant = randomUUID(); const actor = randomUUID();
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const identity = { issuer: `n4-${selector}`, audience: `n4-${selector}`, public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
  const config = resolveConfig({ overrides: {
    native: { binary: path.resolve(binary), environment: {}, configuration: {
      model: selector, backend: { kind: 'redb', cluster_file: null },
      target: { mode: 'create', path: path.join(directory, `${selector}.redb`), tenant, actor }, operator_methods: methods,
    } },
    service: { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 10, effects: null },
  } });
  const native = await openNative(config);
  const operator = openOperator(native, { scope: native.scope, methods });
  let service;
  try {
    service = await operator.startService({ config: config.service });
    const token = (await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' }, privateKeyPem })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector });
    const sha256 = createHash('sha256').update(await readFile(binary)).digest('hex');
    assert.equal(sha256, frozenHash, 'N4 trial must use the frozen N2 native binary');
    return { native, operator, service, serviceConfig: config.service, credential: token,
      serviceRunning: true, client, model, metadata: {
      binary: path.resolve(binary), sha256, model: model.identity, backend: 'redb', pid: native.pid,
    } };
  } catch (error) {
    if (service) await operator.stopService({ service: service.service });
    await native.close();
    throw error;
  }
}

/** Local test proxy drops one complete committed mutation response, then restarts the owned service. */
async function lostReplyRecoveryProxy(workflow) {
  let operationId = null;
  let recoveryPromise = null;
  let upstreamCommit = null;
  let upstreamEndpoint = workflow.service.endpoint;
  const server = createServer((incoming, outgoing) => {
    const chunks = [];
    let bytes = 0;
    incoming.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 65_536) { incoming.destroy(); return; }
      chunks.push(chunk);
    });
    incoming.on('end', () => {
      const body = Buffer.concat(chunks);
      let request;
      try { request = JSON.parse(body.toString('utf8')); }
      catch { outgoing.writeHead(400).end(); return; }
      const drop = request.method === 'records.mutate' && request.params?.operation_id === operationId;
      const upstream = httpRequest(new URL(upstreamEndpoint), { method: 'POST',
        headers: { authorization: incoming.headers.authorization, 'content-type': 'application/json',
          accept: 'application/json', 'content-length': body.length } }, response => {
        const responseChunks = []; let responseBytes = 0;
        response.on('data', chunk => { responseBytes += chunk.length; responseChunks.push(chunk); });
        response.on('end', async () => {
          const responseBody = Buffer.concat(responseChunks, responseBytes);
          if (drop) {
            let envelope;
            try { envelope = JSON.parse(responseBody.toString('utf8')); } catch { envelope = null; }
            upstreamCommit = envelope?.result?.status === 'committed'
              && envelope.result.result?.operation_id === operationId;
            if (upstreamCommit) {
              outgoing.socket?.destroy();
              recoveryPromise = (async () => {
                await workflow.operator.stopService({ service: workflow.service.service });
                workflow.serviceRunning = false;
                workflow.service = await workflow.operator.startService({ config: workflow.serviceConfig });
                workflow.serviceRunning = true;
                upstreamEndpoint = workflow.service.endpoint;
              })();
              try { await recoveryPromise; } catch (error) { recoveryPromise = Promise.reject(error); recoveryPromise.catch(() => {}); }
            } else {
              outgoing.writeHead(response.statusCode ?? 502).end(responseBody);
            }
            return;
          }
          outgoing.writeHead(response.statusCode ?? 502, response.headers);
          outgoing.end(responseBody);
        });
      });
      upstream.on('error', () => { if (!outgoing.destroyed) outgoing.writeHead(502).end(); });
      upstream.end(body);
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const endpoint = `http://127.0.0.1:${address.port}/rpc`;
  const client = connect({ endpoint, credential: workflow.credential, timeoutMs: 10_000 });
  return Object.freeze({ client, endpoint, lose(operation) { operationId = operation; },
    async recover() { if (!recoveryPromise) throw new Error('no committed lost reply was observed'); await recoveryPromise; },
    get upstreamCommit() { return upstreamCommit; },
    close() { return new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); } });
}

function workloadProfile(maxActions, setupMs) {
  return churnProfile({ durationMs: 15_000, ratePerSecond: 100, maxActions: maxActions + 1,
    concurrency: 1, maxPending: 1, maxObservations: maxActions, maxArtifactBytes: 1_000_000,
    sampleIntervalMs: 40, setupMs });
}

function observedProcesses(nativePid) {
  return [{ role: 'controller', pid: process.pid }, ...(Number.isSafeInteger(nativePid) && nativePid > 0 ? [{ role: 'native', pid: nativePid }] : [])];
}

function receiptOracle(expectedKinds, expectedFacts) {
  return ({ observations, identity }) => {
    const obligations = [];
    obligations.push({ name: 'native-identity', status: identity.native?.sha256 === frozenHash ? 'passed' : 'failed' });
    obligations.push({ name: 'source-facts', status: JSON.stringify(identity.sourceFacts) === JSON.stringify(expectedFacts) ? 'passed' : 'failed' });
    obligations.push({ name: 'receipt-progress', status: observations.length === expectedKinds.length
      && observations.every((row, index) => row.status === 'completed' && row.kind === expectedKinds[index]
        && (expectedKinds[index] === 'update'
          ? row.value?.initialOutcome === 'outcome_unknown'
            && row.value?.originalOperationId === row.request?.request?.operation_id
            && row.value?.reconciledStatus?.status === 'committed'
            && row.value?.reconciledStatus?.result?.operation_id === row.request?.request?.operation_id
          : expectedKinds[index] === 'archive' ? row.value?.status === 'archived'
          : expectedKinds[index] === 'read' ? row.value?.pool?.input?.unit === 1 && row.value?.delivery === null
          : row.value?.status === 'committed' && row.value?.result?.operation_id === row.request?.request?.operation_id)) ? 'passed' : 'failed' });
    return obligations;
  };
}

test('N4 real Equipment create/update/delete receipt progress with bounded observation and archive cleanup', { skip: !available && `frozen N2 native binary not found: ${binary}` }, async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n4-equipment-'));
  let workflow;
  let proxy;
  let activeEquipmentSnapshot;
  const started = performance.now();
  try {
    workflow = await openWorkflow(directory, 'equipment');
    const { model, operator, native, metadata } = workflow;
    proxy = await lostReplyRecoveryProxy(workflow);
    const client = proxy.client;
    const pool = randomUUID(), delivery = randomUUID(), reservation = randomUUID();
    const facts = [
      { op: 'create', contract: 'Pool', id: pool, fields: { unit: 1 } },
      { op: 'create', contract: 'Delivery', id: delivery, fields: { pool, at: '0', quantity: '10' } },
      { op: 'update', id: delivery, set: { quantity: '12' } },
      { op: 'delete', id: delivery },
    ];
    const retainedPlans = [];
    const receipts = [];
    let lostReply = null;
    let recovery = null;
    const actions = async function* equipmentActions() {
      const firstPlan = await client.prepare(model.draftFixture([
        { contract: 'Pool', id: pool, fields: { unit: 1 } },
        { contract: 'Delivery', id: delivery, fields: { pool, at: '0', quantity: '10' } },
        { contract: 'Reservation', id: reservation, fields: { pool, starts: '0', ends: '20', requested: '5', active: true } },
      ], { returning: [pool, delivery, reservation] }));
      await savePlan(path.join(directory, 'equipment-create.plan.json'), firstPlan);
      retainedPlans.push(firstPlan);
      yield { id: 'equipment-create', kind: 'create', mutation: true, request: firstPlan,
        run: async () => { const receipt = await client.execute(firstPlan); receipts.push(receipt); return receipt; } };

      const current = await client.call('records.get', { model: model.identity, id: delivery });
      const updatePlan = await client.prepare({ model: model.identity, commands: [{ op: 'update', id: delivery,
        if_version: current.version, set: { quantity: '12' }, unset: [] }], returning: [delivery] });
      await savePlan(path.join(directory, 'equipment-update.plan.json'), updatePlan);
      retainedPlans.push(updatePlan);
      proxy.lose(updatePlan.request.operation_id);
      const serviceBefore = workflow.service.service;
      yield { id: 'equipment-update-lost-reply', kind: 'update', mutation: true, request: updatePlan,
        run: async () => {
          let status;
          try { status = await client.execute(updatePlan); }
          catch (error) {
            if (error.code !== 'outcome_unknown') throw error;
            lostReply = { outcome: error.code, operationId: updatePlan.request.operation_id };
            await proxy.recover();
            status = await client.status(updatePlan);
            activeEquipmentSnapshot = await native.inspect();
            recovery = { serviceStoppedAndRestarted: workflow.service.service !== serviceBefore,
              status: status.status, operationId: status.result?.operation_id ?? null,
              exactOriginalPlanRetained: retainedPlans[1] === updatePlan };
            receipts.push(status);
            return { initialOutcome: 'outcome_unknown', originalOperationId: updatePlan.request.operation_id,
              reconciledStatus: status };
          }
          receipts.push(status);
          return status;
        } };

      const updated = await client.call('records.get', { model: model.identity, id: delivery });
      const deletePlan = await client.prepare({ model: model.identity, commands: [{ op: 'delete', id: delivery,
        if_version: updated.version }], returning: [delivery] });
      await savePlan(path.join(directory, 'equipment-delete.plan.json'), deletePlan);
      retainedPlans.push(deletePlan);
      yield { id: 'equipment-delete', kind: 'delete', mutation: true, request: deletePlan,
        run: async () => { const receipt = await client.execute(deletePlan); receipts.push(receipt); return receipt; } };

      yield { id: 'equipment-read', kind: 'read', mutation: false, run: async () => {
        const poolRecord = await client.call('records.get', { model: model.identity, id: pool });
        let deliveryRead = null;
        try { deliveryRead = await client.call('records.get', { model: model.identity, id: delivery }); }
        catch (error) { if (error.code !== 'not_found') throw error; }
        return { pool: poolRecord, delivery: deliveryRead ?? null };
      } };
    };
    const archivePath = path.join(directory, 'equipment.archive.json');
    const allActions = async function* () {
      yield* actions();
      yield { id: 'equipment-archive', kind: 'archive', mutation: false,
      run: async () => {
        await operator.stopService({ service: workflow.service.service });
        workflow.serviceRunning = false;
        const archived = await operator.archive({ destination: archivePath });
        await new Promise(resolve => setTimeout(resolve, 50));
        return archived;
      } };
    };
    const sourceFacts = { initial: facts.slice(0, 3), updates: [{ id: delivery, quantity: '12' }], deleted: [delivery] };
    const setupMs = performance.now() - started;
    const run = await runWorkload({ scenario: churnScenario({ actions: allActions(), maxActions: 6 }), state: { native, client },
      profile: workloadProfile(5, setupMs), observe: async () => observeResources({ processes: observedProcesses(metadata.pid), native: metadata, paths: [directory] }),
      identity: { trial: 'equipment-receipt-progress', native: metadata, sourceFacts } });
    assert.equal(run.status, 'complete', JSON.stringify({ status: run.status, failed: run.failed, unresolved: run.unresolved,
      dropped: run.dropped, offered: run.offered, completed: run.completed, exhausted: run.exhausted,
      sampleStatuses: run.samples.map(sample => sample.status), cancelled: run.cancelled, timedOut: run.timedOut,
      iteratorUnresolved: run.iteratorUnresolved, iteratorCleanupUnresolved: run.iteratorCleanupUnresolved,
      droppedResults: run.droppedResults, costs: run.costs }));
    assert.deepEqual(run.observations.map(row => row.kind), ['create', 'update', 'delete', 'read', 'archive']);
    assert.deepEqual(run.observations.slice(0, 3).map(row => (row.value.reconciledStatus ?? row.value).result.records.map(record => record.id)), [[pool, delivery, reservation], [delivery], [delivery]]);
    assert.deepEqual(run.observations.slice(0, 3).map(row => row.request), retainedPlans);
    assert.deepEqual(lostReply, { outcome: 'outcome_unknown', operationId: retainedPlans[1].request.operation_id });
    assert.deepEqual(recovery, { serviceStoppedAndRestarted: true, status: 'committed',
      operationId: retainedPlans[1].request.operation_id, exactOriginalPlanRetained: true });
    assert.equal(run.observations[1].value.initialOutcome, 'outcome_unknown');
    assert.equal(run.observations[1].value.reconciledStatus.result.operation_id, retainedPlans[1].request.operation_id);
    assert.equal(proxy.upstreamCommit, true, 'proxy observed the upstream commit before dropping the reply');
    const check = await checkRun({ run, oracle: receiptOracle(['create', 'update', 'delete', 'read', 'archive'], sourceFacts) });
    assert.equal(check.status, 'passed', JSON.stringify({ status: check.status, obligations: check.obligations }));
    assert.equal(run.observations[3].value.pool.input.unit, 1);
    assert.equal(run.observations[3].value.delivery, null);
    assert.equal((await native.check()).status, 'valid');
    const equipmentSnapshot = activeEquipmentSnapshot;
    const equipmentSnapshotCheck = checkSourceSnapshot({ model: 'equipment', facts: {
      [pool]: { contract: 101, fields: { unit: 1 } },
      [delivery]: { contract: 205, fields: { pool, at: '0', quantity: '12' } },
      [reservation]: { contract: 410, fields: { pool, starts: '0', ends: '20', requested: '5', active: true } },
    }, snapshot: equipmentSnapshot });
    assert.ok(!equipmentSnapshotCheck.obligations.some(row => row.status === 'failed'), JSON.stringify({
      obligations: equipmentSnapshotCheck.obligations, actualRoots: equipmentSnapshot.roots,
      expectedRoots: evaluateSources('equipment', { [pool]: { contract: 101, fields: { unit: 1 } },
        [delivery]: { contract: 205, fields: { pool, at: '0', quantity: '12' } },
        [reservation]: { contract: 410, fields: { pool, starts: '0', ends: '20', requested: '5', active: true } } }).roots,
    }));
    assert.equal(equipmentSnapshotCheck.obligations.find(row => row.name === 'query-descriptor-contents')?.status, 'passed');
    assert.equal(equipmentSnapshotCheck.obligations.find(row => row.name === 'role-binding-contents')?.status, 'passed');
    assert.equal(equipmentSnapshot.roots[0].summary.value.count, 3, 'equal-time delivery/output leaves remain separate summary members');
    assert.equal((await readFile(archivePath)).length > 0, true);
    assert.ok(run.durationMs < 15_000);
    assert.ok(performance.now() - started < 15_000);
    t.diagnostic(JSON.stringify({ trial: 'equipment', actualDurationMs: run.durationMs, costs: run.costs, native: metadata,
      samples: run.samples.map(sample => ({ atMs: sample.atMs, status: sample.status,
        platform: sample.value.platform, linuxMetricsAvailable: sample.value.linuxMetricsAvailable,
        controllerPid: sample.value.processes.controller.pid, nativePid: sample.value.processes.native?.pid ?? null,
        observerMs: sample.value.observerMs })),
      receipts: run.observations.filter(row => row.mutation).map(row => {
        const receipt = row.value.reconciledStatus ?? row.value;
        return { initialOutcome: row.value.initialOutcome ?? receipt.status, status: receipt.status,
          operationId: receipt.result.operation_id, recordIds: receipt.result.records.map(record => record.id) };
      }),
      plans: retainedPlans, lostReply, recovery, upstreamCommitObservedBeforeDrop: proxy.upstreamCommit,
      archive: { status: run.observations.at(-1).value.status, path: archivePath }, sourceFacts,
      inspectCheck: { status: equipmentSnapshotCheck.status, obligations: equipmentSnapshotCheck.obligations },
      cleanup: 'finally stops the owned service and host and removes the trial directory' }));
  } finally {
    if (proxy) await proxy.close();
    if (workflow) { try { if (workflow.serviceRunning) await workflow.operator.stopService({ service: workflow.service.service }); } finally { await workflow.native.close(); } }
    await rm(directory, { recursive: true, force: true });
  }
});

test('N4 real Quantity typed proposals retain exact committed receipt progress and source facts', { skip: !available && `frozen N2 native binary not found: ${binary}` }, async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n4-quantity-'));
  let workflow;
  const started = performance.now();
  try {
    workflow = await openWorkflow(directory, 'quantity');
    const { client, model, metadata } = workflow;
    const state = preparePopulation(model, { Source: 1, Scale: 1, Join: 1 }, {
      seed: 'n4-quantity-receipts', batchSize: 1,
      strategies: { Source: () => ({ value: '12' }), Scale: () => ({ factor: { numerator: '1', denominator: '2' }, rounding: 'half_even' }), Join: () => ({}) },
      selectContract(_eligible, remaining) { return remaining.Source ? 'Source' : remaining.Scale ? 'Scale' : 'Join'; },
      selectReference(_child, _field, pools) { return ['Source', pools.Source[0].id]; },
      rules: { Scale(fields) { return fields; } },
    });
    const sourceFacts = { proposals: [], independentDerivedExpectations: { Source: '12', Scale: '6', Join: '24' } };
    const retainedPlans = [];
    const actions = async function* quantityActions() {
      for (const name of ['Source', 'Scale', 'Join']) {
        const proposal = await propose(state, {});
        const plan = await client.prepare({ model: model.identity, commands: proposal.commands, returning: proposal.returning });
        await savePlan(path.join(directory, `quantity-${name}.plan.json`), plan);
        retainedPlans.push(plan);
        state.pending.plan = plan;
        sourceFacts.proposals.push({ contract: name, commands: proposal.commands, additions: proposal.additions });
        yield { id: `quantity-${name}`, kind: 'create', mutation: true, request: plan,
          run: async () => {
            const receipt = await client.execute(plan);
            accept(state, proposal, plan, receipt);
            if (name === 'Join') await new Promise(resolve => setTimeout(resolve, 50));
            return receipt;
          } };
      }
    };
    const setupMs = performance.now() - started;
    const run = await runWorkload({ scenario: churnScenario({ actions: actions(), maxActions: 4 }), state: { population: state, client },
      profile: workloadProfile(3, setupMs), observe: async () => observeResources({ processes: observedProcesses(metadata.pid), native: metadata, paths: [directory] }),
      identity: { trial: 'quantity-receipt-progress', native: metadata, sourceFacts } });
    assert.equal(run.status, 'complete', JSON.stringify({ status: run.status, failed: run.failed, unresolved: run.unresolved,
      dropped: run.dropped, offered: run.offered, completed: run.completed, exhausted: run.exhausted,
      sampleStatuses: run.samples.map(sample => sample.status) }));
    assert.deepEqual(run.observations.map(row => row.kind), ['create', 'create', 'create']);
    assert.deepEqual(run.observations.map(row => row.request), retainedPlans);
    assert.deepEqual(state.accepted, { Source: 1, Scale: 1, Join: 1 });
    assert.deepEqual(run.observations.map(row => row.value.result.records.map(record => record.id)), sourceFacts.proposals.map(row => row.additions.map(item => item.id)));
    const sourceId = sourceFacts.proposals[0].additions[0].id;
    const scaleId = sourceFacts.proposals[1].additions[0].id;
    const joinId = sourceFacts.proposals[2].additions[0].id;
    const source = await client.call('records.get', { model: model.identity, id: sourceId });
    const scale = await client.call('records.get', { model: model.identity, id: scaleId });
    const join = await client.call('records.get', { model: model.identity, id: joinId });
    assert.equal(source.input.value, '12');
    assert.equal(String(source.derived.quantity), '12');
    assert.equal(String(scale.derived.quantity), '6');
    assert.equal(String(join.derived.quantity), '24');
    assert.equal((await workflow.native.check()).status, 'valid');
    const quantityFacts = Object.fromEntries(sourceFacts.proposals.flatMap(({ contract, additions }) => additions.map(item =>
      [item.id, { contract: { Source: 101, Scale: 205, Join: 309 }[contract], fields: item.fields }])));
    const quantitySnapshotCheck = checkSourceSnapshot({ model: 'quantity', facts: quantityFacts, snapshot: await workflow.native.inspect() });
    assert.ok(!quantitySnapshotCheck.obligations.some(row => row.status === 'failed'), JSON.stringify(quantitySnapshotCheck.obligations));
    const check = await checkRun({ run, oracle: receiptOracle(['create', 'create', 'create'], sourceFacts) });
    assert.equal(check.status, 'passed', JSON.stringify({ status: check.status, obligations: check.obligations }));
    assert.ok(run.durationMs < 15_000);
    assert.ok(performance.now() - started < 15_000);
    t.diagnostic(JSON.stringify({ trial: 'quantity', actualDurationMs: run.durationMs, costs: run.costs, native: metadata,
      samples: run.samples.map(sample => ({ atMs: sample.atMs, status: sample.status,
        platform: sample.value.platform, linuxMetricsAvailable: sample.value.linuxMetricsAvailable,
        controllerPid: sample.value.processes.controller.pid, nativePid: sample.value.processes.native?.pid ?? null,
        observerMs: sample.value.observerMs })),
      receipts: run.observations.map(row => ({ status: row.value.status, operationId: row.value.result.operation_id,
        recordIds: row.value.result.records.map(record => record.id) })), plans: retainedPlans, sourceFacts,
      accepted: state.accepted, inspectCheck: { status: quantitySnapshotCheck.status, obligations: quantitySnapshotCheck.obligations },
      cleanup: 'finally stops the owned service and host and removes the trial directory' }));
  } finally {
    if (workflow) { try { if (workflow.serviceRunning) await workflow.operator.stopService({ service: workflow.service.service }); } finally { await workflow.native.close(); } }
    await rm(directory, { recursive: true, force: true });
  }
});
