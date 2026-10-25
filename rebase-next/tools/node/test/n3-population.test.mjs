import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { connect, savePlan } from '../client.mjs';
import { resolveConfig } from '../config.mjs';
import { prepareModel } from '../model.mjs';
import { openNative } from '../native.mjs';
import { openOperator } from '../operator.mjs';
import { accept, preparePopulation, propose, reject } from '../population.mjs';
import { commitPopulationProposal } from '../examples/n3-population.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const binary = process.env.REBASE_NODE_N3_BINARY ?? path.join(root, 'target/n2-native-default/rebase-next');
const available = existsSync(binary);
const methods = ['service.start', 'service.stop', 'identity.issue'];

async function openWorkflow(directory, selector) {
  const tenant = '11111111-1111-4111-8111-111111111111';
  const actor = '22222222-2222-4222-8222-222222222222';
  const pair = generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const identity = { issuer: `n3-${selector}`, audience: `n3-${selector}`, public_keys: { local: publicKeyPem }, max_token_seconds: 300 };
  const config = resolveConfig({ overrides: {
    native: {
      binary: path.resolve(binary), environment: {},
      configuration: { model: selector, backend: { kind: 'redb', cluster_file: null }, target: { mode: 'create', path: path.join(directory, `${selector}.redb`), tenant, actor }, operator_methods: methods },
    },
    service: { listen: '127.0.0.1:0', identity, max_inflight: 8, request_timeout_seconds: 15, effects: null },
  } });
  const native = await openNative(config);
  const operator = openOperator(native, { scope: native.scope, methods });
  let service;
  try {
    service = await operator.startService({ config: config.service });
    const token = (await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' }, privateKeyPem })).token;
    const client = connect({ endpoint: service.endpoint, credential: token });
    const model = prepareModel(await native.catalog({ scope: 'developer' }), { native, selector });
    return { native, operator, service, model, client };
  } catch (error) {
    if (service) await operator.stopService({ service: service.service });
    await native.close();
    throw error;
  }
}

async function commitProposal(job, proposal, client, directory, name) {
  const plan = await client.prepare({ model: job.model.identity, commands: proposal.commands, returning: proposal.returning });
  const planPath = path.join(directory, `${name}.plan.json`);
  await savePlan(planPath, plan);
  job.state.pending.plan = plan;
  const receipt = await client.execute(plan);
  accept(job.state, proposal, plan, receipt);
  return receipt;
}

async function updateQuantitySource(client, model, directory, id, value, label) {
  const current = await client.call('records.get', { model: model.identity, id });
  const plan = await client.prepare({ model: model.identity, commands: [{
    op: 'update', id, if_version: current.version, set: { value }, unset: [],
  }], returning: [id] });
  await savePlan(path.join(directory, `${label}.plan.json`), plan);
  return client.execute(plan);
}

function exactFactorForTarget(currentText, targetValue) {
  let numerator = BigInt(targetValue);
  let denominator = BigInt(currentText);
  let left = numerator < 0n ? -numerator : numerator;
  let right = denominator < 0n ? -denominator : denominator;
  while (right !== 0n) [left, right] = [right, left % right];
  const gcd = left || 1n;
  numerator /= gcd;
  denominator /= gcd;
  if (denominator < 0n) { numerator = -numerator; denominator = -denominator; }
  return { numerator: numerator.toString(), denominator: denominator.toString() };
}

test('N3 Equipment public population uses an existing anchor, typed selector, and retains stale-context rejection', { skip: !available && `native binary not found: ${binary}` }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n3-equipment-'));
  let workflow;
  try {
    workflow = await openWorkflow(directory, 'equipment');
    const { model, client } = workflow;
    const fakerState = preparePopulation(model, { Pool: 1 }, { seed: 'prepared-faker', batchSize: 1 });
    const fakerProposal = await propose(fakerState, {});
    assert.equal(model.validate('Pool', fakerProposal.commands[0].fields).valid, true);
    assert.equal(typeof fakerProposal.commands[0].fields.unit, 'number');

    const poolId = '33333333-3333-4333-8333-333333333333';
    const anchorPlan = await client.prepare(model.draftFixture([{ contract: 'Pool', id: poolId, fields: { unit: 1 } }], { returning: [poolId] }));
    await savePlan(path.join(directory, 'anchor.plan.json'), anchorPlan);
    const anchorReceipt = await client.execute(anchorPlan);
    assert.equal(anchorReceipt.status, 'committed');

    const state = preparePopulation(model, { Delivery: 1, Reservation: 1 }, {
      seed: 'equipment-n3', batchSize: 1,
      existing: { Pool: [{ id: poolId, contract: 'Pool', fields: { unit: 1 } }] },
      strategies: {
        Delivery: () => ({ at: '0', quantity: '10' }),
        Reservation: () => ({}),
      },
      selectContract(eligible, remaining) { return eligible.includes('Delivery') && remaining.Delivery > 0 ? 'Delivery' : 'Reservation'; },
      selectReference(child, field, pools) {
        assert.ok(['Delivery', 'Reservation'].includes(child));
        assert.ok(Object.hasOwn(pools, 'Pool'));
        return ['Pool', poolId];
      },
      rules: { Reservation(fields, context) { return { ...fields, starts: context.start, ends: context.end, requested: context.requested, active: true }; } },
    });
    const delivery = await propose(state, async (child, refs) => {
      const pool = await client.call('records.get', { model: model.identity, id: refs.pool });
      return { observedUnit: pool.input.unit };
    });
    assert.equal(delivery.commands[0].fields.pool, poolId);
    await commitProposal({ state, model }, delivery, client, directory, 'delivery');
    assert.equal(state.accepted.Delivery, 1);
    assert.equal(state.poolIds.Pool[0], poolId);
    assert.equal(state.referenceUsage[`Delivery\0pool\0Pool\0${poolId}`], 1);
    assert.throws(() => accept(state, delivery, state.pending?.plan, { status: 'committed' }), error => error.code === 'pending_mismatch');

    const stale = await propose(state, () => ({ start: '10', end: '10', requested: '8' }));
    const invalidPlan = await client.prepare({ model: model.identity, commands: stale.commands, returning: stale.returning });
    await savePlan(path.join(directory, 'stale-context.plan.json'), invalidPlan);
    state.pending.plan = invalidPlan;
    assert.equal(Object.isFrozen(state.pending), true);
    assert.equal(Object.hasOwn(state.pending, 'planSnapshot'), false);
    const inspectedPlan = state.pending.plan;
    inspectedPlan.request.context = 'caller mutation';
    assert.notEqual(state.pending.plan.request.context, 'caller mutation');
    assert.throws(() => reject(state, stale, invalidPlan, Object.assign(new Error('response lost'), { name: 'RpcError', code: 'outcome_unknown', httpStatus: 200 })), error => error.code === 'outcome_uncertain');
    assert.equal(state.pending.proposal, stale);
    const rebound = structuredClone(invalidPlan);
    rebound.request.operation_id = randomUUID();
    assert.throws(() => { state.pending.plan = rebound; }, error => error.code === 'plan_rebound' || error.code === 'plan_mismatch');
    let nativeRejection;
    await assert.rejects(client.execute(invalidPlan), error => { nativeRejection = error; return error.code === 'invalid_input'; });
    reject(state, stale, invalidPlan, nativeRejection);
    assert.equal(state.accepted.Reservation, 0);
    assert.equal(state.pending, null);
  } finally {
    if (workflow) {
      try { await workflow.operator.stopService({ service: workflow.service.service }); } finally { await workflow.native.close(); }
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test('N3 Quantity public population composes exact rational references through native receipts', { skip: !available && `native binary not found: ${binary}` }, async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-n3-quantity-'));
  let workflow;
  try {
    workflow = await openWorkflow(directory, 'quantity');
    const { model, client } = workflow;
    const state = preparePopulation(model, { Source: 1, Scale: 1, Join: 1 }, {
      seed: 20261025, batchSize: 1,
      strategies: {
        Source: () => ({ value: '12' }),
        Scale: () => ({ factor: { numerator: '1', denominator: '2' }, rounding: 'half_even' }),
        Join: () => ({}),
      },
      rules: { Scale(fields, context) { return { ...fields, factor: context.factor }; } },
      selectContract(eligible, remaining) {
        if (remaining.Source > 0) return 'Source';
        if (remaining.Scale > 0) return 'Scale';
        return 'Join';
      },
      selectReference(child, field, pools) {
        const source = pools.Source?.[0];
        if (!source) throw new Error('expected the accepted Source anchor');
        return ['Source', source.id];
      },
    });
    const sourceResult = await commitPopulationProposal({
      model, client, state, context: {}, planPath: path.join(directory, 'source.plan.json'),
    });
    const source = sourceResult.proposal;
    let scaleMode = 'stale';
    const freshScaleContext = async (child, refs) => {
      assert.equal(child, 'Scale');
      const parent = await client.call('records.get', { model: model.identity, id: refs.parent });
      assert.equal(parent.input.value, '12');
      const targetValue = scaleMode === 'stale' ? 24n : 6n;
      return {
        observedValue: parent.input.value,
        factor: exactFactorForTarget(parent.input.value, targetValue),
      };
    };
    const staleScale = await propose(state, freshScaleContext);
    assert.equal(staleScale.commands[0].fields.parent, source.additions[0].id);
    const stalePlan = await client.prepare({ model: model.identity, commands: staleScale.commands, returning: staleScale.returning });
    await savePlan(path.join(directory, 'stale-quantity-context.plan.json'), stalePlan);
    state.pending.plan = stalePlan;
    await updateQuantitySource(client, model, directory, source.additions[0].id, '1000000000000000000', 'concurrent-source-change');
    let staleContextRejection;
    await assert.rejects(client.execute(stalePlan), error => {
      staleContextRejection = error;
      return ['invalid_input', 'invariant', 'feedback', 'work_limit', 'state_limit', 'overflow'].includes(error.code);
    });
    reject(state, staleScale, stalePlan, staleContextRejection);
    assert.equal(state.accepted.Scale, 0);
    await updateQuantitySource(client, model, directory, source.additions[0].id, '12', 'restore-source');
    scaleMode = 'current';
    const scale = await propose(state, freshScaleContext);
    assert.equal(scale.commands[0].fields.parent, source.additions[0].id);
    await commitProposal({ state, model }, scale, client, directory, 'scale');
    const join = await propose(state, () => ({}));
    assert.equal(join.commands[0].fields.left, source.additions[0].id);
    assert.equal(join.commands[0].fields.right, source.additions[0].id);
    const receipt = await commitProposal({ state, model }, join, client, directory, 'join');
    assert.deepEqual(state.accepted, { Source: 1, Scale: 1, Join: 1 });
    assert.equal(receipt.status, 'committed');
    assert.equal(state.referenceUsage[`Scale\0parent\0Source\0${source.additions[0].id}`], 1);
    assert.equal(state.referenceUsage[`Join\0left\0Source\0${source.additions[0].id}`], 1);
    assert.equal(state.referenceUsage[`Join\0right\0Source\0${source.additions[0].id}`], 1);
    await assert.rejects(propose(state, {}), error => error.code === 'stalled');
  } finally {
    if (workflow) {
      try { await workflow.operator.stopService({ service: workflow.service.service }); } finally { await workflow.native.close(); }
    }
    await rm(directory, { recursive: true, force: true });
  }
});
