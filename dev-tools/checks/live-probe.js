#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { connectDatabase } = require('../../gateway/connection');
const { fixedStoreDirectory } = require('../../gateway/directory');
const { startLiveWakeups } = require('../../gateway/live');
const { createRuntime } = require('../../gateway/runtime');
const { createTableStore } = require('../../gateway/store');
const { workEnvelopeKey } = require('../../gateway/queues/port');
const { parseSchema } = require('../compiler/schema');
const { generateLifecycleFields, generateRuntimeContracts } = require('../compiler/generators/effects');
const { start, client } = require('../temporal-tree/harness');

async function until(check, message) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (await check()) return;
    await delay(20);
  }
  throw new Error(message);
}

// Break an actual WebSocket connection without stopping the database. Writes
// through the direct connection can commit while the subscriber is offline.
async function tcpProxy(targetPort) {
  const sockets = new Set();
  let accepting = true;
  const server = net.createServer(incoming => {
    if (!accepting) { incoming.destroy(); return; }
    const outgoing = net.connect(targetPort, '127.0.0.1');
    for (const socket of [incoming, outgoing]) {
      sockets.add(socket);
      socket.on('error', () => {});
      socket.on('close', () => sockets.delete(socket));
    }
    incoming.on('close', () => outgoing.destroy());
    outgoing.on('close', () => incoming.destroy());
    incoming.pipe(outgoing).pipe(incoming);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    endpoint: 'ws://127.0.0.1:' + server.address().port + '/rpc',
    pause() { accepting = false; for (const socket of sockets) socket.destroy(); },
    resume() { accepting = true; },
    async close() {
      accepting = false;
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

async function nativeLive() {
  let server, proxy, connection, stop;
  const design = { namespace: 'temporal_probe', database: 'fixture' };
  const source = [
    "DEFINE TABLE live_task SCHEMAFULL COMMENT '@rebase-operation queued CREATE';",
    'DEFINE FIELD id ON live_task TYPE string | uuid | array | int | object DEFAULT rand::uuid::v7();',
    'DEFINE FIELD owned_by ON live_task TYPE record DEFAULT rebase_tenant:fixture;',
    'DEFINE FIELD tenant ON live_task TYPE record DEFAULT rebase_tenant:fixture;',
    "DEFINE FIELD value ON live_task TYPE string COMMENT '@rebase-operation-input';",
  ].join('\n');
  const schema = parseSchema(source, '');
  const contract = generateRuntimeContracts(schema).tables.live_task;
  const handlers = {
    tables: ['live_task'],
    contracts: new Map([['live_task', contract]]),
    get(table) { return table === 'live_task' ? { contract, execute() {} } : null; },
  };
  const published = new Set();
  const hints = [];
  let recoveries = 0;
  const errors = [];
  try {
    server = await start({ engine: 'memory' });
    const q = client(server.url);
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;');
    await q(source + '\n' + generateLifecycleFields(schema) + '\n'
      + fs.readFileSync(path.resolve(__dirname, '../../framework/reconciliation.surql'), 'utf8'));
    proxy = await tcpProxy(Number(new URL(server.url).port));
    connection = await connectDatabase({
      ...design, endpoint: proxy.endpoint, username: 'root', password: 'root',
      reconnect: { retryDelay: 30, retryDelayMax: 80, retryDelayJitter: 0, attempts: -1 },
    });
    const store = createTableStore(connection);
    const hadOwnLiveMethod = Object.hasOwn(connection.db, 'live');
    const liveMethod = connection.db.live;
    let liveCalls = 0;
    let partialKills = 0;
    connection.db.live = function (...args) {
      liveCalls += 1;
      if (liveCalls === 2) {
        return { fields() { throw new Error('injected later-table subscription failure'); } };
      }
      const query = liveMethod.apply(this, args);
      return {
        fields(...fields) {
          return Promise.resolve(query.fields(...fields)).then(subscription => {
            const kill = subscription.kill.bind(subscription);
            subscription.kill = (...killArgs) => { partialKills += 1; return kill(...killArgs); };
            return subscription;
          });
        },
      };
    };
    try {
      await assert.rejects(store.watch(['live_task', 'partial_failure_task'], () => {}, () => {}),
        /injected later-table subscription failure/);
      assert.equal(liveCalls, 2);
      assert.equal(partialKills, 1, 'a partial live attachment kills its earlier subscription');
    } finally {
      if (hadOwnLiveMethod) connection.db.live = liveMethod;
      else delete connection.db.live;
    }
    const runtime = createRuntime({
      stores: fixedStoreDirectory(store, design), handlers,
      queue: { async publish(envelope) {
        assert.equal(envelope.version, 2);
        assert.deepEqual(Object.keys(envelope.locator), ['id']);
        published.add(envelope.locator.id);
        hints.push(envelope);
        return { queued: true };
      } },
      options: { defaultContext: design },
    });
    stop = await startLiveWakeups({
      store, runtime, handlers, onError: error => errors.push(error.message),
      reconciler: { async run() { recoveries += 1; return runtime.reconcile(design); } },
    });
    await q("BEGIN; CREATE live_task:committed SET value='committed'; COMMIT;");
    await until(() => published.has('live_task:committed'), 'committed task was not woken');
    await assert.rejects(q("BEGIN; CREATE live_task:cancelled SET value='rolled back'; CANCEL;"), /cancelled transaction/);
    await delay(80);
    assert.equal(published.has('live_task:cancelled'), false, 'cancelled writes must not publish hints');
    const nativeId = await q("LET $created = CREATE ONLY live_task SET value='uuid'; RETURN <string>$created.id;");
    const sdkId = (await store.load(nativeId)).id;
    await runtime.enqueue({ id: nativeId });
    await runtime.enqueue({ id: sdkId });
    assert.notEqual(nativeId, sdkId, 'probe exercises native and SDK UUID quoting');
    assert.equal(new Set(hints.filter(hint => hint.locator.id === sdkId).map(workEnvelopeKey)).size, 1,
      'equivalent record spellings must create the same queue identity');
    console.log('live: committed-only notifications passed');

    proxy.pause();
    await until(() => connection.db.status !== 'connected', 'socket cut did not disconnect the SDK');
    await q("CREATE live_task:missed SET value='committed while offline';");
    assert.equal(published.has('live_task:missed'), false);
    proxy.resume();
    await until(() => recoveries > 0 && published.has('live_task:missed'),
      'reconnect did not reconcile a committed task with a missed live message');
    console.log('live: socket reconnect and durable recovery passed');
    await q("CREATE live_task:resumed SET value='new live message after reconnect';");
    await until(() => published.has('live_task:resumed'), 'managed subscription did not resume');
    console.log('live: managed subscription resumed');
    await stop();
    stop = null;
    const count = published.size;
    await q("CREATE live_task:after_stop SET value='stopped';");
    await delay(80);
    assert.equal(published.size, count, 'shutdown must detach the live callback');
    assert.deepEqual(errors, []);
    stop = await startLiveWakeups({ store, runtime, handlers, reconciler: { run: async () => {} } });
    proxy.pause();
    await until(() => !connection.db.isConnected, 'offline-shutdown probe did not disconnect');
    const stoppedAt = Date.now();
    await stop();
    stop = null;
    assert(Date.now() - stoppedAt < 1500, 'offline live shutdown must not wait for a reconnect');
  } catch (error) {
    console.error('live diagnostic:', error.message, { status: connection?.db.status, recoveries, errors });
    throw error;
  } finally {
    proxy?.resume();
    await stop?.();
    await connection?.close();
    await proxy?.close();
    await server?.close();
  }
}

async function boundedBurst() {
  let emit, stopped = false, recoveries = 0, release;
  const gate = new Promise(resolve => { release = resolve; });
  const seen = [];
  const contract = { mode: 'queued' };
  const handlers = {
    tables: ['burst'], contracts: new Map([['burst', contract]]),
    get() { return { contract }; },
  };
  const stop = await startLiveWakeups({
    handlers, maxPending: 2,
    store: { async watch(_tables, notify) {
      emit = notify;
      return async () => { stopped = true; };
    } },
    runtime: { async enqueue({ id }) { seen.push(id); await gate; } },
    reconciler: { async run() { recoveries += 1; } },
  });
  try {
    emit('burst:first');
    await delay(0);
    for (let i = 0; i < 1000; i += 1) emit('burst:' + i);
    await delay(0);
    assert.equal(seen.length, 1, 'one enqueue is active while its publish is blocked');
    assert(recoveries > 0, 'overflow must request durable reconciliation');
    release();
    await until(() => seen.length === 3, 'bounded pending hints did not drain');
    await stop();
    emit('burst:after_stop');
    await delay(0);
    assert.equal(seen.length, 3, 'the pending set is bounded to two plus one active call');
    assert(stopped);
  } finally { release(); await stop(); }
}

async function attachmentRetryAndStop() {
  const contract = { mode: 'queued' };
  const handlers = {
    tables: ['attach_task'], contracts: new Map([['attach_task', contract]]),
    get() { return { contract }; },
  };
  const errors = [];
  const enqueued = [];
  let attempts = 0;
  let activeWatches = 0;
  let stoppedWatches = 0;
  let notify;
  let recoveries = 0;
  const stop = await startLiveWakeups({
    retryDelayMs: 20,
    maxRetryDelayMs: 40,
    handlers,
    store: { async watch(_tables, onChange) {
      attempts += 1;
      if (attempts === 1) throw new Error('injected first attachment failure');
      activeWatches += 1;
      notify = onChange;
      let active = true;
      return async () => {
        if (!active) return;
        active = false;
        activeWatches -= 1;
        stoppedWatches += 1;
      };
    } },
    runtime: { async enqueue({ id }) { enqueued.push(id); } },
    reconciler: { async run() { recoveries += 1; } },
    onError: error => errors.push(error.message),
  });
  try {
    assert.equal(attempts, 1, 'the first attachment is attempted immediately');
    await until(() => recoveries > 0, 'durable reconciliation did not run after attachment failure');
    await delay(5);
    assert.equal(attempts, 1, 'retry waits for its bounded backoff');
    await until(() => attempts === 2 && activeWatches === 1, 'live attachment did not recover');
    notify('attach_task:recovered');
    await until(() => enqueued.includes('attach_task:recovered'), 'recovered subscription did not enqueue its hint');
    assert.deepEqual(errors, ['injected first attachment failure']);
  } finally {
    await stop();
  }
  assert.equal(activeWatches, 0, 'stop cleans the recovered watcher');
  assert.equal(stoppedWatches, 1);
  await delay(90);
  assert.equal(attempts, 2, 'stop leaves no retry timer behind');
  assert.equal(activeWatches, 0);

  let cancelledAttempts = 0;
  const stopDuringBackoff = await startLiveWakeups({
    retryDelayMs: 30,
    maxRetryDelayMs: 30,
    handlers,
    store: { async watch() { cancelledAttempts += 1; throw new Error('retry cancellation fixture'); } },
    runtime: { async enqueue() {} },
    reconciler: { async run() {} },
  });
  assert.equal(cancelledAttempts, 1);
  await stopDuringBackoff();
  await delay(70);
  assert.equal(cancelledAttempts, 1, 'shutdown cancels a scheduled attachment retry');

  let pendingAttempts = 0;
  let finishPendingAttach;
  let lateActiveWatches = 0;
  let lateStoppedWatches = 0;
  const stopDuringAttach = await startLiveWakeups({
    retryDelayMs: 10,
    maxRetryDelayMs: 10,
    attachShutdownTimeoutMs: 200,
    handlers,
    store: { async watch() {
      pendingAttempts += 1;
      if (pendingAttempts === 1) throw new Error('pending attach fixture');
      return new Promise(resolve => {
        finishPendingAttach = () => {
          lateActiveWatches += 1;
          resolve(async () => { lateActiveWatches -= 1; lateStoppedWatches += 1; });
        };
      });
    } },
    runtime: { async enqueue() {} },
    reconciler: { async run() {} },
  });
  await until(() => pendingAttempts === 2 && finishPendingAttach, 'retry attachment did not start');
  let stopCompleted = false;
  const stopping = stopDuringAttach().then(() => { stopCompleted = true; });
  await delay(5);
  assert.equal(stopCompleted, false, 'shutdown waits briefly for an in-flight attach to clean up');
  finishPendingAttach();
  await stopping;
  assert.equal(lateActiveWatches, 0, 'a watcher resolving during shutdown is immediately cleaned');
  assert.equal(lateStoppedWatches, 1);
  await delay(30);
  assert.equal(pendingAttempts, 2);
  console.log('live: failed initial attachment retried, reconciliation continued, and shutdown cleaned the watcher/timer');
}

async function main() {
  await attachmentRetryAndStop();
  await boundedBurst();
  await nativeLive();
  console.log('Live wakeups passed: initial-attach recovery, partial-attachment cleanup, committed-only hints, actual socket loss, durable reconnect recovery, managed resubscription, bounded bursts, and shutdown.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
