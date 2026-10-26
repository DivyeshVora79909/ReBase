import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, writeFile, stat } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const base = '/home/divyeshvora/.cache/rebase-g10/n5-6836c59';
const sdk = '/home/divyeshvora/javascript/node/projects/ReBase/rebase-next/target/g7-environment/root/usr';
const expectedSource = '6836c592abc99398d5e5440c18015b003859df49';
const runDirectory = path.join(base, `adapter-run-${randomUUID()}`);
await mkdir(runDirectory, { recursive: true, mode: 0o700 });
const report = { sourceCommit: expectedSource, node: process.version, scope: 'bounded local extracted-artifact lifecycle; one local FDB process, not multi-host latency', packages: [], adapters: [], cleanup: [] };
const methods = ['store.check', 'store.inspect', 'store.backup', 'store.restore', 'store.archive', 'store.reset', 'service.start', 'service.stop', 'identity.issue'];
let fdb;
let stage = 'load extracted modules';
try {
  const modules = {};
  for (const label of ['redb', 'all']) {
    const directory = path.join(base, `bundle-${label}`);
    modules[label] = Object.assign({}, ...await Promise.all(['config', 'native', 'operator', 'client', 'release', 'storage-check', 'oracles', 'infra'].map(name => import(pathToFileURL(path.join(directory, 'tools/node', `${name}.mjs`)).href))));
    const environment = label === 'all' ? { FDB_CLIENT_LIB_PATH: path.join(sdk, 'lib'), LD_LIBRARY_PATH: path.join(sdk, 'lib') } : {};
    const verified = await modules[label].verifyRelease({ directory, environment });
    assert.equal(verified.sourceCommit, expectedSource);
    report.packages.push({ label, directory, ...verified });
  }
  stage = 'local FoundationDB bootstrap';
  const port = await freePort();
  const clusterFile = path.join(runDirectory, 'fdb.cluster');
  await writeFile(clusterFile, `rebase_n5:${randomUUID().replaceAll('-', '')}@127.0.0.1:${port}\n`, { flag: 'wx', mode: 0o600 });
  fdb = await modules.all.openFdbEnvironment({ fdbserver: path.join(sdk, 'sbin/fdbserver'), fdbcli: path.join(sdk, 'bin/fdbcli'), clusterFile,
    dataDirectory: path.join(runDirectory, 'fdb-data'), logDirectory: path.join(runDirectory, 'fdb-logs'), serverLog: path.join(runDirectory, 'fdb-server.txt'),
    port, environment: { LD_LIBRARY_PATH: path.join(sdk, 'lib') }, startTimeoutMs: 30_000, stopTimeoutMs: 20_000, commandTimeoutMs: 60_000 });
  report.fdb = { start: await fdb.start(), bootstrap: await fdb.bootstrap(), probe: await fdb.check(), topology: { machines: 1, processes: 1, redundancy: 'single', memoryMiB: 512 } };
  for (const backend of ['redb', 'surrealkv', 'foundationdb']) {
    stage = `${backend} lifecycle`;
    report.adapters.push(await verifyBackend(backend, modules[backend === 'redb' ? 'redb' : 'all'], clusterFile));
    await save();
    console.log(JSON.stringify({ backend, status: report.adapters.at(-1).status, checks: report.adapters.at(-1).checks }));
  }
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.failure = { stage, name: error.name, code: error.code, message: error.message, stack: error.stack };
  process.exitCode = 1;
} finally {
  if (fdb) {
    try { report.cleanup.push({ role: 'foundationdb', ...await fdb.close() }); }
    catch (error) { report.status = 'failed'; report.cleanup.push({ role: 'foundationdb', status: 'failed', message: error.message }); process.exitCode = 1; }
  }
  if (report.cleanup.every(row => row.status === 'stopped')) {
    await rm(runDirectory, { recursive: true, force: true });
    report.ownedDataRemoved = true;
  }
  await save();
  console.log(JSON.stringify({ status: report.status, failure: report.failure, result: path.join(base, 'adapter-acceptance.json'), cleanup: report.cleanup }));
}

async function verifyBackend(kind, api, clusterFile) {
  const label = kind === 'redb' ? 'redb' : 'all';
  const binary = path.join(base, `bundle-${label}`, 'bin/rebase-next');
  const environment = label === 'all' ? { FDB_CLIENT_LIB_PATH: path.join(sdk, 'lib'), LD_LIBRARY_PATH: path.join(sdk, 'lib') } : {};
  const backend = { kind, cluster_file: kind === 'foundationdb' ? clusterFile : null };
  const tenant = randomUUID(), actor = randomUUID();
  const location = suffix => kind === 'foundationdb' ? { namespace: `n5_${kind}_${suffix}_${tenant.replaceAll('-', '')}` } : { path: path.join(runDirectory, `${kind}-${suffix}`) };
  const source = location('source'), restoredLocation = location('restored');
  const hostConfig = target => api.resolveConfig({ overrides: { native: { binary, environment,
    configuration: { model: 'equipment', backend, target, operator_methods: methods } }, runner: { startTimeoutMs: 30_000, closeTimeoutMs: 10_000 } } });
  const keys = generateKeyPairSync('ed25519');
  const identity = { issuer: `n5-${kind}`, audience: 'n5-release', public_keys: { local: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() }, max_token_seconds: 300 };
  const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const serviceConfig = { listen: '127.0.0.1:0', identity, max_inflight: 4, request_timeout_seconds: 15, effects: null };
  const output = { backend: kind, binarySha256: createHash('sha256').update(await readFile(binary)).digest('hex'), checks: [], cleanup: [] };
  const handles = new Set();
  const open = async target => { const h = await api.openNative(hostConfig(target)); handles.add(h); return h; };
  const close = async host => { const pid = host.pid; await host.close(); handles.delete(host); output.cleanup.push({ pid, status: 'stopped' }); };
  let host = await open({ mode: 'create', ...source, tenant, actor });
  try {
    const scope = host.scope;
    let operator = api.openOperator(host, { scope, methods });
    const description = await host.describe();
    assert.equal(description.ownership.mode, kind === 'foundationdb' ? 'shared_transactional' : 'exclusive');
    let peer;
    if (kind === 'foundationdb') { peer = await open({ mode: 'open', ...source, expect_store: scope.store }); await peer.check(); }
    else await assert.rejects(api.openNative(hostConfig({ mode: 'open', ...source, expect_store: scope.store })), error => error.code === 'store_busy');
    output.checks.push('ownership');
    let service = await operator.startService({ config: serviceConfig });
    const token = (await operator.issueIdentity({ identity, request: { tenant, actor, epoch: 0, ttl: 300, key_id: 'local' }, privateKeyPem })).token;
    let client = api.connect({ endpoint: service.endpoint, credential: token });
    await assert.rejects(client.call('store.inspect', { scope }), error => error.code === 'method_not_found');
    const fixture = await host.fixturePlan({ name: (await host.fixtureCatalog())[0].name, namespace: randomUUID() });
    let facts = api.stageSources({}, fixture.commands);
    const plan = await client.prepare({ model: fixture.model, commands: fixture.commands, returning: fixture.returning });
    const receipt = await client.execute(plan);
    assert.equal(receipt.status, 'committed');
    assert.deepEqual((await client.execute(plan)).result, receipt.result);
    output.checks.push('authenticated-fixture', 'original-replay', 'private-method-fence');
    const delivery = fixture.commands.find(row => row.op === 'create' && row.contract === 205).id;
    const current = await client.call('records.get', { model: scope.model, id: delivery });
    const quantity = (BigInt(current.input.quantity) + 2n).toString();
    const update = { op: 'update', id: delivery, if_version: current.version, set: { quantity }, unset: [] };
    const winning = await client.prepare({ model: scope.model, commands: [update], returning: [delivery] });
    const stale = await client.prepare({ model: scope.model, commands: [{ ...update, set: { quantity: (BigInt(quantity) + 1n).toString() } }], returning: [] });
    const winningReceipt = await client.execute(winning); facts = api.stageSources(facts, [update]);
    const before = await operator.inspect();
    await assert.rejects(client.execute(stale), error => error.code === 'stale_version');
    assert.deepEqual(await operator.inspect(), before);
    output.checks.push('CAS-winner', 'stale-mutation-rollback');
    const logical = api.checkSourceSnapshot({ model: 'equipment', facts, snapshot: before });
    assert.equal(logical.obligations.some(row => row.status === 'failed'), false, JSON.stringify(logical));
    output.logical = logical;
    const backupPath = path.join(runDirectory, `${kind}.backup.json`);
    const snapshot = await operator.snapshot({ destination: backupPath });
    assert.equal(snapshot.store, scope.store);
    output.structure = api.checkBackupStructure(await readFile(backupPath));
    assert.equal(output.structure.status, 'passed'); assert.ok(output.structure.nodeCount > 0);
    await operator.check();
    output.checks.push('source-expectations-with-declared-incomplete-obligations', 'independent-physical-structure', 'native-integrity');
    await operator.stopService({ service: service.service });
    const originalAddress = service.address;
    await close(host);
    host = await open({ mode: 'open', ...source, expect_store: scope.store });
    operator = api.openOperator(host, { scope, methods });
    service = await operator.startService({ config: { ...serviceConfig, listen: originalAddress } });
    client = api.connect({ endpoint: service.endpoint, credential: token });
    assert.deepEqual((await client.execute(winning)).result, winningReceipt.result);
    const oldReplay = await client.execute(plan);
    assert.equal(oldReplay.replayed, true);
    assert.deepEqual(oldReplay.result, {
      ...receipt.result,
      records: receipt.result.records.map(row => ({ ...row, record: null })),
    });
    assert.equal((await client.call('records.get', { model: scope.model, id: delivery })).input.quantity, quantity);
    output.checks.push('restart-and-receipt-recovery', 'old-version-receipt-redaction');
    await operator.stopService({ service: service.service });
    await assert.rejects(operator.restore({ backup: backupPath, expectBackupStore: randomUUID(), destination: { backend, target: location('wrong') } }), error => error.code === 'wrong_target');
    const restored = await operator.restore({ backup: backupPath, expectBackupStore: scope.store, destination: { backend, target: restoredLocation } });
    assert.equal(restored.status, 'restored');
    const initialRestoreHost = await open({ mode: 'open', ...restoredLocation, expect_store: scope.store });
    const initialRestorePath = path.join(runDirectory, `${kind}.restored-before.json`);
    await initialRestoreHost.backup({ scope, destination: initialRestorePath });
    await close(initialRestoreHost);
    // Native restore rejects storage_exists transactionally. The current host
    // sanitizes that FDB error to internal; record that wire limitation exactly.
    await assert.rejects(operator.restore({ backup: backupPath, expectBackupStore: scope.store, destination: { backend, target: restoredLocation } }), error => {
      output.existingDestinationError = error.code;
      return error.code === (kind === 'foundationdb' ? 'internal' : 'invalid_destination');
    });
    const restoreHost = await open({ mode: 'open', ...restoredLocation, expect_store: scope.store });
    assert.deepEqual((await restoreHost.inspect()).records, before.records);
    const finalRestorePath = path.join(runDirectory, `${kind}.restored-after.json`);
    await restoreHost.backup({ scope, destination: finalRestorePath });
    assert.deepEqual(JSON.parse(await readFile(finalRestorePath)).payload, JSON.parse(await readFile(initialRestorePath)).payload);
    await restoreHost.check(); await close(restoreHost);
    output.checks.push('wrong-backup-fence', 'isolated-restore', 'existing-destination-fence');
    const archivePath = path.join(runDirectory, `${kind}.archive.json`);
    assert.equal((await operator.archive({ destination: archivePath })).status, 'archived');
    assert.equal(api.checkBackupStructure(await readFile(archivePath)).status, 'passed');
    service = await operator.startService({ config: { ...serviceConfig, listen: originalAddress } });
    await assert.rejects(client.status(plan), error => error.code === 'operation_expired');
    await operator.stopService({ service: service.service });
    await assert.rejects(operator.reset({ expectStore: randomUUID() }), error => error.code === 'wrong_target');
    const reset = await operator.reset({ expectStore: scope.store });
    assert.equal(reset.status, 'reset'); assert.notEqual(reset.store, scope.store);
    await assert.rejects(host.check(), error => error.code === 'wrong_target');
    if (peer) { await assert.rejects(peer.check(), error => error.code === 'wrong_target'); await close(peer); output.checks.push('shared-host-reset-fence'); }
    output.checks.push('archive-expiry', 'reset-identity-fence');
    output.status = 'passed';
  } finally {
    for (const handle of handles) {
      try { await close(handle); }
      catch (error) { output.cleanup.push({ pid: handle.pid, status: 'failed', message: error.message }); }
    }
    report.cleanup.push(...output.cleanup.map(row => ({ role: `${kind}-native`, ...row })));
    assert.ok(output.cleanup.every(row => row.status === 'stopped'), 'every owned native host must close');
  }
  return output;
}
async function freePort() { const server = createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
async function save() { await writeFile(path.join(base, 'adapter-acceptance.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 }); }
