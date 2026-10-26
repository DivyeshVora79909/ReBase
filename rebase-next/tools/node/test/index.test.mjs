import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const expectedExports = [
  'accept', 'checkBackupStructure', 'checkResources', 'checkRun', 'checkSourceBackup',
  'checkSourceSnapshot', 'churnProfile', 'churnScenario', 'connect', 'describeReleaseBuild',
  'evaluateSources', 'explore', 'faultProfile', 'faultScenario', 'logicalReplay',
  'observeResources', 'openFdbEnvironment', 'openNative', 'openOperator', 'overloadProfile',
  'overloadScenario', 'packageRelease', 'parseEnvironment', 'prepareModel', 'preparePopulation',
  'prepareReleaseSource', 'propose', 'reject', 'resolveConfig', 'runWorkload', 'savePlan',
  'shrinkFailure', 'sourceOracle', 'stageSources', 'startFakeProvider', 'verifyRelease', 'walk',
].sort();

test('public barrel has an explicit stable export surface', async () => {
  const api = await import('../index.mjs');
  assert.deepEqual(Object.keys(api).sort(), expectedExports);
});

test('importing the public barrel produces no output or child process', () => {
  const entry = new URL('../index.mjs', import.meta.url).href;
  const script = `
    import { createRequire } from 'node:module';
    import { syncBuiltinESMExports } from 'node:module';
    const require = createRequire(import.meta.url);
    const effects = [];
    const trap = label => (...args) => { effects.push(label); throw new Error('module import attempted ' + label); };
    const childProcess = require('node:child_process');
    const fs = require('node:fs');
    const net = require('node:net');
    const http = require('node:http');
    const https = require('node:https');
    childProcess.spawn = trap('child process');
    childProcess.exec = trap('child process');
    childProcess.execFile = trap('child process');
    fs.writeFileSync = trap('filesystem write');
    fs.appendFileSync = trap('filesystem write');
    fs.mkdirSync = trap('filesystem write');
    fs.promises.writeFile = trap('filesystem write');
    fs.promises.mkdir = trap('filesystem write');
    net.connect = trap('network connection');
    net.createConnection = trap('network connection');
    http.Server.prototype.listen = trap('network listener');
    https.Server.prototype.listen = trap('network listener');
    syncBuiltinESMExports();
    await import(${JSON.stringify(entry)});
    if (effects.length) throw new Error(effects.join(', '));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
    encoding: 'utf8',
    env: { ...process.env, REBASE_IMPORT_PURITY_CHECK: '1' },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});
