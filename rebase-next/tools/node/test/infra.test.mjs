import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { openFdbEnvironment } from '../infra.mjs';

test('managed FoundationDB owner starts, checks, and stops only its own process', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-node-fdb-owner-'));
  const serverBin = path.join(directory, 'fdbserver');
  const cliBin = path.join(directory, 'fdbcli');
  const clusterFile = path.join(directory, 'fdb.cluster');
  const argsFile = path.join(directory, 'arguments.jsonl');
  const port = await freePort();
  await writeFile(clusterFile, '127.0.0.1:4500\n', { mode: 0o600 });
  await executable(serverBin, `const fs=require('node:fs');const net=require('node:net');const a=process.argv.slice(2);fs.appendFileSync(process.env.N5_ARGS,JSON.stringify({role:'server',args:a})+'\\n');const p=Number(a[a.indexOf('-p')+1].split(':').at(-1));const s=net.createServer(c=>c.end());s.listen(p,'127.0.0.1');process.on('SIGTERM',()=>s.close(()=>process.exit(0)));`);
  await executable(cliBin, `const fs=require('node:fs');const a=process.argv.slice(2);fs.appendFileSync(process.env.N5_ARGS,JSON.stringify({role:'cli',args:a})+'\\n');const cmd=a.at(-1)||'';if(cmd==='status')process.stdout.write('FoundationDB status: available\\n');else if(cmd==='configure new single ssd')process.stdout.write('Database configured\\n');else if(cmd.includes('rebase_n5_environment_probe_')){const key=cmd.match(/set (rebase_n5_environment_probe_[0-9a-f]+) verified/)[1];process.stdout.write(key+' is verified\\n');}else process.exit(2);`);
  const owner = await openFdbEnvironment({
    fdbserver: serverBin, fdbcli: cliBin, clusterFile,
    dataDirectory: path.join(directory, 'data'), logDirectory: path.join(directory, 'logs'),
    serverLog: path.join(directory, 'logs', 'fdbserver.log'), host: '127.0.0.1', port,
    environment: { N5_ARGS: argsFile }, startTimeoutMs: 2_000, stopTimeoutMs: 2_000, commandTimeoutMs: 2_000,
  });
  try {
    const [started, concurrentStart] = await Promise.all([owner.start(), owner.start()]);
    assert.deepEqual(concurrentStart, started);
    assert.equal(started.status, 'started');
    assert.equal(started.pid, owner.pid);
    assert.equal(started.address, `127.0.0.1:${port}`);
    assert.match((await owner.status()).stdout, /status: available/);
    assert.match((await owner.bootstrap()).stdout, /configured/);
    assert.equal((await owner.check()).status, 'passed');
    const calls = (await readFile(argsFile, 'utf8')).trim().split('\n').map(JSON.parse);
    assert.deepEqual(calls[0].args.slice(0, 6), ['-p', `127.0.0.1:${port}`, '-C', clusterFile, '-d', path.join(directory, 'data')]);
    assert.equal(calls[1].role, 'cli');
    assert.equal(calls[2].args.includes('--no-status'), true);
    assert.match(calls[3].args.at(-1), /writemode on; begin; set rebase_n5_environment_probe_[0-9a-f]+ verified/);
    const stoppedPid = owner.pid;
    assert.deepEqual(await owner.close(), { status: 'stopped', pid: stoppedPid });
    await assert.rejects(new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => { socket.destroy(); resolve(); });
      socket.once('error', reject);
      socket.setTimeout(250, () => { socket.destroy(); reject(new Error('listener remains')) ; });
    }));
  } finally {
    await owner.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
});

test('managed FoundationDB refuses to claim a listener it did not start', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-node-fdb-existing-'));
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  try {
    const serverBin = path.join(directory, 'fdbserver');
    const cliBin = path.join(directory, 'fdbcli');
    const clusterFile = path.join(directory, 'fdb.cluster');
    await writeFile(clusterFile, 'cluster');
    await executable(serverBin, 'process.exit(0);');
    await executable(cliBin, 'process.exit(0);');
    const owner = await openFdbEnvironment({ fdbserver: serverBin, fdbcli: cliBin, clusterFile,
      dataDirectory: path.join(directory, 'data'), logDirectory: path.join(directory, 'logs'),
      serverLog: path.join(directory, 'logs', 'server.log'), host: '127.0.0.1', port,
      environment: {}, startTimeoutMs: 1_000, stopTimeoutMs: 1_000, commandTimeoutMs: 1_000 });
    await assert.rejects(owner.start(), error => error.code === 'port_in_use');
    assert.equal(owner.pid, null);
  } finally {
    await new Promise(resolve => listener.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test('managed FoundationDB inputs keep paths, timeouts, and ports explicit', async () => {
  await assert.rejects(openFdbEnvironment({ fdbserver: 'fdbserver' }), /absolute path/);
});

test('managed server startup reports spawn errors without losing the owned handle', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-node-fdb-spawn-error-'));
  const serverBin = path.join(directory, 'fdbserver');
  const cliBin = path.join(directory, 'fdbcli');
  const clusterFile = path.join(directory, 'fdb.cluster');
  await writeFile(serverBin, '#!/definitely/missing/n5-interpreter\n', { mode: 0o700 });
  await executable(cliBin, 'process.exit(0);');
  await writeFile(clusterFile, 'cluster');
  const owner = await openFdbEnvironment({ fdbserver: serverBin, fdbcli: cliBin, clusterFile,
    dataDirectory: path.join(directory, 'data'), logDirectory: path.join(directory, 'logs'),
    serverLog: path.join(directory, 'logs', 'server.log'), host: '127.0.0.1', port: await freePort(),
    environment: {}, startTimeoutMs: 500, stopTimeoutMs: 500, commandTimeoutMs: 500 });
  try {
    await assert.rejects(owner.start(), error => error.code === 'ENOENT');
    assert.equal(owner.pid, null);
    assert.deepEqual(await owner.close(), { status: 'stopped', pid: null });
  } finally {
    await owner.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
});

test('managed CLI latches timeout and output-limit failures before process close', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-node-fdb-cli-bound-'));
  const serverBin = path.join(directory, 'fdbserver');
  const cliBin = path.join(directory, 'fdbcli');
  const clusterFile = path.join(directory, 'fdb.cluster');
  await executable(serverBin, 'process.exit(0);');
  await writeFile(clusterFile, 'cluster');
  await executable(cliBin, `const cmd=process.argv.at(-1);if(cmd==='status'){process.on('SIGTERM',()=>process.exit(0));setTimeout(()=>process.exit(0),1000);}else{process.stdout.write('x'.repeat(1100000),()=>process.exit(0));}`);
  const owner = await openFdbEnvironment({ fdbserver: serverBin, fdbcli: cliBin, clusterFile,
    dataDirectory: path.join(directory, 'data'), logDirectory: path.join(directory, 'logs'),
    serverLog: path.join(directory, 'logs', 'server.log'), host: '127.0.0.1', port: await freePort(),
    environment: {}, startTimeoutMs: 500, stopTimeoutMs: 500, commandTimeoutMs: 40 });
  const outputOwner = await openFdbEnvironment({ fdbserver: serverBin, fdbcli: cliBin, clusterFile,
    dataDirectory: path.join(directory, 'data'), logDirectory: path.join(directory, 'logs'),
    serverLog: path.join(directory, 'logs', 'server.log'), host: '127.0.0.1', port: await freePort(),
    environment: {}, startTimeoutMs: 500, stopTimeoutMs: 500, commandTimeoutMs: 5000 });
  try {
    await assert.rejects(owner.status(), error => error.code === 'command_timeout');
    await assert.rejects(outputOwner.bootstrap(), error => error.code === 'output_limit');
  } finally {
    await owner.close().catch(() => {});
    await outputOwner.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
});

test('stop timeout retains the owned server for a later close', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'rebase-node-fdb-stop-timeout-'));
  const serverBin = path.join(directory, 'fdbserver');
  const cliBin = path.join(directory, 'fdbcli');
  const clusterFile = path.join(directory, 'fdb.cluster');
  const port = await freePort();
  await writeFile(clusterFile, 'cluster');
  await executable(serverBin, `const net=require('node:net');const a=process.argv.slice(2);const p=Number(a[a.indexOf('-p')+1].split(':').at(-1));const s=net.createServer(c=>c.end());s.listen(p,'127.0.0.1');process.on('SIGTERM',()=>{});setTimeout(()=>s.close(()=>process.exit(0)),150);`);
  await executable(cliBin, 'process.exit(0);');
  const owner = await openFdbEnvironment({ fdbserver: serverBin, fdbcli: cliBin, clusterFile,
    dataDirectory: path.join(directory, 'data'), logDirectory: path.join(directory, 'logs'),
    serverLog: path.join(directory, 'logs', 'server.log'), host: '127.0.0.1', port,
    environment: {}, startTimeoutMs: 1_000, stopTimeoutMs: 30, commandTimeoutMs: 500 });
  try {
    await owner.start();
    const ownedPid = owner.pid;
    await assert.rejects(owner.close(), error => error.code === 'stop_timeout');
    assert.equal(owner.pid, ownedPid);
    await new Promise(resolve => setTimeout(resolve, 180));
    assert.deepEqual(await owner.close(), { status: 'stopped', pid: ownedPid });
  } finally {
    await owner.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  }
});

async function executable(destination, source) {
  await writeFile(destination, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
  await chmod(destination, 0o700);
}

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
