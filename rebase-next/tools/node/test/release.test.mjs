import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFile, link, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import { describeReleaseBuild, packageRelease, prepareReleaseSource, verifyRelease } from '../release.mjs';

const REPOSITORY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const env = { PATH: process.env.PATH };

test('release export is committed, isolated, content addressed and ignores dirty files', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'node-release-git-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo');
  await mkdir(path.join(repo, 'tools/node'), { recursive: true });
  git(repo, ['init', '-q']);
  git(repo, ['config', 'user.name', 'Release Test']);
  git(repo, ['config', 'user.email', 'release@example.invalid']);
  await writeFile(path.join(repo, 'Cargo.toml'), '[package]\nname="fixture"\nversion="1.2.3"\n');
  await writeFile(path.join(repo, 'tools/node/package-lock.json'), '{"lockfileVersion":3}\n');
  git(repo, ['add', '.']);
  git(repo, ['commit', '-qm', 'fixture']);
  const commit = git(repo, ['rev-parse', 'HEAD']).trim();
  await writeFile(path.join(repo, 'dirty.txt'), 'ignored');
  const source = await prepareReleaseSource({ repository: repo, sourceRef: commit,
    destination: path.join(root, 'export'), environment: env });
  assert.equal(source.sourceCommit, commit);
  assert.deepEqual(Object.keys(source.sourceFiles), ['Cargo.toml', 'tools/node/package-lock.json']);
  assert.equal(await readFile(path.join(source.directory, 'Cargo.toml'), 'utf8'), '[package]\nname="fixture"\nversion="1.2.3"\n');
  assert.throws(() => describeReleaseBuild({ source, features: ['unsupported'], targetDir: path.join(root, 'target'), environment: env }), /explicit array/);
  const spec = describeReleaseBuild({ source, features: ['surrealkv'], targetDir: path.join(root, 'target'), environment: env });
  assert.deepEqual(spec.args.slice(0, 4), ['build', '--locked', '--release', '--manifest-path']);
  assert.equal(spec.profile, 'release');
  assert.equal(spec.sourceFiles['Cargo.toml'], createHash('sha256').update('[package]\nname="fixture"\nversion="1.2.3"\n').digest('hex'));
  await assert.rejects(() => prepareReleaseSource({ repository: repo, sourceRef: commit,
    destination: path.join(repo, 'inside-export'), environment: env }), /outside Git/);
  const alias = path.join(root, 'repo-alias');
  await symlink(repo, alias, 'dir');
  await assert.rejects(() => prepareReleaseSource({ repository: repo, sourceRef: commit,
    destination: path.join(alias, 'aliased-export'), environment: env }), /outside Git/);
  await assert.rejects(() => packageRelease({ source, artifact: {}, output: path.join(alias, 'aliased-package'),
    environment: env, buildEnvironment: env, toolingEnvironment: env }), /outside source export and Git/);
  const nested = await prepareReleaseSource({ repository: path.join(repo, 'tools/node'), sourceRef: commit,
    destination: path.join(root, 'nested-export'), environment: env });
  assert.equal(nested.sourceTree, git(repo, ['rev-parse', `${commit}:tools/node`]).trim());
  assert.deepEqual(Object.keys(nested.sourceFiles), ['package-lock.json']);
});

test('extracted release verifier checks every byte and rejects bad metadata and paths', async t => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'node-release-bundle-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const bundle = path.join(parent, 'bundle');
  await fixture(bundle);
  const result = await verifyRelease({ directory: bundle, checkBinary: false });
  assert.equal(result.status, 'passed');
  assert.equal(result.modelCount, 1);
  await writeFile(path.join(bundle, 'catalogs/model.public.json'), '{"model":"tampered"}\n');
  await assert.rejects(() => verifyRelease({ directory: bundle, checkBinary: false }), /checksum differs/);

  const missing = path.join(parent, 'missing');
  await fixture(missing);
  await rm(path.join(missing, 'catalogs/model.public.json'));
  await assert.rejects(() => verifyRelease({ directory: missing, checkBinary: false }), /missing|regular|checksum/i);

  const unsafe = path.join(parent, 'unsafe');
  await fixture(unsafe);
  await writeFile(path.join(unsafe, 'SHA256SUMS'), `${'a'.repeat(64)}  ../escape\n`);
  await assert.rejects(() => verifyRelease({ directory: unsafe, checkBinary: false }), /invalid|unsafe/i);
});

test('release verifier rejects unlisted files, symlinks and corrupt identities', async t => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'node-release-boundaries-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const extra = path.join(parent, 'extra');
  await fixture(extra);
  await writeFile(path.join(extra, 'unlisted'), 'extra');
  await assert.rejects(() => verifyRelease({ directory: extra, checkBinary: false }), /complete/);

  const corrupt = path.join(parent, 'corrupt');
  await fixture(corrupt);
  const manifest = JSON.parse(await readFile(path.join(corrupt, 'BUNDLE.json'), 'utf8'));
  manifest.models.model.behaviorContract = '';
  await writeFile(path.join(corrupt, 'BUNDLE.json'), `${JSON.stringify(manifest)}\n`);
  await assert.rejects(() => verifyRelease({ directory: corrupt, checkBinary: false }), /checksum differs/);

  const links = path.join(parent, 'links');
  await fixture(links);
  await import('node:fs/promises').then(fs => fs.symlink('/etc/passwd', path.join(links, 'escape')));
  await assert.rejects(() => verifyRelease({ directory: links, checkBinary: false }), /symlink/);

  const semantic = path.join(parent, 'semantic');
  await fixture(semantic);
  const semanticManifest = JSON.parse(await readFile(path.join(semantic, 'BUNDLE.json'), 'utf8'));
  const semanticCatalog = JSON.parse(await readFile(path.join(semantic, 'catalogs/model.public.json'), 'utf8'));
  semanticCatalog.model = 'b'.repeat(64);
  await writeFile(path.join(semantic, 'catalogs/model.public.json'), `${JSON.stringify(semanticCatalog)}\n`);
  semanticManifest.models.model.catalogSha256 = createHash('sha256').update(await readFile(path.join(semantic, 'catalogs/model.public.json'))).digest('hex');
  await writeFile(path.join(semantic, 'BUNDLE.json'), `${JSON.stringify(semanticManifest)}\n`);
  await rewriteChecksums(semantic);
  await assert.rejects(() => verifyRelease({ directory: semantic, checkBinary: false }), /catalog identity differs/);

  const wrongVersion = path.join(parent, 'wrong-version');
  await fixture(wrongVersion);
  const versionManifest = JSON.parse(await readFile(path.join(wrongVersion, 'BUNDLE.json'), 'utf8'));
  versionManifest.packageVersion = '99.0.0';
  await writeFile(path.join(wrongVersion, 'BUNDLE.json'), `${JSON.stringify(versionManifest)}\n`);
  await rewriteChecksums(wrongVersion);
  await assert.rejects(() => verifyRelease({ directory: wrongVersion, checkBinary: false }), /version differs/);

  const wrongFormat = path.join(parent, 'wrong-format');
  await fixture(wrongFormat);
  const formatManifest = JSON.parse(await readFile(path.join(wrongFormat, 'BUNDLE.json'), 'utf8'));
  formatManifest.formats.store = 'forged-store-format';
  await writeFile(path.join(wrongFormat, 'BUNDLE.json'), `${JSON.stringify(formatManifest)}\n`);
  await rewriteChecksums(wrongFormat);
  await assert.rejects(() => verifyRelease({ directory: wrongFormat, checkBinary: false }), /format identities differ/);

  const wrongBuild = path.join(parent, 'wrong-build');
  await fixture(wrongBuild);
  const buildManifest = JSON.parse(await readFile(path.join(wrongBuild, 'BUNDLE.json'), 'utf8'));
  buildManifest.build.buildId = '9'.repeat(64);
  await writeFile(path.join(wrongBuild, 'BUNDLE.json'), `${JSON.stringify(buildManifest)}\n`);
  await rewriteChecksums(wrongBuild);
  await assert.rejects(() => verifyRelease({ directory: wrongBuild, checkBinary: false }), /build identity digest/);
});

test('positive package path discovers native identities and verifies a synthetic binary fixture', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'node-release-positive-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo');
  await mkdir(path.join(repo, 'tools/node'), { recursive: true });
  await mkdir(path.join(repo, 'deploy'), { recursive: true });
  await mkdir(path.join(repo, 'vendor'), { recursive: true });
  git(repo, ['init', '-q']);
  git(repo, ['config', 'user.name', 'Release Test']);
  git(repo, ['config', 'user.email', 'release@example.invalid']);
  await writeFile(path.join(repo, 'Cargo.toml'), '[package]\nname="rebase-next"\nversion="0.16.0"\n');
  await writeFile(path.join(repo, 'Cargo.lock'), 'synthetic locked input\n');
  await copyNodeSources(path.join(repo, 'tools/node'));
  await makeOfflineNpmFixture(repo);
  await writeFile(path.join(repo, 'deploy/rebase-next.service'), '[Service]\nExecStart=/usr/local/bin/rebase-next serve\n');
  git(repo, ['add', '.']);
  git(repo, ['commit', '-qm', 'synthetic package inputs']);
  const source = await prepareReleaseSource({ repository: repo, sourceRef: git(repo, ['rev-parse', 'HEAD']).trim(),
    destination: path.join(root, 'export'), environment: env });
  const targetDir = path.join(root, 'target');
  const binary = path.join(targetDir, 'release/rebase-next');
  await mkdir(path.dirname(binary), { recursive: true });
  // This is packaging-path evidence only. Root's committed-source release build supplies real Cargo provenance.
  await copyFile(path.join(REPOSITORY, 'target/n2-native-default/rebase-next'), binary);
  await link(binary, path.join(root, 'cargo-deps-hardlink'));
  const buildEnvironment = { ...env, CARGO_HOME: path.join(root, 'cargo-home') };
  const spec = describeReleaseBuild({ source, features: [], targetDir, environment: buildEnvironment });
  const sha256 = createHash('sha256').update(await readFile(binary)).digest('hex');
  const receipt = { exitCode: 0, command: [spec.executable, ...spec.args], cwd: spec.cwd,
    sourceCommit: source.sourceCommit, sourceTree: source.sourceTree,
    sourceFilesSha256: createHash('sha256').update(JSON.stringify(source.sourceFiles)).digest('hex'),
    buildLogSha256: '5'.repeat(64), artifactSha256: sha256 };
  const buildId = createHash('sha256').update(JSON.stringify({ command: receipt.command, cwd: receipt.cwd,
    sourceCommit: receipt.sourceCommit, sourceTree: receipt.sourceTree, sourceFilesSha256: receipt.sourceFilesSha256,
    buildLogSha256: receipt.buildLogSha256, artifactSha256: sha256, features: [], profile: 'release',
    locked: true, jobs: 2, incremental: false, outsideGit: true })).digest('hex');
  const result = await packageRelease({ source, artifact: { path: binary, provenance: { spec, receipt, sha256, buildId } },
    output: path.join(root, 'package'), features: [], environment: env, buildEnvironment,
    toolingEnvironment: { PATH: `${path.dirname(process.execPath)}:${process.env.PATH}`,
      HOME: root, NPM_CONFIG_CACHE: '/workspace/.npm-cache' } });
  assert.equal(result.status, 'passed');
  assert.equal(result.modelCount, 6);
  assert.deepEqual(result.supportedBackends, ['redb']);
  const manifest = JSON.parse(await readFile(path.join(root, 'package/BUNDLE.json'), 'utf8'));
  assert.equal(manifest.build.profile, 'release');
  assert.equal(manifest.build.sourceFilesSha256, receipt.sourceFilesSha256);
  assert.equal(manifest.build.command[0], 'cargo');
  assert.equal((await (await import('node:fs/promises')).stat(path.join(root, 'package/bin/rebase-next'))).nlink, 1);
  assert.equal(Object.hasOwn(manifest.sourceFiles, 'tools/node/node_modules/ajv/dist/2020.js'), false);
  assert.match(await readFile(path.join(root, 'package/SHA256SUMS'), 'utf8'), /  tools\/node\/node_modules\/ajv\/dist\/2020\.js\n/);
  assert.deepEqual(Object.keys(manifest.models).sort(), ['calculation', 'effect-demo', 'equipment', 'invoicing', 'measurement', 'quantity'].sort());
  const packedTools = path.join(root, 'package/tools/node');
  await import(pathToFileURL(path.join(packedTools, 'model.mjs')).href);
  await import(pathToFileURL(path.join(packedTools, 'population.mjs')).href);
  await import(pathToFileURL(path.join(packedTools, 'fake-provider.mjs')).href);
  const extractedRelease = await import(pathToFileURL(path.join(packedTools, 'release.mjs')).href);
  assert.equal((await extractedRelease.verifyRelease({ directory: path.join(root, 'package'), environment: env })).status, 'passed');
});

async function fixture(directory) {
  await mkdir(path.join(directory, 'bin'), { recursive: true });
  await mkdir(path.join(directory, 'catalogs'), { recursive: true });
  await mkdir(path.join(directory, 'deploy'), { recursive: true });
  await writeFile(path.join(directory, 'Cargo.toml'), '[package]\nname="rebase-next"\nversion="1.0.0"\n');
  await mkdir(path.join(directory, 'tools/node'), { recursive: true });
  await writeFile(path.join(directory, 'Cargo.lock'), 'lock bytes');
  await writeFile(path.join(directory, 'tools/node/package.json'), '{"type":"module"}\n');
  await writeFile(path.join(directory, 'tools/node/package-lock.json'), '{"lockfileVersion":3}\n');
  await writeFile(path.join(directory, 'bin/rebase-next'), 'release binary bytes');
  const catalog = { model: 'a'.repeat(64), api: 'rebase-local-api-1', codec: 'native-slice-kv-1', capabilities: { limits: { max_rows: 4 } } };
  await writeFile(path.join(directory, 'catalogs/model.public.json'), `${JSON.stringify(catalog)}\n`);
  await writeFile(path.join(directory, 'deploy/rebase-next.service'), 'service template');
  const hash = async name => createHash('sha256').update(await readFile(path.join(directory, name))).digest('hex');
  const model = { version: { version: '1.0.0', model: catalog.model, store_format: 'rebase-store-1' }, model: catalog.model,
    storeFormat: 'rebase-store-1', api: catalog.api, codec: catalog.codec, limits: catalog.capabilities.limits,
    behaviorContract: 'binding:1', catalog: 'catalogs/model.public.json', catalogSha256: await hash('catalogs/model.public.json') };
  const sourceFiles = { 'Cargo.toml': await hash('Cargo.toml'), 'Cargo.lock': await hash('Cargo.lock'),
      'tools/node/package.json': await hash('tools/node/package.json'),
      'tools/node/package-lock.json': await hash('tools/node/package-lock.json') };
  const sourceFilesSha256 = createHash('sha256').update(JSON.stringify(sourceFiles)).digest('hex');
  const command = ['cargo', 'build', '--locked', '--release', '--manifest-path', path.join(directory, 'Cargo.toml'),
    '--target-dir', path.join(parentOf(directory), 'target'), '--jobs', '2', '--bin', 'rebase-next'];
  const buildLogSha256 = '4'.repeat(64), binarySha256 = await hash('bin/rebase-next');
  const sourceCommit = '1'.repeat(40), sourceTree = '2'.repeat(40), features = [];
  const buildIdentity = { command, cwd: directory, sourceCommit, sourceTree, sourceFilesSha256, buildLogSha256,
    artifactSha256: binarySha256, features, profile: 'release', locked: true, jobs: 2, incremental: false, outsideGit: true };
  const manifest = { format: 'rebase-node-release-1', packageVersion: '1.0.0', sourceCommit, sourceTree, sourceFiles,
    build: { profile: 'release', locked: true, jobs: 2, incremental: false, outsideGit: true, features: [],
      exitCode: 0, buildId: createHash('sha256').update(JSON.stringify(buildIdentity)).digest('hex'), buildLogSha256, cwd: directory,
      sourceFilesSha256, command },
    binary: { path: 'bin/rebase-next', sha256: binarySha256, provenance: 'committed-export-build' },
    models: { model }, formats: { store: 'rebase-store-1', nativeCodec: catalog.codec, api: catalog.api, effectCodec: null },
    supportedBackends: ['redb'], deploymentTemplates: { redb: { path: 'deploy/rebase-next.service', sha256: await hash('deploy/rebase-next.service') } },
    nativePrerequisites: { foundationdb: { required: false, bundled: false, library: 'libfdb_c',
      buildEnvironmentVariable: 'FDB_CLIENT_LIB_PATH', runtimeEnvironmentVariable: 'LD_LIBRARY_PATH' } } };
  await writeFile(path.join(directory, 'BUNDLE.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  const names = ['BUNDLE.json', 'Cargo.lock', 'Cargo.toml', 'bin/rebase-next', 'catalogs/model.public.json',
    'deploy/rebase-next.service', 'tools/node/package.json', 'tools/node/package-lock.json'];
  const lines = [];
  for (const name of names) lines.push(`${await hash(name)}  ${name}\n`);
  await writeFile(path.join(directory, 'SHA256SUMS'), lines.join(''));
}

async function rewriteChecksums(directory) {
  const files = [];
  async function walk(current, prefix = '') {
    for (const entry of await (await import('node:fs/promises')).readdir(current, { withFileTypes: true })) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(full, name);
      else if (entry.isFile() && name !== 'SHA256SUMS') files.push(name);
    }
  }
  await walk(directory);
  files.sort();
  const rows = [];
  for (const name of files) rows.push(`${createHash('sha256').update(await readFile(path.join(directory, name))).digest('hex')}  ${name}\n`);
  await writeFile(path.join(directory, 'SHA256SUMS'), rows.join(''));
}

function git(cwd, args) {
  const result = spawnSync('git', args, { cwd, env, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr);
  return result.stdout;
}
function parentOf(value) { return path.dirname(value); }

async function makeOfflineNpmFixture(repo) {
  const committedLock = JSON.parse(await readFile(path.join(REPOSITORY, 'tools/node/package-lock.json'), 'utf8'));
  const packages = Object.entries(committedLock.packages).filter(([name]) => name.startsWith('node_modules/'))
    .map(([name, descriptor]) => [name.slice('node_modules/'.length), descriptor.version]);
  const dependencies = {};
  for (const [name] of packages) {
    const directory = path.join(repo, 'vendor', name);
    await copyRealNpmPackage(path.join(REPOSITORY, 'tools/node/node_modules', name), directory);
    dependencies[name] = `file:../../vendor/${name}`;
  }
  const tools = path.join(repo, 'tools/node');
  await writeFile(path.join(tools, 'package.json'), `${JSON.stringify({ name: '@rebase/test-tools', private: true, type: 'module', dependencies }, null, 2)}\n`);
  const command = spawnSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: tools, env: { PATH: `${path.dirname(process.execPath)}:${process.env.PATH}`, HOME: repo,
      NPM_CONFIG_CACHE: '/workspace/.npm-cache' }, encoding: 'utf8', timeout: 30_000,
  });
  if (command.status !== 0) throw new Error(`offline npm fixture lock failed: ${command.stderr}`);
}

async function copyRealNpmPackage(source, destination) {
  await mkdir(destination, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name), to = path.join(destination, entry.name);
    if (entry.isDirectory()) await copyRealNpmPackage(from, to);
    else if (entry.isFile()) { await mkdir(path.dirname(to), { recursive: true }); await copyFile(from, to); }
    else throw new Error(`NPM fixture package contains an unsupported entry: ${from}`);
  }
}

async function copyNodeSources(destination) {
  const source = path.join(REPOSITORY, 'tools/node');
  async function visit(from, to, prefix = '') {
    for (const entry of await readdir(from, { withFileTypes: true })) {
      if (!prefix && ['node_modules', 'package.json', 'package-lock.json'].includes(entry.name)) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const input = path.join(from, entry.name), output = path.join(to, entry.name);
      if (entry.isDirectory()) {
        await mkdir(output, { recursive: true });
        await visit(input, output, relative);
      } else if (entry.isFile()) {
        await mkdir(path.dirname(output), { recursive: true });
        await copyFile(input, output);
      } else throw new Error(`Unexpected Node source entry in fixture: ${relative}`);
    }
  }
  await visit(source, destination);
}
