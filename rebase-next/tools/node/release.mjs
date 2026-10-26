import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { createReadStream } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { resolveConfig } from './config.mjs';
import { openNative } from './native.mjs';

const MAX_OUTPUT = 8 * 1024 * 1024;
const MAX_FILES = 65_536;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const HASH = /^[0-9a-f]{64}$/;
const OID = /^[0-9a-f]{40,64}$/;
const MODEL_SELECTOR = /^[a-z][a-z0-9-]{0,63}$/;
const FEATURES = new Set(['foundationdb', 'surrealkv']);

/** Export one committed Git tree into a new directory outside the repository.
 * Dirty files are intentionally irrelevant. Symlinks, submodules and unsafe paths fail closed.
 */
export async function prepareReleaseSource({ repository, sourceRef, destination, environment }) {
  if (typeof sourceRef !== 'string' || !sourceRef || sourceRef.startsWith('-') || /[\0\r\n]/.test(sourceRef)) throw new TypeError('sourceRef must be an explicit Git revision');
  validateEnvironment(environment);
  const repo = await realpath(requiredPath(repository, 'repository'));
  const out = await canonicalProspectivePath(requiredPath(destination, 'destination'));
  const gitRoot = (await run(['git', 'rev-parse', '--show-toplevel'], { cwd: repo, environment })).stdout.trim();
  const gitPrefix = (await run(['git', 'rev-parse', '--show-prefix'], { cwd: repo, environment })).stdout.trim().replace(/\/$/, '');
  const commit = (await run(['git', 'rev-parse', '--verify', '--end-of-options', `${sourceRef}^{commit}`], { cwd: repo, environment })).stdout.trim();
  if (!OID.test(commit)) throw new Error('Git returned an invalid source commit identity');
  const treeRef = gitPrefix ? `${commit}:${gitPrefix}` : `${commit}^{tree}`;
  const tree = (await run(['git', 'rev-parse', '--verify', '--end-of-options', treeRef], { cwd: gitRoot, environment })).stdout.trim();
  if (!OID.test(tree)) throw new Error('Git returned an invalid source tree identity');
  const listing = await run(['git', 'ls-tree', '-r', '-z', '--full-tree', tree], { cwd: gitRoot, maxOutput: MAX_OUTPUT, environment });
  const sourceObjects = parseTree(listing.stdout);
  if (!sourceObjects.length) throw new Error('Committed source tree is empty');
  const sizes = await run(['git', 'cat-file', '--batch-check=%(objecttype) %(objectsize)'], {
    cwd: gitRoot, environment, input: `${sourceObjects.map(entry => entry.oid).join('\n')}\n`, maxOutput: MAX_OUTPUT,
  });
  const sizeRows = sizes.stdout.trim().split('\n');
  if (sizeRows.length !== sourceObjects.length) throw new Error('Git source size inventory is incomplete');
  let sourceBytes = 0;
  for (const row of sizeRows) {
    const match = /^blob ([0-9]+)$/.exec(row);
    if (!match || Number(match[1]) > MAX_FILE_BYTES || (sourceBytes += Number(match[1])) > MAX_TOTAL_BYTES) {
      throw new Error('Committed source exceeds release file or total byte limits');
    }
  }
  const outParent = path.dirname(out);
  if (isWithin(repo, out) || isWithin(gitRoot, out)) throw new Error('Release destination must be outside Git');
  await mkdir(outParent, { recursive: true });
  if (await exists(out)) throw new Error('Release destination already exists');
  await mkdir(out, { recursive: false });
  const temp = await mkdtemp(path.join(os.tmpdir(), 'rebase-release-'));
  try {
    const archive = path.join(temp, 'source.tar');
    await run(['git', 'archive', '--format=tar', '--output', archive, tree], { cwd: gitRoot, environment });
    if ((await stat(archive)).size > MAX_TOTAL_BYTES) throw new Error('Committed source archive exceeds the 2 GiB limit');
    await run(['tar', '-xf', archive, '-C', out, '--no-same-owner', '--no-same-permissions'], { cwd: temp, environment });
    await assertRegularTree(out);
    const files = await inventory(out);
    const sourcePaths = new Set(sourceObjects.map(entry => entry.path));
    if (files.length !== sourceObjects.length || files.some(file => !sourcePaths.has(file.path))) {
      throw new Error('Exported file inventory differs from committed Git tree');
    }
    return Object.freeze({ directory: out, sourceCommit: commit, sourceTree: tree,
      sourceFiles: Object.freeze(Object.fromEntries(files.map(f => [f.path, f.sha256]))),
      fileCount: files.length });
  } catch (error) {
    await rm(out, { recursive: true, force: true });
    throw error;
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

/** Return the only supported release build invocation. Does not start Cargo. */
export function describeReleaseBuild({ source, features = [], targetDir, environment }) {
  validateSource(source);
  validateEnvironment(environment);
  const selected = canonicalFeatures(features);
  if (selected.includes('foundationdb') && !targetDir) throw new TypeError('targetDir is required');
  const args = ['build', '--locked', '--release', '--manifest-path', path.join(source.directory, 'Cargo.toml'),
    '--target-dir', path.resolve(requiredPath(targetDir, 'targetDir')), '--jobs', '2', '--bin', 'rebase-next'];
  if (selected.length) args.push('--features', selected.join(','));
  return Object.freeze({ executable: 'cargo', args: Object.freeze(args), cwd: source.directory,
    environment: Object.freeze({ ...environment, CARGO_INCREMENTAL: '0', CARGO_BUILD_JOBS: '2' }),
    profile: 'release', locked: true, outsideGit: true, features: Object.freeze(selected),
    sourceCommit: source.sourceCommit, sourceTree: source.sourceTree, sourceFiles: source.sourceFiles });
}

/** Package a caller-built release executable only when its exact source/build proof matches. */
export async function packageRelease({ source, artifact, output, features = [], environment, buildEnvironment = environment, toolingEnvironment }) {
  validateSource(source);
  validateEnvironment(environment);
  validateEnvironment(buildEnvironment);
  validateEnvironment(toolingEnvironment);
  const selected = canonicalFeatures(features);
  if (selected.includes('foundationdb')) await validateFdbEnvironment(environment);
  const out = await canonicalProspectivePath(requiredPath(output, 'output'));
  if (isWithin(source.directory, out) || await insideGit(out)) throw new Error('Package output must be outside source export and Git');
  if (await exists(out)) throw new Error('Package output already exists');
  const binary = path.resolve(requiredPath(artifact?.path, 'artifact.path'));
  const proof = artifact.provenance;
  const targetFlag = proof?.spec?.args?.indexOf('--target-dir') ?? -1;
  const provenTarget = targetFlag >= 0 ? proof.spec.args[targetFlag + 1] : null;
  const build = describeReleaseBuild({ source, features: selected, targetDir: provenTarget, environment: buildEnvironment });
  const receipt = proof?.receipt;
  const binarySha = proof?.sha256;
  if (!proof || !sameJson(proof.spec, build) || !HASH.test(binarySha ?? '')
      || !receipt || receipt.exitCode !== 0 || receipt.cwd !== build.cwd
      || !sameJson(receipt.command, [build.executable, ...build.args])
      || receipt.sourceCommit !== source.sourceCommit || receipt.sourceTree !== source.sourceTree
      || receipt.sourceFilesSha256 !== await digestJson(source.sourceFiles)
      || receipt.artifactSha256 !== binarySha || !HASH.test(receipt.buildLogSha256 ?? '')) {
    throw new Error('Release artifact provenance does not prove this committed source and build profile');
  }
  const expectedBinary = path.join(path.resolve(provenTarget), 'release', 'rebase-next');
  if (binary !== expectedBinary) throw new Error('Release artifact must be the executable produced by the locked release target');
  if (proof.buildId !== undefined && proof.buildId !== await digestJson(buildReceiptIdentity(receipt, source, binarySha, selected))) {
    throw new Error('Release build identifier differs from its completion receipt');
  }
  const binaryInfo = await lstat(binary);
  if (!binaryInfo.isFile() || binaryInfo.isSymbolicLink()) throw new Error('Release artifact must be a regular file');
  if (await sha256(binary) !== proof.sha256) throw new Error('Release artifact checksum differs from build provenance');
  const buildId = await digestJson(buildReceiptIdentity(receipt, source, binarySha, selected));
  await mkdir(path.dirname(out), { recursive: true });
  const packageRoot = await mkdtemp(path.join(path.dirname(out), '.rebase-release-'));
  try {
    const payload = path.join(packageRoot, 'payload');
    await mkdir(payload, { recursive: true });
    await copySource(source.directory, payload);
    await installLockedNodeTools(payload, toolingEnvironment);
    await mkdir(path.join(payload, 'bin'));
    await copyRegular(binary, path.join(payload, 'bin/rebase-next'), 0o755, { allowHardlink: true });
    const binaryHash = await sha256(path.join(payload, 'bin/rebase-next'));
    const identities = await inspectBinary(path.join(payload, 'bin/rebase-next'), environment);
    const models = identities.models;
    if (!sameJson(identities.backends, ['redb', ...selected])) throw new Error('Built artifact backend capabilities differ from requested Cargo features');
    const requiredModels = new Set(identities.models.map(model => model.selector));
    const catalogDir = path.join(payload, 'catalogs');
    await mkdir(catalogDir);
    for (const item of models) {
      item.catalogPath = `catalogs/${item.selector}.public.json`;
      await writeFile(path.join(payload, item.catalogPath), `${JSON.stringify(item.catalog, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
    }
    const packageVersion = await cargoPackageVersion(path.join(source.directory, 'Cargo.toml'));
    for (const item of models) if (item.version.version !== packageVersion) throw new Error('Binary package version differs from committed Cargo.toml');
    const shared = new Set(models.map(m => JSON.stringify([m.version.store_format, m.catalog.codec, m.catalog.api])));
    if (shared.size !== 1) throw new Error('Compiled model format identities differ');
    const templates = await deploymentTemplates(payload, identities.backends);
    if (Object.keys(templates).length !== identities.backends.length || identities.backends.some(name => !templates[name])) {
      throw new Error('A committed deployment template is missing for a compiled backend');
    }
    for (const item of models) item.catalogSha256 = await sha256(path.join(payload, item.catalogPath));
    const manifest = {
      format: 'rebase-node-release-1', packageVersion, sourceCommit: source.sourceCommit,
      sourceTree: source.sourceTree, sourceFiles: source.sourceFiles,
      build: { profile: 'release', locked: true, jobs: 2, incremental: false, outsideGit: true,
        features: selected, buildId, exitCode: receipt.exitCode, command: receipt.command, cwd: receipt.cwd,
        sourceFilesSha256: receipt.sourceFilesSha256, buildLogSha256: receipt.buildLogSha256 },
      binary: { path: 'bin/rebase-next', sha256: binaryHash, provenance: 'committed-export-build' },
      models: Object.fromEntries(models.map(m => [m.selector, modelManifest(m)])),
      formats: { store: models[0].version.store_format, nativeCodec: models[0].catalog.codec,
        api: models[0].catalog.api, effectCodec: models.find(m => m.catalog.capabilities?.effects?.codec)?.catalog.capabilities.effects.codec ?? null },
      supportedBackends: identities.backends,
      deploymentTemplates: templates,
      nativePrerequisites: { foundationdb: { required: selected.includes('foundationdb'), bundled: false,
        library: 'libfdb_c', buildEnvironmentVariable: 'FDB_CLIENT_LIB_PATH',
        runtimeEnvironmentVariable: 'LD_LIBRARY_PATH' } },
    };
    if (models.length !== requiredModels.size) throw new Error('Native model capability inventory contains duplicates');
    await writeFile(path.join(payload, 'BUNDLE.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
    const files = await inventory(payload);
    if (files.length > MAX_FILES) throw new Error('Release file count exceeds 65,536 entries');
    const sumLines = files.map(file => `${file.sha256}  ${file.path}\n`).join('');
    await writeFile(path.join(payload, 'SHA256SUMS'), sumLines, { flag: 'wx', mode: 0o644 });
    const result = await verifyRelease({ directory: payload, environment });
    await renameOwned(payload, out);
    return result;
  } catch (error) {
    await rm(packageRoot, { recursive: true, force: true });
    throw error;
  } finally {
    await rm(packageRoot, { recursive: true, force: true });
  }
}

/** Verify an extracted release without importing from or consulting a workspace. */
export async function verifyRelease({ directory, checkBinary = true, environment = {} }) {
  validateEnvironment(environment);
  const root = await realpath(requiredPath(directory, 'directory'));
  await assertRegularTree(root);
  const entries = await verifyChecksums(root);
  const manifest = parseJsonBounded(await readSafe(root, 'BUNDLE.json'));
  if (manifest.format !== 'rebase-node-release-1' || !OID.test(manifest.sourceCommit ?? '')
      || !OID.test(manifest.sourceTree ?? '') || !HASH.test(manifest.binary?.sha256 ?? '')) throw new Error('Release manifest identity is incomplete');
  const selected = canonicalFeatures(manifest.build?.features);
  if (manifest.build.profile !== 'release' || manifest.build.locked !== true || manifest.build.jobs !== 2
      || manifest.build.incremental !== false || manifest.build.outsideGit !== true) throw new Error('Release build contract differs');
  const command = manifest.build.command;
  if (manifest.build.exitCode !== 0 || !HASH.test(manifest.build.buildLogSha256 ?? '')
      || manifest.build.sourceFilesSha256 !== await digestJson(manifest.sourceFiles)
      || !Array.isArray(command) || command[0] !== 'cargo' || command[1] !== 'build'
      || command[2] !== '--locked' || command[3] !== '--release' || command[4] !== '--manifest-path'
      || !command[5]?.endsWith(`${path.sep}Cargo.toml`) || command[6] !== '--target-dir'
      || command[8] !== '--jobs' || command[9] !== '2' || command[10] !== '--bin' || command[11] !== 'rebase-next') {
    throw new Error('Release build provenance is incomplete or differs from locked Cargo release');
  }
  const featureArgs = selected.length ? ['--features', selected.join(',')] : [];
  if (!sameJson(command.slice(12), featureArgs)) throw new Error('Release Cargo features differ from manifest');
  const packageVersion = cargoPackageVersionText((await readSafe(root, 'Cargo.toml')).toString('utf8'));
  if (manifest.packageVersion !== packageVersion) throw new Error('Release package version differs from committed Cargo.toml');
  const buildIdentity = { command, cwd: manifest.build.cwd, sourceCommit: manifest.sourceCommit,
    sourceTree: manifest.sourceTree, sourceFilesSha256: manifest.build.sourceFilesSha256,
    buildLogSha256: manifest.build.buildLogSha256, artifactSha256: manifest.binary.sha256,
    features: selected, profile: 'release', locked: true, jobs: 2, incremental: false, outsideGit: true };
  if (manifest.build.buildId !== await digestJson(buildIdentity)) throw new Error('Release build identity digest differs');
  if (manifest.supportedBackends?.[0] !== 'redb' || !Array.isArray(manifest.supportedBackends)
      || new Set(manifest.supportedBackends).size !== manifest.supportedBackends.length) throw new Error('Backend inventory is invalid');
  if (!sameJson(manifest.supportedBackends, ['redb', ...selected])) throw new Error('Backend inventory differs from explicit Cargo features');
  const modelEntries = Object.entries(manifest.models ?? {});
  if (!modelEntries.length || modelEntries.length > 32) throw new Error('Model inventory is empty or over limit');
  const catalogs = [];
  for (const [selector, model] of modelEntries) {
    if (!MODEL_SELECTOR.test(selector) || model.catalog !== `catalogs/${selector}.public.json`
        || entries.get(model.catalog) !== model.catalogSha256 || !HASH.test(model.model ?? '')
        || !model.behaviorContract || !model.limits || !model.api || !model.codec || !model.storeFormat
        || model.version?.version !== manifest.packageVersion || model.version?.model !== model.model
        || model.version?.store_format !== model.storeFormat) {
      throw new Error(`Model identity is incomplete: ${selector}`);
    }
    const catalog = parseJsonBounded(await readSafe(root, model.catalog));
    if (catalog.model !== model.model || catalog.api !== model.api || catalog.codec !== model.codec
        || JSON.stringify(catalog.capabilities?.limits) !== JSON.stringify(model.limits)) throw new Error(`Model catalog identity differs: ${selector}`);
    catalogs.push(catalog);
  }
  const sharedFormats = new Set(modelEntries.map(([, model]) => JSON.stringify([model.storeFormat, model.codec, model.api])));
  if (sharedFormats.size !== 1 || manifest.formats?.store !== modelEntries[0][1].storeFormat
      || manifest.formats?.nativeCodec !== modelEntries[0][1].codec || manifest.formats?.api !== modelEntries[0][1].api) {
    throw new Error('Shared compiled model format identities differ');
  }
  const effectCodecs = catalogs.map(catalog => catalog.capabilities?.effects?.codec).filter(value => value !== undefined);
  if (effectCodecs.length > 1 || (effectCodecs[0] ?? null) !== manifest.formats?.effectCodec) throw new Error('Effect codec identity differs');
  if (entries.get('bin/rebase-next') !== manifest.binary.sha256) throw new Error('Binary checksum differs from manifest');
  for (const [name, hash] of Object.entries(manifest.sourceFiles ?? {})) if (entries.get(name) !== hash) throw new Error(`Committed source checksum differs: ${name}`);
  if (!Object.keys(manifest.sourceFiles ?? {}).length) throw new Error('Source inventory is empty');
  for (const required of ['Cargo.toml', 'Cargo.lock', 'tools/node/package.json', 'tools/node/package-lock.json']) {
    if (!Object.hasOwn(manifest.sourceFiles, required)) throw new Error(`Committed release input is missing: ${required}`);
  }
  const templates = manifest.deploymentTemplates ?? {};
  if (JSON.stringify(Object.keys(templates).sort()) !== JSON.stringify(manifest.supportedBackends.slice().sort())) throw new Error('Deployment template inventory differs from backends');
  for (const [backend, detail] of Object.entries(templates)) {
    if (!detail || typeof detail.path !== 'string' || entries.get(detail.path) !== detail.sha256 || !HASH.test(detail.sha256)) throw new Error(`Deployment template identity is incomplete: ${backend}`);
  }
  const fdb = manifest.nativePrerequisites?.foundationdb;
  if (!fdb || fdb.required !== selected.includes('foundationdb') || fdb.bundled !== false || fdb.library !== 'libfdb_c'
      || fdb.buildEnvironmentVariable !== 'FDB_CLIENT_LIB_PATH' || fdb.runtimeEnvironmentVariable !== 'LD_LIBRARY_PATH') {
    throw new Error('FoundationDB prerequisite inventory differs');
  }
  if (selected.includes('foundationdb')) await validateFdbEnvironment(environment);
  if (checkBinary) {
    const actual = await inspectBinary(path.join(root, 'bin/rebase-next'), environment);
    if (JSON.stringify(actual.backends) !== JSON.stringify(manifest.supportedBackends)) throw new Error('Extracted binary backend capabilities differ');
    if (actual.models.length !== modelEntries.length) throw new Error('Extracted binary model capabilities differ');
    for (const entry of actual.models) {
      const expected = manifest.models[entry.selector];
      if (!expected || entry.catalog.model !== expected.model || entry.catalog.api !== expected.api
          || JSON.stringify(entry.version) !== JSON.stringify(expected.version)
          || entry.version.store_format !== expected.storeFormat || JSON.stringify(entry.catalog) !== JSON.stringify(parseJsonBounded(await readSafe(root, expected.catalog)))
          || entry.developer.behavior_contract !== expected.behaviorContract) throw new Error(`Extracted binary identity differs: ${entry.selector}`);
    }
  }
  return Object.freeze({ status: 'passed', checksummedFiles: entries.size, modelCount: modelEntries.length,
    binaryCatalogsChecked: checkBinary, sourceCommit: manifest.sourceCommit, binarySha256: manifest.binary.sha256,
    features: Object.freeze(selected), supportedBackends: Object.freeze([...manifest.supportedBackends]) });
}

function modelManifest({ selector, version, catalog, developer, catalogSha256 }) {
  return { version, model: version.model, storeFormat: version.store_format, api: catalog.api, codec: catalog.codec,
    limits: catalog.capabilities?.limits, behaviorContract: developer.behavior_contract,
    catalog: `catalogs/${selector}.public.json`, catalogSha256 };
}

function validateSource(source) {
  if (!source || typeof source !== 'object' || typeof source.directory !== 'string' || !OID.test(source.sourceCommit ?? '')
      || !OID.test(source.sourceTree ?? '') || !source.sourceFiles || typeof source.sourceFiles !== 'object') throw new TypeError('source must be a committed export from exportCommittedSource');
  if (!Object.keys(source.sourceFiles).length || Object.entries(source.sourceFiles).some(([p, h]) => !safeRelative(p) || !HASH.test(h))) throw new TypeError('source hash inventory is invalid');
}
function parseTree(buffer) {
  const rows = buffer.toString('utf8').split('\0').filter(Boolean);
  const files = [];
  for (const row of rows) {
    const match = /^(100644|100755) blob ([0-9a-f]{40,64})\t(.+)$/.exec(row);
    if (!match || !safeRelative(match[3])) throw new Error('Committed release source contains an unsafe path or non-regular object');
    files.push({ oid: match[2], path: match[3] });
  }
  files.sort((a, b) => comparePath(a.path, b.path));
  if (new Set(files.map(file => file.path)).size !== files.length || files.length > MAX_FILES) throw new Error('Committed source file inventory is duplicated or too large');
  return files;
}
function safeRelative(name) {
  return typeof name === 'string' && name.length > 0 && !name.includes('\\') && !name.includes('\n') && !name.includes('\0')
    && !path.posix.isAbsolute(name) && name.split('/').every(part => part && part !== '.' && part !== '..') && path.posix.normalize(name) === name;
}
function canonicalFeatures(input) {
  if (!Array.isArray(input) || input.some(x => typeof x !== 'string' || !FEATURES.has(x))) throw new TypeError('features must be an explicit array of foundationdb and/or surrealkv');
  const result = [...new Set(input)].sort();
  if (result.length !== input.length) throw new TypeError('features must not contain duplicates');
  return result;
}
async function inspectBinary(binary, environment) {
  const selectors = new Set();
  const outputs = [];
  let backends;
  const openForModel = selector => openNative(resolveConfig({
    defaults: { native: { binary: path.resolve(binary), environment } },
    overrides: { native: { configuration: { model: selector,
      backend: { kind: 'redb', cluster_file: null }, target: null, operator_methods: [] } } },
  }));
  const discover = await openForModel('calculation');
  let description;
  try { description = await discover.describe(); }
  finally { await discover.close(); }
  const models = description.engine?.compiled_models;
  backends = description.engine?.compiled_backends;
  if (!Array.isArray(models) || !models.length || models.some(x => !MODEL_SELECTOR.test(x))
      || new Set(models).size !== models.length || !Array.isArray(backends) || !backends.includes('redb')) {
    throw new Error('Native binary capability discovery is incomplete');
  }
  for (const selector of models) {
    const native = await openForModel(selector);
    try {
      const [catalog, developer] = await Promise.all([
        native.catalog({ scope: 'public' }), native.catalog({ scope: 'developer' }),
      ]);
      const version = { version: description.engine.version, model: native.selection.model,
        store_format: description.engine.store_format };
      if (version.model !== catalog.model || developer.model !== catalog.model
          || catalog.capabilities?.limits === undefined) throw new Error(`Native binary model catalog is incomplete: ${selector}`);
      outputs.push({ selector, version, catalog, developer });
      selectors.add(selector);
    } finally { await native.close(); }
  }
  if (selectors.size !== outputs.length) throw new Error('Native model capability inventory contains duplicates');
  return { models: outputs, backends: [...backends] };
}
function onceClose(proc) { return new Promise((resolve, reject) => { proc.once('error', reject); proc.once('close', code => resolve(code)); }); }
async function run(args, { cwd, maxOutput = MAX_OUTPUT, environment = {}, input = '' } = {}) {
  validateEnvironment(environment);
  const proc = spawn(args[0], args.slice(1), { cwd, shell: false,
    stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'], env: { ...environment } });
  if (input) proc.stdin.end(input);
  const out = collect(proc.stdout, maxOutput, () => proc.kill('SIGKILL'));
  const err = collect(proc.stderr, maxOutput, () => proc.kill('SIGKILL'));
  const [stdout, stderr, code] = await Promise.all([out, err, onceClose(proc)]);
  if (code !== 0) throw new Error(`${path.basename(args[0])} exited ${code}: ${stderr.toString('utf8').slice(-1024)}`);
  return { stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') };
}
function collect(stream, max = MAX_OUTPUT, overflow = () => {}) { return new Promise((resolve, reject) => { const chunks = []; let bytes = 0; let failed = false; stream.on('data', chunk => { bytes += chunk.length; if (bytes > max) { if (!failed) { failed = true; overflow(); reject(new Error('Process output exceeds bounded byte limit')); } } else if (!failed) chunks.push(chunk); }); stream.on('error', error => { if (!failed) reject(error); }); stream.on('end', () => { if (!failed) resolve(Buffer.concat(chunks)); }); }); }
async function inventory(root) {
  const files = [];
  let total = 0;
  async function visit(dir, prefix = '') {
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) => comparePath(a.name, b.name))) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (!safeRelative(rel)) throw new Error('Unsafe path in release tree');
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Release tree contains a symlink: ${rel}`);
      if (entry.isDirectory()) await visit(full, rel);
      else if (entry.isFile()) {
        const info = await stat(full);
        if (info.nlink !== 1 || info.size > MAX_FILE_BYTES || (total += info.size) > MAX_TOTAL_BYTES) throw new Error(`Release file exceeds link or byte bounds: ${rel}`);
        files.push({ path: rel, sha256: await sha256(full), size: info.size });
        if (files.length > MAX_FILES) throw new Error('Release file count exceeds limit');
      } else throw new Error(`Release tree contains a non-regular entry: ${rel}`);
    }
  }
  await visit(root);
  return files;
}
async function verifyChecksums(root) {
  const bytes = await readSafe(root, 'SHA256SUMS');
  if (bytes.length > MAX_OUTPUT) throw new Error('Checksum inventory exceeds metadata limit');
  const entries = new Map();
  for (const line of bytes.toString('utf8').split('\n').filter(Boolean)) {
    const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
    if (!match || !safeRelative(match[2]) || match[2] === 'SHA256SUMS' || entries.has(match[2])) throw new Error('Checksum inventory is invalid or duplicated');
    const actual = await sha256(path.join(root, match[2]));
    if (actual !== match[1]) throw new Error(`Release checksum differs: ${match[2]}`);
    entries.set(match[2], match[1]);
  }
  if (!entries.has('BUNDLE.json') || !entries.has('bin/rebase-next') || entries.size === 0) throw new Error('Checksum inventory is incomplete');
  const actualFiles = await inventory(root);
  if (actualFiles.length !== entries.size + 1 || actualFiles.some(file => file.path !== 'SHA256SUMS' && !entries.has(file.path))) throw new Error('Checksum inventory does not cover the complete release');
  return entries;
}
async function readSafe(root, relative) { if (!safeRelative(relative)) throw new Error('Unsafe release-relative path'); const full = path.join(root, relative); const info = await lstat(full); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > MAX_OUTPUT && relative !== 'bin/rebase-next') throw new Error(`Missing, non-regular or oversized release file: ${relative}`); return readFile(full); }
function parseJsonBounded(bytes) { if (bytes.length > MAX_OUTPUT) throw new Error('Release metadata exceeds 8 MiB'); return JSON.parse(bytes.toString('utf8')); }
async function assertRegularTree(root) { const info = await stat(root); if (!info.isDirectory()) throw new Error('Release root must be a directory'); await inventory(root); }
async function copySource(source, destination) { for (const file of await inventory(source)) { const from = path.join(source, file.path), to = path.join(destination, file.path); await mkdir(path.dirname(to), { recursive: true }); await copyRegular(from, to); } }
async function copyRegular(from, to, mode, { allowHardlink = false } = {}) { const info = await lstat(from); if (!info.isFile() || info.isSymbolicLink() || (!allowHardlink && info.nlink !== 1) || info.size > MAX_FILE_BYTES) throw new Error('Release input must be a bounded regular file'); await copyFile(from, to, constants.COPYFILE_EXCL); await chmod(to, mode ?? (info.mode & 0o777)); }
async function deploymentTemplates(payload, backends) {
  const out = {};
  const files = new Set((await inventory(payload)).map(file => file.path));
  for (const backend of backends) {
    const suffix = backend === 'redb' ? '' : backend === 'surrealkv' ? '-surreal' : `-${backend}`;
    const name = `deploy/rebase-next${suffix}.service`;
    if (!files.has(name)) continue;
    out[backend] = { path: name, sha256: await sha256(path.join(payload, name)) };
  }
  if (!out.redb) throw new Error('Committed redb deployment template is missing');
  return out;
}
async function installLockedNodeTools(payload, environment) {
  const tools = path.join(payload, 'tools/node');
  const npm = environment.NPM ?? 'npm';
  if (typeof npm !== 'string' || (!path.isAbsolute(npm) && !/^[A-Za-z0-9._-]+$/.test(npm))) throw new TypeError('toolingEnvironment.NPM must name npm or an absolute npm executable');
  await run([npm, 'ci', '--ignore-scripts', '--bin-links=false', '--install-links=true', '--no-audit', '--no-fund'], {
    cwd: tools, environment, maxOutput: MAX_OUTPUT,
  });
}
function validateEnvironment(environment) {
  if (!environment || typeof environment !== 'object' || Array.isArray(environment)
      || Object.entries(environment).some(([key, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof value !== 'string' || value.includes('\0'))) {
    throw new TypeError('environment must be an explicit string-valued environment object');
  }
}
async function validateFdbEnvironment(environment) {
  const value = environment.FDB_CLIENT_LIB_PATH;
  if (!value) throw new Error('FoundationDB release requires FDB_CLIENT_LIB_PATH in the explicit native environment');
  const root = await realpath(value);
  const names = await readdir(root);
  if (!names.some(name => /^libfdb_c\.so(?:\.|$)/.test(name))) throw new Error('FDB_CLIENT_LIB_PATH must contain compatible libfdb_c');
  return root;
}
function requiredPath(value, name) { if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${name} must be an explicit path`); return value; }
async function exists(value) { try { await lstat(value); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } }
function isWithin(parent, child) { const rel = path.relative(path.resolve(parent), path.resolve(child)); return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel)); }
async function insideGit(target) { let current = path.resolve(target); while (true) { if (await exists(path.join(current, '.git'))) return true; const parent = path.dirname(current); if (parent === current) return false; current = parent; } }
async function canonicalProspectivePath(input) {
  const absolute = path.resolve(input);
  const leaf = path.basename(absolute);
  if (!leaf || leaf === '.' || leaf === '..') throw new TypeError('Output path must name a new directory');
  let parent = path.dirname(absolute);
  const missing = [];
  while (!(await exists(parent))) {
    const name = path.basename(parent);
    const next = path.dirname(parent);
    if (next === parent) throw new Error('Unable to resolve output parent');
    missing.unshift(name);
    parent = next;
  }
  return path.join(await realpath(parent), ...missing, leaf);
}
async function sha256(filename) { const hash = createHash('sha256'); for await (const chunk of createReadStream(filename)) hash.update(chunk); return hash.digest('hex'); }
async function cargoPackageVersion(filename) {
  const text = await readFile(filename, 'utf8');
  if (Buffer.byteLength(text) > MAX_OUTPUT) throw new Error('Cargo manifest exceeds release metadata limit');
  return cargoPackageVersionText(text);
}
function cargoPackageVersionText(text) {
  if (Buffer.byteLength(text) > MAX_OUTPUT) throw new Error('Cargo manifest exceeds release metadata limit');
  const packageSection = /^\[package\]\s*([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(text)?.[1];
  const version = /^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"\s*$/m.exec(packageSection ?? '')?.[1];
  if (!version) throw new Error('Committed Cargo package version is missing or unsupported');
  return version;
}
function buildReceiptIdentity(receipt, source, binarySha, features) {
  return { command: receipt.command, cwd: receipt.cwd, sourceCommit: source.sourceCommit,
    sourceTree: source.sourceTree, sourceFilesSha256: receipt.sourceFilesSha256,
    buildLogSha256: receipt.buildLogSha256, artifactSha256: binarySha,
    features, profile: 'release', locked: true, jobs: 2, incremental: false, outsideGit: true };
}
function sameJson(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
async function digestJson(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function comparePath(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
async function renameOwned(from, to) { const { rename } = await import('node:fs/promises'); await rename(from, to); }
