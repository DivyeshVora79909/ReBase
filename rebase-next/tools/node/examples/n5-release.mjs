import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { describeReleaseBuild, packageRelease, prepareReleaseSource, verifyRelease } from '../release.mjs';

/** Build one committed export, package its exact executable, then verify after extraction. */
export async function buildCommittedRelease({ repository, sourceRef, sourceDirectory, targetDir,
  output, gitEnvironment, buildEnvironment, nativeEnvironment, toolingEnvironment, features = [] }) {
  const source = await prepareReleaseSource({ repository, sourceRef, destination: sourceDirectory, environment: gitEnvironment });
  const spec = describeReleaseBuild({ source, features, targetDir, environment: buildEnvironment });
  const buildLogSha256 = await runCargo(spec);
  const binary = path.join(path.resolve(targetDir), 'release', 'rebase-next');
  const sha256 = await fileHash(binary);
  const receipt = { exitCode: 0, command: [spec.executable, ...spec.args], cwd: spec.cwd,
    sourceCommit: source.sourceCommit, sourceTree: source.sourceTree,
    sourceFilesSha256: createHash('sha256').update(JSON.stringify(source.sourceFiles)).digest('hex'),
    buildLogSha256, artifactSha256: sha256 };
  const buildId = createHash('sha256').update(JSON.stringify({ command: receipt.command, cwd: receipt.cwd,
    sourceCommit: receipt.sourceCommit, sourceTree: receipt.sourceTree,
    sourceFilesSha256: receipt.sourceFilesSha256, buildLogSha256, artifactSha256: sha256,
    features: spec.features, profile: 'release', locked: true, jobs: 2, incremental: false, outsideGit: true })).digest('hex');
  const packageResult = await packageRelease({ source, artifact: { path: binary,
    provenance: { spec, receipt, sha256, buildId } }, output, features,
    environment: nativeEnvironment, buildEnvironment, toolingEnvironment });
  return Object.freeze({ source, build: spec, package: packageResult,
    extractedDirectory: path.resolve(output) });
}

/** Call from a standard Node REPL with explicit paths and environment. */
export async function verifyExtractedRelease({ directory, environment = {} }) {
  return verifyRelease({ directory, checkBinary: true, environment });
}

async function fileHash(filename) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}

function runCargo(spec) {
  const hash = createHash('sha256');
  let bytes = 0;
  return new Promise((resolve, reject) => {
    const child = spawn(spec.executable, [...spec.args], { cwd: spec.cwd, env: { ...spec.environment }, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let failed = false;
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 8 * 1024 * 1024) {
        if (!failed) { failed = true; child.kill('SIGKILL'); reject(new Error('Cargo output exceeded 8 MiB')); }
        return;
      }
      hash.update(chunk);
      (stream === child.stdout ? process.stdout : process.stderr).write(chunk);
    });
    child.once('error', error => { if (!failed) reject(error); });
    child.once('close', (code, signal) => {
      if (failed) return;
      if (code !== 0) reject(new Error(`cargo exited ${code ?? signal}`));
      else resolve(hash.digest('hex'));
    });
  });
}
