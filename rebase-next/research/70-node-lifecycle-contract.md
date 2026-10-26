# N5 — independent storage structure and fake-provider contract

Status: implementation contract for two bounded N5 obligations; no N5
acceptance or release-package result is implied. N5 follows accepted N2
lifecycle methods and N4's source-derived checking. N4 and N5 checks remain
separate: source expectations establish which application records, roots,
members, and logical values should exist; this contract adds independent checks
over the physical ordered-tree rows persisted in a native backup.

## Structural snapshot input

`tools/node/storage-check.mjs` accepts explicit backup bytes or text and finite
byte, row, and traversal limits. A complete result reports `passed` and the
checked root/node counts. Invalid, contradictory, or unsupported contents
raise a bounded error; a caller that could not obtain a backup records that
missing input as `incomplete`. The checker has no native host dependency and
must not call `store.check` or reuse Rust checker output as its expected result.

The accepted N2 backup format provides the needed physical rows:

- Envelope `format` is `rebase-backup-1`, with `payload` and SHA-256.
- Payload `format` is `rebase-authorized-observation-1`, with `complete: true`
  and a table map. `native_kv` is an array of `{key,value}` hex byte strings.
- Native KV values are UTF-8 JSON serialized by serde, with a tagged
  `StoredValue` such as `{"type":"node","data":{...}}`; the byte codec is
  not bincode. Native point keys use the stable tags and lengths in
  `src/native_codec.rs`: tag 2 is a root and tag 3 is a tree node. Both carry a
  16-byte UUID followed by a big-endian nonzero u16 slot.
- The backup digest is over the native canonical JSON encoding of the payload.
  The implementation must establish its exact byte rule and reject ambiguous
  duplicate-key input; plain `JSON.parse` alone cannot establish either.

For persisted `root` and `node` values, the checker reconstructs the declared
serde struct/address/key/summary field order and compares it with the original
UTF-8 bytes. Other tagged native values are decoded with strict UTF-8 and
duplicate-key rejection and must be compact JSON; their model-specific serde
field order and semantics are outside this structural check. This is not a
claim that the checker reimplements the entire native codec.

This format was confirmed against a disposable real Equipment store made with
the frozen N2 binary: the backup was complete and held ten native KV rows,
including one tagged physical node. The store and backup were removed after
inspection. No native rebuild was required.

The checker parses only the small physical type vocabulary needed for tree
verification. All six compiled models use decimal-string `TimeKey`s. Five use
the `Standard` index (`Financial` and `Quote` kinds); Measurement uses the
`Statistics` index (`Observation` leaves and dimensioned summaries). It must
not duplicate contract formulas or the source oracle. It does:

1. Decode the complete bounded KV inventory, rejecting invalid hex, malformed
   key tags/lengths, duplicate native keys, invalid UTF-8, duplicate JSON keys,
   and key/value tag disagreement.
2. Build typed maps of roots and nodes. Walk each root from `head`, rejecting
   missing nodes, cycles, repeated reachability, cross-root links, wrong
   parent pointers, wrong key/address identity, and depth at or above 64.
3. Recompute each node's height and AVL balance from its children; compare the
   root height and first/last addresses; derive in-order IDs and check each
   node's `prev`/`next` links and strict full-key order.
4. Recompute each node and root span from in-order keys and compare the stored
   span. Empty roots must have no head, first/last, or span and height zero.
5. Independently recompute each node summary from the left summary, the node's
   `(key, leaf)` singleton, and the right summary, then recompute each root
   summary. Use small checked reference folds for Financial, Quote, and
   Statistics summaries (including exact decimal strings, dimension
   combination, and overflow rejection). This verifies the
   persisted monoid caches without running the production tree or business
   calculation engine.
6. Require every persisted tree node to be reachable exactly once. When the
   caller supplies source-derived expected root/member identities from N4, also
   compare the complete expected membership inventory; the structural checker
   does not infer which source records ought to publish a root.

Report physical structure, cached-summary folds, and optional source membership
as distinct obligations. The old Python `verify_oracles.py` checked source
semantics only. `g8_check.py` checked backup shape, row bounds and duplicate
keys, then compared source-derived logical outcomes. Neither independently
checked tree links or topology. This is a new strengthening of N4's independent
checking obligation, not a Python structural feature being preserved.

## Fake-provider fixture

`tools/node/fake-provider.mjs` exports an explicitly invoked `startFakeProvider`
that returns a caller-owned local HTTP service handle. Importing the module has
no side effects. The provider is separate from the native application process,
so it stays available during application shutdown and can be reopened from its
durable directory after process loss. The returned handle owns `endpoint`,
mode updates, hold/release controls, counts, accepted markers, and awaited
`close`; tests and examples close it in `finally`.

Use only `node:http` and `node:fs/promises`. Node 24's built-in `node:sqlite` is
still experimental; do not add it or an external database dependency for this
small deterministic fixture. Persist a bounded JSON state image with a
single-writer promise queue, a private temporary file, file sync, atomic rename,
and directory sync on supported platforms. Validate the image on open. The
fixture makes a single-process, single-writer durability claim for committed
local state, not SQLite transaction semantics or concurrent distributed
provider behavior. Serialize requests before reading or changing state.

Preserve the contract used by the old `tools/fake_provider.py` fixture:

- A submission binds the execution identity to the exact request digest.
  Repeating identical content returns the recorded state; changed content for
  the same identity returns conflict. Empty lookup remains unknown.
- Explicit per-execution modes cover `success`, `waiting`, `not_accepted`,
  `reject_once`, `failed`, `lost_response`, and a held response that the caller
  can release. `waiting` can later reconcile to success; `empty` forces a GET
  lookup to remain unknown even after an accepted submission. Acceptance and
  call counts are durable and independently inspectable.
- Bodies, retained executions/calls, identifiers, and waits have explicit hard
  limits; at most 64 response holds and 64 pause waiters may be active. The
  service binds only to loopback and uses OS-selected ports. The returned handle
  rejects operations after awaited close.

The provider test must cover same-content replay, content conflict, unknown
lookup, each material mode, loss after durable acceptance, wait/reconcile,
application-side restart/reopen, serialized concurrent submissions, bounded
input rejection, and awaited cleanup. This service is a test fixture, not a
production provider or a distributed failure simulator.

## Managed local FoundationDB process

`tools/node/infra.mjs` exports `openFdbEnvironment` for explicitly owned local
FDB test infrastructure. The caller supplies absolute `fdbserver`, `fdbcli`,
cluster-file, data, log, and server-log paths, a loopback port, and a complete
child environment. `start` launches only the requested server with an argument
array (`shell: false`), waits a bounded time for its listener, and returns the
owned process identity. `status`, `bootstrap`, and `check` invoke the supplied
CLI with bounded output and timeouts. The check writes, reads, and clears a
random probe key. `stop`/`close` send SIGTERM only to that handle's ChildProcess
and report a bounded timeout without escalating to a PID lookup or kill.

The module never reads or writes a PID file and refuses an already-listening
port. This is a local test-process owner, not a general FDB cluster manager;
callers own choosing a matching cluster file and endpoint, and cleanup after a
stop timeout. Focused tests use fake executable processes. A real FDB lifecycle
witness remains an acceptance task and must use the installed caller-selected
binaries and serialized environment.

## N5 boundary

N2 already owns scoped native `check`, `inspect`, `snapshot`, `restore`,
`archive`, `reset`, service lifecycle, and identity functions. N5 composes those
functions and the independent checks above; it does not add duplicate operator
verbs. N2's adapter trials remain evidence only for their recorded source,
binary, backend, and lifecycle cases. N5 packaging and extracted-artifact
acceptance are separately owned and are not closed by these two modules.

Native source remains unchanged if the complete backup rows continue to expose
the current typed tree keys and values. If that ceases to hold, the checker
must report structural coverage incomplete and identify the smallest typed
snapshot export needed; `store.check` is never a substitute for independent
evidence.

## Release API and environment separation

The release surface is four ordinary functions, not a package-specific domain
CLI:

- `prepareReleaseSource({ repository, sourceRef, destination, environment })`
  resolves one explicit Git commit/tree, rejects symlinks, submodules, unsafe
  paths, and output inside Git, then exports and hashes that committed tree.
  `environment` is the explicit Git/archive process environment (provided as
  `gitEnvironment` by the composition example).
- `describeReleaseBuild({ source, features, targetDir, environment })` returns
  the only supported Cargo command: locked release build of `rebase-next`,
  outside Git, with two jobs and incremental compilation disabled. Optional
  backend features are explicit. This function describes the invocation and
  does not run Cargo; its `environment` belongs to the build process
  (`buildEnvironment` in the composition example). The argument vector is
  `cargo build --locked --release --manifest-path <export>/Cargo.toml
  --target-dir <target> --jobs 2 --bin rebase-next [--features <features>]`.
- `packageRelease({ source, artifact, output, features, environment,
  buildEnvironment, toolingEnvironment })` accepts a binary only with a
  receipt matching the committed export, exact Cargo arguments/environment,
  feature set, source file digest, build log digest, and artifact digest.
  `environment` is used for native binary discovery and runtime prerequisites,
  `buildEnvironment` reconstructs the locked build specification, and
  `toolingEnvironment` supplies npm for the copied Node package. Node tools are
  installed from the copied package and lock files with `npm ci`, lifecycle
  scripts disabled, and lockfile integrity checks in effect. These environment
  objects remain distinct and caller supplied. `toolingEnvironment.NPM` names
  npm; packaging runs `npm ci --ignore-scripts --bin-links=false
  --install-links=true --no-audit --no-fund` against the copied package and
  lock file. The lock file's package integrity fields bind downloaded package
  bytes. The process output cap is 8 MiB.
- `verifyRelease({ directory, checkBinary, environment })` checks a package at
  its extracted path, verifies its complete checksums and manifest, and can
  inspect the extracted executable. It does not import from the workspace or
  run Cargo.

The package contains the native `bin/rebase-next` executable, ordinary Node ESM
tools, locked Node dependencies, model catalogs, deployment templates, bundle
manifest and checksums. It does not add a project-specific legacy domain CLI.
The source export and package are bounded to 65,536 files, 512 MiB per file,
and 2 GiB total; release process output and manifest metadata are also bounded.
FoundationDB's client library is an explicit build/runtime prerequisite when
that Cargo feature is selected, not a bundled dependency. Source export uses
Git environment, Cargo uses build environment, model/backend discovery and
extracted runtime checks use native environment, and npm dependency installation
uses tooling environment. Passing the package fixture test with a previously
built binary does not replace the committed source release build and
extracted-package checks.
