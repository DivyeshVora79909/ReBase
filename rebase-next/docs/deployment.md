# ReBase Next deployment

## Current 0.16.0 source and release bundles

The verified current artifacts are 0.16.0, built from commit `8ddc88fa`.
Both the SDK-free redb variant and the FoundationDB/SurrealKV-enabled variant
pass isolated extracted workflows. The [G8.4 evidence](../research/evidence/2026-10-25-g84-release.json)
records exact archive/binary hashes, source identity, six-model inventory and
per-backend results; [G8 results](../research/53-workload-deployment-result.md)
describe workload and recovery boundaries. A new package from another commit
needs its own artifact identity and affected acceptance. Historical 0.6.0
acceptance remains separate below.

The package tool builds committed `HEAD` from a Git archive outside the
checkout. Commit the intended source and tools first. Python 3.11+, Git, the
pinned Rust toolchain, a C/C++ toolchain, CMake and GNU `readelf` are required.
The shared Cargo cache defaults to `target/verification-build`; select another
with `--target-dir` if needed. Default features build a redb-only binary without
a FoundationDB SDK:

```sh
python3 -B tools/package.py --out target/g8-package-redb --target-dir target/verification-build
```

Optional Cargo features are explicit. A FoundationDB build requires a
compatible `libfdb_c` SDK directory; this environment's verified SDK path is
`target/g7-environment/lib` (FoundationDB 7.3.77). SurrealKV requires no native
SDK. The following builds one artifact advertising redb, SurrealKV and
FoundationDB:

```sh
FDB_CLIENT_LIB_PATH="$PWD/target/g7-environment/lib" \
LD_LIBRARY_PATH="$PWD/target/g7-environment/lib" \
  python3 -B tools/package.py --features foundationdb,surrealkv \
    --out target/g8-package-all --target-dir target/verification-build
```

The artifact records all six compiled models: `calculation`, `equipment`,
`invoicing`, `measurement`, `effect-demo` and `quantity`. It also records the
exact feature/backend set, shared storage/API/codec formats, each model's
catalog and behavior identity, native prerequisites and compatible service
templates. Every bundle contains `BUNDLE.json`, `SHA256SUMS`, source inputs,
public catalogs and `bin/rebase-next`. The archive checksum is emitted beside
the archive. Check that recorded checksum before extraction; then verify every
payload entry from the extracted root:

```sh
cd target/g8-package-redb
sha256sum --check rebase-next-*-linux-x86_64-redb.tar.gz.sha256
mkdir -p /tmp/rebase-next-release
tar -xzf rebase-next-*-linux-x86_64-redb.tar.gz -C /tmp/rebase-next-release
cd /tmp/rebase-next-release/rebase-next-*-linux-x86_64-redb
sha256sum --check SHA256SUMS
```

Run extracted acceptance from outside Git with a new private output directory.
The runner checks the extracted executable's six model identities, backend
availability, checksums, authenticated equipment workflow, recovery and
configuration boundaries on every advertised backend. Python imports and
native library lookup are isolated from the checkout and ambient paths. A
redb-only artifact needs no library argument. A FoundationDB-feature artifact
needs the matching client library even for redb startup because it is a dynamic
binary dependency; its extracted run also needs an explicitly managed test
cluster, cluster file, owned database process and disposable data/log paths.
For example, from `rebase-next/`:

```sh
python3 -B tools/g8_release.py \
  --bundle /tmp/rebase-next-release/rebase-next-0.16.0-linux-x86_64-redb \
  --out /tmp/rebase-next-acceptance-redb
```

For a FoundationDB-enabled artifact, add the explicit prerequisite arguments:

```sh
python3 -B tools/g8_release.py \
  --bundle /tmp/rebase-next-release/rebase-next-0.16.0-linux-x86_64-redb-foundationdb-surrealkv \
  --out /tmp/rebase-next-acceptance-all \
  --native-library-path "$PWD/target/g7-environment/lib" \
  --cluster-file /path/to/disposable/fdb.cluster \
  --database-pid 12345 \
  --database-data /path/to/disposable/fdb-data \
  --database-log /path/to/disposable/fdb-log
```

Use the archive name and source commit reported by the package command rather
than assuming the illustrative versioned paths above. Preserve `result.json`,
`summary.md` and private workflow outputs; record the artifact SHA256, source
commit, selected features and acceptance result together. The systemd templates
are `deploy/rebase-next.service` for redb, `deploy/rebase-next-surreal.service`
for SurrealKV and `deploy/rebase-next-foundationdb.service` for FoundationDB.
The latter requires explicit client-library and cluster configuration. No
claim of native commit-ack interception, replicated failover or disk/power-loss
durability follows from these local service/recovery and short workflow checks.

## Historical 0.6.0 deployment

This historical section documents the **previously verified 0.6.0 bundle**, whose results are
recorded in the [0.6 release report](../research/29-deployment-result.md). The
0.16.0 source checkout includes later model and storage capabilities and uses
incompatible store 10 /native codec 7 /effect codec 4 /API 4. Use the source from the recorded 0.6.0 commit when
reproducing this bundle; do not treat a package built from the current checkout
as the verified 0.6.0 artifact. See [exact time windows](reactive-windows.md)
and [storage upgrades](storage.md#data-identity-and-upgrades) for current source.

This release supports `calculation`, `equipment` and [invoicing](invoicing.md)
on one embedded redb store owned by one server process. Select one model per store;
its identity is checked on every open and operation. It provides exact connected calculations, historical
invariants, private outputs, transaction-scoped DAG authority, authenticated HTTP,
replay receipts, bounded queries, model tools and verified offline recovery.
The release is suitable for bounded applications and developer harnesses within
the limits below. General model loading, a full accounting model, external effects,
distributed storage and a frontend remain separate capability gates.

The [0.6 release result](../research/29-deployment-result.md) records the verified
bundle, exact source/artifact hashes, three-model workflows and recovery checks.
The [G3d/G3e checkpoint](../research/28-settlement-refund-gate.md) owns their gate.
Calculation/equipment's larger population evidence remains
in the [G2 result](../research/24-population-scaling-result.md). Invoicing retains
64 public sources/256 outputs/512 retained roles.

## Build and verify a release bundle

From the Git checkout, using Python 3.12+, Git, Rust 1.95.0, a C/C++ toolchain,
CMake and GNU `readelf` (binutils):

```sh
python3 -B tools/package.py --out target/my-bundle
cd target/my-bundle
sha256sum --check rebase-next-0.6.0-linux-x86_64.tar.gz.sha256
tar -xzf rebase-next-0.6.0-linux-x86_64.tar.gz
cd rebase-next-0.6.0-linux-x86_64
sha256sum --check SHA256SUMS
mkdir -p target
python3 -B tools/harness.py --binary bin/rebase-next --out target/calculation-workflow --writes 0
python3 -B tools/capacity.py --binary bin/rebase-next --out target/model-recovery --populations 64
python3 -B tools/invoicing.py --binary bin/rebase-next --out target/invoicing-workflow
```

Packaging reads **committed HEAD**, exports only `rebase-next/` into a temporary
directory outside Git, and builds that copy with the locked dependencies. It
reuses the Cargo cache at `target/native-slice/build`; choose another cache with
`--target-dir`. The new output directory contains the archive, its checksum,
`build.log`, `BUNDLE.json` and `result.json`. Build failures preserve the log.
Uncommitted edits are excluded; commit intended source/tool changes first.

The archive includes `bin/rebase-next`, source, locked dependencies' version
metadata, schemas, tests, model tools and deployment templates. `BUNDLE.json`
records the exact source commit/tree/file hashes, binary hash, three model
identities and limits, Rust version and dynamic-library requirements. Source
dependencies can be downloaded by Cargo when rebuilding; they are not vendored.
Generated stores, issuer keys, tokens and plans are excluded. Public test fixture
keys remain under `tests/fixtures/` solely to reproduce the tests.

The extracted workflows use the packaged binary/tools without Git or the original
checkout. Python 3.11+ and OpenSSL are sufficient once the binary's host libraries
are available. The calculation workflow checks fixture composition, replay and
receipt archiving. Both 64-source model runs and the invoicing workflow check
source arithmetic, rollback, crash recovery and verified restore. These commands
retain private disposable data under the extracted `target/` and stop all servers
they start. Each output directory must be new.

## Run a self-contained acceptance scenario

From this directory, using Rust 1.95.0, a C/C++ toolchain and CMake for AWS-LC:

```sh
export CARGO_TARGET_DIR=target/native-slice/build
export CARGO_INCREMENTAL=0
cargo build --locked --release --bin rebase-next
python3 -B tools/test_client.py -v
python3 -B tools/harness.py --binary target/native-slice/build/release/rebase-next --out target/my-release-run --writes 128 --readers 4
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --out target/my-capacity-run
python3 -B tools/invoicing.py --binary target/native-slice/build/release/rebase-next --out target/my-invoicing-run
```

The harness exercises the calculation developer workflow and concurrent workload.
The capacity probe defaults to both models at 64, 256, 1,024 and 4,096 public
sources. Use `--models equipment` or `--models calculation` for one model, or
`--populations 64 256` for a smaller run. Each run needs a new output directory.
The [population result](../research/24-population-scaling-result.md) records
executed evidence and the observed fanout boundaries; the command alone does
not establish acceptance. See [equipment](equipment.md) for allocation semantics.

The harness requires Python 3.11+ and OpenSSL. It creates a **new** directory,
generates its own issuer key and credentials, initializes a secured store, and
exercises the real HTTP process. It performs the developer workflow, fills the
declared source limit in batches of at most 64 commands, rejects an extra source,
reconciles concurrent duplicate requests, checks one winner among competing
edits, runs atomic date moves with concurrent
root reads, invalidates a cursor, kills/reopens the process after acknowledged
commits, then backs up/restores and reads the restored service. All servers it
starts are stopped before the command exits.

The capacity probe derives allocations and calculation values from authored
sources, checks bounded selective edits and real fanout, and exercises
retargeting, lifecycle, authorization, replay, pages, restart and verified restore.
It records work counters, loaded bytes and latency in `result.json`. Oversized
fanout may reach `work_limit`; the probe verifies logical application-table
rollback and absence of a success receipt. Its reported boundary brackets apply
to those authored workloads, rather than every possible causal closure.

To exercise the retained-role ceiling or large-store credential revocation on
restored copies of accepted data, use a new output directory for each auxiliary
trial:

```sh
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --churn-from target/my-capacity-run/equipment-4096 --out target/my-churn-run
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --authority-from target/my-capacity-run --out target/my-authority-run
```

`result.json` records exact outcomes, latency, counts and Linux process memory.
The same directory retains the usable `app.redb`, `server.json`, private issuer
key, short-lived token, saved operation plans and backup/restore artifacts.
Keep it private. Start **one** instance when exploring the retained data:

```sh
target/native-slice/build/release/rebase-next serve target/my-release-run/app.redb --config target/my-release-run/server.json
```

The config contains its selected loopback port. `token-request.json` can be used
with `auth issue` and the retained issuer private key to issue a fresh token for
this disposable store. The [developer guide](developer-tools.md) shows how to
author and apply further operations. After stopping the server, use `inspect`,
`check`, `backup` and `receipts archive` as documented in the
[storage guide](storage.md). Old uncertain plans keep their original context.

Use `--writes 0` for just the D5 workflow, or 1–512 writes and 1–8 readers for
the bounded workload. Each reader performs twice the selected write count.
These options vary the measured work without changing the model's limits.
Packaged releases include the source/tooling tree plus `bin/rebase-next` and
`SHA256SUMS`. Verify the checksums, then use `--binary bin/rebase-next` in the
harness command. Generated private stores/keys are excluded from the package.
Record versions come from the current record; a newly created record's version
need not be `1`. Never manufacture a version from a local counter.

## Deploy one service on Linux

Build on a compatible target host. The supplied binary artifact targets Linux
x86_64 with glibc 2.38 or newer plus libgcc_s/libm; its manifest records the
build host and dynamic dependencies.
It is not a static cross-platform executable. Source is included so another
architecture can build its own binary with the pinned toolchain/lockfile.

The following commands install on a host you administer. They are not run by the
build or harness. Run them from the extracted bundle; for a source build, replace
`bin/rebase-next` with `target/native-slice/build/release/rebase-next`:

```sh
sudo useradd --system --home-dir /var/lib/rebase-next --shell /usr/sbin/nologin rebase-next
sudo install -m 0755 bin/rebase-next /usr/local/bin/rebase-next
sudo install -d -m 0700 -o rebase-next -g rebase-next /var/lib/rebase-next
sudo install -d -m 0750 -o root -g rebase-next /etc/rebase-next
```

Prepare identity material on the trusted operator/issuer machine:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out issuer-private.pem
openssl pkey -in issuer-private.pem -pubout -out issuer-public.pem
python3 - <<'PY'
import json
from pathlib import Path
config = json.loads(Path('deploy/server.example.json').read_text())
config['identity']['public_keys']['main'] = Path('issuer-public.pem').read_text()
Path('server.json').write_text(json.dumps(config, indent=2) + '\n')
PY
sudo install -m 0640 -o root -g rebase-next server.json /etc/rebase-next/server.json
```

Keep the private key with the issuer; the server only receives public keys.
Use a real issuer/audience convention for your application. The
[identity guide](server.md) specifies the Ed25519 JWT profile, issuance and
rotation. Generate distinct tenant and administrator UUIDs, then initialize the
new file once and install the [service unit](../deploy/rebase-next.service):

```sh
sudo -u rebase-next /usr/local/bin/rebase-next init /var/lib/rebase-next/app.redb --tenant 00000000-0000-4000-8000-000000000001 --actor 00000000-0000-4000-8000-000000000002
sudo install -m 0644 deploy/rebase-next.service /etc/systemd/system/rebase-next.service
sudo systemctl daemon-reload
sudo systemctl enable --now rebase-next
curl --fail http://127.0.0.1:8080/health
```

The default service unit and commands select `calculation`. To deploy equipment
or invoicing, place the corresponding `--model` selector **before** the command
on initialization and every subsequent operator/server invocation. For invoicing:

```sh
sudo -u rebase-next /usr/local/bin/rebase-next --model invoicing init /var/lib/rebase-next/invoicing.redb --tenant 00000000-0000-4000-8000-000000000001 --actor 00000000-0000-4000-8000-000000000002
/usr/local/bin/rebase-next --model invoicing version
```

Set the installed service's `ExecStart` to
`/usr/local/bin/rebase-next --model invoicing serve /var/lib/rebase-next/invoicing.redb --config /etc/rebase-next/server.json`
and reload systemd before starting it. The server configuration contains identity,
listen and admission settings; model selection belongs to the command line.
Use the same identity provisioning steps for every model. There is no RPC model
switch; a client uses the identity returned by `session.describe`/`model.describe`.

The sample IDs illustrate the two distinct roles; replace them with your own
canonical UUIDs and issue credentials for that administrator. `/health` is
liveness only. Issue a token using the [server guide](server.md), save it in a
private `token.txt`, and check actual readiness from the trusted client machine:

```sh
python3 -B tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt call session.describe
```

Then execute a declared query or an [invoicing fixture](invoicing.md).
Startup runs complete current-state verification.
The template limits the process to 512 MiB, 96 tasks and 1024 file descriptors;
it grants writes only to its state directory. Those are deployment limits, not
claims that every supported workload fits every constrained host.

For public access, keep the backend on loopback and configure a supported TLS
reverse proxy with connection, header/body-read deadlines and request-rate limits.
Do not expose operator files, the inspector or the issuer key. Proxy headers do
not grant authority. Clients always send a verified bearer credential to `/rpc`.
The service handles SIGTERM by draining admitted work. A deadline, connection
loss or forced stop can leave a committed operation without a delivered response;
reconcile the saved plan rather than constructing a new operation.

## Supported resource envelope

| Boundary | Enforced limit or behavior |
| --- | --- |
| Storage/tenancy | One process, one redb file, one tenant; serialized writers and concurrent snapshot readers |
| Models | `calculation`: ten public source contracts plus private Pin/Output; `equipment`: Pool 101, Delivery 205, Reservation 410, private Output 900; `invoicing`: eight public and seven private contracts |
| Calculation/equipment population | 4,096 public sources, 8,192 active outputs, 16,384 retained output reservations |
| Invoicing population | 64 public sources, 256 active outputs, 512 retained output reservations |
| Authority | 128 principals, at most eight direct parents each, 1280 reader streams opened per query |
| Mutation | 1–64 unique source commands, at most 32 returning IDs, 200000 charged engine work units |
| Query | UUID ordering through declared paths; 1–32 results and 1–128 candidate visits per page; bounded existence may be unknown |
| Exact values | Canonical integer strings with native bounds; see each authored schema; no floating money or implicit rounding |
| Receipts | 1024 per active window; offline archive advances the fence; no automatic eviction or blind retry across expiry |
| Network | 64 KiB requests; configurable 1–64 admitted workers and 1–120 second operation deadline; sample 16/15 |
| Client | 2 MiB reply cap; one call per invocation, explicit saved context and no implicit retries |
| Backup | Complete private snapshot and verified restore, capped at 64 MiB |

A work unit is an engine counter, not a CPU time or memory guarantee. Admission
permits remain held while timed-out blocking work finishes. In this 0.6.0
binary, ordered point-addressed reverse AVL indexes select affected endpoint
ranges and the prefix-gate graph preserves final producer dependencies without
pairwise graph construction. Later source range and segment-cover behavior
is documented separately; it is not part of this deployment evidence.
Full fanout still consumes work and can reject at the same fixed budget. These
paths do not make every mutation logarithmic. A global cursor revision does not
provide snapshot pagination across mutations. Reducing source
count or archiving receipts does not automatically shrink the redb file.

## Verification and upgrades

The [settlement/deployment checkpoint](../research/28-settlement-refund-gate.md)
and [population result](../research/24-population-scaling-result.md) record
their respective workload evidence and source/build identities. The
[earlier calculation release evidence](../research/evidence/2026-10-22-d6-release.json)
retains its original bounded workload and process measurements. These observations
do not establish power-loss durability, a sustained throughput target, the full
DAG/population cross-product, remote-network latency or distributed capacity.

Before replacing a deployed binary, stop the service, run `check`, create a
verified backup, and compare `version` model/store identities with the intended
release. Version 0.6.0 uses `rebase-store-4` and native codec
`native-slice-kv-4`; calculation behavior is `rebase-calculation-contract-4` and
equipment behavior is `equipment-reservations-3`. Their 0.4/0.5 identities remain
compatible. Invoicing behavior is now `invoice-assessments-2`; its 0.5 store
requires the retained 0.5 binary, with no implicit migration. Resolved declarations
also contribute to each model identity. Format 2 and 3 stores/backups
are deliberately incompatible. There is no silent migration, automatic reset or
reinterpretation of old native payloads. Keep the
previous compatible binary and its verified backups; create/check those backups
with that binary before upgrading. An older-format backup must be restored using
its compatible old binary. Use a new store when model or format identity changes
unless an explicit reviewed migration is supplied. Clean incompatible opens
preserve physical bytes; crashed stores can require allocator recovery first,
so recover them with their matching binary. Test a restored compatible
copy offline, then use one instance as the replacement. Roll back with the
pre-upgrade snapshot and its matching binary. Keep saved plans and receipt
archives for reconciliation and keep identity key backups separately.

Run the focused checks before changing a deployment build:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release --all-targets
python3 -B tools/test_client.py -v
```

Current acceptance also includes the earlier independent source-oracle corpora
at their recorded checkpoints. Rerun those when calculation, binding or storage
semantics change. Adding a transport/client wrapper does not require another
full mathematical audit.
