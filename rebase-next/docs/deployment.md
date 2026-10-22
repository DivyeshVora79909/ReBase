# ReBase Next 0.3.0 deployment and acceptance

This release supports two compiled models, `calculation` and `equipment`, on one
embedded redb store owned by one server process. Select one model per store;
its identity is checked on every open and operation. It provides exact connected calculations, historical
invariants, private outputs, transaction-scoped DAG authority, authenticated HTTP,
replay receipts, bounded queries, model tools and verified offline recovery.
The release is suitable for bounded applications and developer harnesses within
the limits below. General model loading, a full accounting model, external effects,
distributed storage and a frontend remain separate capability gates.

## Run a self-contained acceptance scenario

From this directory, using Rust 1.95.0, a C/C++ toolchain and CMake for AWS-LC:

```sh
export CARGO_TARGET_DIR=target/native-slice/build
cargo build --locked --release --bin rebase-next
python3 -B tools/test_client.py -v
python3 -B tools/harness.py --binary target/native-slice/build/release/rebase-next --out target/my-release-run --writes 128 --readers 4
```

This harness exercises the default calculation model; its dated capacity evidence
does not establish equipment workload capacity. The equipment model has focused
arithmetic, lifecycle and real HTTP acceptance through the same runtime. See
[the equipment model](equipment.md) for its allocation semantics.

The harness requires Python 3.11+ and OpenSSL. It creates a **new** directory,
generates its own issuer key and credentials, initializes a secured store, and
exercises the real HTTP process. It performs the developer workflow, fills the
64-source limit, rejects an extra source, reconciles concurrent duplicate requests,
checks one winner among competing edits, runs atomic date moves with concurrent
root reads, invalidates a cursor, kills/reopens the process after acknowledged
commits, then backs up/restores and reads the restored service. All servers it
starts are stopped before the command exits.

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
build or harness. Use the packaged `bin/rebase-next` or the release build above:

```sh
sudo useradd --system --home-dir /var/lib/rebase-next --shell /usr/sbin/nologin rebase-next
sudo install -m 0755 target/native-slice/build/release/rebase-next /usr/local/bin/rebase-next
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

The default service unit and commands select `calculation`. To deploy equipment,
place `--model equipment` **before** the command on initialization and every
subsequent operator/server invocation. For example:

```sh
sudo -u rebase-next /usr/local/bin/rebase-next --model equipment init /var/lib/rebase-next/equipment.redb --tenant 00000000-0000-4000-8000-000000000001 --actor 00000000-0000-4000-8000-000000000002
/usr/local/bin/rebase-next --model equipment version
```

Set the installed service's `ExecStart` to
`/usr/local/bin/rebase-next --model equipment serve /var/lib/rebase-next/equipment.redb --config /etc/rebase-next/server.json`
and reload systemd before starting it. The server configuration contains identity,
listen and admission settings; model selection belongs to the command line.
Use the same identity provisioning steps for either model. There is no RPC model
switch; a client uses the identity returned by `session.describe`/`model.describe`.

The sample IDs illustrate the two distinct roles; replace them with your own
canonical UUIDs and issue credentials for that administrator. `/health` is
liveness only. Check actual readiness with authenticated `session.describe`
and a declared query. Startup runs complete current-state verification.
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
| Models | `calculation`: ten public source contracts plus private Pin/Output; `equipment`: Pool 101, Delivery 205, Reservation 410, private Output 900 |
| Population | Each model: 64 public sources, 48 active outputs, 256 retained output reservations; calculation additionally caps Quote/Posting/Adjustment/Basis at 16 each |
| Authority | 128 principals, at most eight direct parents each, 1280 reader streams opened per query |
| Mutation | 1–64 unique source commands, at most 32 returning IDs, 200000 charged engine work units |
| Query | UUID ordering through declared paths; 1–32 results and 1–128 candidate visits per page; bounded existence may be unknown |
| Exact values | Canonical integer strings with native bounds; see each authored schema; no floating money or implicit rounding |
| Receipts | 1024 per active window; offline archive advances the fence; no automatic eviction or blind retry across expiry |
| Network | 64 KiB requests; configurable 1–64 admitted workers and 1–120 second operation deadline; sample 16/15 |
| Client | 2 MiB reply cap; one call per invocation, explicit saved context and no implicit retries |
| Backup | Complete private snapshot and verified restore, capped at 64 MiB |

A work unit is an engine counter, not a CPU time or memory guarantee. Admission
permits remain held while timed-out blocking work finishes. The model uses
conservative invalidation and a global cursor revision; neither promises a
minimal affected set or snapshot pagination across mutations. Reducing source
count or archiving receipts does not automatically shrink the redb file.

## Verification and upgrades

The [dated calculation release evidence](../research/evidence/2026-10-22-d6-release.json)
records the actual workload and process measurements.
It establishes bounded execution, process restart and verified restore, not a
power-loss test, sustained throughput target, full DAG/population cross-product,
remote-network latency or distributed capacity.

Before replacing a deployed binary, stop the service, run `check`, create a
verified backup, and compare `version` model/store identities with the intended
release. Version 0.3.0 changes storage to `rebase-store-3` and native codec
`native-slice-kv-3`; the model identity includes the selected compiled binding.
Format 2 stores/backups are deliberately incompatible. There is no silent
migration, automatic reset or reinterpretation of old native payloads. Keep the
previous compatible binary and its verified backups; create/check those backups
with that binary before upgrading. A format 2 backup must be restored using its
compatible old binary, not the 0.3.0 restore command. Use a new store for 0.3.0
unless an explicit reviewed migration is supplied. Test a restored compatible
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
